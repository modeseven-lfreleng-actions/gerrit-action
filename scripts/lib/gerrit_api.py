#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Gerrit REST API client for DEVELOPMENT_BECOME_ANY_ACCOUNT mode.

This module provides a clean Python interface for interacting with Gerrit's
REST API when running in DEVELOPMENT_BECOME_ANY_ACCOUNT mode. It handles:

- Cookie-based session authentication (becoming any account)
- XSRF token management for write operations
- JSON response parsing (stripping Gerrit's magic prefix)
- Account and SSH key management

Usage:
    from gerrit_api import GerritDevClient

    client = GerritDevClient("http://localhost:8080")
    client.become_account(1000000)

    # Create a user
    account = client.create_account("testuser", name="Test User")

    # Add SSH keys
    client.add_ssh_key(account["_account_id"], "ssh-ed25519 AAAA... user@host")

    # Add to Administrators group
    client.add_to_group(account["_account_id"], "Administrators")
"""

from __future__ import annotations

import contextlib
import json
import logging
import sys
import time
from typing import Any, cast
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)

# Gerrit API constants
GERRIT_MAGIC_JSON_PREFIX = ")]}'\n"
DEFAULT_TIMEOUT = 30
DEFAULT_ADMIN_ACCOUNTS = [1000000, 1]  # Gerrit 3.x uses 1000000, older uses 1


class GerritAPIError(Exception):
    """Base exception for Gerrit API errors."""

    def __init__(
        self, message: str, status_code: int | None = None, response_text: str = ""
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class GerritAuthError(GerritAPIError):
    """Authentication failed."""


class GerritNotFoundError(GerritAPIError):
    """Resource not found."""


class GerritConflictError(GerritAPIError):
    """Resource already exists or conflict."""


def _strip_gerrit_prefix(content: str) -> str:
    """Strip Gerrit's magic JSON prefix from response content."""
    if content.startswith(GERRIT_MAGIC_JSON_PREFIX):
        return content[len(GERRIT_MAGIC_JSON_PREFIX) :]
    # Also handle without newline
    elif content.startswith(")]}'"):
        return content[4:]
    return content


def _parse_response(response: requests.Response, allow_non_json: bool = False) -> Any:
    """Parse Gerrit API response, handling magic prefix and errors.

    Args:
        response: The requests Response object
        allow_non_json: If True, return raw text for non-JSON responses and
            JSON decode failures instead of raising an error.
    """
    content_type = response.headers.get("content-type", "")

    # Check for errors first
    if response.status_code == 401:
        raise GerritAuthError(
            "Authentication failed",
            status_code=response.status_code,
            response_text=response.text,
        )
    if response.status_code == 403:
        raise GerritAuthError(
            f"Permission denied: {response.text}",
            status_code=response.status_code,
            response_text=response.text,
        )
    if response.status_code == 404:
        raise GerritNotFoundError(
            "Resource not found",
            status_code=response.status_code,
            response_text=response.text,
        )
    if response.status_code == 409:
        raise GerritConflictError(
            f"Conflict: {response.text}",
            status_code=response.status_code,
            response_text=response.text,
        )
    if not response.ok:
        raise GerritAPIError(
            f"API request failed: {response.text}",
            status_code=response.status_code,
            response_text=response.text,
        )

    # Handle empty responses (common for successful PUT/POST/DELETE)
    if not response.content:
        return None

    content = response.text.strip()
    if not content:
        return None

    # Parse JSON if content type indicates JSON
    if "application/json" in content_type:
        content = _strip_gerrit_prefix(content)
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            if allow_non_json:
                return content
            raise GerritAPIError(
                f"Failed to parse JSON response: {e}",
                status_code=response.status_code,
                response_text=response.text,
            ) from e

    # For non-JSON responses, return raw content or raise
    if allow_non_json:
        return content
    raise GerritAPIError(
        f"Unexpected non-JSON content-type: {content_type}",
        status_code=response.status_code,
        response_text=response.text,
    )


class GerritDevClient:
    """
    Gerrit REST API client for DEVELOPMENT_BECOME_ANY_ACCOUNT mode.

    This client handles cookie-based session authentication by "becoming"
    a specified account, and properly manages XSRF tokens for write operations.

    Args:
        base_url: Base URL of the Gerrit server (e.g., "http://localhost:8080")
        verify_ssl: Whether to verify SSL certificates (default: True)
        timeout: Request timeout in seconds (default: 30)

    Example:
        >>> client = GerritDevClient("http://localhost:8080")
        >>> client.become_account(1000000)
        >>> client.get_account("self")
        {'_account_id': 1000000, 'name': 'Administrator', ...}
    """

    def __init__(
        self,
        base_url: str,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._xsrf_token: str | None = None
        self._account_id: int | None = None

        # Create session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _make_url(self, endpoint: str, authenticated: bool = True) -> str:
        """Construct full URL for an endpoint."""
        endpoint = endpoint.lstrip("/")
        if authenticated and not endpoint.startswith("a/"):
            endpoint = f"a/{endpoint}"
        return urljoin(self.base_url + "/", endpoint)

    def _get_headers(self, content_type: str | None = None) -> dict[str, str]:
        """Get headers including XSRF token if available."""
        headers = {"Accept": "application/json"}
        if self._xsrf_token:
            headers["X-Gerrit-Auth"] = self._xsrf_token
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _extract_xsrf_token(self) -> str | None:
        """Extract XSRF token from session cookies."""
        for cookie in self.session.cookies:
            if cookie.name == "XSRF_TOKEN":
                return str(cookie.value)
        return None

    def become_account(self, account_id: int) -> bool:
        """
        Authenticate by "becoming" the specified account.

        In DEVELOPMENT_BECOME_ANY_ACCOUNT mode, Gerrit allows becoming any
        account by visiting /login/?account_id=<id>. This sets session cookies
        including the XSRF token needed for write operations.

        Args:
            account_id: The account ID to become (e.g., 1000000 for default admin)

        Returns:
            True if authentication succeeded

        Raises:
            GerritAuthError: If authentication fails
        """
        # Login endpoint lives under the same context path as all other endpoints.
        # When Gerrit is configured with httpd.listenUrl that includes a path
        # (e.g., http://*:8080/r/), the login endpoint is at /r/login/, not /login/.
        login_url = f"{self.base_url}/login/?account_id={account_id}"
        logger.debug(f"Becoming account {account_id} via {login_url}")

        response = self.session.get(
            login_url,
            allow_redirects=True,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

        # Log detailed response information for debugging authentication
        # failures (e.g. OOTB redirect issues, context-path mismatches).
        logger.debug(
            f"Login response: HTTP {response.status_code}, final URL: {response.url}"
        )
        if response.history:
            for i, r in enumerate(response.history):
                logger.debug(
                    f"  redirect [{i}]: HTTP {r.status_code} -> "
                    f"{r.headers.get('Location', '(no Location header)')}"
                )
        cookie_names = [c.name for c in self.session.cookies]
        logger.debug(f"Session cookies after login: {cookie_names}")

        # Check for GerritAccount cookie
        has_account_cookie = any(
            c.name == "GerritAccount" for c in self.session.cookies
        )

        if not has_account_cookie:
            raise GerritAuthError(
                f"Failed to become account {account_id}: no session cookie set "
                f"(HTTP {response.status_code}, final URL: {response.url})",
                status_code=response.status_code,
            )

        # Extract and store XSRF token
        self._xsrf_token = self._extract_xsrf_token()
        self._account_id = account_id

        logger.debug(
            f"Successfully became account {account_id}, "
            f"XSRF token: {'present' if self._xsrf_token else 'missing'}"
        )

        return True

    def _create_first_account(self) -> int:
        """Create the first account on a fresh Gerrit instance.

        In ``DEVELOPMENT_BECOME_ANY_ACCOUNT`` mode, the
        ``BecomeAnyAccountLoginServlet`` exposes an
        ``?action=create_account`` endpoint (via POST) that:

        1. Creates a new account with an auto-generated username
           (``user1``, ``user2``, …) and a UUID-based external ID.
        2. Logs the session in as the newly created account (sets the
           ``GerritAccount`` cookie).
        3. Redirects to the Gerrit root.

        This is the **correct** bootstrap mechanism for a fresh instance
        where zero accounts exist.  The older ``?account_id=X`` approach
        requires the account to already be present in the database.

        Returns:
            The ``_account_id`` of the newly created account.

        Raises:
            GerritAuthError: If account creation or authentication fails.
        """
        login_url = f"{self.base_url}/login/"
        logger.info("Creating first account via login servlet (action=create_account)")
        logger.debug(f"POST {login_url} data=action=create_account")

        try:
            response = self.session.post(
                login_url,
                data={"action": "create_account"},
                allow_redirects=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except Exception as exc:
            raise GerritAuthError(
                f"Bootstrap POST to {login_url} failed: {exc}"
            ) from exc

        logger.debug(
            f"Bootstrap response: HTTP {response.status_code}, "
            f"final URL: {response.url}"
        )
        if response.history:
            for i, r in enumerate(response.history):
                logger.debug(
                    f"  redirect [{i}]: HTTP {r.status_code} -> "
                    f"{r.headers.get('Location', '(no Location header)')}"
                )
        cookie_names = [c.name for c in self.session.cookies]
        logger.debug(f"Session cookies after bootstrap: {cookie_names}")

        # Verify that the servlet set a session cookie
        has_account_cookie = any(
            c.name == "GerritAccount" for c in self.session.cookies
        )
        if not has_account_cookie:
            raise GerritAuthError(
                "Bootstrap account creation did not set a session cookie "
                f"(HTTP {response.status_code}, final URL: {response.url})",
                status_code=response.status_code,
            )

        # Extract XSRF token (needed for subsequent write operations)
        self._xsrf_token = self._extract_xsrf_token()

        # Discover the account ID of the account we just created
        try:
            account_info = self.get_account("self")
            account_id: int = account_info["_account_id"]
        except (GerritAPIError, KeyError) as exc:
            raise GerritAuthError(
                "Bootstrap account was created but failed to retrieve "
                f"account details: {exc}"
            ) from exc

        self._account_id = account_id
        logger.info(f"Bootstrapped first account (ID: {account_id})")
        return account_id

    def become_admin(self) -> int:
        """Become an admin account, bootstrapping if necessary.

        Authentication strategy (each step is attempted only if the
        previous one failed):

        1. **Try known admin account IDs** – on a previously initialised
           instance accounts 1000000 and 1 typically exist already.
        2. **Bootstrap via ``action=create_account``** – on a *fresh*
           instance no accounts exist.  The ``BecomeAnyAccountLoginServlet``
           can create the first account and authenticate us in one step.
        3. **Retry known IDs** – the bootstrap POST may have created the
           account as a side-effect but failed to set the session cookie
           (e.g. due to a context-path redirect mismatch).  A brief pause
           lets the account be indexed, then we retry ``?account_id=X``.

        Returns:
            The account ID that was successfully authenticated.

        Raises:
            GerritAuthError: If no admin account could be authenticated
                after all strategies have been exhausted.
        """
        errors: list[str] = []

        # --- Pass 1: try known admin account IDs (fast path) ----------------
        for account_id in DEFAULT_ADMIN_ACCOUNTS:
            try:
                self.become_account(account_id)
                logger.info(f"Authenticated as admin account {account_id}")
                return account_id
            except GerritAuthError as exc:
                logger.debug(f"become_account({account_id}) failed: {exc}")
                errors.append(f"become({account_id}): {exc}")

        # --- Pass 2: bootstrap first account via login servlet ---------------
        logger.info(
            "No existing admin account found. "
            "Bootstrapping first account via login servlet..."
        )
        try:
            account_id = self._create_first_account()
            return account_id
        except GerritAuthError as exc:
            logger.warning(f"Bootstrap account creation failed: {exc}")
            errors.append(f"bootstrap: {exc}")

        # --- Pass 3: retry known IDs after bootstrap side-effect -------------
        # The bootstrap POST may have created the account even though the
        # redirect did not produce a session cookie.  Wait briefly for the
        # account to be indexed and try again.
        logger.info("Retrying known admin account IDs after bootstrap attempt...")
        time.sleep(2)
        for account_id in DEFAULT_ADMIN_ACCOUNTS:
            try:
                self.become_account(account_id)
                logger.info(
                    f"Authenticated as admin account {account_id} "
                    "(post-bootstrap retry)"
                )
                return account_id
            except GerritAuthError as exc:
                logger.debug(
                    f"become_account({account_id}) post-bootstrap failed: {exc}"
                )
                errors.append(f"retry({account_id}): {exc}")

        # All strategies exhausted
        error_detail = "; ".join(errors)
        raise GerritAuthError(
            "Failed to authenticate as any admin account. "
            f"Strategies tried: {error_detail}"
        )

    def get(self, endpoint: str, **kwargs: Any) -> Any:
        """
        Make an authenticated GET request.

        Args:
            endpoint: API endpoint (e.g., "accounts/self")
            **kwargs: Additional arguments to pass to requests

        Returns:
            Parsed JSON response
        """
        url = self._make_url(endpoint)
        headers = self._get_headers()
        headers.update(kwargs.pop("headers", {}))

        response = self.session.get(
            url,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        return _parse_response(response)

    def put(
        self,
        endpoint: str,
        data: dict[str, Any] | str | None = None,
        content_type: str = "application/json",
        **kwargs: Any,
    ) -> Any:
        """
        Make an authenticated PUT request.

        Args:
            endpoint: API endpoint
            data: Request body (dict for JSON, str for plain text)
            content_type: Content-Type header value
            **kwargs: Additional arguments to pass to requests

        Returns:
            Parsed JSON response
        """
        url = self._make_url(endpoint)
        headers = self._get_headers(content_type)
        headers.update(kwargs.pop("headers", {}))

        body: str | None = json.dumps(data) if isinstance(data, dict) else data

        response = self.session.put(
            url,
            data=body,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        return _parse_response(response)

    def post(
        self,
        endpoint: str,
        data: dict[str, Any] | str | None = None,
        content_type: str = "application/json",
        **kwargs: Any,
    ) -> Any:
        """
        Make an authenticated POST request.

        Args:
            endpoint: API endpoint
            data: Request body (dict for JSON, str for plain text)
            content_type: Content-Type header value
            **kwargs: Additional arguments to pass to requests

        Returns:
            Parsed JSON response
        """
        url = self._make_url(endpoint)
        headers = self._get_headers(content_type)
        headers.update(kwargs.pop("headers", {}))

        body: str | None = json.dumps(data) if isinstance(data, dict) else data

        response = self.session.post(
            url,
            data=body,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        return _parse_response(response)

    def delete(self, endpoint: str, **kwargs: Any) -> Any:
        """
        Make an authenticated DELETE request.

        Args:
            endpoint: API endpoint
            **kwargs: Additional arguments to pass to requests

        Returns:
            Parsed JSON response
        """
        url = self._make_url(endpoint)
        headers = self._get_headers()
        headers.update(kwargs.pop("headers", {}))

        response = self.session.delete(
            url,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        return _parse_response(response)

    # =========================================================================
    # Account Management
    # =========================================================================

    def get_account(self, account: str | int) -> dict[str, Any]:
        """
        Get account details.

        Args:
            account: Account identifier (ID, username, email, or "self")

        Returns:
            Account info dict with _account_id, name, email, username, etc.
        """
        return cast(dict[str, Any], self.get(f"accounts/{account}"))

    def account_exists(self, account: str | int) -> bool:
        """Check if an account exists."""
        try:
            self.get_account(account)
            return True
        except GerritNotFoundError:
            return False

    def create_account(
        self,
        username: str,
        name: str | None = None,
        email: str | None = None,
        ssh_key: str | None = None,
        groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new account.

        Args:
            username: Username for the new account
            name: Full name (optional, defaults to username)
            email: Email address (optional)
            ssh_key: SSH public key to add (optional)
            groups: List of group names to add the account to (optional)

        Returns:
            Created account info

        Raises:
            GerritConflictError: If account already exists
        """
        payload: dict[str, Any] = {"username": username}
        if name:
            payload["name"] = name
        if email:
            payload["email"] = email
        if ssh_key:
            payload["ssh_key"] = ssh_key
        if groups:
            payload["groups"] = groups

        return cast(dict[str, Any], self.put(f"accounts/{username}", data=payload))

    def get_or_create_account(
        self,
        username: str,
        name: str | None = None,
        email: str | None = None,
    ) -> dict[str, Any]:
        """
        Get an existing account or create it if it doesn't exist.

        Args:
            username: Username to look up or create
            name: Full name for new account
            email: Email for new account

        Returns:
            Account info dict
        """
        try:
            return self.get_account(username)
        except GerritNotFoundError:
            try:
                return self.create_account(username, name=name, email=email)
            except GerritConflictError:
                # Race condition - account was created between check and create
                return self.get_account(username)

    def set_account_name(self, account: str | int, name: str) -> str:
        """Set the full name for an account."""
        return cast(str, self.put(f"accounts/{account}/name", data={"name": name}))

    # =========================================================================
    # SSH Key Management
    # =========================================================================

    def list_ssh_keys(self, account: str | int = "self") -> list[dict[str, Any]]:
        """
        List SSH keys for an account.

        Args:
            account: Account identifier (default: "self")

        Returns:
            List of SSH key info dicts
        """
        return cast(list[dict[str, Any]], self.get(f"accounts/{account}/sshkeys"))

    def add_ssh_key(self, account: str | int, ssh_key: str) -> dict[str, Any]:
        """
        Add an SSH public key to an account.

        Args:
            account: Account identifier (ID, username, or "self")
            ssh_key: SSH public key in OpenSSH format

        Returns:
            Added SSH key info

        Raises:
            GerritAPIError: If the key is invalid
        """
        return cast(
            dict[str, Any],
            self.post(
                f"accounts/{account}/sshkeys",
                data=ssh_key,
                content_type="text/plain",
            ),
        )

    def add_ssh_keys(
        self, account: str | int, ssh_keys: list[str]
    ) -> list[dict[str, Any]]:
        """
        Add multiple SSH keys to an account.

        Args:
            account: Account identifier
            ssh_keys: List of SSH public keys

        Returns:
            List of added SSH key infos
        """
        results = []
        for key in ssh_keys:
            key = key.strip()
            if not key or key.startswith("#"):
                continue
            try:
                result = self.add_ssh_key(account, key)
                results.append(result)
                logger.debug(f"Added SSH key {result.get('seq', '?')} to {account}")
            except GerritConflictError:
                logger.debug(f"SSH key already exists for {account}")
            except GerritAPIError as e:
                logger.warning(f"Failed to add SSH key to {account}: {e}")
        return results

    def delete_ssh_key(self, account: str | int, key_seq: int) -> None:
        """Delete an SSH key by sequence number."""
        self.delete(f"accounts/{account}/sshkeys/{key_seq}")

    # =========================================================================
    # Group Management
    # =========================================================================

    def get_group(self, group: str) -> dict[str, Any]:
        """Get group details."""
        return cast(dict[str, Any], self.get(f"groups/{group}"))

    def list_group_members(self, group: str) -> list[dict[str, Any]]:
        """List members of a group."""
        return cast(list[dict[str, Any]], self.get(f"groups/{group}/members"))

    def add_to_group(self, account: str | int, group: str) -> dict[str, Any] | None:
        """
        Add an account to a group.

        Args:
            account: Account identifier
            group: Group name (e.g., "Administrators")

        Returns:
            Account info of the added member, or None if response isn't JSON
        """
        url = self._make_url(f"groups/{group}/members/{account}")
        headers = self._get_headers()

        response = self.session.put(
            url,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

        # Group membership PUT may return non-JSON response on success
        result = _parse_response(response, allow_non_json=True)
        if isinstance(result, dict):
            return cast(dict[str, Any], result)
        return None

    def remove_from_group(self, account: str | int, group: str) -> None:
        """Remove an account from a group."""
        self.delete(f"groups/{group}/members/{account}")

    # =========================================================================
    # Cache Management
    # =========================================================================

    def flush_cache(self, cache_name: str | None = None) -> None:
        """
        Flush Gerrit caches.

        Args:
            cache_name: Specific cache to flush, or None to flush important caches
        """
        if cache_name:
            with contextlib.suppress(GerritAPIError):
                self.post(f"config/server/caches/{cache_name}/flush")
        else:
            # Flush caches important for account management
            # Note: Cache names vary by Gerrit version
            for cache in [
                "accounts",
                "groups",
                "sshkeys",
                "ldap_groups",
            ]:
                try:
                    self.post(f"config/server/caches/{cache}/flush")
                    logger.debug(f"Flushed cache: {cache}")
                except GerritAPIError:
                    pass  # Cache may not exist or flush not supported

    # =========================================================================
    # High-level Operations
    # =========================================================================

    def setup_user_with_ssh_keys(
        self,
        username: str,
        ssh_keys: list[str],
        name: str | None = None,
        email: str | None = None,
        add_to_admins: bool = True,
    ) -> dict[str, Any]:
        """
        Set up a user account with SSH keys.

        This is a high-level operation that:
        1. Creates the account if it doesn't exist
        2. Adds the provided SSH keys
        3. Optionally adds the user to Administrators group
        4. Flushes relevant caches

        Args:
            username: Username to create/update
            ssh_keys: List of SSH public keys to add
            name: Full name (defaults to username)
            email: Email address (defaults to username@example.com)
            add_to_admins: Whether to add to Administrators group

        Returns:
            Account info dict
        """
        logger.info(f"Setting up user: {username}")

        # Default values
        if not name:
            name = username
        if not email:
            email = f"{username}@example.com"

        # Get or create account
        account = self.get_or_create_account(username, name=name, email=email)
        account_id = account["_account_id"]
        logger.info(f"Account ID: {account_id}")

        # Add SSH keys
        if ssh_keys:
            # Filter empty lines and comments
            valid_keys = [
                k.strip()
                for k in ssh_keys
                if k.strip() and not k.strip().startswith("#")
            ]
            if valid_keys:
                added = self.add_ssh_keys(account_id, valid_keys)
                logger.info(f"Added {len(added)} SSH keys")

        # Add to Administrators group
        if add_to_admins:
            try:
                self.add_to_group(account_id, "Administrators")
                logger.info(f"Added {username} to Administrators group")
            except GerritConflictError:
                logger.debug(f"{username} already in Administrators group")
            except GerritAPIError as e:
                logger.warning(f"Failed to add to Administrators: {e}")

        # Flush caches
        self.flush_cache()
        logger.info(f"User {username} configured successfully")

        return account


def validate_ssh_key(key: str) -> bool:
    """
    Validate SSH public key format.

    Args:
        key: SSH public key string

    Returns:
        True if the key appears to be valid
    """
    key = key.strip()
    if not key or key.startswith("#"):
        return True  # Empty or comment is OK (will be skipped)

    # Valid SSH key types
    valid_types = (
        "ssh-rsa",
        "ssh-ed25519",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ssh-ed25519",
        "sk-ecdsa-sha2-nistp256",
    )

    parts = key.split()
    if len(parts) < 2:
        return False

    return parts[0] in valid_types


def parse_ssh_keys(keys_string: str) -> list[str]:
    """
    Parse a string containing one or more SSH keys.

    Args:
        keys_string: Newline-separated SSH public keys

    Returns:
        List of individual SSH key strings
    """
    keys = []
    for line in keys_string.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            if validate_ssh_key(line):
                keys.append(line)
            else:
                logger.warning(f"Invalid SSH key format: {line[:50]}...")
    return keys


# =============================================================================
# CLI Interface
# =============================================================================


def main() -> int:
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Gerrit API client for DEVELOPMENT_BECOME_ANY_ACCOUNT mode"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        help="Gerrit base URL",
    )
    parser.add_argument(
        "--account-id",
        type=int,
        default=1000000,
        help="Account ID to become",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # whoami command
    subparsers.add_parser("whoami", help="Show current account info")

    # create-user command
    create_parser = subparsers.add_parser("create-user", help="Create a user account")
    create_parser.add_argument("username", help="Username to create")
    create_parser.add_argument("--name", help="Full name")
    create_parser.add_argument("--email", help="Email address")
    create_parser.add_argument("--ssh-key", help="SSH public key to add")
    create_parser.add_argument(
        "--admin",
        action="store_true",
        help="Add to Administrators group",
    )

    # add-ssh-key command
    ssh_parser = subparsers.add_parser("add-ssh-key", help="Add SSH key to account")
    ssh_parser.add_argument("account", help="Account username or ID")
    ssh_parser.add_argument("ssh_key", help="SSH public key")

    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        client = GerritDevClient(args.url)
        client.become_account(args.account_id)

        if args.command == "whoami":
            account = client.get_account("self")
            print(json.dumps(account, indent=2))

        elif args.command == "create-user":
            ssh_keys = [args.ssh_key] if args.ssh_key else []
            account = client.setup_user_with_ssh_keys(
                username=args.username,
                ssh_keys=ssh_keys,
                name=args.name,
                email=args.email,
                add_to_admins=args.admin,
            )
            print(json.dumps(account, indent=2))

        elif args.command == "add-ssh-key":
            result = client.add_ssh_key(args.account, args.ssh_key)
            print(json.dumps(result, indent=2))

        return 0

    except GerritAPIError as e:
        logger.error(f"API error: {e}")
        if e.response_text:
            logger.error(f"Response: {e.response_text}")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
