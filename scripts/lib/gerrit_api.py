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
import http.cookiejar
import json
import logging
import sys
import time
from typing import Any, cast
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)


def _cookie_names_from_header(cookie_header: str) -> set[str]:
    """Parse cookie names from a ``Cookie`` header value.

    Returns a set of cookie names (the part before ``=`` in each
    ``name=value`` pair separated by ``; ``).
    """
    names: set[str] = set()
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            names.add(pair.split("=", 1)[0])
    return names


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


def _looks_like_method_mangle(exc: GerritAPIError) -> bool:
    """Detect Gerrit's "Not implemented: <garbled>POST <uri>" response.

    Gerrit's :class:`RestApiServlet` formats unknown-HTTP-method errors
    as ``"Not implemented: <method> <uri>"``.  We have seen the method
    portion arrive corrupted (e.g. ``alPOST``, ``lPOST``) when several
    POSTs are issued in quick succession over a single keepalive TCP
    connection through certain proxy stacks.  The HTTP verb our client
    actually sends is correct; the corruption happens between the
    socket and the servlet.

    We use this helper to distinguish that benign, retry-friendly
    pattern from genuine API errors so we can suppress the noisy
    warning and try once on a fresh connection.

    Returns ``True`` only when the verb token is an *actually mangled*
    POST (it ends with ``POST`` but is not exactly ``POST``) and, when
    the status code is known, it is the ``405 Method Not Allowed`` that
    Gerrit returns for an unrecognised method.  This avoids masking a
    genuine ``405`` (e.g. an endpoint that truly does not accept POST),
    whose verb token is the clean ``POST``.
    """
    # A real "Not implemented" response uses HTTP 405; if we have a
    # status code and it is something else, this is not the mangle
    # pattern.
    if exc.status_code is not None and exc.status_code != 405:
        return False
    body = (exc.response_text or str(exc) or "").strip()
    if "Not implemented:" not in body:
        return False
    after = body.split("Not implemented:", 1)[1].strip()
    # Format is "<method> <uri>"; inspect only the verb token so a
    # clean "POST /..." (a genuine 405) is not treated as corruption.
    verb = after.split(None, 1)[0] if after else ""
    return verb.endswith("POST") and verb != "POST"


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

    def _dismiss_ootb_redirect(self) -> None:
        """Pre-access the Gerrit base URL to clear the OOTB first-time redirect.

        On a **fresh** Gerrit instance the ``FirstTimeRedirect`` servlet
        filter intercepts every request (including ``/login/``) and
        redirects it to ``httpd.firstTimeRedirectUrl`` *before* the
        ``BecomeAnyAccountLoginServlet`` has a chance to run.  This
        means the session cookie is never set on the first login
        attempt.

        Fetching the base URL once satisfies the OOTB filter so that
        subsequent requests (in particular ``/login/``) are handled
        normally by the Gerrit servlets.
        """
        base_page_url = self.base_url + "/"
        logger.debug(
            "Pre-accessing %s to dismiss OOTB first-time redirect", base_page_url
        )
        try:
            self.session.get(
                base_page_url,
                allow_redirects=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except Exception as exc:
            # Non-fatal: the main login flow will surface any real errors.
            logger.debug("OOTB pre-access failed (non-fatal): %s", exc)

    def _ensure_xsrf_token(self) -> None:
        """Fetch the Gerrit index page to obtain the XSRF_TOKEN cookie.

        The XSRF token is set by the PolyGerrit front-end page.  When
        the login redirect chain does not end on the main Gerrit page
        (e.g. because it lands on a 404 from the OOTB plugin-manager
        intro page), the token cookie is never set.

        This method explicitly fetches the base URL while the session
        already carries the ``GerritAccount`` cookie, which causes
        Gerrit to emit the ``XSRF_TOKEN`` cookie in the response.
        """
        if self._xsrf_token:
            return  # Already have one

        base_page_url = self.base_url + "/"
        logger.debug(
            "XSRF token missing after login; fetching %s to obtain it",
            base_page_url,
        )
        try:
            self.session.get(
                base_page_url,
                allow_redirects=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            self._xsrf_token = self._extract_xsrf_token()
            if self._xsrf_token:
                logger.debug("XSRF token obtained from base page ✅")
            else:
                logger.warning(
                    "XSRF token still missing after fetching base page; "
                    "write operations may fail"
                )
        except Exception as exc:
            logger.warning("Failed to fetch base page for XSRF token: %s", exc)

    def become_account(self, account_id: int) -> bool:
        """
        Authenticate by "becoming" the specified account.

        In DEVELOPMENT_BECOME_ANY_ACCOUNT mode, Gerrit allows becoming any
        account by visiting /login/?account_id=<id>. This sets session cookies
        including the XSRF token needed for write operations.

        On a fresh Gerrit instance the OOTB ``FirstTimeRedirect`` filter
        can intercept the login request, so we first dismiss it by
        fetching the base URL.  The login request itself is made with
        ``allow_redirects=False`` to capture the ``Set-Cookie`` header
        directly from the 302 response, avoiding redirect chains that
        may strip the context path and land on a 404.  After obtaining
        the session cookie we explicitly fetch the base page to acquire
        the XSRF token (which is set by the PolyGerrit front-end).

        After obtaining the session cookie, this method verifies that the
        cookie would actually be transmitted by preparing (but not sending)
        a request and inspecting the ``Cookie`` header.  Python's
        ``http.cookiejar`` has known issues with ``localhost`` cookies
        (they can be stored in the jar but never sent back), so the
        verification step catches this and applies a domain workaround.
        If the workaround is needed, ``accounts/self`` is called to
        confirm the session is valid end-to-end.

        Args:
            account_id: The account ID to become (e.g., 1000000 for default admin)

        Returns:
            True if authentication succeeded

        Raises:
            GerritAuthError: If authentication fails
        """
        # --- Dismiss OOTB first-time redirect on fresh instances -----------
        # The FirstTimeRedirect filter intercepts *all* requests (including
        # /login/) on the very first access.  Pre-fetching the base URL
        # satisfies the filter so that /login/ is handled normally.
        self._dismiss_ootb_redirect()

        # Login endpoint lives under the same context path as all other endpoints.
        # When Gerrit is configured with httpd.listenUrl that includes a path
        # (e.g., http://*:8080/r/), the login endpoint is at /r/login/, not /login/.
        login_url = f"{self.base_url}/login/?account_id={account_id}"
        logger.debug(f"Becoming account {account_id} via {login_url}")

        # --- Do NOT follow redirects ----------------------------------------
        # The login servlet returns a 302 with Set-Cookie in the *first*
        # response.  Following redirects can land on pages outside the
        # context path (e.g. /plugins/plugin-manager/static/intro.html)
        # which returns 404 and may confuse cookie handling.  We only
        # need the Set-Cookie header from the 302 itself.
        response = self.session.get(
            login_url,
            allow_redirects=False,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

        # Log detailed response information for debugging authentication
        # failures (e.g. OOTB redirect issues, context-path mismatches).
        logger.debug(
            f"Login response: HTTP {response.status_code}, "
            f"Location: {response.headers.get('Location', '(none)')}"
        )
        cookie_details = [(c.name, c.domain, c.path) for c in self.session.cookies]
        logger.debug(f"Session cookies after login: {cookie_details}")

        # Check for GerritAccount cookie
        has_account_cookie = any(
            c.name == "GerritAccount" for c in self.session.cookies
        )

        if not has_account_cookie:
            raise GerritAuthError(
                f"Failed to become account {account_id}: no session cookie set "
                f"(HTTP {response.status_code}, "
                f"Location: {response.headers.get('Location', '(none)')})",
                status_code=response.status_code,
            )

        # Extract and store XSRF token (may be missing at this point)
        self._xsrf_token = self._extract_xsrf_token()
        self._account_id = account_id

        # --- Ensure XSRF token is available ---------------------------------
        # The XSRF_TOKEN cookie is set by the PolyGerrit front-end page,
        # not by the login servlet itself.  Since we no longer follow the
        # redirect chain, we must explicitly fetch the base page.
        self._ensure_xsrf_token()

        logger.debug(
            f"Successfully became account {account_id}, "
            f"XSRF token: {'present' if self._xsrf_token else 'missing'}"
        )

        # --- Verify the cookie actually works ---
        # Python's http.cookiejar can silently refuse to send cookies for
        # "localhost" due to domain-matching rules.  Detect this by making
        # a test request and checking whether the cookie was transmitted.
        self._verify_auth_or_fix_cookies(account_id)

        return True

    def _verify_auth_or_fix_cookies(self, account_id: int) -> None:
        """Verify session cookies are sent and fix localhost cookie issues.

        After ``become_account`` stores the session cookies, this method
        prepares (but does not send) a request to ``accounts/self`` and
        inspects the ``Cookie`` header to confirm that the session cookie
        would actually be transmitted.  If the header looks good, the
        method returns immediately **without** making a network call
        (header-only verification).

        If the cookie exists in the jar but is **not** present in the
        prepared header (a known ``http.cookiejar`` problem with
        ``localhost`` domains), this method removes the original
        localhost-scoped cookies and re-adds them with an empty domain
        so that ``requests`` will attach them unconditionally.  After
        the fix-up, ``accounts/self`` is called to confirm the session
        is valid end-to-end.

        Raises
        ------
        GerritAuthError
            If the cookie cannot be made to work after the fix-up.
        """
        verify_url = self._make_url("accounts/self")

        # Prepare (but don't send) the request to inspect headers
        req = requests.Request("GET", verify_url, headers=self._get_headers())
        prepared = self.session.prepare_request(req)
        cookie_header = prepared.headers.get("Cookie", "")

        if "GerritAccount" in _cookie_names_from_header(cookie_header):
            logger.debug("Auth verification: cookie is transmitted ✅")
            return

        # Guard: only apply the localhost workaround when the base URL
        # actually targets a loopback address.  This prevents cookies
        # from being broadened to domain="" when talking to a real host.
        parsed = urlparse(self.base_url)
        hostname = (parsed.hostname or "").lower()
        is_localhost = hostname in ("localhost", "127.0.0.1", "::1")

        if not is_localhost:
            raise GerritAuthError(
                f"Auth cookie exists in jar but is not being transmitted for host "
                f"'{hostname}'. Localhost workaround is disabled; authenticated "
                f"session cannot be established."
            )

        # Cookie exists in jar but won't be sent — likely a localhost
        # domain-matching issue.
        logger.warning(
            "Auth cookie exists in jar but is not being transmitted "
            "(localhost cookie-jar bug). Applying workaround…"
        )
        logger.debug(
            "Cookie domains in jar: %s",
            [(c.name, c.domain, c.path) for c in self.session.cookies],
        )

        # Workaround: replace each localhost-scoped cookie with one whose
        # domain is empty so the jar sends it unconditionally.
        # We clone all original attributes and only override the domain
        # to avoid dropping flags like secure, expires, etc.
        fixed: list[str] = []
        originals: list[Any] = []
        for cookie in list(self.session.cookies):
            domain = getattr(cookie, "domain", "")
            if domain and "localhost" in str(domain):
                originals.append(cookie)
                fixed.append(getattr(cookie, "name", ""))

        # Remove originals, then re-add with empty domain
        for cookie in originals:
            c_name = getattr(cookie, "name", "")
            c_domain = getattr(cookie, "domain", "")
            c_path = getattr(cookie, "path", "/")

            # Defensive: remove any pre-existing empty-domain cookie
            # with the same name to avoid duplicates if run twice.
            with contextlib.suppress(KeyError):
                self.session.cookies.clear(domain="", path=c_path, name=c_name)
            # Remove the original localhost-scoped cookie.
            # cookiejar may store the domain in various forms, so
            # wrap each clear() individually to tolerate KeyError.
            with contextlib.suppress(KeyError):
                self.session.cookies.clear(domain=c_domain, path=c_path, name=c_name)
            # Also sweep any remaining cookies with the same name
            # that still carry a localhost domain.
            for remaining in list(self.session.cookies):
                if getattr(remaining, "name", "") == c_name and "localhost" in str(
                    getattr(remaining, "domain", "")
                ):
                    with contextlib.suppress(KeyError):
                        self.session.cookies.clear(
                            domain=getattr(remaining, "domain", ""),
                            path=getattr(remaining, "path", "/"),
                            name=c_name,
                        )

            # Re-add with domain="" while preserving all other attributes
            # from the original cookie (secure, expires, rest/HttpOnly, …).
            new_cookie = http.cookiejar.Cookie(
                version=getattr(cookie, "version", 0),
                name=c_name,
                value=getattr(cookie, "value", "") or "",
                port=getattr(cookie, "port", None),
                port_specified=getattr(cookie, "port_specified", False),
                domain="",
                domain_specified=False,
                domain_initial_dot=False,
                path=c_path,
                path_specified=getattr(cookie, "path_specified", True),
                secure=getattr(cookie, "secure", False),
                expires=getattr(cookie, "expires", None),
                discard=getattr(cookie, "discard", True),
                comment=getattr(cookie, "comment", None),
                comment_url=getattr(cookie, "comment_url", None),
                rest=getattr(cookie, "_rest", {}),
            )
            self.session.cookies.set_cookie(new_cookie)

        if fixed:
            logger.info(
                "Fixed %d cookie(s) with localhost domain: %s",
                len(fixed),
                ", ".join(fixed),
            )

        # Re-extract XSRF token from the (possibly updated) cookie jar
        self._xsrf_token = self._extract_xsrf_token()

        # Verify the fix worked
        req2 = requests.Request("GET", verify_url, headers=self._get_headers())
        prepared2 = self.session.prepare_request(req2)
        cookie_header2 = prepared2.headers.get("Cookie", "")

        if "GerritAccount" not in _cookie_names_from_header(cookie_header2):
            # Avoid logging raw cookie values; include only non-sensitive metadata.
            cookie_names = [getattr(c, "name", "") for c in self.session.cookies]
            raise GerritAuthError(
                f"Auth cookie for account {account_id} is not being "
                f"transmitted even after localhost workaround. "
                f"Cookie jar contains {len(cookie_names)} cookie(s): "
                f"{', '.join(cookie_names)}",
            )

        # Final confirmation: actually call the endpoint and verify
        # we are authenticated as the expected account.
        try:
            account_info = self.get("accounts/self")
            actual_id = account_info.get("_account_id")
            if actual_id is None:
                raise GerritAuthError(
                    f"Auth cookie is transmitted but accounts/self response "
                    f"does not contain _account_id for requested account {account_id}."
                )
            if int(actual_id) != int(account_id):
                raise GerritAuthError(
                    f"Auth cookie authenticated as unexpected account {actual_id} "
                    f"instead of requested account {account_id}."
                )
            logger.debug(
                "Auth verification: accounts/self returned ID %s (expected %s) ✅",
                actual_id,
                account_id,
            )
        except GerritAuthError as exc:
            raise GerritAuthError(
                f"Auth cookie is transmitted but Gerrit rejected it "
                f"for account {account_id}: {exc}"
            ) from exc

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
        # Dismiss the OOTB first-time redirect before the bootstrap POST,
        # just as we do in become_account().
        self._dismiss_ootb_redirect()

        login_url = f"{self.base_url}/login/"
        logger.info("Creating first account via login servlet (action=create_account)")
        logger.debug(f"POST {login_url} data=action=create_account")

        try:
            # Use allow_redirects=False to capture the Set-Cookie header
            # from the 302 response directly, avoiding redirect chains
            # that may strip the context path.
            response = self.session.post(
                login_url,
                data={"action": "create_account"},
                allow_redirects=False,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except Exception as exc:
            raise GerritAuthError(
                f"Bootstrap POST to {login_url} failed: {exc}"
            ) from exc

        logger.debug(
            f"Bootstrap response: HTTP {response.status_code}, "
            f"Location: {response.headers.get('Location', '(none)')}"
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
                f"(HTTP {response.status_code}, "
                f"Location: {response.headers.get('Location', '(none)')})",
                status_code=response.status_code,
            )

        # Extract XSRF token and fetch base page if needed
        self._xsrf_token = self._extract_xsrf_token()
        self._ensure_xsrf_token()

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
        logger.debug("GET %s", url)

        response = self.session.get(
            url,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        if not response.ok:
            cookie_hdr = response.request.headers.get("Cookie", "")
            cookie_info = (
                ", ".join(sorted(_cookie_names_from_header(cookie_hdr)))
                if cookie_hdr
                else "(none)"
            )
            logger.debug(
                "GET %s → HTTP %s  (cookie names: %s)",
                url,
                response.status_code,
                cookie_info,
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
        logger.debug("PUT %s", url)

        body: str | None = json.dumps(data) if isinstance(data, dict) else data

        response = self.session.put(
            url,
            data=body,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        if not response.ok:
            cookie_hdr = response.request.headers.get("Cookie", "")
            cookie_info = (
                ", ".join(sorted(_cookie_names_from_header(cookie_hdr)))
                if cookie_hdr
                else "(none)"
            )
            logger.debug(
                "PUT %s → HTTP %s  (cookie names: %s)",
                url,
                response.status_code,
                cookie_info,
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
        logger.debug("POST %s", url)

        body: str | None = json.dumps(data) if isinstance(data, dict) else data

        response = self.session.post(
            url,
            data=body,
            headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_ssl,
            **kwargs,
        )

        if not response.ok:
            cookie_hdr = response.request.headers.get("Cookie", "")
            cookie_info = (
                ", ".join(sorted(_cookie_names_from_header(cookie_hdr)))
                if cookie_hdr
                else "(none)"
            )
            logger.debug(
                "POST %s → HTTP %s  (cookie names: %s)",
                url,
                response.status_code,
                cookie_info,
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

        Each key is POSTed as ``text/plain`` to ``accounts/{id}/sshkeys``.
        We have observed an intermittent benign failure where Gerrit
        rejects one of several back-to-back POSTs on the same TCP
        connection with a ``"Not implemented: <garbled>POST <uri>"``
        response (the verb seen by Gerrit picks up 1-2 stray bytes,
        e.g. ``"alPOST"``).  This appears to be an HTTP keepalive /
        request-line corruption interaction in our path through
        Tailscale + the runner's request stack rather than a real
        method mismatch — keys 1 and 2 succeed, key 3 trips the
        garbled verb, and a separate fresh connection retries fine.

        We therefore:

        * Detect the ``"Not implemented:"`` body and retry once on
          a fresh ``Session`` (which forces a new TCP connection
          and bypasses any keepalive corruption).
        * If the retry succeeds, we don't pollute the log with a
          warning — the user-visible outcome is correct.
        * If it still fails, we emit a single ``INFO`` summary
          rather than a per-key WARNING, since the key add is
          best-effort and downstream auth still works via the keys
          that did land.

        Args:
            account: Account identifier
            ssh_keys: List of SSH public keys

        Returns:
            List of added SSH key infos
        """
        results: list[dict[str, Any]] = []
        deferred_failures: list[str] = []
        # ``ssh_keys`` may include blank lines and ``#`` comments;
        # the loop skips those without attempting any POST.  Tracking
        # the number of keys we actually tried makes the summary log
        # below match reality ("1 of 2 attempted failed" instead of
        # the misleading "1 of 5 keys failed" when 3 of the 5 entries
        # were comment/whitespace lines).
        attempted = 0

        for key in ssh_keys:
            key = key.strip()
            if not key or key.startswith("#"):
                continue
            attempted += 1
            try:
                result = self.add_ssh_key(account, key)
                results.append(result)
                logger.debug(f"Added SSH key {result.get('seq', '?')} to {account}")
                continue
            except GerritConflictError:
                logger.debug(f"SSH key already exists for {account}")
                continue
            except GerritAPIError as exc:
                if not _looks_like_method_mangle(exc):
                    # Genuine API error (validation, auth, etc.) —
                    # surface it as before.
                    logger.warning(f"Failed to add SSH key to {account}: {exc}")
                    continue

            # Fall-through: method-mangle path.  Retry once on a
            # fresh connection by closing and reopening the
            # underlying session adapters.  The reused requests
            # Session keeps cookies and XSRF state, so we only
            # need to clear the connection pool.
            # Closing a session is a best-effort hint; if it fails
            # the retry below will still go through whatever pool
            # requests rebuilds.
            with contextlib.suppress(Exception):
                self.session.close()

            try:
                result = self.add_ssh_key(account, key)
                results.append(result)
                logger.debug(
                    "Added SSH key %s to %s after fresh-connection retry",
                    result.get("seq", "?"),
                    account,
                )
            except GerritConflictError:
                logger.debug(f"SSH key already exists for {account} (after retry)")
            except GerritAPIError as exc:
                # Retry also failed — record but do not WARN per key.
                deferred_failures.append(str(exc))

        if deferred_failures:
            # Emit a single concise INFO line summarising any keys
            # that could not be added even after retry.  Downstream
            # auth still works for any keys that did land, and the
            # admin-group setup proceeds regardless.  The total uses
            # ``attempted`` rather than ``len(ssh_keys)`` so blank/
            # comment-only entries do not inflate the denominator.
            logger.info(
                "%d of %d SSH key(s) for %s could not be added "
                "(non-fatal); proceeding without them",
                len(deferred_failures),
                attempted,
                account,
            )
            # Surface the individual retry-path errors at DEBUG so they
            # are diagnosable when troubleshooting, without inflating
            # the concise INFO summary above.
            for idx, failure in enumerate(deferred_failures, start=1):
                logger.debug(
                    "  SSH key failure %d/%d for %s: %s",
                    idx,
                    len(deferred_failures),
                    account,
                    failure,
                )

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
           (with retry and post-add verification)
        4. Flushes relevant caches

        Args:
            username: Username to create/update
            ssh_keys: List of SSH public keys to add
            name: Full name (defaults to username)
            email: Email address (defaults to username@example.com)
            add_to_admins: Whether to add to Administrators group

        Returns:
            Account info dict

        Raises:
            GerritAPIError: If the user cannot be added to the
                Administrators group after retries and the
                add_to_admins flag is True.
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

        # Add to Administrators group with retry and verification
        if add_to_admins:
            self._add_to_admins_with_retry(username, account_id)

        # Flush caches
        self.flush_cache()
        logger.info(f"User {username} configured successfully")

        return account

    def _add_to_admins_with_retry(
        self,
        username: str,
        account_id: int,
        max_attempts: int = 3,
        retry_delay: float = 2.0,
    ) -> None:
        """Add an account to the Administrators group with retry.

        Retries on transient failures (the Gerrit auth subsystem may
        lag behind the health check on container startup).  After a
        successful API call the membership is verified by listing the
        group members and confirming the account ID is present.

        Args:
            username: Username (for log messages).
            account_id: Gerrit account ID to add.
            max_attempts: Maximum number of add attempts.
            retry_delay: Initial delay between retries (doubles
                each attempt).

        Raises:
            GerritAPIError: If the account cannot be added or
                verified after all attempts.
        """
        group = "Administrators"
        last_error: GerritAPIError | None = None
        delay = retry_delay

        for attempt in range(1, max_attempts + 1):
            try:
                self.add_to_group(account_id, group)
                logger.info(
                    "Added %s to %s group (attempt %d/%d)",
                    username,
                    group,
                    attempt,
                    max_attempts,
                )
            except GerritConflictError:
                logger.debug(
                    "%s already in %s group",
                    username,
                    group,
                )
            except GerritAPIError as exc:
                last_error = exc
                if attempt < max_attempts:
                    logger.warning(
                        "Attempt %d/%d to add %s to %s failed: %s (retrying in %.0fs)",
                        attempt,
                        max_attempts,
                        username,
                        group,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    delay *= 2
                    continue
                # Final attempt failed — fall through to raise
                break

            # --- Verify membership after a successful add -----------
            if self._verify_group_membership(account_id, group):
                logger.info(
                    "Verified %s is in %s group ✅",
                    username,
                    group,
                )
                return

            # Verification failed — treat as transient and retry
            last_error = GerritAPIError(
                f"Verification failed: {username} (account {account_id}) "
                f"not found in {group} members after add_to_group "
                f"reported success"
            )
            if attempt < max_attempts:
                logger.warning(
                    "Attempt %d/%d: %s not found in %s members "
                    "after add (retrying in %.0fs)",
                    attempt,
                    max_attempts,
                    username,
                    group,
                    delay,
                )
                time.sleep(delay)
                delay *= 2
                continue

        # All attempts exhausted
        raise GerritAPIError(
            f"Failed to add {username} to {group} after "
            f"{max_attempts} attempt(s): {last_error}"
        )

    def _verify_group_membership(
        self,
        account_id: int,
        group: str,
    ) -> bool:
        """Check whether an account is a member of a group.

        Args:
            account_id: Gerrit account ID to look for.
            group: Group name to inspect.

        Returns:
            True if the account is present in the group's member
            list, False otherwise (including on API errors).
        """
        try:
            members = self.list_group_members(group)
            return any(m.get("_account_id") == account_id for m in members)
        except GerritAPIError as exc:
            logger.warning(
                "Could not verify %s membership in %s: %s",
                account_id,
                group,
                exc,
            )
            return False


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
