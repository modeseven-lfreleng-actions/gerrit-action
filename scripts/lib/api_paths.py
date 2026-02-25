# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""API path detection and validation for Gerrit servers.

Replaces ``detect-api-paths.sh`` (213 lines) with a testable Python
implementation that uses :mod:`requests` instead of ``curl`` for HTTP
redirect detection and path probing.

Usage::

    from api_paths import detect_api_path, validate_api_path, get_gerrit_version

    path = detect_api_path("gerrit.example.org")
    if validate_api_path("gerrit.example.org", path):
        version = get_gerrit_version("gerrit.example.org", path)
        print(f"Gerrit {version} at path: {path}")
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Gerrit API responses have a magic XSSI-protection prefix
_GERRIT_MAGIC_PREFIX = re.compile(r"^\)\]\}'\s*")

# Common Gerrit context paths to probe when redirect detection fails
_COMMON_PATHS = ("/r", "/gerrit", "/infra", "")

# HTTP status codes that indicate a valid Gerrit endpoint
_VALID_STATUS_CODES = {200, 401}

# Default timeouts for HTTP requests (connect, read) in seconds
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 30
_PROBE_TIMEOUT = 5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_api_path(
    gerrit_host: str,
    provided_path: str | None = None,
    *,
    timeout: int = _CONNECT_TIMEOUT,
) -> str:
    """Detect the API path prefix for a Gerrit server.

    The detection strategy is:

    1. If *provided_path* is given, normalise and return it.
    2. Try HTTP redirect detection — follow redirects from
       ``https://<host>/`` and extract the path component.
    3. Probe common paths (``/r``, ``/gerrit``, ``/infra``, ``""``) by
       hitting the ``/config/server/version`` endpoint.
    4. Fall back to ``""`` (root) if nothing works.

    Parameters
    ----------
    gerrit_host:
        Hostname (and optional port) of the Gerrit server.
    provided_path:
        If the caller already knows the path (e.g. from the action
        config), pass it here to skip detection entirely.
    timeout:
        Connection timeout in seconds for each HTTP request.

    Returns
    -------
    str
        The normalised API path (e.g. ``"/r"``, ``"/gerrit"``, or
        ``""`` for root).
    """
    if provided_path is not None:
        normalised = _normalise_path(provided_path)
        logger.info(
            "Using provided api_path for %s: %s",
            gerrit_host,
            normalised or "(root)",
        )
        return normalised

    # --- Strategy 1: redirect detection ---
    path = _detect_via_redirect(gerrit_host, timeout=timeout)
    if path is not None:
        logger.info("Detected API path via redirect for %s: %s", gerrit_host, path)
        return path

    # --- Strategy 2: probe common paths ---
    path = _detect_via_probe(gerrit_host, timeout=timeout)
    if path is not None:
        logger.info("Detected API path via probe for %s: %s", gerrit_host, path)
        return path

    # --- Fallback ---
    logger.warning(
        "Could not detect API path for %s, using empty path (root)", gerrit_host
    )
    return ""


def validate_api_path(
    gerrit_host: str,
    api_path: str,
    *,
    timeout: int = _PROBE_TIMEOUT,
) -> bool:
    """Validate that ``/config/server/version`` is reachable at *api_path*.

    Returns *True* if the endpoint responds with HTTP 200.
    """
    url = f"https://{gerrit_host}{api_path}/config/server/version"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code == 200:
            logger.debug("Validated API path %s for %s ✅", api_path, gerrit_host)
            return True
        logger.debug(
            "Validation failed for %s%s (HTTP %d)",
            gerrit_host,
            api_path,
            resp.status_code,
        )
    except requests.RequestException as exc:
        logger.debug(
            "Validation request failed for %s%s: %s", gerrit_host, api_path, exc
        )
    return False


def get_gerrit_version(
    gerrit_host: str,
    api_path: str = "",
    *,
    timeout: int = _PROBE_TIMEOUT,
) -> str:
    """Fetch the Gerrit version string from the server.

    Returns the version (e.g. ``"3.13.1"``) or ``""`` if the version
    could not be determined.
    """
    url = f"https://{gerrit_host}{api_path}/config/server/version"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code != 200:
            return ""
        # Strip XSSI prefix and surrounding quotes/whitespace
        text = _GERRIT_MAGIC_PREFIX.sub("", resp.text).strip().strip('"')
        return text
    except requests.RequestException as exc:
        logger.debug("Failed to fetch version from %s: %s", url, exc)
        return ""


def detect_and_record_api_paths(
    instances: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    """Detect API paths for a list of instances.

    This is the high-level orchestrator that replaces the main loop in
    ``detect-api-paths.sh``.

    Parameters
    ----------
    instances:
        List of dicts, each with at least ``slug``, ``gerrit`` (host),
        and optionally ``api_path``.

    Returns
    -------
    dict
        Mapping of ``slug`` to ``{gerrit_host, api_path, api_url}``.
    """
    results: dict[str, dict[str, str]] = {}

    for inst in instances:
        slug = inst.get("slug", "")
        gerrit_host = inst.get("gerrit", "")
        provided_path = inst.get("api_path") or None

        if not slug or not gerrit_host:
            logger.warning(
                "Skipping instance with missing slug or gerrit host: %s", inst
            )
            continue

        logger.info("========================================")
        logger.info("Instance: %s (%s)", slug, gerrit_host)
        logger.info("========================================")

        # Detect API path
        api_path = detect_api_path(gerrit_host, provided_path)

        # Validate
        if validate_api_path(gerrit_host, api_path):
            logger.info("  Validation: ✅ API path confirmed")
            version = get_gerrit_version(gerrit_host, api_path)
            if version:
                logger.info("  Gerrit version: %s", version)
        else:
            logger.warning("  Validation: ⚠️  Could not validate API path")

        # Build full API URL
        api_url = f"https://{gerrit_host}{api_path}"
        logger.info("  API URL: %s", api_url)

        results[slug] = {
            "gerrit_host": gerrit_host,
            "api_path": api_path,
            "api_url": api_url,
        }

    return results


# ---------------------------------------------------------------------------
# Internal detection strategies
# ---------------------------------------------------------------------------


def _detect_via_redirect(
    gerrit_host: str,
    *,
    timeout: int = _CONNECT_TIMEOUT,
) -> str | None:
    """Attempt to detect API path via HTTP redirect.

    Follow redirects from ``https://<host>/`` and check whether the
    final URL has a path component that differs from ``/``.

    Returns the detected path or *None* if detection failed.
    """
    base_url = f"https://{gerrit_host}/"
    try:
        resp = requests.get(
            base_url,
            allow_redirects=True,
            timeout=(timeout, _READ_TIMEOUT),
        )
        if resp.url and resp.url != base_url:
            parsed = urlparse(resp.url)
            path = parsed.path.rstrip("/")
            # Normalise bare "/" to ""
            if path and path != "/":
                return _normalise_path(path)
    except requests.RequestException as exc:
        logger.debug("Redirect detection failed for %s: %s", gerrit_host, exc)

    return None


def _detect_via_probe(
    gerrit_host: str,
    *,
    timeout: int = _PROBE_TIMEOUT,
) -> str | None:
    """Probe common Gerrit context paths.

    Tries ``/r``, ``/gerrit``, ``/infra``, and ``""`` (root) by
    requesting ``/config/server/version`` at each path.

    Returns the first path that responds with 200 or 401, or *None*.
    """
    for path in _COMMON_PATHS:
        url = f"https://{gerrit_host}{path}/config/server/version"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
            )
            if resp.status_code in _VALID_STATUS_CODES:
                return path
        except requests.RequestException:
            continue

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_path(path: str) -> str:
    """Normalise an API path prefix.

    * Ensures a leading ``/``.
    * Strips a trailing ``/``.
    * Collapses bare ``"/"`` to ``""``.
    * Returns ``""`` for empty input.
    """
    path = path.strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/")
    if path == "/":
        return ""
    return path
