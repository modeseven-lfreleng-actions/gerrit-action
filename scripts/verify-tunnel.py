#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Verify tunnel connectivity to a Gerrit instance.

Replaces the inline shell ``curl`` loop in the workflow with a Python
script that provides **comprehensive diagnostic output** on failure —
HTTP status codes, connection error details, DNS resolution info, and
retry progress — instead of a bare ``exit code 7``.

Usage::

    # From a GitHub Actions workflow step
    python scripts/verify-tunnel.py

    # Locally with environment variables
    BORE_HOST=bore.pub HTTP_PORT=60479 \\
        python scripts/verify-tunnel.py

    # With API path
    BORE_HOST=bore.pub HTTP_PORT=60479 \\
    API_PATH=/infra USE_API_PATH=true \\
        python scripts/verify-tunnel.py

Environment Variables
---------------------
BORE_HOST
    Tunnel hostname (e.g. ``bore.pub``).
HTTP_PORT
    Tunnel HTTP port number.
API_PATH
    Optional API path prefix (e.g. ``/infra``, ``/r``).
USE_API_PATH
    If ``"true"`` and ``API_PATH`` is set, include the API path in
    the URL.
MAX_ATTEMPTS
    Number of retry attempts (default: ``5``).
RETRY_DELAY
    Seconds between retries (default: ``3``).
DEBUG
    If ``"true"``, enable verbose diagnostic output.
"""

from __future__ import annotations

import contextlib
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from logging_utils import setup_logging  # noqa: E402

logger = logging.getLogger(__name__)

# We use requests if available (it's a project dependency), but fall
# back to urllib so the script can also run in minimal environments.
try:
    import requests  # noqa: F401

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


class TunnelCheckResult:
    """Outcome of a single HTTP probe against the tunnel."""

    def __init__(
        self,
        *,
        success: bool = False,
        status_code: int | None = None,
        body: str = "",
        error: str = "",
        error_type: str = "",
        elapsed_ms: float = 0.0,
    ) -> None:
        self.success = success
        self.status_code = status_code
        self.body = body
        self.error = error
        self.error_type = error_type
        self.elapsed_ms = elapsed_ms

    def __repr__(self) -> str:
        if self.success:
            return f"<OK status={self.status_code} {self.elapsed_ms:.0f}ms>"
        return f"<FAIL type={self.error_type} status={self.status_code} error={self.error!r}>"


def _probe_with_requests(url: str, timeout: float = 10.0) -> TunnelCheckResult:
    """Probe *url* using the ``requests`` library."""
    start = time.monotonic()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)  # pyright: ignore[reportPossiblyUnbound, reportPossiblyUnboundVariable]
        elapsed = (time.monotonic() - start) * 1000

        body = resp.text.strip()
        if resp.status_code == 200:
            return TunnelCheckResult(
                success=True,
                status_code=resp.status_code,
                body=body,
                elapsed_ms=elapsed,
            )

        return TunnelCheckResult(
            success=False,
            status_code=resp.status_code,
            body=body[:500],
            error=f"HTTP {resp.status_code} {resp.reason}",
            error_type="http_error",
            elapsed_ms=elapsed,
        )

    except requests.exceptions.ConnectionError as exc:  # pyright: ignore[reportPossiblyUnbound, reportPossiblyUnboundVariable]
        elapsed = (time.monotonic() - start) * 1000
        inner = str(exc)
        if "Connection refused" in inner or "ConnectTimeoutError" in inner:
            error_type = "connection_refused"
        elif "Name or service not known" in inner or "getaddrinfo" in inner:
            error_type = "dns_failure"
        else:
            error_type = "connection_error"
        return TunnelCheckResult(
            success=False,
            error=inner[:300],
            error_type=error_type,
            elapsed_ms=elapsed,
        )

    except requests.exceptions.Timeout as exc:  # pyright: ignore[reportPossiblyUnbound, reportPossiblyUnboundVariable]
        elapsed = (time.monotonic() - start) * 1000
        return TunnelCheckResult(
            success=False,
            error=str(exc)[:300],
            error_type="timeout",
            elapsed_ms=elapsed,
        )

    except requests.exceptions.RequestException as exc:  # pyright: ignore[reportPossiblyUnbound, reportPossiblyUnboundVariable]
        elapsed = (time.monotonic() - start) * 1000
        return TunnelCheckResult(
            success=False,
            error=str(exc)[:300],
            error_type="request_error",
            elapsed_ms=elapsed,
        )


def _probe_with_urllib(url: str, timeout: float = 10.0) -> TunnelCheckResult:
    """Probe *url* using the stdlib ``urllib`` (fallback)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - start) * 1000
            body = resp.read().decode("utf-8", errors="replace").strip()
            status = resp.getcode()
            if status == 200:
                return TunnelCheckResult(
                    success=True,
                    status_code=status,
                    body=body,
                    elapsed_ms=elapsed,
                )
            return TunnelCheckResult(
                success=False,
                status_code=status,
                body=body[:500],
                error=f"HTTP {status}",
                error_type="http_error",
                elapsed_ms=elapsed,
            )

    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - start) * 1000
        body = ""
        with contextlib.suppress(Exception):
            body = exc.read().decode("utf-8", errors="replace")[:500]
        return TunnelCheckResult(
            success=False,
            status_code=exc.code,
            body=body,
            error=f"HTTP {exc.code} {exc.reason}",
            error_type="http_error",
            elapsed_ms=elapsed,
        )

    except urllib.error.URLError as exc:
        elapsed = (time.monotonic() - start) * 1000
        reason = str(exc.reason)
        if "Connection refused" in reason:
            error_type = "connection_refused"
        elif "Name or service not known" in reason or "getaddrinfo" in reason:
            error_type = "dns_failure"
        elif "timed out" in reason:
            error_type = "timeout"
        else:
            error_type = "connection_error"
        return TunnelCheckResult(
            success=False,
            error=reason[:300],
            error_type=error_type,
            elapsed_ms=elapsed,
        )

    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        return TunnelCheckResult(
            success=False,
            error=str(exc)[:300],
            error_type="unexpected",
            elapsed_ms=elapsed,
        )


def probe_url(url: str, timeout: float = 10.0) -> TunnelCheckResult:
    """Probe *url* using the best available HTTP client."""
    if _HAS_REQUESTS:
        return _probe_with_requests(url, timeout=timeout)
    return _probe_with_urllib(url, timeout=timeout)


# ---------------------------------------------------------------------------
# DNS / network diagnostics
# ---------------------------------------------------------------------------


def diagnose_host(host: str, port: int) -> list[str]:
    """Return a list of diagnostic strings about *host*:*port*.

    Performs DNS resolution and a raw TCP connect to gather information
    that helps debug tunnel failures.
    """
    diag: list[str] = []

    # DNS resolution
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        unique_ips = sorted({str(addr[4][0]) for addr in addrs})
        diag.append(f"DNS resolution: {host} -> {', '.join(unique_ips)}")
    except socket.gaierror as exc:
        diag.append(f"DNS resolution FAILED: {exc}")
        return diag  # no point trying TCP if DNS fails

    # Raw TCP connect
    for ip in unique_ips[:3]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect((ip, port))
            diag.append(f"TCP connect to {ip}:{port}: OK")
        except OSError as exc:
            diag.append(f"TCP connect to {ip}:{port}: FAILED ({exc})")
        finally:
            sock.close()

    return diag


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Run the tunnel verification with retries and diagnostics.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on failure.
    """
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    setup_logging(debug=debug)

    bore_host = os.environ.get("BORE_HOST", "").strip()
    http_port = os.environ.get("HTTP_PORT", "").strip()
    api_path = os.environ.get("API_PATH", "").strip()
    use_api_path = os.environ.get("USE_API_PATH", "false").strip().lower() == "true"
    max_attempts = int(os.environ.get("MAX_ATTEMPTS", "5"))
    retry_delay = int(os.environ.get("RETRY_DELAY", "3"))

    # --- Validate inputs ---
    if not bore_host:
        logger.error("BORE_HOST is not set — cannot verify tunnel")
        print("::error::BORE_HOST environment variable is required", file=sys.stderr)
        return 1

    if not http_port:
        logger.error("HTTP_PORT is not set — cannot verify tunnel")
        print("::error::HTTP_PORT environment variable is required", file=sys.stderr)
        return 1

    try:
        port_num = int(http_port)
    except ValueError:
        logger.error("HTTP_PORT is not a valid integer: %r", http_port)
        return 1

    # --- Build URL ---
    effective_api_path = ""
    if use_api_path and api_path:
        effective_api_path = api_path if api_path.startswith("/") else f"/{api_path}"

    url = f"http://{bore_host}:{port_num}{effective_api_path}/config/server/version"

    logger.info("Verifying tunnel connectivity…")
    logger.info("")
    logger.info("  Tunnel host:  %s", bore_host)
    logger.info("  HTTP port:    %s", http_port)
    logger.info("  API path:     %s", effective_api_path or "(none)")
    logger.info("  Target URL:   %s", url)
    logger.info("  Max attempts: %d", max_attempts)
    logger.info("  Retry delay:  %ds", retry_delay)
    logger.info("")

    # --- Pre-flight diagnostics ---
    if debug:
        logger.debug("Running pre-flight network diagnostics…")
        for line in diagnose_host(bore_host, port_num):
            logger.debug("  %s", line)
        logger.debug("")

    # --- Retry loop ---
    last_result: TunnelCheckResult | None = None
    error_summary: list[str] = []

    for attempt in range(1, max_attempts + 1):
        logger.info("  Attempt %d/%d: %s", attempt, max_attempts, url)

        result = probe_url(url, timeout=10.0)
        last_result = result

        if result.success:
            # Parse the Gerrit version from the response body.
            # Gerrit wraps JSON responses in )]}' prefix.
            version = result.body
            for prefix in (")]}'", ")]}'\n", '"'):
                version = version.lstrip(prefix)
            version = version.strip().strip('"')

            logger.info("")
            logger.info("  Tunnel verified ✅ (Gerrit %s)", version)
            logger.info("  Response time: %.0fms", result.elapsed_ms)
            logger.info("")

            # Write success to step summary if available
            summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary_file:
                try:
                    with open(summary_file, "a") as fh:
                        fh.write(
                            f"**Tunnel Verification** ✅\n\n"
                            f"- URL: `{url}`\n"
                            f"- Gerrit version: `{version}`\n"
                            f"- Response time: {result.elapsed_ms:.0f}ms\n"
                            f"- Attempt: {attempt}/{max_attempts}\n\n"
                        )
                except OSError:
                    pass

            return 0

        # Log failure details for this attempt
        detail = f"[{result.error_type}]"
        if result.status_code is not None:
            detail += f" HTTP {result.status_code}"
        if result.error:
            # Truncate for readability but keep enough for debugging
            error_msg = result.error[:200]
            detail += f" — {error_msg}"
        if result.body:
            detail += f"\n    Response body: {result.body[:200]}"

        logger.warning("    FAILED: %s (%.0fms)", detail, result.elapsed_ms)
        error_summary.append(f"Attempt {attempt}: {detail}")

        if attempt < max_attempts:
            logger.info("    Retrying in %ds…", retry_delay)
            time.sleep(retry_delay)

    # --- All attempts exhausted ---
    logger.error("")
    logger.error("  ❌ Tunnel verification failed after %d attempts", max_attempts)
    logger.error("")
    logger.error("  URL: %s", url)
    if last_result:
        logger.error("  Last error type: %s", last_result.error_type)
        if last_result.status_code is not None:
            logger.error("  Last HTTP status: %d", last_result.status_code)
        if last_result.error:
            logger.error("  Last error: %s", last_result.error[:300])

    # Network diagnostics on failure
    logger.error("")
    logger.error("  Network diagnostics:")
    for line in diagnose_host(bore_host, port_num):
        logger.error("    %s", line)

    # Common failure explanations
    logger.error("")
    logger.error("  Possible causes:")
    if last_result and last_result.error_type == "connection_refused":
        logger.error("    - Bore tunnel process may have exited or not started")
        logger.error("    - The assigned port may have been reclaimed by bore.pub")
        logger.error("    - Gerrit container may not be listening on the expected port")
    elif last_result and last_result.error_type == "dns_failure":
        logger.error("    - DNS resolution failed for %s", bore_host)
        logger.error("    - Check network connectivity and DNS configuration")
    elif last_result and last_result.error_type == "timeout":
        logger.error("    - Connection timed out — tunnel may be overloaded or down")
        logger.error("    - Gerrit may still be starting up")
    elif last_result and last_result.error_type == "http_error":
        logger.error("    - Gerrit is reachable but returned an error")
        logger.error(
            "    - Check API path configuration (current: %s)",
            effective_api_path or "(none)",
        )
        if last_result.status_code == 404:
            logger.error("    - HTTP 404 suggests the API path is incorrect")
        elif last_result.status_code == 401:
            logger.error("    - HTTP 401 suggests authentication is required")
    else:
        logger.error("    - Unexpected error — check logs above for details")

    logger.error("")

    # Attempt history
    logger.error("  Attempt history:")
    for entry in error_summary:
        logger.error("    %s", entry)
    logger.error("")

    # GitHub Actions error annotation
    error_msg = f"Tunnel verification failed after {max_attempts} attempts"
    if last_result:
        error_msg += f" (last: {last_result.error_type}"
        if last_result.status_code is not None:
            error_msg += f", HTTP {last_result.status_code}"
        error_msg += ")"
    print(f"::error::{error_msg}", file=sys.stderr)

    # Write failure to step summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            lines = [
                "**Tunnel Verification** ❌\n",
                "",
                f"Failed to verify tunnel connectivity after {max_attempts} attempts.\n",
                "",
                f"- URL: `{url}`",
                f"- Last error: `{last_result.error_type if last_result else 'unknown'}`",
            ]
            if last_result and last_result.status_code is not None:
                lines.append(f"- HTTP status: `{last_result.status_code}`")
            lines.append("")
            with open(summary_file, "a") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError:
            pass

    return 1


def main() -> int:
    """Entry point with top-level error handling."""
    try:
        return run()
    except KeyboardInterrupt:
        logger.info("Interrupted")
        return 130
    except Exception as exc:
        logger.exception("Unexpected error during tunnel verification: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
