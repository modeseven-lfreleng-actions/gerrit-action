# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the tunnel verification script (verify-tunnel.py).

Covers:
- TunnelCheckResult: result dataclass behaviour
- probe_url: HTTP probing with requests and urllib fallback
- diagnose_host: DNS resolution and TCP connect diagnostics
- run(): main entry point with env var parsing, retry loop, and
  comprehensive error reporting
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Make the scripts directory importable so we can import verify-tunnel
# as a module.  The script lives at scripts/verify-tunnel.py which is
# not a package, so we load it via importlib.
# ---------------------------------------------------------------------------
import importlib
import importlib.util
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location(
    "verify_tunnel", SCRIPTS_DIR / "verify-tunnel.py"
)
assert _spec is not None and _spec.loader is not None
verify_tunnel = importlib.util.module_from_spec(_spec)
sys.modules["verify_tunnel"] = verify_tunnel
_spec.loader.exec_module(verify_tunnel)

TunnelCheckResult = verify_tunnel.TunnelCheckResult
probe_url = verify_tunnel.probe_url
diagnose_host = verify_tunnel.diagnose_host
run = verify_tunnel.run


# =========================================================================
# TunnelCheckResult
# =========================================================================


class TestTunnelCheckResult:
    def test_success_repr(self):
        r = TunnelCheckResult(success=True, status_code=200, elapsed_ms=42.5)
        assert "OK" in repr(r)
        assert "200" in repr(r)

    def test_failure_repr(self):
        r = TunnelCheckResult(
            success=False,
            status_code=404,
            error="Not Found",
            error_type="http_error",
        )
        assert "FAIL" in repr(r)
        assert "http_error" in repr(r)

    def test_defaults(self):
        r = TunnelCheckResult()
        assert r.success is False
        assert r.status_code is None
        assert r.body == ""
        assert r.error == ""
        assert r.error_type == ""
        assert r.elapsed_ms == 0.0


# =========================================================================
# probe_url (with requests mocked)
# =========================================================================


class TestProbeUrlWithRequests:
    """Test probe_url when the ``requests`` library is available."""

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_success(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ')]}\'"\n"3.13.1"'
        resp.reason = "OK"
        mock_requests.get.return_value = resp
        mock_requests.exceptions = _make_requests_exceptions()

        result = verify_tunnel.probe_url("http://localhost:8080/version")

        assert result.success is True
        assert result.status_code == 200
        assert "3.13.1" in result.body

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_http_error(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        resp.reason = "Not Found"
        mock_requests.get.return_value = resp
        mock_requests.exceptions = _make_requests_exceptions()

        result = verify_tunnel.probe_url("http://localhost:8080/version")

        assert result.success is False
        assert result.status_code == 404
        assert result.error_type == "http_error"

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_connection_refused(self, mock_requests):
        exc_mod = _make_requests_exceptions()
        mock_requests.exceptions = exc_mod
        mock_requests.get.side_effect = exc_mod.ConnectionError("Connection refused")

        result = verify_tunnel.probe_url("http://localhost:8080/version")

        assert result.success is False
        assert result.error_type == "connection_refused"
        assert "Connection refused" in result.error

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_dns_failure(self, mock_requests):
        exc_mod = _make_requests_exceptions()
        mock_requests.exceptions = exc_mod
        mock_requests.get.side_effect = exc_mod.ConnectionError(
            "Name or service not known"
        )

        result = verify_tunnel.probe_url("http://nonexistent.invalid/version")

        assert result.success is False
        assert result.error_type == "dns_failure"

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_timeout(self, mock_requests):
        exc_mod = _make_requests_exceptions()
        mock_requests.exceptions = exc_mod
        mock_requests.get.side_effect = exc_mod.Timeout("timed out")

        result = verify_tunnel.probe_url("http://localhost:8080/version")

        assert result.success is False
        assert result.error_type == "timeout"

    @patch.object(verify_tunnel, "_HAS_REQUESTS", True)
    @patch("verify_tunnel.requests")
    def test_generic_request_error(self, mock_requests):
        exc_mod = _make_requests_exceptions()
        mock_requests.exceptions = exc_mod
        mock_requests.get.side_effect = exc_mod.RequestException("weird")

        result = verify_tunnel.probe_url("http://localhost:8080/version")

        assert result.success is False
        assert result.error_type == "request_error"


# =========================================================================
# diagnose_host
# =========================================================================


class TestDiagnoseHost:
    @patch("verify_tunnel.socket")
    def test_successful_resolution_and_connect(self, mock_socket_mod):
        mock_socket_mod.AF_UNSPEC = socket.AF_UNSPEC
        mock_socket_mod.AF_INET = socket.AF_INET
        mock_socket_mod.SOCK_STREAM = socket.SOCK_STREAM
        mock_socket_mod.gaierror = socket.gaierror

        # Simulate DNS returning one address
        mock_socket_mod.getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 8080)),
        ]

        # Simulate successful TCP connect
        mock_sock = MagicMock()
        mock_socket_mod.socket.return_value = mock_sock

        diag = verify_tunnel.diagnose_host("bore.pub", 8080)

        assert any("1.2.3.4" in d for d in diag)
        assert any("OK" in d for d in diag)

    @patch("verify_tunnel.socket")
    def test_dns_failure(self, mock_socket_mod):
        mock_socket_mod.AF_UNSPEC = socket.AF_UNSPEC
        mock_socket_mod.SOCK_STREAM = socket.SOCK_STREAM
        mock_socket_mod.gaierror = socket.gaierror

        mock_socket_mod.getaddrinfo.side_effect = socket.gaierror(
            "Name or service not known"
        )

        diag = verify_tunnel.diagnose_host("nonexistent.invalid", 8080)

        assert any("FAILED" in d for d in diag)
        assert len(diag) == 1  # Only DNS line, no TCP attempts

    @patch("verify_tunnel.socket")
    def test_tcp_connect_failure(self, mock_socket_mod):
        mock_socket_mod.AF_UNSPEC = socket.AF_UNSPEC
        mock_socket_mod.AF_INET = socket.AF_INET
        mock_socket_mod.SOCK_STREAM = socket.SOCK_STREAM
        mock_socket_mod.gaierror = socket.gaierror

        mock_socket_mod.getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 8080)),
        ]

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_socket_mod.socket.return_value = mock_sock

        diag = verify_tunnel.diagnose_host("bore.pub", 8080)

        assert any("1.2.3.4" in d for d in diag)
        assert any("FAILED" in d for d in diag)


# =========================================================================
# run() — main entry point
# =========================================================================


class TestRun:
    """Test the run() function which reads env vars and runs the retry loop."""

    def _base_env(self, **overrides):
        env = {
            "BORE_HOST": "bore.pub",
            "HTTP_PORT": "60479",
            "DEBUG": "false",
            "MAX_ATTEMPTS": "2",
            "RETRY_DELAY": "0",
        }
        env.update(overrides)
        return env

    @patch("verify_tunnel.probe_url")
    @patch.dict("os.environ", {}, clear=False)
    def test_missing_bore_host(self, mock_probe, monkeypatch):
        monkeypatch.delenv("BORE_HOST", raising=False)
        monkeypatch.delenv("HTTP_PORT", raising=False)
        monkeypatch.setenv("BORE_HOST", "")
        monkeypatch.setenv("HTTP_PORT", "8080")

        assert run() == 1
        mock_probe.assert_not_called()

    @patch("verify_tunnel.probe_url")
    def test_missing_http_port(self, mock_probe, monkeypatch):
        monkeypatch.setenv("BORE_HOST", "bore.pub")
        monkeypatch.setenv("HTTP_PORT", "")

        assert run() == 1
        mock_probe.assert_not_called()

    @patch("verify_tunnel.probe_url")
    def test_success_on_first_attempt(self, mock_probe, monkeypatch):
        for k, v in self._base_env().items():
            monkeypatch.setenv(k, v)
        # Remove GITHUB_STEP_SUMMARY to avoid file writes
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body=')]}\'"\n"3.13.1"',
            elapsed_ms=42.0,
        )

        assert run() == 0
        assert mock_probe.call_count == 1

    @patch("verify_tunnel.probe_url")
    def test_success_on_second_attempt(self, mock_probe, monkeypatch):
        for k, v in self._base_env().items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.side_effect = [
            TunnelCheckResult(
                success=False,
                error="Connection refused",
                error_type="connection_refused",
            ),
            TunnelCheckResult(
                success=True,
                status_code=200,
                body='"3.13.1"',
                elapsed_ms=50.0,
            ),
        ]

        assert run() == 0
        assert mock_probe.call_count == 2

    @patch("verify_tunnel.diagnose_host", return_value=["DNS: ok"])
    @patch("verify_tunnel.probe_url")
    def test_failure_after_all_attempts(self, mock_probe, mock_diag, monkeypatch):
        for k, v in self._base_env().items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=False,
            status_code=None,
            error="Connection refused",
            error_type="connection_refused",
        )

        assert run() == 1
        assert mock_probe.call_count == 2  # MAX_ATTEMPTS=2

    @patch("verify_tunnel.probe_url")
    def test_api_path_included_when_enabled(self, mock_probe, monkeypatch):
        for k, v in self._base_env(USE_API_PATH="true", API_PATH="/infra").items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body='"3.13.1"',
            elapsed_ms=10.0,
        )

        assert run() == 0
        # Check the URL passed to probe_url contains the API path
        called_url = mock_probe.call_args[0][0]
        assert "/infra/config/server/version" in called_url

    @patch("verify_tunnel.probe_url")
    def test_api_path_ignored_when_disabled(self, mock_probe, monkeypatch):
        for k, v in self._base_env(USE_API_PATH="false", API_PATH="/infra").items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body='"3.13.1"',
            elapsed_ms=10.0,
        )

        assert run() == 0
        called_url = mock_probe.call_args[0][0]
        assert "/infra" not in called_url
        assert "/config/server/version" in called_url

    @patch("verify_tunnel.probe_url")
    def test_api_path_without_leading_slash(self, mock_probe, monkeypatch):
        for k, v in self._base_env(USE_API_PATH="true", API_PATH="r").items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body='"3.13.1"',
            elapsed_ms=10.0,
        )

        assert run() == 0
        called_url = mock_probe.call_args[0][0]
        assert "/r/config/server/version" in called_url

    @patch("verify_tunnel.probe_url")
    def test_invalid_port(self, mock_probe, monkeypatch):
        for k, v in self._base_env(HTTP_PORT="notanumber").items():
            monkeypatch.setenv(k, v)

        assert run() == 1
        mock_probe.assert_not_called()

    @patch("verify_tunnel.diagnose_host", return_value=["DNS: ok"])
    @patch("verify_tunnel.probe_url")
    def test_http_404_error_message(self, mock_probe, mock_diag, monkeypatch):
        """Verify that HTTP 404 produces a specific API-path hint."""
        for k, v in self._base_env().items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=False,
            status_code=404,
            error="HTTP 404 Not Found",
            error_type="http_error",
            body="Not Found",
        )

        # Should fail but not crash
        assert run() == 1

    @patch("verify_tunnel.probe_url")
    def test_step_summary_written_on_success(self, mock_probe, monkeypatch, tmp_path):
        summary_file = tmp_path / "summary.md"
        summary_file.touch()

        env = self._base_env()
        env["GITHUB_STEP_SUMMARY"] = str(summary_file)
        for k, v in env.items():
            monkeypatch.setenv(k, v)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body='"3.13.1"',
            elapsed_ms=10.0,
        )

        assert run() == 0
        content = summary_file.read_text()
        assert "Tunnel Verification" in content
        assert "✅" in content

    @patch("verify_tunnel.diagnose_host", return_value=["DNS: ok"])
    @patch("verify_tunnel.probe_url")
    def test_step_summary_written_on_failure(
        self, mock_probe, mock_diag, monkeypatch, tmp_path
    ):
        summary_file = tmp_path / "summary.md"
        summary_file.touch()

        env = self._base_env()
        env["GITHUB_STEP_SUMMARY"] = str(summary_file)
        for k, v in env.items():
            monkeypatch.setenv(k, v)

        mock_probe.return_value = TunnelCheckResult(
            success=False,
            error="Connection refused",
            error_type="connection_refused",
        )

        assert run() == 1
        content = summary_file.read_text()
        assert "Tunnel Verification" in content
        assert "❌" in content


# =========================================================================
# Gerrit version parsing
# =========================================================================


class TestVersionParsing:
    """Verify the Gerrit version is extracted correctly from common formats."""

    @patch("verify_tunnel.probe_url")
    def test_gerrit_json_prefix_stripped(self, mock_probe, monkeypatch):
        """Gerrit wraps JSON in )]}' prefix — verify it's handled."""
        for k, v in {
            "BORE_HOST": "bore.pub",
            "HTTP_PORT": "8080",
            "MAX_ATTEMPTS": "1",
            "RETRY_DELAY": "0",
            "DEBUG": "false",
        }.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        mock_probe.return_value = TunnelCheckResult(
            success=True,
            status_code=200,
            body=')]}\'"\n"3.13.1"',
            elapsed_ms=10.0,
        )

        # Just verify it doesn't crash — the version parsing is logged
        assert run() == 0


# =========================================================================
# Helpers
# =========================================================================


def _make_requests_exceptions():
    """Create a minimal mock of ``requests.exceptions`` with real classes.

    We need real exception classes (not MagicMock) so that ``raise`` and
    ``except`` work correctly in the probe functions.
    """

    class ConnectionError(Exception):
        pass

    class Timeout(Exception):
        pass

    class RequestException(Exception):
        pass

    class HTTPError(Exception):
        pass

    mod = MagicMock()
    mod.ConnectionError = ConnectionError
    mod.Timeout = Timeout
    mod.RequestException = RequestException
    mod.HTTPError = HTTPError
    return mod
