# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the api_paths module.

Covers:
- Path normalisation edge cases
- Redirect-based API path detection
- Probe-based API path detection
- Fallback behaviour
- API path validation
- Gerrit version fetching
- Multi-instance detect_and_record_api_paths orchestrator
"""

from __future__ import annotations

from unittest.mock import patch

import requests
from api_paths import (
    _detect_via_probe,
    _detect_via_redirect,
    _normalise_path,
    detect_and_record_api_paths,
    detect_api_path,
    get_gerrit_version,
    validate_api_path,
)
from conftest import MockResponse

# =========================================================================
# Path normalisation
# =========================================================================


class TestNormalisePath:
    def test_empty_string(self):
        assert _normalise_path("") == ""

    def test_whitespace_only(self):
        assert _normalise_path("   ") == ""

    def test_bare_slash(self):
        assert _normalise_path("/") == ""

    def test_leading_slash_preserved(self):
        assert _normalise_path("/r") == "/r"

    def test_leading_slash_added(self):
        assert _normalise_path("r") == "/r"

    def test_trailing_slash_stripped(self):
        assert _normalise_path("/r/") == "/r"

    def test_both_slashes(self):
        assert _normalise_path("/gerrit/") == "/gerrit"

    def test_no_slashes(self):
        assert _normalise_path("infra") == "/infra"

    def test_multi_segment(self):
        assert _normalise_path("/some/path") == "/some/path"

    def test_multi_segment_no_leading(self):
        assert _normalise_path("some/path/") == "/some/path"

    def test_whitespace_stripped(self):
        assert _normalise_path("  /r  ") == "/r"


# =========================================================================
# Redirect detection
# =========================================================================


class TestDetectViaRedirect:
    @patch("api_paths.requests.get")
    def test_redirect_detected(self, mock_get):
        """When the server redirects to /r/, detect the /r path."""
        mock_get.return_value = MockResponse(
            status_code=200,
            url="https://gerrit.example.org/r/",
        )
        result = _detect_via_redirect("gerrit.example.org")
        assert result == "/r"

    @patch("api_paths.requests.get")
    def test_redirect_to_gerrit_path(self, mock_get):
        mock_get.return_value = MockResponse(
            status_code=200,
            url="https://gerrit.example.org/gerrit/dashboard/self",
        )
        result = _detect_via_redirect("gerrit.example.org")
        assert result == "/gerrit/dashboard/self"

    @patch("api_paths.requests.get")
    def test_no_redirect(self, mock_get):
        """When there is no redirect, return None."""
        mock_get.return_value = MockResponse(
            status_code=200,
            url="https://gerrit.example.org/",
        )
        result = _detect_via_redirect("gerrit.example.org")
        assert result is None

    @patch("api_paths.requests.get")
    def test_redirect_to_bare_slash(self, mock_get):
        """Redirect to / should return None (no path detected)."""
        mock_get.return_value = MockResponse(
            status_code=200,
            url="https://gerrit.example.org/",
        )
        result = _detect_via_redirect("gerrit.example.org")
        assert result is None

    @patch("api_paths.requests.get")
    def test_request_exception(self, mock_get):
        """Network errors return None."""
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = _detect_via_redirect("gerrit.example.org")
        assert result is None

    @patch("api_paths.requests.get")
    def test_timeout_exception(self, mock_get):
        mock_get.side_effect = requests.Timeout("Timeout")
        result = _detect_via_redirect("gerrit.example.org")
        assert result is None


# =========================================================================
# Probe detection
# =========================================================================


class TestDetectViaProbe:
    @patch("api_paths.requests.get")
    def test_probe_finds_r(self, mock_get):
        """Probe /r/config/server/version returns 200 → detect /r."""

        def side_effect(url, **kwargs):
            if "/r/" in url:
                return MockResponse(status_code=200)
            return MockResponse(status_code=404)

        mock_get.side_effect = side_effect
        result = _detect_via_probe("gerrit.example.org")
        assert result == "/r"

    @patch("api_paths.requests.get")
    def test_probe_finds_gerrit(self, mock_get):
        def side_effect(url, **kwargs):
            if "/gerrit/" in url:
                return MockResponse(status_code=200)
            return MockResponse(status_code=404)

        mock_get.side_effect = side_effect
        result = _detect_via_probe("gerrit.example.org")
        assert result == "/gerrit"

    @patch("api_paths.requests.get")
    def test_probe_finds_root(self, mock_get):
        """Root path (empty string) is probed last."""

        def side_effect(url, **kwargs):
            # Only root path succeeds
            if url == "https://gerrit.example.org/config/server/version":
                return MockResponse(status_code=200)
            return MockResponse(status_code=404)

        mock_get.side_effect = side_effect
        result = _detect_via_probe("gerrit.example.org")
        assert result == ""

    @patch("api_paths.requests.get")
    def test_probe_401_is_valid(self, mock_get):
        """HTTP 401 indicates a valid Gerrit endpoint (auth required)."""

        def side_effect(url, **kwargs):
            if "/r/" in url:
                return MockResponse(status_code=401)
            return MockResponse(status_code=404)

        mock_get.side_effect = side_effect
        result = _detect_via_probe("gerrit.example.org")
        assert result == "/r"

    @patch("api_paths.requests.get")
    def test_probe_403_is_not_valid(self, mock_get):
        """HTTP 403 is NOT in the valid status codes for probing."""

        def side_effect(url, **kwargs):
            return MockResponse(status_code=403)

        mock_get.side_effect = side_effect
        result = _detect_via_probe("gerrit.example.org")
        assert result is None

    @patch("api_paths.requests.get")
    def test_probe_all_fail(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("refused")
        result = _detect_via_probe("gerrit.example.org")
        assert result is None

    @patch("api_paths.requests.get")
    def test_probe_order_r_then_gerrit_then_infra_then_root(self, mock_get):
        """Verify probing order: /r, /gerrit, /infra, (root)."""
        call_urls = []

        def side_effect(url, **kwargs):
            call_urls.append(url)
            return MockResponse(status_code=404)

        mock_get.side_effect = side_effect
        _detect_via_probe("gerrit.example.org")

        assert len(call_urls) == 4
        assert "/r/" in call_urls[0]
        assert "/gerrit/" in call_urls[1]
        assert "/infra/" in call_urls[2]
        # Root path: no prefix before /config/server/version
        assert call_urls[3] == "https://gerrit.example.org/config/server/version"


# =========================================================================
# High-level detect_api_path
# =========================================================================


class TestDetectApiPath:
    def test_provided_path_returned_immediately(self):
        """When a path is provided, detection is skipped entirely."""
        result = detect_api_path("gerrit.example.org", provided_path="r")
        assert result == "/r"

    def test_provided_path_normalised(self):
        result = detect_api_path("gerrit.example.org", provided_path="/gerrit/")
        assert result == "/gerrit"

    def test_provided_empty_path(self):
        result = detect_api_path("gerrit.example.org", provided_path="")
        assert result == ""

    def test_provided_slash_path(self):
        result = detect_api_path("gerrit.example.org", provided_path="/")
        assert result == ""

    @patch("api_paths._detect_via_redirect")
    @patch("api_paths._detect_via_probe")
    def test_redirect_succeeds(self, mock_probe, mock_redirect):
        mock_redirect.return_value = "/r"
        result = detect_api_path("gerrit.example.org")
        assert result == "/r"
        mock_probe.assert_not_called()

    @patch("api_paths._detect_via_redirect")
    @patch("api_paths._detect_via_probe")
    def test_fallback_to_probe(self, mock_probe, mock_redirect):
        mock_redirect.return_value = None
        mock_probe.return_value = "/gerrit"
        result = detect_api_path("gerrit.example.org")
        assert result == "/gerrit"

    @patch("api_paths._detect_via_redirect")
    @patch("api_paths._detect_via_probe")
    def test_fallback_to_empty(self, mock_probe, mock_redirect):
        mock_redirect.return_value = None
        mock_probe.return_value = None
        result = detect_api_path("gerrit.example.org")
        assert result == ""


# =========================================================================
# Validation
# =========================================================================


class TestValidateApiPath:
    @patch("api_paths.requests.get")
    def test_valid_path_200(self, mock_get):
        mock_get.return_value = MockResponse(status_code=200)
        assert validate_api_path("gerrit.example.org", "/r") is True

    @patch("api_paths.requests.get")
    def test_invalid_path_404(self, mock_get):
        mock_get.return_value = MockResponse(status_code=404)
        assert validate_api_path("gerrit.example.org", "/r") is False

    @patch("api_paths.requests.get")
    def test_invalid_path_401(self, mock_get):
        """validate_api_path only accepts 200, not 401."""
        mock_get.return_value = MockResponse(status_code=401)
        assert validate_api_path("gerrit.example.org", "/r") is False

    @patch("api_paths.requests.get")
    def test_network_error(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("refused")
        assert validate_api_path("gerrit.example.org", "/r") is False

    @patch("api_paths.requests.get")
    def test_url_construction(self, mock_get):
        mock_get.return_value = MockResponse(status_code=200)
        validate_api_path("gerrit.example.org", "/infra")
        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert call_url == "https://gerrit.example.org/infra/config/server/version"

    @patch("api_paths.requests.get")
    def test_empty_path(self, mock_get):
        mock_get.return_value = MockResponse(status_code=200)
        validate_api_path("gerrit.example.org", "")
        call_url = mock_get.call_args[0][0]
        assert call_url == "https://gerrit.example.org/config/server/version"


# =========================================================================
# Gerrit version
# =========================================================================


class TestGetGerritVersion:
    @patch("api_paths.requests.get")
    def test_version_with_xssi_prefix(self, mock_get):
        mock_get.return_value = MockResponse(
            status_code=200,
            text=')]}\'  \n"3.13.1"',
        )
        assert get_gerrit_version("gerrit.example.org", "/r") == "3.13.1"

    @patch("api_paths.requests.get")
    def test_version_plain(self, mock_get):
        mock_get.return_value = MockResponse(
            status_code=200,
            text='"3.10.0"',
        )
        assert get_gerrit_version("gerrit.example.org") == "3.10.0"

    @patch("api_paths.requests.get")
    def test_version_not_200(self, mock_get):
        mock_get.return_value = MockResponse(status_code=404)
        assert get_gerrit_version("gerrit.example.org") == ""

    @patch("api_paths.requests.get")
    def test_version_network_error(self, mock_get):
        mock_get.side_effect = requests.Timeout("timeout")
        assert get_gerrit_version("gerrit.example.org") == ""

    @patch("api_paths.requests.get")
    def test_version_url_construction(self, mock_get):
        mock_get.return_value = MockResponse(status_code=200, text=')]}\'  \n"3.13.1"')
        get_gerrit_version("gerrit.example.org", "/r")
        call_url = mock_get.call_args[0][0]
        assert call_url == "https://gerrit.example.org/r/config/server/version"


# =========================================================================
# detect_and_record_api_paths (orchestrator)
# =========================================================================


class TestDetectAndRecordApiPaths:
    @patch("api_paths.get_gerrit_version")
    @patch("api_paths.validate_api_path")
    @patch("api_paths.detect_api_path")
    def test_single_instance(self, mock_detect, mock_validate, mock_version):
        mock_detect.return_value = "/r"
        mock_validate.return_value = True
        mock_version.return_value = "3.13.1"

        instances = [
            {"slug": "onap", "gerrit": "gerrit.onap.org", "api_path": None},
        ]
        results = detect_and_record_api_paths(instances)

        assert "onap" in results
        assert results["onap"]["gerrit_host"] == "gerrit.onap.org"
        assert results["onap"]["api_path"] == "/r"
        assert results["onap"]["api_url"] == "https://gerrit.onap.org/r"

    @patch("api_paths.get_gerrit_version")
    @patch("api_paths.validate_api_path")
    @patch("api_paths.detect_api_path")
    def test_multiple_instances(self, mock_detect, mock_validate, mock_version):
        def detect_side_effect(host, provided_path):
            if host == "gerrit.onap.org":
                return "/r"
            return "/infra"

        mock_detect.side_effect = detect_side_effect
        mock_validate.return_value = True
        mock_version.return_value = "3.13.1"

        instances = [
            {"slug": "onap", "gerrit": "gerrit.onap.org", "api_path": None},
            {"slug": "lf", "gerrit": "gerrit.lf.org", "api_path": None},
        ]
        results = detect_and_record_api_paths(instances)

        assert len(results) == 2
        assert results["onap"]["api_path"] == "/r"
        assert results["lf"]["api_path"] == "/infra"

    @patch("api_paths.get_gerrit_version")
    @patch("api_paths.validate_api_path")
    @patch("api_paths.detect_api_path")
    def test_provided_api_path_passed_through(
        self, mock_detect, mock_validate, mock_version
    ):
        mock_detect.return_value = "/gerrit"
        mock_validate.return_value = True
        mock_version.return_value = ""

        instances = [
            {"slug": "test", "gerrit": "gerrit.test.org", "api_path": "gerrit"},
        ]
        detect_and_record_api_paths(instances)

        # detect_api_path should have been called with the provided path
        mock_detect.assert_called_once_with("gerrit.test.org", "gerrit")

    @patch("api_paths.validate_api_path")
    @patch("api_paths.detect_api_path")
    def test_validation_failure_still_records(self, mock_detect, mock_validate):
        """Even if validation fails, the path is still recorded."""
        mock_detect.return_value = "/r"
        mock_validate.return_value = False

        instances = [
            {"slug": "test", "gerrit": "gerrit.test.org", "api_path": None},
        ]
        results = detect_and_record_api_paths(instances)

        assert "test" in results
        assert results["test"]["api_path"] == "/r"

    @patch("api_paths.detect_api_path")
    def test_skips_instance_missing_slug(self, mock_detect):
        instances = [
            {"gerrit": "gerrit.test.org"},
        ]
        results = detect_and_record_api_paths(instances)
        assert len(results) == 0
        mock_detect.assert_not_called()

    @patch("api_paths.detect_api_path")
    def test_skips_instance_missing_gerrit(self, mock_detect):
        instances = [
            {"slug": "test"},
        ]
        results = detect_and_record_api_paths(instances)
        assert len(results) == 0
        mock_detect.assert_not_called()

    @patch("api_paths.detect_api_path")
    def test_empty_instances_list(self, mock_detect):
        results = detect_and_record_api_paths([])
        assert results == {}
        mock_detect.assert_not_called()

    @patch("api_paths.get_gerrit_version")
    @patch("api_paths.validate_api_path")
    @patch("api_paths.detect_api_path")
    def test_root_path_api_url(self, mock_detect, mock_validate, mock_version):
        mock_detect.return_value = ""
        mock_validate.return_value = True
        mock_version.return_value = "3.13.1"

        instances = [
            {"slug": "test", "gerrit": "gerrit.test.org", "api_path": None},
        ]
        results = detect_and_record_api_paths(instances)

        assert results["test"]["api_url"] == "https://gerrit.test.org"
