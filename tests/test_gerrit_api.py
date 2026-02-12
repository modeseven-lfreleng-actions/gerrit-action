# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
# mypy: disable-error-code="arg-type"
# pyright: reportArgumentType=false

"""Unit tests for the Gerrit API client library."""

from __future__ import annotations

import json
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from gerrit_api import (
    GerritAPIError,
    GerritAuthError,
    GerritConflictError,
    GerritDevClient,
    GerritNotFoundError,
    _parse_response,
    _strip_gerrit_prefix,
    parse_ssh_keys,
    validate_ssh_key,
)

# Import fixtures and helpers from conftest (pytest auto-discovers conftest.py)
# We need to import directly for the constants/helpers used in tests

# Sample Gerrit API responses (duplicated here to avoid import issues)
SAMPLE_ACCOUNT = {
    "_account_id": 1000000,
    "name": "Administrator",
    "email": "admin@example.com",
    "username": "admin",
    "avatars": [
        {
            "url": "http://www.gravatar.com/avatar/abc123.jpg?d=identicon&r=pg&s=32",
            "height": 32,
        }
    ],
}

SAMPLE_ACCOUNT_CREATED = {
    "_account_id": 1000001,
    "name": "Test User",
    "email": "testuser@example.com",
    "username": "testuser",
    "avatars": [],
}

SAMPLE_SSH_KEY = {
    "seq": 1,
    "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test@example.com",
    "encoded_key": "AAAAC3NzaC1lZDI1NTE5AAAAI...",
    "algorithm": "ssh-ed25519",
    "comment": "test@example.com",
    "valid": True,
}

SAMPLE_GROUP_MEMBERS = [
    SAMPLE_ACCOUNT,
    {
        "_account_id": 1000001,
        "name": "Test User",
        "email": "testuser@example.com",
        "username": "testuser",
        "avatars": [],
    },
]


def make_gerrit_response(data: Any) -> str:
    """Create a Gerrit API response with magic prefix."""
    prefix = ")]}'\n"
    return prefix + json.dumps(data)


class MockResponse:
    """Mock requests.Response for testing."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        headers: dict[str, str] | None = None,
        url: str = "",
        history: list | None = None,
    ) -> None:
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._json_data = json_data
        self._text = text
        self.headers: dict[str, str] = headers or {"content-type": "application/json"}
        self.url = url
        self.history: list = history if history is not None else []

    @property
    def text(self) -> str:
        if self._text:
            return self._text
        if self._json_data is not None:
            return make_gerrit_response(self._json_data)
        return ""

    @property
    def content(self) -> bytes:
        return self.text.encode("utf-8")

    def json(self) -> Any:
        return self._json_data


class MockCookieJar:
    """Mock cookie jar for testing session management."""

    def __init__(self, cookies=None):
        self._cookies = []
        if cookies:
            for name, value in cookies:
                cookie = MagicMock()
                cookie.name = name
                cookie.value = value
                self._cookies.append(cookie)

    def __iter__(self):
        return iter(self._cookies)

    def __len__(self):
        return len(self._cookies)


class MockSession:
    """Mock requests.Session for testing."""

    def __init__(self):
        self.cookies = MockCookieJar()
        self._responses = {}
        self._request_history = []

    def mount(self, prefix, adapter):
        """Mock mount method."""
        pass

    def set_cookies(self, cookies):
        """Set cookies on the mock session."""
        self.cookies = MockCookieJar(cookies)

    def add_response(self, method, url_pattern, response):
        """Add a mock response for a specific method and URL pattern."""
        key = f"{method.upper()}:{url_pattern}"
        self._responses[key] = response

    def _find_response(self, method: str, url: str) -> MockResponse:
        """Find a matching mock response."""
        # Try exact match first
        key = f"{method.upper()}:{url}"
        if key in self._responses:
            return cast(MockResponse, self._responses[key])

        # Try pattern matching - prefer longer/more specific matches
        best_match = None
        best_match_len = 0
        for pattern, response in self._responses.items():
            method_prefix, url_pattern = pattern.split(":", 1)
            # Combined condition to satisfy SIM102
            if (
                method.upper() == method_prefix
                and url_pattern in url
                and len(url_pattern) > best_match_len
            ):
                best_match = response
                best_match_len = len(url_pattern)

        if best_match is not None:
            return cast(MockResponse, best_match)

        # Default to 404
        return MockResponse(status_code=404, text="Not found")

    def _record_request(self, method, url, **kwargs):
        """Record a request for later inspection."""
        self._request_history.append(
            {
                "method": method,
                "url": url,
                **kwargs,
            }
        )

    def get(self, url, **kwargs):
        """Mock GET request."""
        self._record_request("GET", url, **kwargs)
        return self._find_response("GET", url)

    def post(self, url, **kwargs):
        """Mock POST request."""
        self._record_request("POST", url, **kwargs)
        return self._find_response("POST", url)

    def put(self, url, **kwargs):
        """Mock PUT request."""
        self._record_request("PUT", url, **kwargs)
        return self._find_response("PUT", url)

    def delete(self, url, **kwargs):
        """Mock DELETE request."""
        self._record_request("DELETE", url, **kwargs)
        return self._find_response("DELETE", url)


# Pytest fixtures
@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    return MockSession()


@pytest.fixture
def mock_requests(mock_session):
    """Patch requests.Session to return our mock session."""
    with patch("requests.Session", return_value=mock_session):
        yield mock_session


@pytest.fixture
def authenticated_session(mock_session):
    """Create a mock session that's already authenticated."""
    # Add login response
    mock_session.add_response(
        "GET",
        "/login/",
        MockResponse(status_code=302),
    )

    # Set cookies as if login succeeded
    mock_session.set_cookies(
        [
            ("GerritAccount", "test-session-cookie"),
            ("XSRF_TOKEN", "test-xsrf-token"),
        ]
    )

    # Add self account response
    mock_session.add_response(
        "GET",
        "/a/accounts/self",
        MockResponse(json_data=SAMPLE_ACCOUNT),
    )

    return mock_session


class TestStripGerritPrefix:
    """Tests for _strip_gerrit_prefix function."""

    def test_strips_standard_prefix(self):
        """Test stripping the standard Gerrit magic prefix."""
        content = ')]}\'\n{"key": "value"}'
        result = _strip_gerrit_prefix(content)
        assert result == '{"key": "value"}'

    def test_strips_prefix_without_newline(self):
        """Test stripping prefix without newline."""
        content = ")]}'some content"
        result = _strip_gerrit_prefix(content)
        assert result == "some content"

    def test_returns_content_without_prefix(self):
        """Test content without prefix is returned unchanged."""
        content = '{"key": "value"}'
        result = _strip_gerrit_prefix(content)
        assert result == content

    def test_empty_string(self):
        """Test empty string input."""
        assert _strip_gerrit_prefix("") == ""


class TestParseResponse:
    """Tests for _parse_response function."""

    def test_parses_json_response(self):
        """Test parsing a valid JSON response."""
        response = MockResponse(
            status_code=200,
            json_data={"key": "value"},
        )
        result = _parse_response(response)
        assert result == {"key": "value"}

    def test_raises_auth_error_on_401(self):
        """Test 401 response raises GerritAuthError."""
        response = MockResponse(status_code=401, text="Unauthorized")
        with pytest.raises(GerritAuthError):
            _parse_response(response)

    def test_raises_auth_error_on_403(self):
        """Test 403 response raises GerritAuthError."""
        response = MockResponse(status_code=403, text="Forbidden")
        with pytest.raises(GerritAuthError):
            _parse_response(response)

    def test_raises_not_found_on_404(self):
        """Test 404 response raises GerritNotFoundError."""
        response = MockResponse(status_code=404, text="Not found")
        with pytest.raises(GerritNotFoundError):
            _parse_response(response)

    def test_raises_conflict_on_409(self):
        """Test 409 response raises GerritConflictError."""
        response = MockResponse(status_code=409, text="Conflict")
        with pytest.raises(GerritConflictError):
            _parse_response(response)

    def test_raises_api_error_on_other_errors(self):
        """Test other error codes raise GerritAPIError."""
        response = MockResponse(status_code=500, text="Server error")
        with pytest.raises(GerritAPIError):
            _parse_response(response)

    def test_returns_none_for_empty_response(self):
        """Test empty response returns None."""
        response = MockResponse(status_code=204, text="")
        result = _parse_response(response)
        assert result is None

    def test_allow_non_json_flag(self):
        """Test allow_non_json flag returns raw content."""
        response = MockResponse(
            status_code=200,
            text="plain text response",
            headers={"content-type": "text/plain"},
        )
        result = _parse_response(response, allow_non_json=True)
        assert result == "plain text response"

    def test_non_json_content_type_raises_without_allow_non_json(self):
        """Test non-JSON content-type raises GerritAPIError when allow_non_json is False."""
        response = MockResponse(
            status_code=200,
            text="plain text response",
            headers={"content-type": "text/plain"},
        )
        with pytest.raises(GerritAPIError, match="Unexpected non-JSON content-type"):
            _parse_response(response, allow_non_json=False)

    def test_json_decode_failure_raises_without_allow_non_json(self):
        """Test JSON decode failure raises GerritAPIError when allow_non_json is False."""
        response = MockResponse(
            status_code=200,
            text="not valid json",
            headers={"content-type": "application/json"},
        )
        with pytest.raises(GerritAPIError, match="Failed to parse JSON response"):
            _parse_response(response, allow_non_json=False)

    def test_json_decode_failure_returns_content_with_allow_non_json(self):
        """Test JSON decode failure returns raw content when allow_non_json is True."""
        response = MockResponse(
            status_code=200,
            text="not valid json",
            headers={"content-type": "application/json"},
        )
        result = _parse_response(response, allow_non_json=True)
        assert result == "not valid json"


class TestValidateSshKey:
    """Tests for validate_ssh_key function."""

    def test_valid_ed25519_key(self):
        """Test valid ed25519 key."""
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnLxJUC2hdNYAY... user@host"
        assert validate_ssh_key(key) is True

    def test_valid_rsa_key(self):
        """Test valid RSA key."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host"
        assert validate_ssh_key(key) is True

    def test_valid_ecdsa_key(self):
        """Test valid ECDSA key."""
        key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAy... user@host"
        assert validate_ssh_key(key) is True

    def test_valid_sk_ed25519_key(self):
        """Test valid security key ed25519."""
        key = "sk-ssh-ed25519 AAAAG... user@host"
        assert validate_ssh_key(key) is True

    def test_empty_string_is_valid(self):
        """Test empty string is considered valid (will be skipped)."""
        assert validate_ssh_key("") is True

    def test_comment_is_valid(self):
        """Test comment line is considered valid (will be skipped)."""
        assert validate_ssh_key("# This is a comment") is True

    def test_invalid_key_type(self):
        """Test invalid key type."""
        key = "ssh-invalid AAAAB3... user@host"
        assert validate_ssh_key(key) is False

    def test_malformed_key(self):
        """Test malformed key with only type."""
        key = "ssh-rsa"
        assert validate_ssh_key(key) is False

    def test_random_text_is_invalid(self):
        """Test random text is invalid."""
        assert validate_ssh_key("not a valid ssh key") is False


class TestParseSshKeys:
    """Tests for parse_ssh_keys function."""

    def test_parses_single_key(self):
        """Test parsing a single SSH key."""
        keys_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"
        result = parse_ssh_keys(keys_str)
        assert len(result) == 1
        assert result[0] == keys_str

    def test_parses_multiple_keys(self):
        """Test parsing multiple SSH keys."""
        keys_str = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user1@host
ssh-rsa AAAAB3NzaC1yc2E... user2@host
ecdsa-sha2-nistp256 AAAAE2... user3@host"""
        result = parse_ssh_keys(keys_str)
        assert len(result) == 3

    def test_skips_empty_lines(self):
        """Test empty lines are skipped."""
        keys_str = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user1@host

ssh-rsa AAAAB3NzaC1yc2E... user2@host
"""
        result = parse_ssh_keys(keys_str)
        assert len(result) == 2

    def test_skips_comments(self):
        """Test comment lines are skipped."""
        keys_str = """# This is a comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host
# Another comment"""
        result = parse_ssh_keys(keys_str)
        assert len(result) == 1

    def test_skips_invalid_keys(self):
        """Test invalid keys are skipped with warning."""
        keys_str = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host
not-a-valid-key
ssh-rsa AAAAB3NzaC1yc2E... user2@host"""
        result = parse_ssh_keys(keys_str)
        assert len(result) == 2

    def test_empty_input(self):
        """Test empty input returns empty list."""
        assert parse_ssh_keys("") == []


class TestGerritDevClientInit:
    """Tests for GerritDevClient initialization."""

    def test_strips_trailing_slash_from_url(self):
        """Test trailing slash is stripped from base URL."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080/")
        assert client.base_url == "http://localhost:8080"

    def test_sets_default_timeout(self):
        """Test default timeout is set."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080")
        assert client.timeout == 30

    def test_custom_timeout(self):
        """Test custom timeout can be set."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080", timeout=60)
        assert client.timeout == 60

    def test_base_url_without_path(self) -> None:
        """Test base_url is set correctly when no API path is present."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080")
        assert client.base_url == "http://localhost:8080"

    def test_base_url_preserves_single_path(self) -> None:
        """Test base_url preserves single path segment (e.g., /r)."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080/r")
        assert client.base_url == "http://localhost:8080/r"

    def test_base_url_preserves_multi_path(self) -> None:
        """Test base_url preserves multiple path segments."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080/gerrit/api")
        assert client.base_url == "http://localhost:8080/gerrit/api"

    def test_base_url_strips_trailing_slash(self) -> None:
        """Test base_url strips trailing slashes."""
        with patch("requests.Session"):
            client = GerritDevClient("http://localhost:8080/r/")
        assert client.base_url == "http://localhost:8080/r"

    def test_base_url_preserves_port(self) -> None:
        """Test base_url preserves non-standard ports."""
        with patch("requests.Session"):
            client = GerritDevClient("http://gerrit.example.com:9080/r")
        assert client.base_url == "http://gerrit.example.com:9080/r"

    def test_base_url_with_https(self) -> None:
        """Test base_url works with HTTPS."""
        with patch("requests.Session"):
            client = GerritDevClient("https://gerrit.example.com/r")
        assert client.base_url == "https://gerrit.example.com/r"


class TestGerritDevClientAuthentication:
    """Tests for GerritDevClient authentication methods."""

    def test_become_account_success(self, mock_requests: MockSession) -> None:
        """Test successful account authentication."""
        # Setup mock responses
        mock_requests.add_response(
            "GET",
            "/login/",
            MockResponse(status_code=302),
        )
        mock_requests.set_cookies(
            [
                ("GerritAccount", "session-cookie"),
                ("XSRF_TOKEN", "xsrf-token"),
            ]
        )

        client = GerritDevClient("http://localhost:8080")
        result = client.become_account(1000000)

        assert result is True
        assert client._account_id == 1000000
        assert client._xsrf_token == "xsrf-token"

    def test_become_account_failure(self, mock_requests: MockSession) -> None:
        """Test authentication failure."""
        # No cookies set
        mock_requests.add_response(
            "GET",
            "/login/",
            MockResponse(status_code=200),
        )

        client = GerritDevClient("http://localhost:8080")
        with pytest.raises(GerritAuthError):
            client.become_account(1000000)

    def test_become_admin_tries_multiple_accounts(
        self, mock_requests: MockSession
    ) -> None:
        """Test become_admin tries multiple account IDs in pass 1."""
        # First account fails, second succeeds
        call_count = 0

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            nonlocal call_count
            call_count += 1
            if "1000000" in url:
                return MockResponse(status_code=404, url=url)
            mock_requests.set_cookies(
                [
                    ("GerritAccount", "session"),
                    ("XSRF_TOKEN", "token"),
                ]
            )
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080")
        result = client.become_admin()

        assert result == 1  # Second account ID tried
        assert call_count == 2

    def test_become_admin_bootstraps_on_fresh_instance(
        self, mock_requests: MockSession
    ) -> None:
        """Test become_admin creates first account on a fresh instance.

        On a fresh Gerrit instance no accounts exist, so pass 1
        (become_account with known IDs) fails.  Pass 2 uses the
        BecomeAnyAccountLoginServlet's ``action=create_account`` endpoint
        to bootstrap the first account.
        """
        get_count = 0
        post_count = 0

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            nonlocal get_count
            get_count += 1
            # Pass 1 login attempts: no accounts exist → no cookie
            if "/login/" in url:
                return MockResponse(status_code=200, url=url)
            # GET /a/accounts/self after bootstrap succeeds
            if "accounts/self" in url:
                return MockResponse(
                    json_data={
                        "_account_id": 1000000,
                        "name": "user1",
                        "username": "user1",
                    },
                )
            return MockResponse(status_code=404, url=url)

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            nonlocal post_count
            post_count += 1
            # Bootstrap POST to /login/ with action=create_account
            mock_requests.set_cookies(
                [
                    ("GerritAccount", "session"),
                    ("XSRF_TOKEN", "token"),
                ]
            )
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080")
        result = client.become_admin()

        assert result == 1000000
        # Pass 1: 2 failed login GETs (account 1000000, account 1)
        assert get_count >= 2
        # Pass 2: 1 bootstrap POST
        assert post_count == 1

    def test_become_admin_bootstrap_side_effect_retry(
        self, mock_requests: MockSession
    ) -> None:
        """Test pass 3: bootstrap creates account but cookie is lost.

        The bootstrap POST may create the account as a side-effect but
        fail to set the session cookie (e.g. due to a context-path
        redirect mismatch).  Pass 3 retries known account IDs after a
        brief pause and succeeds because the account now exists.
        """
        get_count = 0
        post_count = 0

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            nonlocal get_count
            get_count += 1
            # Pass 1 (calls 1-2): no accounts exist
            if get_count <= 2 and "/login/" in url:
                return MockResponse(status_code=200, url=url)
            # Pass 3 (after bootstrap side-effect): account 1000000 exists
            if "/login/" in url and "1000000" in url:
                mock_requests.set_cookies(
                    [
                        ("GerritAccount", "session"),
                        ("XSRF_TOKEN", "token"),
                    ]
                )
                return MockResponse(status_code=302, url=url)
            return MockResponse(status_code=200, url=url)

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            nonlocal post_count
            post_count += 1
            # Bootstrap POST: account created but no cookie set (redirect
            # lost it due to context-path mismatch)
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        import time

        with patch.object(time, "sleep"):
            client = GerritDevClient("http://localhost:8080")
            result = client.become_admin()

        assert result == 1000000
        assert post_count == 1  # Bootstrap attempted once

    def test_become_admin_all_strategies_fail(self, mock_requests: MockSession) -> None:
        """Test become_admin raises GerritAuthError when everything fails."""

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            return MockResponse(status_code=200, url=url)

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            return MockResponse(status_code=200, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        import time

        with patch.object(time, "sleep"):
            client = GerritDevClient("http://localhost:8080")
            with pytest.raises(GerritAuthError, match="Strategies tried"):
                client.become_admin()

    def test_create_first_account_success(self, mock_requests: MockSession) -> None:
        """Test _create_first_account creates account and authenticates."""
        post_count = 0

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            if "accounts/self" in url:
                return MockResponse(
                    json_data={
                        "_account_id": 1000000,
                        "name": "user1",
                        "username": "user1",
                    },
                )
            return MockResponse(status_code=404, url=url)

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            nonlocal post_count
            post_count += 1
            mock_requests.set_cookies(
                [
                    ("GerritAccount", "bootstrap-session"),
                    ("XSRF_TOKEN", "bootstrap-xsrf"),
                ]
            )
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080")
        result = client._create_first_account()

        assert result == 1000000
        assert client._account_id == 1000000
        assert client._xsrf_token == "bootstrap-xsrf"
        assert post_count == 1

    def test_create_first_account_no_cookie(self, mock_requests: MockSession) -> None:
        """Test _create_first_account raises when no session cookie is set."""

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            # POST succeeds but no cookie set (e.g. wrong auth mode)
            return MockResponse(status_code=200, url=url)

        mock_requests.post = mock_post  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080")
        with pytest.raises(GerritAuthError, match="session cookie"):
            client._create_first_account()

    def test_create_first_account_self_lookup_fails(
        self, mock_requests: MockSession
    ) -> None:
        """Test _create_first_account raises when accounts/self fails."""

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            # Cookie is set but accounts/self returns an error
            return MockResponse(status_code=500, text="Internal Server Error")

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            mock_requests.set_cookies(
                [
                    ("GerritAccount", "session"),
                    ("XSRF_TOKEN", "token"),
                ]
            )
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080")
        with pytest.raises(GerritAuthError, match="account details"):
            client._create_first_account()

    def test_create_first_account_with_context_path(
        self, mock_requests: MockSession
    ) -> None:
        """Test _create_first_account uses the correct URL with context path."""
        posted_urls: list[str] = []

        def mock_get(url: str, **kwargs: Any) -> MockResponse:
            if "accounts/self" in url:
                return MockResponse(
                    json_data={
                        "_account_id": 1000000,
                        "name": "user1",
                        "username": "user1",
                    },
                )
            return MockResponse(status_code=404, url=url)

        def mock_post(url: str, **kwargs: Any) -> MockResponse:
            posted_urls.append(url)
            mock_requests.set_cookies(
                [
                    ("GerritAccount", "session"),
                    ("XSRF_TOKEN", "token"),
                ]
            )
            return MockResponse(status_code=302, url=url)

        mock_requests.get = mock_get  # type: ignore[method-assign]
        mock_requests.post = mock_post  # type: ignore[method-assign]

        client = GerritDevClient("http://localhost:8080/r")
        client._create_first_account()

        assert len(posted_urls) == 1
        assert posted_urls[0] == "http://localhost:8080/r/login/"


class TestGerritDevClientAPIRequests:
    """Tests for GerritDevClient API request methods."""

    def test_get_request_includes_auth_header(
        self,
        authenticated_session: MockSession,
    ) -> None:
        """Test GET request includes X-Gerrit-Auth header."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-xsrf-token"

            authenticated_session.add_response(
                "GET",
                "/a/test",
                MockResponse(json_data={"result": "ok"}),
            )

            client.get("test")

        # Check the request was made with auth header
        request = authenticated_session._request_history[-1]
        assert "X-Gerrit-Auth" in request.get("headers", {})
        assert request["headers"]["X-Gerrit-Auth"] == "test-xsrf-token"

    def test_put_request_with_json_data(
        self,
        authenticated_session: MockSession,
    ) -> None:
        """Test PUT request with JSON data."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "PUT",
                "/a/test",
                MockResponse(json_data={"created": True}),
            )

            result = client.put("test", data={"key": "value"})

        assert result == {"created": True}
        request = authenticated_session._request_history[-1]
        assert request["method"] == "PUT"
        assert json.loads(request["data"]) == {"key": "value"}

    def test_post_request_with_plain_text(
        self,
        authenticated_session: MockSession,
    ) -> None:
        """Test POST request with plain text data."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "POST",
                "/a/test",
                MockResponse(json_data={"added": True}),
            )

            result = client.post("test", data="plain text", content_type="text/plain")

        assert result == {"added": True}
        request = authenticated_session._request_history[-1]
        assert request["data"] == "plain text"


class TestGerritDevClientAccountManagement:
    """Tests for GerritDevClient account management methods."""

    def test_get_account(self, authenticated_session: MockSession) -> None:
        """Test getting account details."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/accounts/testuser",
                MockResponse(json_data=SAMPLE_ACCOUNT_CREATED),
            )

            result = client.get_account("testuser")

        assert result["_account_id"] == 1000001
        assert result["username"] == "testuser"

    def test_account_exists_true(self, authenticated_session: MockSession) -> None:
        """Test account_exists returns True when account exists."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/accounts/testuser",
                MockResponse(json_data=SAMPLE_ACCOUNT_CREATED),
            )

            assert client.account_exists("testuser") is True

    def test_account_exists_false(self, authenticated_session: MockSession) -> None:
        """Test account_exists returns False when account doesn't exist."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/accounts/nonexistent",
                MockResponse(status_code=404, text="Not found"),
            )

            assert client.account_exists("nonexistent") is False

    def test_create_account(self, authenticated_session: MockSession) -> None:
        """Test creating a new account."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "PUT",
                "/a/accounts/testuser",
                MockResponse(status_code=201, json_data=SAMPLE_ACCOUNT_CREATED),
            )

            result = client.create_account(
                "testuser",
                name="Test User",
                email="testuser@example.com",
            )

        assert result["_account_id"] == 1000001
        assert result["username"] == "testuser"

    def test_get_or_create_account_existing(
        self,
        authenticated_session: MockSession,
    ) -> None:
        """Test get_or_create returns existing account."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/accounts/admin",
                MockResponse(json_data=SAMPLE_ACCOUNT),
            )

            result = client.get_or_create_account("admin")

        assert result["_account_id"] == 1000000
        assert result["username"] == "admin"


class TestGerritDevClientSshKeyManagement:
    """Tests for GerritDevClient SSH key management methods."""

    def test_add_ssh_key(self, authenticated_session: MockSession) -> None:
        """Test adding an SSH key."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "POST",
                "/a/accounts/1000000/sshkeys",
                MockResponse(status_code=201, json_data=SAMPLE_SSH_KEY),
            )

            result = client.add_ssh_key(
                1000000,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... test@example.com",
            )

        assert result["seq"] == 1
        assert result["valid"] is True

    def test_list_ssh_keys(self, authenticated_session: MockSession) -> None:
        """Test listing SSH keys."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/accounts/self/sshkeys",
                MockResponse(json_data=[SAMPLE_SSH_KEY]),
            )

            result = client.list_ssh_keys()

        assert len(result) == 1
        assert result[0]["seq"] == 1

    def test_add_ssh_keys_multiple(self, authenticated_session: MockSession) -> None:
        """Test adding multiple SSH keys."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "POST",
                "/a/accounts/1000000/sshkeys",
                MockResponse(status_code=201, json_data=SAMPLE_SSH_KEY),
            )

            keys = [
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... key1@example.com",
                "ssh-rsa AAAAB3NzaC1yc2E... key2@example.com",
            ]
            result = client.add_ssh_keys(1000000, keys)

        assert len(result) == 2


class TestGerritDevClientGroupManagement:
    """Tests for GerritDevClient group management methods."""

    def test_add_to_group(self, authenticated_session: MockSession) -> None:
        """Test adding account to group."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "PUT",
                "/a/groups/Administrators/members/1000001",
                MockResponse(status_code=201, json_data=SAMPLE_ACCOUNT_CREATED),
            )

            result = client.add_to_group(1000001, "Administrators")

        assert result is not None
        assert result["_account_id"] == 1000001

    def test_list_group_members(self, authenticated_session: MockSession) -> None:
        """Test listing group members."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            authenticated_session.add_response(
                "GET",
                "/a/groups/Administrators/members",
                MockResponse(json_data=SAMPLE_GROUP_MEMBERS),
            )

            result = client.list_group_members("Administrators")

        assert len(result) == 2
        assert result[0]["username"] == "admin"


class TestGerritDevClientHighLevelOperations:
    """Tests for GerritDevClient high-level operations."""

    def test_setup_user_with_ssh_keys(self, authenticated_session: MockSession) -> None:
        """Test the high-level setup_user_with_ssh_keys method."""
        with patch("requests.Session", return_value=authenticated_session):
            client = GerritDevClient("http://localhost:8080")
            client._xsrf_token = "test-token"

            # Account doesn't exist
            authenticated_session.add_response(
                "GET",
                "/a/accounts/newuser",
                MockResponse(status_code=404, text="Not found"),
            )

            # Create account
            authenticated_session.add_response(
                "PUT",
                "/a/accounts/newuser",
                MockResponse(status_code=201, json_data=SAMPLE_ACCOUNT_CREATED),
            )

            # Add SSH key
            authenticated_session.add_response(
                "POST",
                "/a/accounts/1000001/sshkeys",
                MockResponse(status_code=201, json_data=SAMPLE_SSH_KEY),
            )

            # Add to administrators
            authenticated_session.add_response(
                "PUT",
                "/a/groups/Administrators/members/1000001",
                MockResponse(status_code=201, json_data=SAMPLE_ACCOUNT_CREATED),
            )

            # Cache flush (will fail, but that's OK)
            authenticated_session.add_response(
                "POST",
                "/a/config/server/caches/",
                MockResponse(status_code=404),
            )

            result = client.setup_user_with_ssh_keys(
                username="newuser",
                ssh_keys=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... test@example.com"],
                name="New User",
                email="newuser@example.com",
            )

        assert result["_account_id"] == 1000001


class TestGerritExceptions:
    """Tests for Gerrit exception classes."""

    def test_gerrit_api_error_attributes(self) -> None:
        """Test GerritAPIError stores attributes correctly."""
        error = GerritAPIError(
            "Test error",
            status_code=500,
            response_text="Server error",
        )
        assert str(error) == "Test error"
        assert error.status_code == 500
        assert error.response_text == "Server error"

    def test_gerrit_auth_error_is_api_error(self) -> None:
        """Test GerritAuthError is a subclass of GerritAPIError."""
        error = GerritAuthError("Auth failed", status_code=401)
        assert isinstance(error, GerritAPIError)

    def test_gerrit_not_found_error_is_api_error(self) -> None:
        """Test GerritNotFoundError is a subclass of GerritAPIError."""
        error = GerritNotFoundError("Not found", status_code=404)
        assert isinstance(error, GerritAPIError)

    def test_gerrit_conflict_error_is_api_error(self) -> None:
        """Test GerritConflictError is a subclass of GerritAPIError."""
        error = GerritConflictError("Conflict", status_code=409)
        assert isinstance(error, GerritAPIError)
