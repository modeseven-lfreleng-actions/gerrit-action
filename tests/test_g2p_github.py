# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the g2p_github module."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from g2p_config import (
    G2PConfig,
)
from g2p_github import (
    GITHUB_API_BASE,
    OPTIONAL_ORG_SECRETS,
    REQUIRED_ORG_SECRETS,
    REQUIRED_ORG_VARIABLES,
    REQUIRED_WORKFLOW_INPUTS,
    G2PCheckResult,
    _filter_workflows,
    _github_request,
    _graphql_query,
    check_github_config,
    check_magic_repo,
    check_org_access,
    check_org_secrets,
    check_org_variables,
    check_repos_exist,
    check_token_valid,
    check_workflow_inputs,
    check_workflows,
    format_check_results,
    format_check_results_summary,
    provision_org_config,
    provision_org_secret,
    provision_org_variable,
    results_to_json,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_urlopen_response(
    status: int = 200,
    body: dict[str, Any] | list[Any] | str = "",
) -> MagicMock:
    """Create a mock for urllib.request.urlopen context manager."""
    if isinstance(body, (dict, list)):
        raw_bytes = json.dumps(body).encode("utf-8")
    else:
        raw_bytes = body.encode("utf-8")

    resp = MagicMock()
    resp.status = status
    resp.read.return_value = raw_bytes
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _make_http_error(
    status: int,
    body: dict[str, Any] | str = "",
) -> Exception:
    """Create a mock HTTPError."""
    from urllib.error import HTTPError

    if isinstance(body, dict):
        raw_bytes = json.dumps(body).encode("utf-8")
    else:
        raw_bytes = body.encode("utf-8")

    err = HTTPError(
        url="https://api.github.com/test",
        code=status,
        msg=f"HTTP {status}",
        hdrs=MagicMock(),
        fp=None,
    )
    err.read = MagicMock(return_value=raw_bytes)  # type: ignore[method-assign]
    return err


def _minimal_config(**overrides: Any) -> G2PConfig:
    """Build a minimal enabled G2PConfig with optional overrides."""
    defaults: dict[str, Any] = {
        "enabled": True,
        "github_owner": "test-org",
        "github_token": "ghp_testtoken123",
        "validation_mode": "warn",
        "validate_workflows": True,
        "validate_repos": [],
        "org_setup": "skip",
    }
    defaults.update(overrides)
    return G2PConfig(**defaults)


# ===================================================================
# G2PCheckResult
# ===================================================================


class TestG2PCheckResult:
    """Tests for the G2PCheckResult dataclass."""

    def test_defaults(self) -> None:
        r = G2PCheckResult(check_name="test", passed=True, message="ok")
        assert r.severity == "error"
        assert r.details == {}

    def test_str_passed(self) -> None:
        r = G2PCheckResult(
            check_name="test",
            passed=True,
            message="all good",
            severity="info",
        )
        s = str(r)
        assert "✅" in s
        assert "info" in s
        assert "test" in s

    def test_str_failed(self) -> None:
        r = G2PCheckResult(
            check_name="test",
            passed=False,
            message="bad",
            severity="error",
        )
        s = str(r)
        assert "❌" in s
        assert "error" in s

    def test_details_stored(self) -> None:
        r = G2PCheckResult(
            check_name="t",
            passed=True,
            message="m",
            details={"key": "value"},
        )
        assert r.details["key"] == "value"


# ===================================================================
# _github_request
# ===================================================================


class TestGithubRequest:
    """Tests for the low-level HTTP helper."""

    @patch("g2p_github.urlopen")
    def test_successful_json_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"login": "bot"})
        status, data = _github_request(f"{GITHUB_API_BASE}/user", "ghp_tok")
        assert status == 200
        assert isinstance(data, dict)
        assert data["login"] == "bot"

    @patch("g2p_github.urlopen")
    def test_successful_list_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, [{"id": 1}, {"id": 2}])
        status, data = _github_request(f"{GITHUB_API_BASE}/repos", "ghp_tok")
        assert status == 200
        assert isinstance(data, list)
        assert len(data) == 2

    @patch("g2p_github.urlopen")
    def test_non_json_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, "plain text")
        status, data = _github_request(f"{GITHUB_API_BASE}/test", "ghp_tok")
        assert status == 200
        assert data == "plain text"

    @patch("g2p_github.urlopen")
    def test_http_error_json_body(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, {"message": "Bad credentials"})
        status, data = _github_request(f"{GITHUB_API_BASE}/user", "ghp_bad")
        assert status == 401
        assert isinstance(data, dict)
        assert data["message"] == "Bad credentials"

    @patch("g2p_github.urlopen")
    def test_http_error_text_body(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(500, "Server Error")
        status, data = _github_request(f"{GITHUB_API_BASE}/test", "ghp_tok")
        assert status == 500
        assert data == "Server Error"

    @patch("g2p_github.urlopen")
    def test_sets_auth_header(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {})
        _github_request(f"{GITHUB_API_BASE}/user", "ghp_mytoken")
        req = mock_urlopen.call_args[0][0]
        # urllib.request.Request normalises header names: first letter
        # capitalised, rest lowercased.  Access via .headers dict to
        # make the stored casing explicit in the assertion.
        assert req.headers["Authorization"] == "Bearer ghp_mytoken"

    @patch("g2p_github.urlopen")
    def test_sets_api_version_header(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {})
        _github_request(f"{GITHUB_API_BASE}/user", "ghp_tok")
        req = mock_urlopen.call_args[0][0]
        # urllib normalises "X-GitHub-Api-Version" to
        # "X-github-api-version" internally.
        assert req.headers["X-github-api-version"] == "2022-11-28"

    @patch("g2p_github.urlopen")
    def test_post_with_body(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"ok": True})
        body = json.dumps({"query": "test"}).encode("utf-8")
        status, data = _github_request(
            f"{GITHUB_API_BASE}/graphql",
            "ghp_tok",
            method="POST",
            body=body,
        )
        assert status == 200
        req = mock_urlopen.call_args[0][0]
        # urllib normalises "Content-Type" to "Content-type".
        assert req.headers["Content-type"] == "application/json"
        assert req.method == "POST"


# ===================================================================
# _graphql_query
# ===================================================================


class TestGraphqlQuery:
    """Tests for the GraphQL helper."""

    @patch("g2p_github.urlopen")
    def test_successful_query(self, mock_urlopen: MagicMock) -> None:
        response_data = {
            "data": {"organization": {"repositories": {"nodes": [{"name": "repo1"}]}}}
        }
        mock_urlopen.return_value = _make_urlopen_response(200, response_data)
        status, data = _graphql_query("ghp_tok", "query { test }")
        assert status == 200
        assert "data" in data

    @patch("g2p_github.urlopen")
    def test_with_variables(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"data": {}})
        _graphql_query(
            "ghp_tok",
            "query($v: String!) { test(v: $v) }",
            variables={"v": "val"},
        )
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data)
        assert "variables" in body
        assert body["variables"]["v"] == "val"

    @patch("g2p_github.urlopen")
    def test_non_dict_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, "not json dict")
        status, data = _graphql_query("ghp_tok", "query { test }")
        assert status == 200
        assert "raw" in data

    @patch("g2p_github.urlopen")
    def test_error_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, {"message": "Unauthorized"})
        status, data = _graphql_query("ghp_tok", "query { test }")
        assert status == 401


# ===================================================================
# check_token_valid
# ===================================================================


class TestCheckTokenValid:
    """Tests for token validation."""

    @patch("g2p_github.urlopen")
    def test_valid_token(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"login": "bot-user"})
        r = check_token_valid("ghp_good")
        assert r.passed is True
        assert r.check_name == "token_valid"
        assert "bot-user" in r.message
        assert r.details.get("login") == "bot-user"

    @patch("g2p_github.urlopen")
    def test_invalid_token_401(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, {"message": "Bad credentials"})
        r = check_token_valid("ghp_bad")
        assert r.passed is False
        assert r.severity == "error"
        assert "401" in r.message

    @patch("g2p_github.urlopen")
    def test_invalid_token_403(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(403, {"message": "Forbidden"})
        r = check_token_valid("ghp_forbidden")
        assert r.passed is False
        assert "403" in r.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        r = check_token_valid("ghp_tok")
        assert r.passed is False
        assert "Network error" in r.message

    @patch("g2p_github.urlopen")
    def test_non_dict_200_response(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, "not a dict")
        r = check_token_valid("ghp_tok")
        assert r.passed is True
        assert "unknown" in r.message


# ===================================================================
# check_org_access
# ===================================================================


class TestCheckOrgAccess:
    """Tests for organisation access validation."""

    @patch("g2p_github.urlopen")
    def test_org_exists(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"login": "onap", "type": "Organization"}
        )
        r = check_org_access("ghp_tok", "onap")
        assert r.passed is True
        assert r.check_name == "org_access"
        assert "onap" in r.message

    @patch("g2p_github.urlopen")
    def test_org_not_found_but_user_exists(self, mock_urlopen: MagicMock) -> None:
        # First call (orgs) → 404, second call (users) → 200
        mock_urlopen.side_effect = [
            _make_http_error(404, {"message": "Not Found"}),
            _make_urlopen_response(200, {"login": "myuser", "type": "User"}),
        ]
        r = check_org_access("ghp_tok", "myuser")
        assert r.passed is True
        assert "user account" in r.message
        assert r.details.get("account_type") == "user"

    @patch("g2p_github.urlopen")
    def test_neither_org_nor_user(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            _make_http_error(404, {"message": "Not Found"}),
            _make_http_error(404, {"message": "Not Found"}),
        ]
        r = check_org_access("ghp_tok", "nonexistent")
        assert r.passed is False
        assert "404" in r.message
        assert "user check returned HTTP 404" in r.message
        assert r.details["org_status"] == 404
        assert r.details["user_status"] == 404

    @patch("g2p_github.urlopen")
    def test_forbidden(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(403, "Forbidden")
        r = check_org_access("ghp_tok", "secret-org")
        assert r.passed is False
        assert "403" in r.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("DNS failure")
        r = check_org_access("ghp_tok", "onap")
        assert r.passed is False
        assert "Network error" in r.message

    @patch("g2p_github.urlopen")
    def test_user_check_network_error_fallback(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        # Org check returns 404, user check has network error
        mock_urlopen.side_effect = [
            _make_http_error(404, {"message": "Not Found"}),
            URLError("timeout"),
        ]
        r = check_org_access("ghp_tok", "flaky")
        assert r.passed is False
        assert "404" in r.message
        assert "user check also failed" in r.message
        assert r.details["org_status"] == 404
        assert r.details["user_status"] == 0


# ===================================================================
# check_magic_repo
# ===================================================================


class TestCheckMagicRepo:
    """Tests for .github magic repository validation."""

    @patch("g2p_github.urlopen")
    def test_repo_exists(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"name": ".github", "full_name": "onap/.github"}
        )
        r = check_magic_repo("ghp_tok", "onap")
        assert r.passed is True
        assert r.check_name == "magic_repo"
        assert ".github" in r.message

    @patch("g2p_github.urlopen")
    def test_repo_not_found(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(404, {"message": "Not Found"})
        r = check_magic_repo("ghp_tok", "new-org")
        assert r.passed is False
        assert r.severity == "warning"
        assert "not found" in r.message

    @patch("g2p_github.urlopen")
    def test_auth_error_401(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, "Unauthorized")
        r = check_magic_repo("ghp_tok", "onap")
        assert r.passed is False
        assert r.severity == "error"
        assert "401" in r.message
        assert "authentication or permission" in r.message

    @patch("g2p_github.urlopen")
    def test_auth_error_403(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(403, "Forbidden")
        r = check_magic_repo("ghp_tok", "onap")
        assert r.passed is False
        assert r.severity == "error"
        assert "403" in r.message
        assert "authentication or permission" in r.message

    @patch("g2p_github.urlopen")
    def test_unexpected_status(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(500, "Server Error")
        r = check_magic_repo("ghp_tok", "onap")
        assert r.passed is False
        assert r.severity == "warning"
        assert "500" in r.message
        assert "may not work" in r.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("timeout")
        r = check_magic_repo("ghp_tok", "onap")
        assert r.passed is False
        assert r.severity == "warning"


# ===================================================================
# _filter_workflows
# ===================================================================


class TestFilterWorkflows:
    """Tests for workflow filtering logic."""

    def test_matches_gerrit_verify(self) -> None:
        workflows = [
            {"path": ".github/workflows/gerrit-verify.yaml", "state": "active"},
            {"path": ".github/workflows/build.yaml", "state": "active"},
        ]
        result = _filter_workflows(workflows, "verify")
        assert len(result) == 1
        assert "gerrit-verify" in result[0]["path"]

    def test_matches_gerrit_merge(self) -> None:
        workflows = [
            {"path": ".github/workflows/gerrit-merge.yaml", "state": "active"},
            {"path": ".github/workflows/gerrit-verify.yaml", "state": "active"},
        ]
        result = _filter_workflows(workflows, "merge")
        assert len(result) == 1

    def test_case_insensitive(self) -> None:
        workflows = [
            {"path": ".github/workflows/Gerrit-Verify.yaml", "state": "active"},
        ]
        result = _filter_workflows(workflows, "verify")
        assert len(result) == 1

    def test_skips_inactive(self) -> None:
        workflows = [
            {"path": ".github/workflows/gerrit-verify.yaml", "state": "disabled"},
        ]
        result = _filter_workflows(workflows, "verify")
        assert len(result) == 0

    def test_skips_non_gerrit(self) -> None:
        workflows = [
            {"path": ".github/workflows/ci-verify.yaml", "state": "active"},
        ]
        result = _filter_workflows(workflows, "verify")
        assert len(result) == 0

    def test_multiple_matches(self) -> None:
        workflows = [
            {"path": ".github/workflows/gerrit-verify.yaml", "state": "active"},
            {
                "path": ".github/workflows/gerrit-required-verify.yaml",
                "state": "active",
            },
        ]
        result = _filter_workflows(workflows, "verify")
        assert len(result) == 2

    def test_empty_workflows(self) -> None:
        result = _filter_workflows([], "verify")
        assert result == []

    def test_missing_path_field(self) -> None:
        workflows = [{"state": "active"}]
        result = _filter_workflows(workflows, "verify")
        assert result == []

    def test_required_workflows(self) -> None:
        workflows = [
            {
                "path": ".github/workflows/gerrit-required-verify.yaml",
                "state": "active",
            },
            {"path": ".github/workflows/gerrit-required-merge.yaml", "state": "active"},
        ]
        verify = _filter_workflows(workflows, "verify")
        merge = _filter_workflows(workflows, "merge")
        assert len(verify) == 1
        assert len(merge) == 1


# ===================================================================
# check_workflows
# ===================================================================


class TestCheckWorkflows:
    """Tests for workflow validation."""

    @patch("g2p_github.urlopen")
    def test_workflows_found(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 2,
                "workflows": [
                    {"path": ".github/workflows/gerrit-verify.yaml", "state": "active"},
                    {"path": ".github/workflows/build.yaml", "state": "active"},
                ],
            },
        )
        r = check_workflows("ghp_tok", "onap", ".github", "verify")
        assert r.passed is True
        assert "1" in r.message
        assert r.check_name == "workflows_.github_verify"

    @patch("g2p_github.urlopen")
    def test_no_matching_workflows(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 1,
                "workflows": [
                    {"path": ".github/workflows/build.yaml", "state": "active"},
                ],
            },
        )
        r = check_workflows("ghp_tok", "onap", ".github", "verify")
        assert r.passed is False
        assert r.severity == "warning"

    @patch("g2p_github.urlopen")
    def test_repo_not_found(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(404, "Not Found")
        r = check_workflows("ghp_tok", "onap", "missing-repo", "verify")
        assert r.passed is False
        assert "404" in r.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("timeout")
        r = check_workflows("ghp_tok", "onap", ".github", "verify")
        assert r.passed is False
        assert "Network error" in r.message

    @patch("g2p_github.urlopen")
    def test_check_name_includes_repo_and_filter(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"workflows": []})
        r = check_workflows("ghp_tok", "org", "ci-management", "merge")
        assert r.check_name == "workflows_ci-management_merge"

    @patch("g2p_github.urlopen")
    def test_unexpected_response_format(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, "not a dict")
        r = check_workflows("ghp_tok", "onap", ".github", "verify")
        assert r.passed is False
        assert "Unexpected" in r.message

    @patch("g2p_github.urlopen")
    def test_empty_workflows_list(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(200, {"workflows": []})
        r = check_workflows("ghp_tok", "onap", ".github", "verify")
        assert r.passed is False
        assert r.details.get("total_workflows") == 0


# ===================================================================
# check_repos_exist
# ===================================================================


class TestCheckReposExist:
    """Tests for REST-based repository existence check."""

    def test_empty_repos_list(self) -> None:
        r = check_repos_exist("ghp_tok", "onap", [])
        assert r.passed is True
        assert r.check_name == "repos_exist"

    @patch("g2p_github.urlopen")
    def test_all_repos_found(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            _make_urlopen_response(200, {"name": "ci-management", "archived": False}),
            _make_urlopen_response(200, {"name": "releng-lftools", "archived": False}),
        ]
        r = check_repos_exist("ghp_tok", "onap", ["ci-management", "releng-lftools"])
        assert r.passed is True
        assert "2" in r.message

    @patch("g2p_github.urlopen")
    def test_missing_repos(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            _make_urlopen_response(200, {"name": "ci-management", "archived": False}),
            _make_http_error(404, "Not Found"),
        ]
        r = check_repos_exist("ghp_tok", "onap", ["ci-management", "nonexistent"])
        assert r.passed is False
        assert r.severity == "warning"
        assert "nonexistent" in r.message
        assert "nonexistent" in r.details["missing"]

    @patch("g2p_github.urlopen")
    def test_archived_repos_noted(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"name": "old-repo", "archived": True}
        )
        r = check_repos_exist("ghp_tok", "onap", ["old-repo"])
        assert r.passed is True
        assert "archived" in r.message.lower()
        assert "old-repo" in r.details["archived"]

    @patch("g2p_github.urlopen")
    def test_http_error(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, "Unauthorized")
        r = check_repos_exist("ghp_tok", "onap", ["repo1"])
        assert r.passed is False
        assert "401" in r.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        r = check_repos_exist("ghp_tok", "onap", ["repo1"])
        assert r.passed is False
        assert r.severity == "warning"
        assert "Network error" in r.message

    @patch("g2p_github.urlopen")
    def test_multiple_repos_mixed(self, mock_urlopen: MagicMock) -> None:
        """One found, one archived, one missing."""
        mock_urlopen.side_effect = [
            _make_urlopen_response(200, {"name": "repo1", "archived": False}),
            _make_urlopen_response(200, {"name": "repo2", "archived": True}),
            _make_http_error(404, "Not Found"),
        ]
        r = check_repos_exist("ghp_tok", "onap", ["repo1", "repo2", "repo3"])
        assert r.passed is False
        assert "repo3" in r.details["missing"]
        assert "repo2" in r.details["archived"]
        assert "repo1" in r.details["found"]


# ===================================================================
# check_github_config (aggregate runner)
# ===================================================================


class TestCheckGithubConfig:
    """Tests for the aggregate check runner."""

    def test_no_token_returns_single_warning(self) -> None:
        config = _minimal_config(github_token="")
        results = check_github_config(config)
        assert len(results) == 1
        assert results[0].check_name == "token_provided"
        assert results[0].passed is False
        assert results[0].severity == "warning"

    @patch("g2p_github.urlopen")
    def test_invalid_token_stops_early(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(401, {"message": "Bad credentials"})
        config = _minimal_config()
        results = check_github_config(config)
        # Should have: token_provided (pass), token_valid (fail)
        assert len(results) == 2
        assert results[0].check_name == "token_provided"
        assert results[0].passed is True
        assert results[1].check_name == "token_valid"
        assert results[1].passed is False

    @patch("g2p_github.urlopen")
    def test_org_not_found_stops_early(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check (404) and user fallback (404)
            _make_http_error(404, "Not Found"),
            _make_http_error(404, "Not Found"),
        ]
        config = _minimal_config()
        results = check_github_config(config)
        # token_provided, token_valid, org_access
        assert len(results) == 3
        assert results[2].check_name == "org_access"
        assert results[2].passed is False

    @patch("g2p_github.urlopen")
    def test_full_pass_with_workflows(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check
            _make_urlopen_response(200, {"login": "onap"}),
            # magic repo check
            _make_urlopen_response(200, {"name": ".github"}),
            # .github verify workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-verify.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # .github merge workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-merge.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
        ]
        config = _minimal_config(validate_repos=[])
        results = check_github_config(config)
        # token_provided, token_valid, org_access, magic_repo,
        # workflows_verify, workflows_merge
        assert len(results) == 6
        assert all(r.passed for r in results)

    @patch("g2p_github.urlopen")
    def test_validate_repos_triggers_per_repo_checks(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check
            _make_urlopen_response(200, {"login": "onap"}),
            # magic repo
            _make_urlopen_response(200, {"name": ".github"}),
            # .github verify
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-verify.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # .github merge
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-merge.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # ci-management verify
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-verify.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # ci-management merge
            _make_urlopen_response(200, {"workflows": []}),
            # repos_exist REST (one call per repo)
            _make_urlopen_response(200, {"name": "ci-management", "archived": False}),
        ]
        config = _minimal_config(validate_repos=["ci-management"])
        results = check_github_config(config)
        check_names = [r.check_name for r in results]
        assert "workflows_ci-management_verify" in check_names
        assert "workflows_ci-management_merge" in check_names
        assert "repos_exist" in check_names

    @patch("g2p_github.urlopen")
    def test_validate_workflows_false_skips_workflow_checks(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check
            _make_urlopen_response(200, {"login": "onap"}),
            # magic repo
            _make_urlopen_response(200, {"name": ".github"}),
        ]
        config = _minimal_config(validate_workflows=False, validate_repos=[])
        results = check_github_config(config)
        check_names = [r.check_name for r in results]
        assert not any("workflows_" in n for n in check_names)


# ===================================================================
# format_check_results
# ===================================================================


class TestFormatCheckResults:
    """Tests for result formatting."""

    def test_all_passed_no_annotations(self) -> None:
        results = [
            G2PCheckResult("a", True, "ok", "info"),
            G2PCheckResult("b", True, "ok", "info"),
        ]
        annotations, has_fatal = format_check_results(results, "error")
        assert annotations == []
        assert has_fatal is False

    def test_error_mode_with_error_severity(self) -> None:
        results = [
            G2PCheckResult("token_valid", False, "Token bad", "error"),
        ]
        annotations, has_fatal = format_check_results(results, "error")
        assert has_fatal is True
        # Annotations are retained so callers can surface them in
        # summaries; the logger also emits the ::error:: prefix.
        assert any("::error::" in a for a in annotations)

    def test_warn_mode_with_error_severity(self) -> None:
        results = [
            G2PCheckResult("token_valid", False, "Token bad", "error"),
        ]
        annotations, has_fatal = format_check_results(results, "warn")
        assert has_fatal is False
        assert any("::warning::" in a for a in annotations)

    def test_warning_severity_always_warning(self) -> None:
        results = [
            G2PCheckResult("magic_repo", False, "Missing", "warning"),
        ]
        annotations, has_fatal = format_check_results(results, "error")
        assert has_fatal is False
        assert any("::warning::" in a for a in annotations)

    def test_info_severity_not_annotated(self) -> None:
        results = [
            G2PCheckResult("some_check", False, "Info message", "info"),
        ]
        annotations, has_fatal = format_check_results(results, "error")
        assert annotations == []
        assert has_fatal is False

    def test_mixed_results(self) -> None:
        results = [
            G2PCheckResult("a", True, "pass", "info"),
            G2PCheckResult("b", False, "warn msg", "warning"),
            G2PCheckResult("c", False, "err msg", "error"),
        ]
        annotations, has_fatal = format_check_results(results, "error")
        assert has_fatal is True
        assert len(annotations) == 2  # warning + error

    def test_empty_results(self) -> None:
        annotations, has_fatal = format_check_results([], "error")
        assert annotations == []
        assert has_fatal is False


# ===================================================================
# results_to_json
# ===================================================================


class TestResultsToJson:
    """Tests for JSON serialisation of results."""

    def test_serialises_results(self) -> None:
        results = [
            G2PCheckResult("a", True, "ok", "info"),
            G2PCheckResult("b", False, "bad", "error"),
        ]
        raw = results_to_json(results)
        data = json.loads(raw)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["check_name"] == "a"
        assert data[0]["passed"] is True
        assert data[1]["passed"] is False

    def test_empty_results(self) -> None:
        raw = results_to_json([])
        data = json.loads(raw)
        assert data == []

    def test_fields_present(self) -> None:
        results = [
            G2PCheckResult("test", True, "msg", "warning"),
        ]
        raw = results_to_json(results)
        data = json.loads(raw)
        item = data[0]
        assert "check_name" in item
        assert "passed" in item
        assert "message" in item
        assert "severity" in item
        # details should NOT be in the serialised output
        assert "details" not in item


# ===================================================================
# Constants validation
# ===================================================================


class TestConstants:
    """Verify module-level constants."""

    def test_required_workflow_inputs(self) -> None:
        assert isinstance(REQUIRED_WORKFLOW_INPUTS, tuple)
        assert len(REQUIRED_WORKFLOW_INPUTS) == 9
        assert all(inp.startswith("GERRIT_") for inp in REQUIRED_WORKFLOW_INPUTS)

    def test_github_api_base(self) -> None:
        assert GITHUB_API_BASE == "https://api.github.com"

    def test_required_inputs_include_key_fields(self) -> None:
        assert "GERRIT_BRANCH" in REQUIRED_WORKFLOW_INPUTS
        assert "GERRIT_PROJECT" in REQUIRED_WORKFLOW_INPUTS
        assert "GERRIT_REFSPEC" in REQUIRED_WORKFLOW_INPUTS
        assert "GERRIT_CHANGE_ID" in REQUIRED_WORKFLOW_INPUTS
        assert "GERRIT_EVENT_TYPE" in REQUIRED_WORKFLOW_INPUTS


# ===================================================================
# check_org_secrets
# ===================================================================


class TestCheckOrgSecrets:
    """Tests for the org secrets audit check."""

    @patch("g2p_github.urlopen")
    def test_all_required_present(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 3,
                "secrets": [
                    {"name": "GERRIT_SSH_PRIVKEY"},
                    {"name": "GERRIT_SSH_PRIVKEY_G2G"},
                    {"name": "OTHER_SECRET"},
                ],
            },
        )
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is True
        assert result.check_name == "org_secrets"
        assert "GERRIT_SSH_PRIVKEY" not in result.details.get("missing_required", [])
        assert "GERRIT_SSH_PRIVKEY_G2G" not in result.details.get(
            "missing_optional", []
        )

    @patch("g2p_github.urlopen")
    def test_required_missing(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 1,
                "secrets": [{"name": "UNRELATED"}],
            },
        )
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "error"
        assert "GERRIT_SSH_PRIVKEY" in result.details["missing_required"]

    @patch("g2p_github.urlopen")
    def test_empty_secrets(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"total_count": 0, "secrets": []}
        )
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "error"

    @patch("g2p_github.urlopen")
    def test_permission_denied_403(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(403, {"message": "Forbidden"})
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "warning"
        assert "insufficient permissions" in result.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "warning"

    @patch("g2p_github.urlopen")
    def test_optional_missing_passes_as_info(self, mock_urlopen: MagicMock) -> None:
        """Missing OPTIONAL secret is informational, not a warning.

        ``GERRIT_SSH_PRIVKEY_G2G`` is only relevant to orgs that run
        gerrit-to-gerrit replication; its absence in the standard
        Gerrit -> GitHub flow is expected and must not produce
        warnings or fail the audit.  The optional name is still
        recorded in ``details['missing_optional']`` for visibility.
        """
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 1,
                "secrets": [{"name": "GERRIT_SSH_PRIVKEY"}],
            },
        )
        result = check_org_secrets("ghp_token", "test-org")
        assert result.passed is True
        assert result.severity == "info"
        assert "GERRIT_SSH_PRIVKEY_G2G" in result.details.get("missing_optional", [])
        # Message keeps the breadcrumb so the optional gap is still
        # discoverable in logs and the step summary table.
        assert "optional missing" in result.message


# ===================================================================
# check_org_variables
# ===================================================================


class TestCheckOrgVariables:
    """Tests for the org variables audit check."""

    @patch("g2p_github.urlopen")
    def test_all_present_and_populated(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 4,
                "variables": [
                    {"name": "GERRIT_SERVER", "value": "host:29418"},
                    {"name": "GERRIT_SSH_USER", "value": "lfci"},
                    {"name": "GERRIT_KNOWN_HOSTS", "value": "host ssh-ed25519 AAA"},
                    {"name": "GERRIT_URL", "value": "https://gerrit.example.org/r/"},
                ],
            },
        )
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is True
        assert result.check_name == "org_variables"

    @patch("g2p_github.urlopen")
    def test_some_missing(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 2,
                "variables": [
                    {"name": "GERRIT_SERVER", "value": "host:29418"},
                    {"name": "GERRIT_SSH_USER", "value": "lfci"},
                ],
            },
        )
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "error"
        assert "GERRIT_KNOWN_HOSTS" in result.details["missing"]
        assert "GERRIT_URL" in result.details["missing"]

    @patch("g2p_github.urlopen")
    def test_empty_values_warned(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {
                "total_count": 4,
                "variables": [
                    {"name": "GERRIT_SERVER", "value": "host:29418"},
                    {"name": "GERRIT_SSH_USER", "value": ""},
                    {"name": "GERRIT_KNOWN_HOSTS", "value": "data"},
                    {"name": "GERRIT_URL", "value": "url"},
                ],
            },
        )
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "warning"
        assert "GERRIT_SSH_USER" in result.details["empty"]

    @patch("g2p_github.urlopen")
    def test_permission_denied_403(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(403, {"message": "Forbidden"})
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "warning"
        assert "insufficient permissions" in result.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "warning"

    @patch("g2p_github.urlopen")
    def test_none_present(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"total_count": 0, "variables": []}
        )
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert result.severity == "error"
        assert len(result.details["missing"]) == 4

    @patch("g2p_github.urlopen")
    def test_unexpected_status(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = _make_http_error(500, "Internal Server Error")
        result = check_org_variables("ghp_token", "test-org")
        assert result.passed is False
        assert "500" in result.message


# ===================================================================
# check_workflow_inputs
# ===================================================================


class TestCheckWorkflowInputs:
    """Tests for the workflow inputs check."""

    @patch("g2p_github.urlopen")
    def test_all_inputs_present(self, mock_urlopen: MagicMock) -> None:
        workflow_text = (
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      GERRIT_BRANCH:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_CHANGE_ID:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_CHANGE_NUMBER:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_CHANGE_URL:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_EVENT_TYPE:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_PATCHSET_NUMBER:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_PATCHSET_REVISION:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_PROJECT:\n"
            "        required: true\n"
            "        type: string\n"
            "      GERRIT_REFSPEC:\n"
            "        required: true\n"
            "        type: string\n"
            "jobs: {}\n"
        )
        graphql_resp = {
            "data": {
                "repository": {
                    "object": {
                        "text": workflow_text,
                    }
                }
            }
        }
        mock_urlopen.return_value = _make_urlopen_response(200, graphql_resp)
        result = check_workflow_inputs(
            "ghp_token",
            "test-org",
            ".github",
            ".github/workflows/gerrit-verify.yaml",
        )
        assert result.passed is True

    @patch("g2p_github.urlopen")
    def test_missing_inputs(self, mock_urlopen: MagicMock) -> None:
        workflow_text = (
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      GERRIT_BRANCH:\n"
            "        required: true\n"
            "      GERRIT_PROJECT:\n"
            "        required: true\n"
        )
        graphql_resp = {
            "data": {
                "repository": {
                    "object": {
                        "text": workflow_text,
                    }
                }
            }
        }
        mock_urlopen.return_value = _make_urlopen_response(200, graphql_resp)
        result = check_workflow_inputs(
            "ghp_token",
            "test-org",
            ".github",
            ".github/workflows/gerrit-verify.yaml",
        )
        assert result.passed is False
        assert result.severity == "warning"
        assert len(result.details["missing"]) == 7

    @patch("g2p_github.urlopen")
    def test_no_workflow_dispatch(self, mock_urlopen: MagicMock) -> None:
        workflow_text = "on:\n  push:\n    branches:\n      - main\n"
        graphql_resp = {
            "data": {
                "repository": {
                    "object": {
                        "text": workflow_text,
                    }
                }
            }
        }
        mock_urlopen.return_value = _make_urlopen_response(200, graphql_resp)
        result = check_workflow_inputs(
            "ghp_token",
            "test-org",
            ".github",
            ".github/workflows/gerrit-verify.yaml",
        )
        assert result.passed is False
        assert len(result.details["missing"]) == 9

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = check_workflow_inputs(
            "ghp_token",
            "test-org",
            ".github",
            ".github/workflows/gerrit-verify.yaml",
        )
        assert result.passed is False
        assert result.severity == "warning"

    @patch("g2p_github.urlopen")
    def test_file_not_found(self, mock_urlopen: MagicMock) -> None:
        graphql_resp = {
            "data": {
                "repository": {
                    "object": None,
                }
            }
        }
        mock_urlopen.return_value = _make_urlopen_response(200, graphql_resp)
        result = check_workflow_inputs(
            "ghp_token",
            "test-org",
            ".github",
            ".github/workflows/nonexistent.yaml",
        )
        assert result.passed is False
        assert result.severity == "warning"


# ===================================================================
# format_check_results_summary
# ===================================================================


class TestFormatCheckResultsSummary:
    """Tests for the step summary renderer."""

    def test_all_pass_verify_mode(self) -> None:
        results = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=True,
                message="All secrets present",
            ),
            G2PCheckResult(
                check_name="org_variables",
                passed=True,
                message="All variables present",
            ),
        ]
        summary = format_check_results_summary(results, "test-org", "verify")
        assert "## G2P Organisation Audit: `test-org`" in summary
        assert "PASS" in summary
        assert "verify" in summary

    def test_failures_verify_mode(self) -> None:
        results = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message="Missing GERRIT_SSH_PRIVKEY",
                severity="error",
            ),
        ]
        summary = format_check_results_summary(results, "test-org", "verify")
        assert "FAIL" in summary
        assert "### Absent Items" in summary
        assert "GERRIT_SSH_PRIVKEY" in summary

    def test_provision_mode_with_items(self) -> None:
        results = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=True,
                message="All present",
            ),
        ]
        provisioned = [
            "Created secret GERRIT_SSH_PRIVKEY",
            "Created variable GERRIT_SERVER",
        ]
        summary = format_check_results_summary(
            results, "test-org", "provision", provisioned
        )
        assert "provision" in summary
        assert "### Provisioned Items" in summary
        assert "GERRIT_SSH_PRIVKEY" in summary
        assert "GERRIT_SERVER" in summary

    def test_empty_results(self) -> None:
        summary = format_check_results_summary([], "test-org", "skip")
        assert "## G2P Organisation Audit:" in summary


# ===================================================================
# check_github_config with org audit
# ===================================================================


class TestCheckGithubConfigWithOrgAudit:
    """Tests for check_github_config org-audit integration.

    Note: as of the org provisioning rework, ``check_github_config``
    no longer runs ``check_org_secrets`` / ``check_org_variables``
    directly — those run in ``configure-g2p.py`` as a dedicated
    audit phase so the audit can re-run after provisioning.
    """

    @patch("g2p_github.urlopen")
    def test_org_checks_not_included_in_verify_mode(
        self, mock_urlopen: MagicMock
    ) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check
            _make_urlopen_response(200, {"login": "test-org"}),
            # magic repo
            _make_urlopen_response(200, {"name": ".github"}),
            # .github verify workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-verify.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # .github merge workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-merge.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
        ]
        config = _minimal_config(org_setup="verify")
        results = check_github_config(config)
        check_names = [r.check_name for r in results]
        assert "org_secrets" not in check_names
        assert "org_variables" not in check_names

    @patch("g2p_github.urlopen")
    def test_org_checks_not_included_when_skip(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = [
            # token check
            _make_urlopen_response(200, {"login": "bot"}),
            # org check
            _make_urlopen_response(200, {"login": "test-org"}),
            # magic repo
            _make_urlopen_response(200, {"name": ".github"}),
            # .github verify workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-verify.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
            # .github merge workflows
            _make_urlopen_response(
                200,
                {
                    "workflows": [
                        {
                            "path": ".github/workflows/gerrit-merge.yaml",
                            "state": "active",
                        },
                    ]
                },
            ),
        ]
        config = _minimal_config(org_setup="skip")
        results = check_github_config(config)
        check_names = [r.check_name for r in results]
        assert "org_secrets" not in check_names
        assert "org_variables" not in check_names


# ===================================================================
# New constants for org audit
# ===================================================================


class TestOrgAuditConstants:
    """Tests for the org audit constants."""

    def test_required_org_secrets(self) -> None:
        assert "GERRIT_SSH_PRIVKEY" in REQUIRED_ORG_SECRETS

    def test_optional_org_secrets(self) -> None:
        assert "GERRIT_SSH_PRIVKEY_G2G" in OPTIONAL_ORG_SECRETS

    def test_required_org_variables(self) -> None:
        assert "GERRIT_SERVER" in REQUIRED_ORG_VARIABLES
        assert "GERRIT_SSH_USER" in REQUIRED_ORG_VARIABLES
        assert "GERRIT_KNOWN_HOSTS" in REQUIRED_ORG_VARIABLES
        assert "GERRIT_URL" in REQUIRED_ORG_VARIABLES

    def test_required_org_variables_count(self) -> None:
        assert len(REQUIRED_ORG_VARIABLES) == 4


# ===================================================================
# Provisioning function tests
# ===================================================================


def _make_fake_nacl_modules() -> tuple[MagicMock, MagicMock, dict[str, Any]]:
    """Build fake nacl modules for testing encryption path.

    Returns a tuple of (mock_public_key_cls, mock_sealed_box_cls,
    modules_dict) where modules_dict can be passed to
    patch.dict("sys.modules", ...).
    """
    from types import ModuleType

    mock_nacl = ModuleType("nacl")
    mock_nacl_public = ModuleType("nacl.public")

    mock_pk_cls = MagicMock(name="PublicKey")
    mock_sb_cls = MagicMock(name="SealedBox")
    mock_sb_instance = MagicMock()
    mock_sb_instance.encrypt.return_value = b"encrypted_bytes"
    mock_sb_cls.return_value = mock_sb_instance

    mock_nacl_public.PublicKey = mock_pk_cls  # type: ignore[attr-defined]
    mock_nacl_public.SealedBox = mock_sb_cls  # type: ignore[attr-defined]

    modules = {"nacl": mock_nacl, "nacl.public": mock_nacl_public}
    return mock_pk_cls, mock_sb_cls, modules


class TestProvisionOrgSecret:
    """Tests for provision_org_secret."""

    @patch("g2p_github.urlopen")
    def test_success_created(self, mock_urlopen: MagicMock) -> None:
        """Secret created successfully (201)."""
        _, _, nacl_mods = _make_fake_nacl_modules()
        key_resp = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        put_resp = _make_urlopen_response(201, "")
        mock_urlopen.side_effect = [key_resp, put_resp]
        with patch.dict("sys.modules", nacl_mods):
            result = provision_org_secret(
                "ghp_tok", "test-org", "MY_SECRET", "secret_val"
            )
        assert result.passed is True
        assert result.check_name == "provision_secret_MY_SECRET"
        assert "Created/updated" in result.message

    @patch("g2p_github.urlopen")
    def test_success_updated(self, mock_urlopen: MagicMock) -> None:
        """Secret updated successfully (204)."""
        _, _, nacl_mods = _make_fake_nacl_modules()
        key_resp = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        put_resp = _make_urlopen_response(204, "")
        mock_urlopen.side_effect = [key_resp, put_resp]
        with patch.dict("sys.modules", nacl_mods):
            result = provision_org_secret(
                "ghp_tok", "test-org", "MY_SECRET", "secret_val"
            )
        assert result.passed is True

    @patch("g2p_github.urlopen")
    def test_public_key_network_error(self, mock_urlopen: MagicMock) -> None:
        """URLError when fetching the org public key."""
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "Network error fetching org public key" in result.message

    @patch("g2p_github.urlopen")
    def test_public_key_non_200(self, mock_urlopen: MagicMock) -> None:
        """Non-200 status on the public-key fetch."""
        mock_urlopen.side_effect = _make_http_error(403, {"message": "Forbidden"})
        result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "Failed to fetch org public key" in result.message

    @patch("g2p_github.urlopen")
    def test_public_key_missing_key_id(self, mock_urlopen: MagicMock) -> None:
        """Public key response missing key_id."""
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"key_id": "", "key": "dGVzdHB1YmtleQ=="}
        )
        result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "missing key_id or key" in result.message

    @patch("g2p_github.urlopen")
    def test_public_key_missing_key(self, mock_urlopen: MagicMock) -> None:
        """Public key response missing key value."""
        mock_urlopen.return_value = _make_urlopen_response(
            200, {"key_id": "keyid123", "key": ""}
        )
        result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "missing key_id or key" in result.message

    @patch("g2p_github.urlopen")
    def test_nacl_import_error(self, mock_urlopen: MagicMock) -> None:
        """ImportError when PyNaCl is not installed."""
        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        with patch.dict("sys.modules", {"nacl": None, "nacl.public": None}):
            result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "PyNaCl is required" in result.message

    @patch("g2p_github.urlopen")
    def test_encryption_error(self, mock_urlopen: MagicMock) -> None:
        """Generic exception during encryption."""
        from types import ModuleType

        mock_urlopen.return_value = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        mock_nacl = ModuleType("nacl")
        mock_nacl_public = ModuleType("nacl.public")

        def _bad_public_key(_data: bytes) -> None:
            msg = "bad key data"
            raise ValueError(msg)

        mock_nacl_public.PublicKey = _bad_public_key  # type: ignore[attr-defined]
        mock_nacl_public.SealedBox = MagicMock  # type: ignore[attr-defined]

        mods = {"nacl": mock_nacl, "nacl.public": mock_nacl_public}
        with patch.dict("sys.modules", mods):
            result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "Failed to encrypt secret value" in result.message

    @patch("g2p_github.urlopen")
    def test_put_network_error(self, mock_urlopen: MagicMock) -> None:
        """URLError on the PUT request."""
        from urllib.error import URLError

        _, _, nacl_mods = _make_fake_nacl_modules()
        key_resp = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        mock_urlopen.side_effect = [
            key_resp,
            URLError("Connection reset"),
        ]
        with patch.dict("sys.modules", nacl_mods):
            result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "Network error creating secret" in result.message

    @patch("g2p_github.urlopen")
    def test_put_failure_status(self, mock_urlopen: MagicMock) -> None:
        """PUT returns unexpected status (e.g. 422)."""
        _, _, nacl_mods = _make_fake_nacl_modules()
        key_resp = _make_urlopen_response(
            200,
            {"key_id": "keyid123", "key": "dGVzdHB1YmtleQ=="},
        )
        put_resp = _make_urlopen_response(422, "")
        mock_urlopen.side_effect = [key_resp, put_resp]
        with patch.dict("sys.modules", nacl_mods):
            result = provision_org_secret("ghp_tok", "test-org", "MY_SECRET", "val")
        assert result.passed is False
        assert "422" in result.message


class TestProvisionOrgVariable:
    """Tests for provision_org_variable."""

    @patch("g2p_github.urlopen")
    def test_create_new_variable(self, mock_urlopen: MagicMock) -> None:
        """POST creates a new variable (201)."""
        mock_urlopen.return_value = _make_urlopen_response(201, "")
        result = provision_org_variable("ghp_tok", "test-org", "MY_VAR", "my_value")
        assert result.passed is True
        assert result.check_name == "provision_variable_MY_VAR"
        assert "Created" in result.message

    @patch("g2p_github.urlopen")
    def test_update_existing_variable(self, mock_urlopen: MagicMock) -> None:
        """PATCH updates an existing variable (204)."""
        mock_urlopen.return_value = _make_urlopen_response(204, "")
        result = provision_org_variable(
            "ghp_tok", "test-org", "MY_VAR", "new_val", exists=True
        )
        assert result.passed is True
        assert "Updated" in result.message

    @patch("g2p_github.urlopen")
    def test_conflict_409_retries_with_patch(self, mock_urlopen: MagicMock) -> None:
        """POST 409 retries with PATCH and succeeds."""
        post_resp = _make_urlopen_response(409, "")
        patch_resp = _make_urlopen_response(204, "")
        mock_urlopen.side_effect = [post_resp, patch_resp]
        result = provision_org_variable("ghp_tok", "test-org", "MY_VAR", "val")
        assert result.passed is True
        assert "Updated" in result.message

    @patch("g2p_github.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        """URLError during request."""
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")
        result = provision_org_variable("ghp_tok", "test-org", "MY_VAR", "val")
        assert result.passed is False
        assert "Network error" in result.message

    @patch("g2p_github.urlopen")
    def test_unexpected_status(self, mock_urlopen: MagicMock) -> None:
        """Unexpected HTTP status (e.g. 500)."""
        mock_urlopen.side_effect = _make_http_error(500, "Internal Server Error")
        result = provision_org_variable("ghp_tok", "test-org", "MY_VAR", "val")
        assert result.passed is False
        assert "500" in result.message

    @patch("g2p_github.urlopen")
    def test_409_on_patch_does_not_recurse(self, mock_urlopen: MagicMock) -> None:
        """PATCH returning 409 falls through to error."""
        mock_urlopen.return_value = _make_urlopen_response(409, "")
        result = provision_org_variable(
            "ghp_tok", "test-org", "MY_VAR", "val", exists=True
        )
        assert result.passed is False
        assert "409" in result.message


class TestProvisionOrgConfig:
    """Tests for provision_org_config."""

    @patch("g2p_github.provision_org_secret")
    def test_provisions_secret_when_audit_reports_missing(
        self, mock_prov_secret: MagicMock
    ) -> None:
        """Provisions GERRIT_SSH_PRIVKEY when audit flags it missing."""
        mock_prov_secret.return_value = G2PCheckResult(
            check_name="provision_secret_GERRIT_SSH_PRIVKEY",
            passed=True,
            message="Created/updated org secret 'GERRIT_SSH_PRIVKEY'",
            severity="info",
        )
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message="Missing required secrets",
                details={
                    "missing_required": ["GERRIT_SSH_PRIVKEY"],
                },
            ),
        ]
        gerrit_info = {"ssh_private_key": "-----BEGIN OPENSSH-----"}
        results = provision_org_config(config, audit, gerrit_info)
        # Always-overwrite semantics: every required secret is
        # provisioned regardless of prior audit pass/fail state.
        secret_results = [
            r for r in results if r.check_name.startswith("provision_secret_")
        ]
        assert len(secret_results) == 1
        assert secret_results[0].passed is True
        mock_prov_secret.assert_called_once()

    @patch("g2p_github.provision_org_secret")
    def test_overwrites_secret_even_when_already_present(
        self, mock_prov_secret: MagicMock
    ) -> None:
        """Re-runs always overwrite GERRIT_SSH_PRIVKEY in provision mode.

        A previous provision run leaves the secret in place, but the
        Gerrit container's ephemeral key changes on every build, so
        we must overwrite to keep Gerrit and the org in sync.
        """
        mock_prov_secret.return_value = G2PCheckResult(
            check_name="provision_secret_GERRIT_SSH_PRIVKEY",
            passed=True,
            message="Created/updated org secret 'GERRIT_SSH_PRIVKEY'",
            severity="info",
        )
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=True,
                message="All required org secrets present",
                details={
                    "missing_required": [],
                    "missing_optional": [],
                    "found": ["GERRIT_SSH_PRIVKEY"],
                },
            ),
        ]
        gerrit_info = {"ssh_private_key": "-----BEGIN OPENSSH-----"}
        provision_org_config(config, audit, gerrit_info)
        mock_prov_secret.assert_called_once()

    @patch("g2p_github.provision_org_variable")
    def test_provisions_variables_when_audit_reports_missing(
        self, mock_prov_var: MagicMock
    ) -> None:
        """Creates each required variable from the run's gerrit_info."""
        mock_prov_var.return_value = G2PCheckResult(
            check_name="provision_variable_X",
            passed=True,
            message="Created org variable",
            severity="info",
        )
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message="Missing variables",
                details={
                    "missing": [
                        "GERRIT_SERVER",
                        "GERRIT_SSH_USER",
                        "GERRIT_KNOWN_HOSTS",
                        "GERRIT_URL",
                    ],
                    "empty": [],
                    "found": [],
                },
            ),
        ]
        gerrit_info = {
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        results = provision_org_config(config, audit, gerrit_info)
        var_results = [
            r for r in results if r.check_name.startswith("provision_variable_")
        ]
        # Every required variable is provisioned on every run.
        assert len(var_results) == len(REQUIRED_ORG_VARIABLES)
        # All four use POST (exists=False) because audit shows none found.
        assert all(
            call.kwargs.get("exists") is False for call in mock_prov_var.call_args_list
        )

    @patch("g2p_github.provision_org_variable")
    def test_overwrites_existing_variables_with_patch(
        self, mock_prov_var: MagicMock
    ) -> None:
        """Existing variables get PATCHed with current values on re-run.

        Tunnel host/port and known_hosts can change between provision
        runs, so stale values must be overwritten rather than left.
        """
        mock_prov_var.return_value = G2PCheckResult(
            check_name="provision_variable_X",
            passed=True,
            message="Updated",
            severity="info",
        )
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_variables",
                passed=True,
                message="All present",
                details={
                    "missing": [],
                    "empty": [],
                    "found": list(REQUIRED_ORG_VARIABLES),
                },
            ),
        ]
        gerrit_info = {
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        provision_org_config(config, audit, gerrit_info)
        # All four variables were already present → exists=True (PATCH)
        assert mock_prov_var.call_count == len(REQUIRED_ORG_VARIABLES)
        for call in mock_prov_var.call_args_list:
            assert call.kwargs.get("exists") is True

    @patch("g2p_github.provision_org_variable")
    def test_empty_var_uses_patch(self, mock_prov_var: MagicMock) -> None:
        """Variables present-but-empty use exists=True (PATCH)."""
        mock_prov_var.return_value = G2PCheckResult(
            check_name="provision_variable_X",
            passed=True,
            message="Updated",
            severity="info",
        )
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message="Empty variables",
                details={
                    "missing": [],
                    "empty": ["GERRIT_URL"],
                    "found": ["GERRIT_URL"],
                },
            ),
        ]
        gerrit_info = {
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        provision_org_config(config, audit, gerrit_info)
        # Locate the GERRIT_URL call and confirm PATCH (exists=True).
        url_calls = [
            c for c in mock_prov_var.call_args_list if c.args[2] == "GERRIT_URL"
        ]
        assert len(url_calls) == 1
        assert url_calls[0].kwargs.get("exists") is True
        assert url_calls[0].args[3] == "https://gerrit.example.org/r/"

    def test_no_audit_results_skips_variable_existence_inference(self) -> None:
        """No audit results: variables default to POST (exists=False).

        With always-overwrite semantics, secrets and variables are
        still attempted using the run's gerrit_info; only the
        existence hint (POST vs PATCH) is unavailable.
        """
        config = _minimal_config(org_setup="provision")
        gerrit_info = {
            "ssh_private_key": "key_data",
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        with (
            patch("g2p_github.provision_org_secret") as mock_secret,
            patch("g2p_github.provision_org_variable") as mock_var,
        ):
            mock_secret.return_value = G2PCheckResult(
                check_name="provision_secret_GERRIT_SSH_PRIVKEY",
                passed=True,
                message="ok",
                severity="info",
            )
            mock_var.return_value = G2PCheckResult(
                check_name="provision_variable_X",
                passed=True,
                message="ok",
                severity="info",
            )
            provision_org_config(config, [], gerrit_info)
            # All required items still get provisioned.
            assert mock_secret.call_count == 1
            assert mock_var.call_count == len(REQUIRED_ORG_VARIABLES)
            # No audit data → exists=False everywhere.
            for call in mock_var.call_args_list:
                assert call.kwargs.get("exists") is False

    def test_all_passed_audit_still_overwrites(self) -> None:
        """Passing audit results do NOT skip provisioning.

        This is the critical re-run safety property: a prior run
        leaving everything in place must not stop the current run
        from overwriting with its own (potentially different)
        values.
        """
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=True,
                message="All present",
                details={"found": ["GERRIT_SSH_PRIVKEY"]},
            ),
            G2PCheckResult(
                check_name="org_variables",
                passed=True,
                message="All present",
                details={
                    "missing": [],
                    "empty": [],
                    "found": list(REQUIRED_ORG_VARIABLES),
                },
            ),
        ]
        gerrit_info = {
            "ssh_private_key": "key_data",
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        with (
            patch("g2p_github.provision_org_secret") as mock_secret,
            patch("g2p_github.provision_org_variable") as mock_var,
        ):
            mock_secret.return_value = G2PCheckResult(
                check_name="x", passed=True, message="ok"
            )
            mock_var.return_value = G2PCheckResult(
                check_name="x", passed=True, message="ok"
            )
            provision_org_config(config, audit, gerrit_info)
            assert mock_secret.call_count == 1
            assert mock_var.call_count == len(REQUIRED_ORG_VARIABLES)

    def test_missing_secret_value_records_failure(self) -> None:
        """Provision attempt records a failure when no SSH key is available."""
        config = _minimal_config(org_setup="provision")
        # Empty gerrit_info — no ssh_private_key
        results = provision_org_config(config, [], {})
        secret_failures = [
            r
            for r in results
            if r.check_name == "provision_secret_GERRIT_SSH_PRIVKEY" and not r.passed
        ]
        assert len(secret_failures) == 1
        assert secret_failures[0].severity == "error"

    def test_missing_variable_value_records_failure(self) -> None:
        """Variable with no run-time value emits an explicit failure."""
        config = _minimal_config(org_setup="provision")
        # Provide some values but omit GERRIT_SERVER prerequisites
        gerrit_info = {
            "ssh_private_key": "key_data",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
            # ssh_host / ssh_port intentionally absent
        }
        with patch("g2p_github.provision_org_variable") as mock_var:
            mock_var.return_value = G2PCheckResult(
                check_name="x", passed=True, message="ok"
            )
            results = provision_org_config(config, [], gerrit_info)
        server_failures = [
            r
            for r in results
            if r.check_name == "provision_variable_GERRIT_SERVER" and not r.passed
        ]
        assert len(server_failures) == 1
        assert server_failures[0].severity == "error"

    def test_uses_org_token_when_provided(self) -> None:
        """Prefers org_token over config.github_token."""
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message="Missing",
                details={
                    "missing": ["GERRIT_URL"],
                    "empty": [],
                    "found": [],
                },
            ),
        ]
        gerrit_info = {
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        with patch("g2p_github.provision_org_variable") as mock_prov:
            mock_prov.return_value = G2PCheckResult(
                check_name="x", passed=True, message="ok"
            )
            provision_org_config(config, audit, gerrit_info, org_token="elevated_tok")
            # All required variables are provisioned every run with
            # the elevated token, regardless of which were flagged
            # missing in the audit.
            assert mock_prov.call_count == len(REQUIRED_ORG_VARIABLES)
            for call in mock_prov.call_args_list:
                assert call.args[0] == "elevated_tok"
                assert call.args[1] == "test-org"

    def test_gerrit_server_built_from_host_port(self) -> None:
        """GERRIT_SERVER value constructed from ssh_host:ssh_port."""
        config = _minimal_config(org_setup="provision")
        audit = [
            G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message="Missing",
                details={
                    "missing": ["GERRIT_SERVER"],
                    "empty": [],
                    "found": [],
                },
            ),
        ]
        gerrit_info = {
            "ssh_host": "gerrit.example.org",
            "ssh_port": "29418",
            "ssh_user": "ci",
            "known_hosts": "host_key_data",
            "http_url": "https://gerrit.example.org/r/",
        }
        with patch("g2p_github.provision_org_variable") as mock_prov:
            mock_prov.return_value = G2PCheckResult(
                check_name="x", passed=True, message="ok"
            )
            provision_org_config(config, audit, gerrit_info)
            server_calls = [
                c for c in mock_prov.call_args_list if c.args[2] == "GERRIT_SERVER"
            ]
            assert len(server_calls) == 1
            assert server_calls[0].args[0] == "ghp_testtoken123"
            assert server_calls[0].args[1] == "test-org"
            assert server_calls[0].args[3] == "gerrit.example.org:29418"
            assert server_calls[0].kwargs.get("exists") is False

    def test_only_known_secret_names_provisioned(self) -> None:
        """Provisioning is limited to REQUIRED_ORG_SECRETS regardless of audit."""
        config = _minimal_config(org_setup="provision")
        # Audit invents an unrelated 'missing_required' entry; the
        # provisioner ignores it because it iterates the canonical
        # REQUIRED_ORG_SECRETS tuple, not the audit's ad-hoc list.
        audit = [
            G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message="Missing",
                details={
                    "missing_required": ["UNKNOWN_SECRET"],
                },
            ),
        ]
        gerrit_info = {"ssh_private_key": "key_data"}
        with patch("g2p_github.provision_org_secret") as mock_secret:
            mock_secret.return_value = G2PCheckResult(
                check_name="provision_secret_GERRIT_SSH_PRIVKEY",
                passed=True,
                message="ok",
                severity="info",
            )
            provision_org_config(config, audit, gerrit_info)
            # Only the canonical required secret is touched.
            assert mock_secret.call_count == 1
            assert mock_secret.call_args.args[2] == "GERRIT_SSH_PRIVKEY"
