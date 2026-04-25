# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub API checks for g2p configuration validation.

Validates that the target GitHub organisation is correctly configured
for ``gerrit_to_platform`` workflow dispatch by checking token
validity, org access, the ``.github`` magic repo, and workflow
naming conventions.

All HTTP calls use :mod:`urllib.request` to avoid adding dependencies
beyond the standard library (the ``requests`` package lives in the
scripts venv, not the g2p tools venv).

Usage::

    from g2p_config import G2PConfig
    from g2p_github import check_github_config

    config = G2PConfig.from_environment()
    results = check_github_config(config)
    for r in results:
        print(f"[{r.severity}] {r.check_name}: {r.message}")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from g2p_config import G2PConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_API_BASE = "https://api.github.com"
"""Base URL for the GitHub REST API."""

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
"""URL for the GitHub GraphQL API."""

REQUIRED_WORKFLOW_INPUTS: tuple[str, ...] = (
    "GERRIT_BRANCH",
    "GERRIT_CHANGE_ID",
    "GERRIT_CHANGE_NUMBER",
    "GERRIT_CHANGE_URL",
    "GERRIT_EVENT_TYPE",
    "GERRIT_PATCHSET_NUMBER",
    "GERRIT_PATCHSET_REVISION",
    "GERRIT_PROJECT",
    "GERRIT_REFSPEC",
)
"""Standard ``GERRIT_*`` inputs every g2p workflow must accept."""

REQUIRED_ORG_SECRETS: tuple[str, ...] = ("GERRIT_SSH_PRIVKEY",)
"""Secrets that must exist at the org level."""

OPTIONAL_ORG_SECRETS: tuple[str, ...] = ("GERRIT_SSH_PRIVKEY_G2G",)
"""Secrets that are optional and reported only for visibility.

The single entry here, ``GERRIT_SSH_PRIVKEY_G2G``, is the SSH
private key used by **gerrit-to-gerrit (G2G) replication** — i.e.
when a Gerrit instance pushes changes to *another* Gerrit instance
rather than to GitHub.  Most LF deployments do not run G2G
replication; they only mirror Gerrit → GitHub via the G2P workflow
this action configures.

Because the key is irrelevant to the standard Gerrit → GitHub
flow, an absent ``GERRIT_SSH_PRIVKEY_G2G`` is reported with
``passed=True, severity='info'`` so it neither appears in the
warning stream nor blocks the run.  Orgs that *do* perform G2G
replication should populate the secret out of band; the audit
will record it as ``found`` once present.
"""

REQUIRED_ORG_VARIABLES: tuple[str, ...] = (
    "GERRIT_SERVER",
    "GERRIT_SSH_USER",
    "GERRIT_KNOWN_HOSTS",
    "GERRIT_URL",
)
"""Variables that must exist at the org level."""

_HTTP_TIMEOUT = 30
"""Default timeout in seconds for HTTP calls."""


# ---------------------------------------------------------------------------
# Check result model
# ---------------------------------------------------------------------------


@dataclass
class G2PCheckResult:
    """Outcome of a single GitHub-side validation check.

    Attributes:
        check_name: Machine-readable name (e.g. ``"token_valid"``).
        passed: Whether the check succeeded.
        message: Human-readable description of the outcome.
        severity: One of ``"error"``, ``"warning"``, or ``"info"``.
        details: Optional extra data for debugging.
    """

    check_name: str
    passed: bool
    message: str
    severity: str = "error"
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        status = "✅" if self.passed else "❌"
        return f"{status} [{self.severity}] {self.check_name}: {self.message}"


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------


def _github_request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    accept: str = "application/vnd.github+json",
) -> tuple[int, dict[str, Any] | list[Any] | str]:
    """Make an authenticated GitHub API request.

    Parameters
    ----------
    url:
        Full URL to call.
    token:
        GitHub PAT for the ``Authorization`` header.
    method:
        HTTP method.
    body:
        Optional request body (for POST/GraphQL).
    accept:
        ``Accept`` header value.

    Returns
    -------
    tuple[int, dict | list | str]
        HTTP status code and the parsed JSON response (or raw text on
        parse failure).  ``HTTPError`` responses are caught and
        returned as ``(status, body)``; other network-level failures
        propagate as exceptions.

    Raises
    ------
    URLError
        On network-level failures (DNS resolution, connection refused,
        timeout, etc.).  Callers must handle this — each check
        function catches ``URLError`` and returns an appropriate
        :class:`G2PCheckResult`.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"

    req = Request(url, data=body, headers=headers, method=method)

    try:
        with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            try:
                data: dict[str, Any] | list[Any] | str = json.loads(raw)
            except json.JSONDecodeError:
                data = raw
            return resp.status, data
    except HTTPError as exc:
        raw_err = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw_err)
        except json.JSONDecodeError:
            data = raw_err
        return exc.code, data


def _graphql_query(
    token: str,
    query: str,
    variables: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Execute a GitHub GraphQL query.

    Parameters
    ----------
    token:
        GitHub PAT.
    query:
        GraphQL query string.
    variables:
        Optional query variables.

    Returns
    -------
    tuple[int, dict]
        HTTP status and the full JSON response body.
    """
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables

    body = json.dumps(payload).encode("utf-8")
    status, data = _github_request(
        GITHUB_GRAPHQL_URL,
        token,
        method="POST",
        body=body,
    )
    if isinstance(data, dict):
        return status, data
    return status, {"raw": data}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_token_valid(token: str) -> G2PCheckResult:
    """Verify the token is valid by calling ``GET /user``.

    Parameters
    ----------
    token:
        GitHub PAT to validate.

    Returns
    -------
    G2PCheckResult
        Passed if ``GET /user`` returns 200.
    """
    try:
        status, data = _github_request(f"{GITHUB_API_BASE}/user", token)
    except URLError as exc:
        return G2PCheckResult(
            check_name="token_valid",
            passed=False,
            message=f"Network error checking token: {exc}",
            severity="error",
        )

    if status == 200:
        login = data.get("login", "unknown") if isinstance(data, dict) else "unknown"
        return G2PCheckResult(
            check_name="token_valid",
            passed=True,
            message=f"Token valid (authenticated as {login})",
            severity="info",
            details={"login": login},
        )

    return G2PCheckResult(
        check_name="token_valid",
        passed=False,
        message=f"Token authentication failed (HTTP {status})",
        severity="error",
        details={"status": status},
    )


def check_org_access(token: str, owner: str) -> G2PCheckResult:
    """Verify the token can access the target organisation.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub organisation or user login.

    Returns
    -------
    G2PCheckResult
        Passed if ``GET /orgs/{owner}`` returns 200.
    """
    try:
        status, data = _github_request(f"{GITHUB_API_BASE}/orgs/{owner}", token)
    except URLError as exc:
        return G2PCheckResult(
            check_name="org_access",
            passed=False,
            message=f"Network error checking org {owner}: {exc}",
            severity="error",
        )

    if status == 200:
        return G2PCheckResult(
            check_name="org_access",
            passed=True,
            message=f"Organisation '{owner}' is accessible",
            severity="info",
        )

    if status == 404:
        # Could be a user account instead of an org — try /users
        user_status = 0
        user_error = ""
        try:
            user_status, _ = _github_request(f"{GITHUB_API_BASE}/users/{owner}", token)
        except URLError as user_exc:
            user_status = 0
            user_error = str(user_exc)

        if user_status == 200:
            return G2PCheckResult(
                check_name="org_access",
                passed=True,
                message=f"'{owner}' is a user account (not an org)",
                severity="info",
                details={"account_type": "user"},
            )

        # Build a message that includes the user-check outcome
        msg = f"Organisation '{owner}' not found (HTTP 404)"
        if user_error:
            msg += f"; user check also failed: {user_error}"
        elif user_status != 0:
            msg += f"; user check returned HTTP {user_status}"

        return G2PCheckResult(
            check_name="org_access",
            passed=False,
            message=msg,
            severity="error",
            details={
                "org_status": 404,
                "user_status": user_status,
            },
        )

    return G2PCheckResult(
        check_name="org_access",
        passed=False,
        message=f"Org access check failed for '{owner}' (HTTP {status})",
        severity="error",
        details={"status": status},
    )


def check_magic_repo(token: str, owner: str) -> G2PCheckResult:
    """Verify the ``.github`` magic repository exists.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub organisation or user login.

    Returns
    -------
    G2PCheckResult
        Passed if ``GET /repos/{owner}/.github`` returns 200.
    """
    try:
        status, _ = _github_request(f"{GITHUB_API_BASE}/repos/{owner}/.github", token)
    except URLError as exc:
        return G2PCheckResult(
            check_name="magic_repo",
            passed=False,
            message=f"Network error checking .github repo: {exc}",
            severity="warning",
        )

    if status == 200:
        return G2PCheckResult(
            check_name="magic_repo",
            passed=True,
            message=f"Repository '{owner}/.github' exists",
            severity="info",
        )

    if status == 404:
        return G2PCheckResult(
            check_name="magic_repo",
            passed=False,
            message=(
                f"Repository '{owner}/.github' not found"
                " — required workflows will not work"
            ),
            severity="warning",
        )

    if status in (401, 403):
        return G2PCheckResult(
            check_name="magic_repo",
            passed=False,
            message=(
                f"Unable to access repository '{owner}/.github' "
                f"(HTTP {status} — authentication or permission issue). "
                "Required workflows will be inaccessible."
            ),
            severity="error",
        )

    return G2PCheckResult(
        check_name="magic_repo",
        passed=False,
        message=(
            f"Failed to check repository '{owner}/.github' "
            f"(HTTP {status}). Required workflows may not work."
        ),
        severity="warning",
    )


def check_workflows(
    token: str,
    owner: str,
    repo: str,
    search_filter: str,
) -> G2PCheckResult:
    """Check that a repository has matching Gerrit workflows.

    A workflow matches if its path (filename) contains both ``gerrit``
    and the *search_filter* (e.g. ``verify`` or ``merge``),
    case-insensitively.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub org or user.
    repo:
        Repository name (e.g. ``.github`` or ``ci-management``).
    search_filter:
        Workflow type filter (``"verify"`` or ``"merge"``).

    Returns
    -------
    G2PCheckResult
        Passed if at least one matching active workflow is found.
    """
    check_name = f"workflows_{repo}_{search_filter}"
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/actions/workflows?per_page=100"

    try:
        status, data = _github_request(url, token)
    except URLError as exc:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=f"Network error listing workflows: {exc}",
            severity="warning",
        )

    if status != 200:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=(f"Could not list workflows for {owner}/{repo} (HTTP {status})"),
            severity="warning",
            details={"status": status},
        )

    if not isinstance(data, dict):
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message="Unexpected response format from workflows API",
            severity="warning",
        )

    workflows = data.get("workflows", [])
    matching = _filter_workflows(workflows, search_filter)

    if matching:
        names = [w.get("path", w.get("name", "?")) for w in matching]
        return G2PCheckResult(
            check_name=check_name,
            passed=True,
            message=(
                f"Found {len(matching)} '{search_filter}' workflow(s) "
                f"in {owner}/{repo}: {names}"
            ),
            severity="info",
            details={"workflows": names},
        )

    return G2PCheckResult(
        check_name=check_name,
        passed=False,
        message=(
            f"No '{search_filter}' Gerrit workflows found in "
            f"{owner}/{repo} — expected filename containing "
            f"'gerrit' and '{search_filter}'"
        ),
        severity="warning",
        details={"total_workflows": len(workflows)},
    )


def _filter_workflows(
    workflows: list[dict[str, Any]],
    search_filter: str,
) -> list[dict[str, Any]]:
    """Filter workflows by g2p naming convention.

    A workflow matches if:

    - It is ``"active"``
    - Its ``path`` contains ``"gerrit"`` (case-insensitive)
    - Its ``path`` contains *search_filter* (case-insensitive)

    Parameters
    ----------
    workflows:
        List of workflow objects from the GitHub API.
    search_filter:
        The filter keyword (e.g. ``"verify"``).

    Returns
    -------
    list[dict]
        Matching workflow objects.
    """
    results: list[dict[str, Any]] = []
    sf_lower = search_filter.lower()

    for wf in workflows:
        if wf.get("state") != "active":
            continue
        path = wf.get("path", "").lower()
        if "gerrit" in path and sf_lower in path:
            results.append(wf)

    return results


def check_repos_exist(
    token: str,
    owner: str,
    repos: list[str],
) -> G2PCheckResult:
    """Check that specified repositories exist via the REST API.

    Makes individual ``GET /repos/{owner}/{repo}`` calls for each
    repository in the list.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub org or user.
    repos:
        List of repository names to verify.

    Returns
    -------
    G2PCheckResult
        Passed if all repositories were found.
    """
    if not repos:
        return G2PCheckResult(
            check_name="repos_exist",
            passed=True,
            message="No repositories specified for validation",
            severity="info",
        )

    found_names: set[str] = set()
    missing: list[str] = []
    archived: list[str] = []

    for repo in repos:
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
        try:
            status, data = _github_request(url, token)
        except URLError as exc:
            return G2PCheckResult(
                check_name="repos_exist",
                passed=False,
                message=f"Network error checking repositories: {exc}",
                severity="warning",
            )

        if status == 404:
            missing.append(repo)
            continue

        if status != 200:
            return G2PCheckResult(
                check_name="repos_exist",
                passed=False,
                message=f"HTTP {status} checking repo '{repo}'",
                severity="warning",
                details={"status": status, "repo": repo},
            )

        if isinstance(data, dict):
            found_names.add(data.get("name", repo))
            if data.get("archived", False):
                archived.append(data.get("name", repo))
        else:
            found_names.add(repo)

    details: dict[str, Any] = {
        "found": sorted(found_names),
        "missing": missing,
        "archived": archived,
    }

    if missing:
        return G2PCheckResult(
            check_name="repos_exist",
            passed=False,
            message=f"Repositories not found: {missing}",
            severity="warning",
            details=details,
        )

    msg = f"All {len(repos)} repositories found in '{owner}'"
    if archived:
        msg += f" (archived: {archived})"

    return G2PCheckResult(
        check_name="repos_exist",
        passed=True,
        message=msg,
        severity="info",
        details=details,
    )


def check_org_secrets(
    token: str,
    owner: str,
) -> G2PCheckResult:
    """Check the org has required Actions secrets.

    Uses REST: ``GET /orgs/{owner}/actions/secrets``
    Falls back gracefully on 403 (insufficient permissions).

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub organisation login.

    Returns
    -------
    G2PCheckResult
        Passed if all required secret names exist.
    """
    secret_names: set[str] = set()
    page = 1

    while True:
        url = f"{GITHUB_API_BASE}/orgs/{owner}/actions/secrets?per_page=100&page={page}"

        try:
            status, data = _github_request(url, token)
        except URLError as exc:
            return G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message=f"Network error checking org secrets: {exc}",
                severity="warning",
            )

        if status == 403:
            return G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message=(
                    f"Cannot audit org secrets for '{owner}' — "
                    "insufficient permissions (classic PAT needs "
                    "'admin:org' scope, or fine-grained token needs "
                    "'Organization secrets: Read' permission)"
                ),
                severity="warning",
            )

        if status != 200:
            return G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message=(f"Failed to list org secrets for '{owner}' (HTTP {status})"),
                severity="warning",
                details={"status": status},
            )

        if not isinstance(data, dict):
            return G2PCheckResult(
                check_name="org_secrets",
                passed=False,
                message="Unexpected response format from org secrets API",
                severity="warning",
            )

        page_secrets = data.get("secrets", [])
        if not page_secrets:
            break

        secret_names.update(
            s["name"] for s in page_secrets if isinstance(s, dict) and "name" in s
        )

        if len(page_secrets) < 100:
            break

        page += 1

    missing_required = [s for s in REQUIRED_ORG_SECRETS if s not in secret_names]
    missing_optional = [s for s in OPTIONAL_ORG_SECRETS if s not in secret_names]
    found = [
        s for s in (*REQUIRED_ORG_SECRETS, *OPTIONAL_ORG_SECRETS) if s in secret_names
    ]

    details: dict[str, Any] = {
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "found": found,
    }

    if missing_required:
        return G2PCheckResult(
            check_name="org_secrets",
            passed=False,
            message=(
                f"Org '{owner}' is missing required secret(s): {missing_required}"
            ),
            severity="error",
            details=details,
        )

    msg = f"All required org secrets present in '{owner}'"
    if missing_optional:
        # Optional secrets (currently only GERRIT_SSH_PRIVKEY_G2G,
        # used for gerrit-to-gerrit replication) are recorded for
        # visibility but never demote the result to a warning or
        # failure: most deployments do not need them, and surfacing
        # them as advisories created noise on every run without
        # actionable signal.  See OPTIONAL_ORG_SECRETS for context.
        msg += f" (optional missing: {missing_optional})"

    return G2PCheckResult(
        check_name="org_secrets",
        passed=True,
        message=msg,
        severity="info",
        details=details,
    )


def check_org_variables(
    token: str,
    owner: str,
) -> G2PCheckResult:
    """Check the org has required Actions variables.

    Uses REST: ``GET /orgs/{owner}/actions/variables``
    Also checks that variable values are non-empty.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub organisation login.

    Returns
    -------
    G2PCheckResult
        Passed if all required variables exist and hold data.
    """
    var_map: dict[str, str] = {}
    page = 1

    while True:
        url = (
            f"{GITHUB_API_BASE}/orgs/{owner}/actions/variables?per_page=100&page={page}"
        )

        try:
            status, data = _github_request(url, token)
        except URLError as exc:
            return G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message=f"Network error checking org variables: {exc}",
                severity="warning",
            )

        if status == 403:
            return G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message=(
                    f"Cannot audit org variables for '{owner}' — "
                    "insufficient permissions (classic PAT needs "
                    "'admin:org' scope, or fine-grained token needs "
                    "'Organization variables: Read' permission)"
                ),
                severity="warning",
            )

        if status != 200:
            return G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message=(f"Failed to list org variables for '{owner}' (HTTP {status})"),
                severity="warning",
                details={"status": status},
            )

        if not isinstance(data, dict):
            return G2PCheckResult(
                check_name="org_variables",
                passed=False,
                message=("Unexpected response format from org variables API"),
                severity="warning",
            )

        page_vars = data.get("variables", [])
        if not page_vars:
            break

        for v in page_vars:
            if isinstance(v, dict) and "name" in v:
                var_map[v["name"]] = v.get("value", "")

        if len(page_vars) < 100:
            break

        page += 1

    missing = [v for v in REQUIRED_ORG_VARIABLES if v not in var_map]
    empty = [
        v for v in REQUIRED_ORG_VARIABLES if v in var_map and not var_map[v].strip()
    ]
    found = [v for v in REQUIRED_ORG_VARIABLES if v in var_map]

    details: dict[str, Any] = {
        "missing": missing,
        "empty": empty,
        "found": found,
    }

    if missing:
        return G2PCheckResult(
            check_name="org_variables",
            passed=False,
            message=(f"Org '{owner}' is missing required variable(s): {missing}"),
            severity="error",
            details=details,
        )

    if empty:
        return G2PCheckResult(
            check_name="org_variables",
            passed=False,
            message=(f"Org '{owner}' has empty variable(s): {empty}"),
            severity="warning",
            details=details,
        )

    return G2PCheckResult(
        check_name="org_variables",
        passed=True,
        message=(f"All required org variables present and populated in '{owner}'"),
        severity="info",
        details=details,
    )


def check_workflow_inputs(
    token: str,
    owner: str,
    repo: str,
    workflow_path: str,
) -> G2PCheckResult:
    """Verify a workflow file has required GERRIT_* inputs.

    Uses GraphQL to fetch file content, then parses the YAML
    to check for required ``workflow_dispatch`` inputs.

    Parameters
    ----------
    token:
        GitHub PAT.
    owner:
        GitHub org or user.
    repo:
        Repository name.
    workflow_path:
        Path to the workflow file (e.g.
        ``.github/workflows/gerrit-verify.yaml``).

    Returns
    -------
    G2PCheckResult
        Passed if all required inputs are present.
    """
    check_name = f"workflow_inputs_{repo}_{workflow_path.split('/')[-1]}"

    query = """
    query WorkflowContent($owner: String!, $repo: String!, $expr: String!) {
      repository(owner: $owner, name: $repo) {
        object(expression: $expr) {
          ... on Blob {
            text
          }
        }
      }
    }
    """
    variables = {
        "owner": owner,
        "repo": repo,
        "expr": f"HEAD:{workflow_path}",
    }

    try:
        status, data = _graphql_query(token, query, variables)
    except URLError as exc:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=f"Network error fetching workflow content: {exc}",
            severity="warning",
        )

    if status != 200:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=(f"Failed to fetch workflow content (HTTP {status})"),
            severity="warning",
            details={"status": status},
        )

    # Navigate the GraphQL response
    repo_data = data.get("data", {}).get("repository", {})
    obj = repo_data.get("object")
    if not obj or "text" not in obj:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=(
                f"Could not retrieve content of {workflow_path} in {owner}/{repo}"
            ),
            severity="warning",
        )

    # Parse the YAML content
    try:
        import yaml

        workflow = yaml.safe_load(obj["text"])
    except Exception as exc:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=(f"Failed to parse {workflow_path}: {exc}"),
            severity="warning",
        )

    if not isinstance(workflow, dict):
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=f"Workflow {workflow_path} is not a valid YAML mapping",
            severity="warning",
        )

    # Extract workflow_dispatch inputs
    on_block = workflow.get("on", workflow.get(True, {}))
    if isinstance(on_block, dict):
        dispatch = on_block.get("workflow_dispatch", {})
    else:
        dispatch = {}

    if not isinstance(dispatch, dict):
        dispatch = {}

    inputs = dispatch.get("inputs", {})
    if not isinstance(inputs, dict):
        inputs = {}

    input_names = set(inputs.keys())
    missing = [name for name in REQUIRED_WORKFLOW_INPUTS if name not in input_names]

    details: dict[str, Any] = {
        "missing": missing,
        "found": [name for name in REQUIRED_WORKFLOW_INPUTS if name in input_names],
        "workflow_path": workflow_path,
    }

    if missing:
        return G2PCheckResult(
            check_name=check_name,
            passed=False,
            message=(
                f"Workflow {workflow_path} in {owner}/{repo} "
                f"is missing required input(s): {missing}"
            ),
            severity="warning",
            details=details,
        )

    return G2PCheckResult(
        check_name=check_name,
        passed=True,
        message=(
            f"Workflow {workflow_path} has all "
            f"{len(REQUIRED_WORKFLOW_INPUTS)} required inputs"
        ),
        severity="info",
        details=details,
    )


def provision_org_secret(
    token: str,
    owner: str,
    secret_name: str,
    secret_value: str,
) -> G2PCheckResult:
    """Create or update an org-level Actions secret.

    Fetches the org public key, encrypts the value with PyNaCl,
    and PUTs the encrypted secret.

    Parameters
    ----------
    token:
        GitHub PAT with org admin scope.
    owner:
        GitHub organisation login.
    secret_name:
        Name of the secret to create/update.
    secret_value:
        Plaintext value to encrypt and store.

    Returns
    -------
    G2PCheckResult
        Passed if the secret was created/updated successfully.
    """
    # Step 1: Fetch the org public key
    key_url = f"{GITHUB_API_BASE}/orgs/{owner}/actions/secrets/public-key"
    try:
        status, key_data = _github_request(key_url, token)
    except URLError as exc:
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message=f"Network error fetching org public key: {exc}",
            severity="error",
        )

    if status != 200 or not isinstance(key_data, dict):
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message=(f"Failed to fetch org public key for '{owner}' (HTTP {status})"),
            severity="error",
        )

    key_id = key_data.get("key_id", "")
    public_key_b64 = key_data.get("key", "")
    if not key_id or not public_key_b64:
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message="Org public key response missing key_id or key",
            severity="error",
        )

    # Step 2: Encrypt the secret value
    try:
        import base64

        from nacl.public import (  # pyright: ignore[reportMissingImports]
            PublicKey,
            SealedBox,
        )

        public_key_bytes = base64.b64decode(public_key_b64)
        sealed_box = SealedBox(PublicKey(public_key_bytes))
        encrypted = sealed_box.encrypt(
            secret_value.encode("utf-8"),
        )
        encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
    except ImportError:
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message=(
                "PyNaCl is required for secret provisioning — "
                "install with: pip install PyNaCl"
            ),
            severity="error",
        )
    except Exception as exc:
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message=f"Failed to encrypt secret value: {exc}",
            severity="error",
        )

    # Step 3: PUT the encrypted secret
    put_url = f"{GITHUB_API_BASE}/orgs/{owner}/actions/secrets/{secret_name}"
    body = json.dumps(
        {
            "encrypted_value": encrypted_b64,
            "key_id": key_id,
            "visibility": "all",
        }
    ).encode("utf-8")

    try:
        status, _ = _github_request(put_url, token, method="PUT", body=body)
    except URLError as exc:
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=False,
            message=f"Network error creating secret: {exc}",
            severity="error",
        )

    if status in (201, 204):
        return G2PCheckResult(
            check_name=f"provision_secret_{secret_name}",
            passed=True,
            message=f"Created/updated org secret '{secret_name}'",
            severity="info",
        )

    return G2PCheckResult(
        check_name=f"provision_secret_{secret_name}",
        passed=False,
        message=(f"Failed to create org secret '{secret_name}' (HTTP {status})"),
        severity="error",
        details={"status": status},
    )


def provision_org_variable(
    token: str,
    owner: str,
    variable_name: str,
    variable_value: str,
    *,
    exists: bool = False,
) -> G2PCheckResult:
    """Create or update an org-level Actions variable.

    Uses POST for new variables and PATCH for existing ones.

    Parameters
    ----------
    token:
        GitHub PAT with org admin scope.
    owner:
        GitHub organisation login.
    variable_name:
        Name of the variable.
    variable_value:
        Value to set.
    exists:
        Whether the variable already exists (use PATCH).

    Returns
    -------
    G2PCheckResult
        Passed if the variable was created/updated.
    """
    body_dict: dict[str, str] = {
        "name": variable_name,
        "value": variable_value,
        "visibility": "all",
    }
    body = json.dumps(body_dict).encode("utf-8")

    if exists:
        url = f"{GITHUB_API_BASE}/orgs/{owner}/actions/variables/{variable_name}"
        method = "PATCH"
    else:
        url = f"{GITHUB_API_BASE}/orgs/{owner}/actions/variables"
        method = "POST"

    try:
        status, _ = _github_request(url, token, method=method, body=body)
    except URLError as exc:
        return G2PCheckResult(
            check_name=f"provision_variable_{variable_name}",
            passed=False,
            message=f"Network error creating variable: {exc}",
            severity="error",
        )

    # POST returns 201, PATCH returns 204 (no content)
    if status in (201, 204):
        action = "Updated" if exists else "Created"
        return G2PCheckResult(
            check_name=f"provision_variable_{variable_name}",
            passed=True,
            message=(f"{action} org variable '{variable_name}'"),
            severity="info",
        )

    # 409 on POST means it already exists — retry with PATCH
    if status == 409 and not exists:
        logger.info(
            "Variable '%s' already exists; switching to PATCH",
            variable_name,
        )
        return provision_org_variable(
            token,
            owner,
            variable_name,
            variable_value,
            exists=True,
        )

    return G2PCheckResult(
        check_name=f"provision_variable_{variable_name}",
        passed=False,
        message=(
            f"Failed to create/update org variable '{variable_name}' (HTTP {status})"
        ),
        severity="error",
        details={"status": status},
    )


def provision_org_config(
    config: G2PConfig,
    audit_results: list[G2PCheckResult],
    gerrit_info: dict[str, str],
    org_token: str | None = None,
) -> list[G2PCheckResult]:
    """Auto-provision absent org configuration.

    Inspects audit results to determine what is missing, then
    creates secrets and variables as needed.

    Parameters
    ----------
    config:
        G2P configuration.
    audit_results:
        Results from the audit phase.
    gerrit_info:
        Dict with keys: ``ssh_private_key``, ``ssh_host``,
        ``ssh_port``, ``ssh_user``, ``http_url``,
        ``known_hosts``.
    org_token:
        Elevated-permission token for org write ops.
        Falls back to ``config.github_token``.

    Returns
    -------
    list[G2PCheckResult]
        Results of provisioning operations.
    """
    token = org_token or config.github_token
    owner = config.github_owner
    results: list[G2PCheckResult] = []

    # Look up the variables audit entry so we can pick the correct
    # HTTP verb (POST vs PATCH) per variable.  Secrets do not need
    # this lookup because the GitHub Actions secrets API uses a
    # single PUT verb for both create and update.
    variables_check = next(
        (r for r in audit_results if r.check_name == "org_variables"),
        None,
    )

    # Provision required secrets.
    #
    # In ``provision`` mode we ALWAYS overwrite required secrets with
    # the current run's values, regardless of whether they were
    # already present.  Each Gerrit container build produces a fresh
    # ephemeral SSH key, so a "GERRIT_SSH_PRIVKEY exists already"
    # state from a previous run would silently leave the GitHub org
    # holding a stale key that does not match the live Gerrit
    # instance — workflows would dispatch successfully but fail at
    # push time.  Always overwriting keeps Gerrit and the org in
    # lock-step for every provision run.
    ssh_private_key = gerrit_info.get("ssh_private_key", "")
    if ssh_private_key:
        for secret_name in REQUIRED_ORG_SECRETS:
            if secret_name == "GERRIT_SSH_PRIVKEY":
                results.append(
                    provision_org_secret(token, owner, secret_name, ssh_private_key)
                )
    else:
        logger.warning(
            "No SSH private key available; skipping required secret provisioning"
        )
        # Surface this as an explicit failed result so the
        # post-provision audit can flag it.
        results.append(
            G2PCheckResult(
                check_name="provision_secret_GERRIT_SSH_PRIVKEY",
                passed=False,
                message=(
                    "No SSH private key available to provision GERRIT_SSH_PRIVKEY"
                ),
                severity="error",
            )
        )

    # Provision required variables.
    #
    # As with secrets, every required variable is overwritten on each
    # provision run.  Tunnel host/port assignments and known_hosts
    # values can change between runs, and stale variables would
    # cause downstream workflows to talk to the wrong endpoint.
    ssh_host = gerrit_info.get("ssh_host")
    ssh_port = gerrit_info.get("ssh_port")
    gerrit_server = f"{ssh_host}:{ssh_port}" if ssh_host and ssh_port else ""

    variable_map: dict[str, str] = {
        "GERRIT_SERVER": gerrit_server,
        "GERRIT_SSH_USER": gerrit_info.get("ssh_user", ""),
        "GERRIT_KNOWN_HOSTS": gerrit_info.get("known_hosts", ""),
        "GERRIT_URL": gerrit_info.get("http_url", ""),
    }

    # Determine which variables already exist so we can pick the
    # correct HTTP verb (POST for create, PATCH for update).  Use
    # the audit details when available; fall back to assuming the
    # variable does not exist.
    existing_vars: set[str] = set()
    if variables_check is not None:
        details = variables_check.details
        # ``found`` lists variables that exist (any value), while
        # ``empty`` lists those that exist but have an empty value.
        existing_vars.update(details.get("found", []))
        existing_vars.update(details.get("empty", []))

    for var_name in REQUIRED_ORG_VARIABLES:
        value = variable_map.get(var_name, "")
        if not value:
            logger.warning(
                "No value available for variable '%s'; skipping",
                var_name,
            )
            results.append(
                G2PCheckResult(
                    check_name=f"provision_variable_{var_name}",
                    passed=False,
                    message=(f"No value available to provision variable '{var_name}'"),
                    severity="error",
                )
            )
            continue
        results.append(
            provision_org_variable(
                token,
                owner,
                var_name,
                value,
                exists=var_name in existing_vars,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Aggregate check runner
# ---------------------------------------------------------------------------


def check_github_config(
    config: G2PConfig,
) -> list[G2PCheckResult]:
    """Run all applicable GitHub-side validation checks.

    The checks follow a dependency chain: if the token is missing or
    invalid, later checks that need it are skipped.

    Parameters
    ----------
    config:
        A validated :class:`G2PConfig` instance.

    Returns
    -------
    list[G2PCheckResult]
        Ordered list of check outcomes.
    """
    results: list[G2PCheckResult] = []

    # -- Check 1: Token exists -------------------------------------------
    if not config.github_token:
        results.append(
            G2PCheckResult(
                check_name="token_provided",
                passed=False,
                message=(
                    "No GitHub token provided; g2p cannot dispatch "
                    "workflows until a token is configured"
                ),
                severity="warning",
            )
        )
        # Cannot run any API checks without a token.
        return results

    results.append(
        G2PCheckResult(
            check_name="token_provided",
            passed=True,
            message="GitHub token provided",
            severity="info",
        )
    )

    # -- Check 2: Token valid --------------------------------------------
    token_result = check_token_valid(config.github_token)
    results.append(token_result)
    if not token_result.passed:
        # Cannot proceed with an invalid token.
        return results

    # -- Check 3: Org accessible -----------------------------------------
    org_result = check_org_access(config.github_token, config.github_owner)
    results.append(org_result)
    if not org_result.passed:
        return results

    # -- Check 4: .github magic repo -------------------------------------
    results.append(check_magic_repo(config.github_token, config.github_owner))

    # -- Check 5 & 6: Workflow checks ------------------------------------
    if config.validate_workflows:
        # Check .github repo for required workflows
        for search_filter in ("verify", "merge"):
            results.append(
                check_workflows(
                    config.github_token,
                    config.github_owner,
                    ".github",
                    search_filter,
                )
            )

        # Check per-repo workflows
        for repo in config.validate_repos:
            for search_filter in ("verify", "merge"):
                results.append(
                    check_workflows(
                        config.github_token,
                        config.github_owner,
                        repo,
                        search_filter,
                    )
                )

    # -- Check 7: Repositories exist (if specified) ----------------------
    if config.validate_repos:
        results.append(
            check_repos_exist(
                config.github_token,
                config.github_owner,
                config.validate_repos,
            )
        )

    # Note: org-level secret and variable checks intentionally run in
    # a later phase (see ``configure-g2p.py``) so that the audit can
    # re-run *after* provisioning has a chance to create missing items.
    # Running them here would emit warnings for items we are about to
    # create, which is misleading.

    return results


# ---------------------------------------------------------------------------
# Result processing helpers
# ---------------------------------------------------------------------------


def format_check_results(
    results: list[G2PCheckResult],
    mode: str,
) -> tuple[list[str], bool]:
    """Format check results as GitHub Actions annotations.

    Parameters
    ----------
    results:
        Check results from :func:`check_github_config`.
    mode:
        Validation mode (``"error"``, ``"warn"``, or ``"skip"``).

    Returns
    -------
    tuple[list[str], bool]
        A list of annotation strings and a boolean indicating whether
        any fatal failures occurred (only *True* when *mode* is
        ``"error"`` and a check with ``severity="error"`` failed).
    """
    annotations: list[str] = []
    has_fatal = False

    for result in results:
        if result.passed:
            logger.info("%s", result)
            continue

        if result.severity == "error":
            if mode == "error":
                # Strict mode: annotate once via the logger
                # (the _GitHubActionsFormatter emits ::error::) and
                # record the annotation string for callers that need
                # to surface it elsewhere (e.g. test assertions or a
                # collated summary). Marks the run fatal.
                logger.error("%s", result.message)
                annotations.append(f"::error::{result.message}")
                has_fatal = True
            elif mode == "warn":
                logger.warning("%s", result.message)
                annotations.append(f"::warning::{result.message}")
            # mode == "skip" should never reach here
        elif result.severity == "warning":
            logger.warning("%s", result.message)
            annotations.append(f"::warning::{result.message}")
        else:
            logger.info("%s", result)

    return annotations, has_fatal


def results_to_json(results: list[G2PCheckResult]) -> str:
    """Serialise check results to a JSON string for action outputs.

    Parameters
    ----------
    results:
        Check results.

    Returns
    -------
    str
        JSON array of check result objects.
    """
    return json.dumps(
        [
            {
                "check_name": r.check_name,
                "passed": r.passed,
                "message": r.message,
                "severity": r.severity,
            }
            for r in results
        ],
        indent=2,
    )


def format_check_results_summary(
    results: list[G2PCheckResult],
    owner: str,
    mode: str,
    provisioned: list[str] | None = None,
) -> str:
    """Render check results as a Markdown summary table.

    Parameters
    ----------
    results:
        Check outcomes from the audit phase.
    owner:
        GitHub org name (for the heading).
    mode:
        The ``g2p_org_setup`` mode value.
    provisioned:
        Descriptions of items auto-provisioned
        (used when mode is ``'provision'``).

    Returns
    -------
    str
        Markdown content for ``$GITHUB_STEP_SUMMARY``.
    """
    lines: list[str] = [
        f"## G2P Organisation Audit: `{owner}`",
        "",
        "| Check | Status | Details |",
        "|-------|--------|---------|",
    ]

    def _md_table_cell(text: str) -> str:
        """Escape characters that break Markdown table cells."""
        return text.replace("|", r"\|").replace("\n", "<br>")

    for r in results:
        status = "PASS ✅" if r.passed else "FAIL ❌"
        if not r.passed and r.severity == "warning":
            status = "WARN ⚠️"
        name = _md_table_cell(r.check_name)
        msg = _md_table_cell(r.message)
        lines.append(f"| {name} | {status} | {msg} |")

    lines.append("")

    if mode == "provision":
        lines.append("**Mode:** `provision` — auto-provisioning enabled.")
    elif mode == "verify":
        lines.append("**Mode:** `verify` — reporting only, no changes made.")
    else:
        lines.append(f"**Mode:** `{mode}`")

    lines.append("")

    if provisioned:
        lines.append("### Provisioned Items")
        lines.append("")
        for item in provisioned:
            lines.append(f"- {item}")
        lines.append("")

    # List absent items when in verify mode
    if mode == "verify":
        absent: list[str] = []
        for r in results:
            if not r.passed and r.severity == "error":
                absent.append(f"- **{r.check_name}**: {r.message}")
        if absent:
            lines.append("### Absent Items")
            lines.append("")
            lines.extend(absent)
            lines.append("")

    return "\n".join(lines)
