# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Shared pytest fixtures for gerrit-action tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove gerrit-action-specific environment variables.

    This prevents host environment from leaking into tests.
    """
    env_vars = [
        "GERRIT_SETUP",
        "WORK_DIR",
        "AUTH_TYPE",
        "SSH_PRIVATE_KEY",
        "SSH_KNOWN_HOSTS",
        "HTTP_USERNAME",
        "HTTP_PASSWORD",
        "BEARER_TOKEN",
        "REMOTE_SSH_USER",
        "REMOTE_SSH_PORT",
        "GERRIT_VERSION",
        "PLUGIN_VERSION",
        "BASE_HTTP_PORT",
        "BASE_SSH_PORT",
        "SYNC_REFS",
        "REPLICATION_THREADS",
        "SYNC_ON_STARTUP",
        "FETCH_EVERY",
        "REPLICATION_TIMEOUT",
        "SKIP_PLUGIN_INSTALL",
        "ADDITIONAL_PLUGINS",
        "GERRIT_INIT_ARGS",
        "DEBUG",
        "USE_API_PATH",
        "TUNNEL_HOST",
        "TUNNEL_PORTS",
        "MAX_PROJECTS",
        "ENABLE_CACHE",
        "CACHE_KEY_SUFFIX",
        "CHECK_SERVICE",
        "EXIT",
        "REQUIRE_REPLICATION_SUCCESS",
        "REPLICATION_WAIT_TIMEOUT",
        "SSH_AUTH_KEYS",
        "SSH_AUTH_USERNAME",
        "GITHUB_OUTPUT",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_ACTIONS",
        "GERRIT_URL",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


# ---------------------------------------------------------------------------
# Temp directory helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def work_dir(tmp_path: Path) -> Path:
    """Create a temporary working directory mimicking $WORK_DIR."""
    wd = tmp_path / "gerrit-action"
    wd.mkdir()
    return wd


@pytest.fixture()
def github_output(tmp_path: Path) -> Path:
    """Create a temporary file for $GITHUB_OUTPUT."""
    f = tmp_path / "github_output"
    f.touch()
    return f


@pytest.fixture()
def github_summary(tmp_path: Path) -> Path:
    """Create a temporary file for $GITHUB_STEP_SUMMARY."""
    f = tmp_path / "github_summary"
    f.touch()
    return f


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------


SAMPLE_INSTANCE_METADATA: dict[str, dict[str, Any]] = {
    "onap": {
        "cid": "abc123def456",
        "ip": "172.17.0.2",
        "http_port": 18080,
        "ssh_port": 29418,
        "url": "http://172.17.0.2:8080",
        "gerrit_host": "gerrit.onap.org",
        "project": "",
        "api_path": "/r",
        "api_url": "https://gerrit.onap.org/r",
        "expected_project_count": 10,
        "ssh_host_keys": {
            "ssh_host_ed25519_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
        },
    },
    "lf": {
        "cid": "789ghi012jkl",
        "ip": "172.17.0.3",
        "http_port": 18081,
        "ssh_port": 29419,
        "url": "http://172.17.0.3:8080",
        "gerrit_host": "gerrit.linuxfoundation.org",
        "project": "releng/lftools",
        "api_path": "/infra",
        "api_url": "https://gerrit.linuxfoundation.org/infra",
        "expected_project_count": 5,
        "ssh_host_keys": {},
    },
}


SAMPLE_API_PATHS: dict[str, dict[str, str]] = {
    "onap": {
        "gerrit_host": "gerrit.onap.org",
        "api_path": "/r",
        "api_url": "https://gerrit.onap.org/r",
    },
    "lf": {
        "gerrit_host": "gerrit.linuxfoundation.org",
        "api_path": "/infra",
        "api_url": "https://gerrit.linuxfoundation.org/infra",
    },
}


SAMPLE_GERRIT_SETUP = json.dumps(
    [
        {"slug": "onap", "gerrit": "gerrit.onap.org", "api_path": "r"},
        {
            "slug": "lf",
            "gerrit": "gerrit.linuxfoundation.org",
            "project": "releng/lftools",
            "api_path": "infra",
        },
    ]
)


@pytest.fixture()
def sample_instances() -> dict[str, dict[str, Any]]:
    """Return sample instance metadata."""
    return SAMPLE_INSTANCE_METADATA.copy()


@pytest.fixture()
def sample_api_paths() -> dict[str, dict[str, str]]:
    """Return sample API paths."""
    return SAMPLE_API_PATHS.copy()


@pytest.fixture()
def instances_json(work_dir: Path) -> Path:
    """Write sample instances.json to the work dir and return its path."""
    path = work_dir / "instances.json"
    path.write_text(json.dumps(SAMPLE_INSTANCE_METADATA, indent=2))
    return path


@pytest.fixture()
def api_paths_json(work_dir: Path) -> Path:
    """Write sample api_paths.json to the work dir and return its path."""
    path = work_dir / "api_paths.json"
    path.write_text(json.dumps(SAMPLE_API_PATHS, indent=2))
    return path


# ---------------------------------------------------------------------------
# Docker mock helpers
# ---------------------------------------------------------------------------


def make_completed_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    """Create a mock subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.fixture()
def mock_subprocess_run():
    """Patch subprocess.run and return the mock.

    The default return value is a successful docker command with empty
    stdout/stderr.  Tests can override ``mock.return_value`` or use
    ``mock.side_effect`` for sequences of calls.
    """
    with patch("subprocess.run") as mock:
        mock.return_value = make_completed_process()
        yield mock


@pytest.fixture()
def mock_docker(mock_subprocess_run):
    """Create a DockerManager with subprocess.run patched.

    Returns a tuple of (docker_manager, subprocess_mock) so that tests
    can both use the manager and inspect the calls.
    """
    from docker_manager import DockerManager

    docker = DockerManager()
    return docker, mock_subprocess_run


# ---------------------------------------------------------------------------
# Requests mock helpers
# ---------------------------------------------------------------------------


class MockResponse:
    """Minimal mock for requests.Response."""

    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        url: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.url = url or ""
        self.headers = headers or {}
        self.content = text.encode("utf-8")

    def json(self) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            from requests.exceptions import HTTPError

            raise HTTPError(f"{self.status_code}", response=self)  # type: ignore[arg-type]
