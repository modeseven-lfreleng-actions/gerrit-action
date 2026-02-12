# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the start-instances.py orchestrator script.

Tests cover all the functions extracted from ``start-instances.sh``:
- Docker image management (ensure_custom_image)
- SSH authentication setup
- Remote project list fetching
- Replication config generation
- Secure config generation
- Plugin download
- Gerrit site initialisation
- Gerrit configuration (gerrit.config)
- Project pre-creation
- SSH host key capture
- Instance startup orchestration
- Main run() function
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

# ---------------------------------------------------------------------------
# Path setup – ensure scripts and lib are importable
# ---------------------------------------------------------------------------
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
LIB_DIR = SCRIPTS_DIR / "lib"
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(LIB_DIR))

from config import ActionConfig, ApiPathStore, InstanceConfig, InstanceStore  # noqa: E402  # isort: skip
from errors import DockerError, GerritActionError  # noqa: E402  # isort: skip

# Import the hyphenated module via importlib
_spec = importlib.util.spec_from_file_location(
    "start_instances", SCRIPTS_DIR / "start-instances.py"
)
assert _spec is not None and _spec.loader is not None
start_instances = importlib.util.module_from_spec(_spec)
sys.modules["start_instances"] = start_instances
_spec.loader.exec_module(start_instances)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cp(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    """Create a CompletedProcess for use as a mock return value."""
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _make_config(**overrides: Any) -> ActionConfig:
    """Build an ActionConfig with sensible defaults for testing."""
    defaults: dict[str, Any] = {
        "auth_type": "ssh",
        "ssh_private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        "ssh_known_hosts": "",
        "http_username": "",
        "http_password": "",
        "bearer_token": "",
        "remote_ssh_user": "gerrit",
        "remote_ssh_port": 29418,
        "gerrit_version": "3.13.1-ubuntu24",
        "plugin_version": "stable-3.13",
        "skip_plugin_install": False,
        "additional_plugins": "",
        "gerrit_init_args": "",
        "base_http_port": 18080,
        "base_ssh_port": 29418,
        "sync_on_startup": True,
        "sync_refs": "+refs/heads/*:refs/heads/*,+refs/tags/*:refs/tags/*",
        "replication_threads": 4,
        "replication_timeout": 120,
        "fetch_every": "60s",
        "require_replication_success": False,
        "replication_wait_timeout": 180,
        "check_service": True,
        "exit": False,
        "enable_cache": False,
        "cache_key_suffix": "",
        "debug": False,
        "use_api_path": False,
        "max_projects": 500,
        "tunnel_host": "",
        "tunnel_ports_json": "",
        "ssh_auth_keys": "",
        "ssh_auth_username": "",
        "work_dir": "/tmp/test-gerrit-action",
        "instances": [
            InstanceConfig(
                slug="test",
                gerrit_host="gerrit.example.org",
                project="",
                api_path="",
                ssh_user="gerrit",
                ssh_port=29418,
                max_projects=500,
            ),
        ],
    }
    defaults.update(overrides)
    return ActionConfig(**defaults)


def _make_instance(**overrides: Any) -> InstanceConfig:
    """Build an InstanceConfig with defaults."""
    defaults: dict[str, Any] = {
        "slug": "test",
        "gerrit_host": "gerrit.example.org",
        "project": "",
        "api_path": "",
        "ssh_user": "gerrit",
        "ssh_port": 29418,
        "max_projects": 500,
    }
    defaults.update(overrides)
    return InstanceConfig(**defaults)


# =====================================================================
# ensure_custom_image
# =====================================================================


class TestEnsureCustomImage:
    """Tests for ensure_custom_image()."""

    def test_image_already_exists(self) -> None:
        docker = MagicMock()
        docker.image_exists.return_value = True
        config = _make_config()

        result = start_instances.ensure_custom_image(docker, config)

        assert result == config.custom_image
        docker.image_exists.assert_called_once_with(config.custom_image)
        docker.build_image.assert_not_called()

    def test_build_when_dockerfile_present(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.image_exists.return_value = False
        config = _make_config()

        # Patch SCRIPT_DIR so Dockerfile resolves to tmp_path
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM scratch\n")

        with patch.object(start_instances, "SCRIPT_DIR", tmp_path / "scripts"):
            # Make SCRIPT_DIR.parent point to tmp_path
            (tmp_path / "scripts").mkdir(exist_ok=True)
            result = start_instances.ensure_custom_image(docker, config)

        assert result == config.custom_image
        docker.build_image.assert_called_once()

    def test_fallback_when_no_dockerfile(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.image_exists.return_value = False
        config = _make_config()

        # Point SCRIPT_DIR.parent to a dir without Dockerfile
        with patch.object(start_instances, "SCRIPT_DIR", tmp_path / "scripts"):
            (tmp_path / "scripts").mkdir(exist_ok=True)
            result = start_instances.ensure_custom_image(docker, config)

        expected = f"gerritcodereview/gerrit:{config.gerrit_version}"
        assert result == expected
        docker.build_image.assert_not_called()

    def test_fallback_on_build_failure(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.image_exists.return_value = False
        docker.build_image.side_effect = DockerError("build failed")
        config = _make_config()

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM scratch\n")

        with patch.object(start_instances, "SCRIPT_DIR", tmp_path / "scripts"):
            (tmp_path / "scripts").mkdir(exist_ok=True)
            result = start_instances.ensure_custom_image(docker, config)

        expected = f"gerritcodereview/gerrit:{config.gerrit_version}"
        assert result == expected


class TestVerifyCustomImage:
    """Tests for _verify_custom_image()."""

    def test_both_tools_present(self) -> None:
        docker = MagicMock()
        docker.run_ephemeral.side_effect = [
            "uv 0.10.2\n",
            "/usr/local/bin/change-merged\n",
        ]

        start_instances._verify_custom_image(docker, "test:latest")

        assert docker.run_ephemeral.call_count == 2

    def test_tool_missing_logs_warning(self) -> None:
        docker = MagicMock()
        docker.run_ephemeral.side_effect = DockerError("not found")

        # Should not raise
        start_instances._verify_custom_image(docker, "test:latest")


# =====================================================================
# setup_ssh_auth
# =====================================================================


class TestSetupSshAuth:
    """Tests for setup_ssh_auth()."""

    def test_creates_directory_structure(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        start_instances.setup_ssh_auth(
            instance_dir=instance_dir,
            gerrit_host="gerrit.example.org",
            ssh_user="gerrit",
            ssh_port=29418,
            ssh_private_key="PRIVATE_KEY_CONTENT",
            ssh_known_hosts="known_hosts_content",
        )

        ssh_dir = instance_dir / "ssh"
        assert ssh_dir.is_dir()
        assert (ssh_dir / "id_rsa").exists()
        assert (ssh_dir / "known_hosts").exists()
        assert (ssh_dir / "config").exists()

    def test_private_key_content(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        start_instances.setup_ssh_auth(
            instance_dir=instance_dir,
            gerrit_host="gerrit.example.org",
            ssh_user="gerrit",
            ssh_port=29418,
            ssh_private_key="MY_SECRET_KEY",
            ssh_known_hosts="",
        )

        assert (instance_dir / "ssh" / "id_rsa").read_text() == "MY_SECRET_KEY"

    def test_provided_known_hosts(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        start_instances.setup_ssh_auth(
            instance_dir=instance_dir,
            gerrit_host="gerrit.example.org",
            ssh_user="gerrit",
            ssh_port=29418,
            ssh_private_key="key",
            ssh_known_hosts="host.example ssh-ed25519 AAAA...",
        )

        content = (instance_dir / "ssh" / "known_hosts").read_text()
        assert "host.example" in content

    def test_auto_keyscan_when_no_known_hosts(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        with patch("start_instances.subprocess.run") as mock_run:
            mock_run.return_value = _cp(stdout="scanned-key-data\n")
            start_instances.setup_ssh_auth(
                instance_dir=instance_dir,
                gerrit_host="gerrit.example.org",
                ssh_user="gerrit",
                ssh_port=29418,
                ssh_private_key="key",
                ssh_known_hosts="",
            )

        content = (instance_dir / "ssh" / "known_hosts").read_text()
        assert "scanned-key-data" in content

    def test_keyscan_failure_creates_empty_file(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        with patch(
            "start_instances.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ssh-keyscan", timeout=30),
        ):
            start_instances.setup_ssh_auth(
                instance_dir=instance_dir,
                gerrit_host="gerrit.example.org",
                ssh_user="gerrit",
                ssh_port=29418,
                ssh_private_key="key",
                ssh_known_hosts="",
            )

        assert (instance_dir / "ssh" / "known_hosts").exists()

    def test_ssh_config_content(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        start_instances.setup_ssh_auth(
            instance_dir=instance_dir,
            gerrit_host="gerrit.example.org",
            ssh_user="myuser",
            ssh_port=12345,
            ssh_private_key="key",
            ssh_known_hosts="hosts",
        )

        config_text = (instance_dir / "ssh" / "config").read_text()
        assert "Host gerrit.example.org" in config_text
        assert "User myuser" in config_text
        assert "Port 12345" in config_text
        assert "IdentityFile /var/gerrit/ssh/id_rsa" in config_text

    def test_private_key_permissions(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"

        start_instances.setup_ssh_auth(
            instance_dir=instance_dir,
            gerrit_host="gerrit.example.org",
            ssh_user="gerrit",
            ssh_port=29418,
            ssh_private_key="key",
            ssh_known_hosts="hosts",
        )

        id_rsa = instance_dir / "ssh" / "id_rsa"
        mode = id_rsa.stat().st_mode & 0o777
        assert mode == 0o600


# =====================================================================
# fetch_remote_projects
# =====================================================================


class TestFetchRemoteProjects:
    """Tests for fetch_remote_projects()."""

    def test_success_parses_json(self) -> None:
        config = _make_config()
        response_body = ')]}\'\n{"project-a": {}, "project-b": {}}'

        mock_resp = MagicMock()
        mock_resp.text = response_body
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp):
            result = start_instances.fetch_remote_projects(
                "gerrit.example.org", "/r", "", 100, config
            )

        assert sorted(result) == ["project-a", "project-b"]

    def test_with_api_path(self) -> None:
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = ')]}\'\n{"p1": {}}'
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "/r", "", 50, config
            )

        url = mock_get.call_args[0][0]
        assert "gerrit.example.org/r/projects/" in url

    def test_without_api_path(self) -> None:
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = ')]}\'\n{"p1": {}}'
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 50, config
            )

        url = mock_get.call_args[0][0]
        assert "gerrit.example.org/projects/" in url

    def test_with_project_filter(self) -> None:
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = ')]}\'\n{"match": {}}'
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "myproject.*", 100, config
            )

        url = mock_get.call_args[0][0]
        assert "r=" in url

    def test_http_basic_auth(self) -> None:
        config = _make_config(
            auth_type="http_basic",
            http_username="user",
            http_password="pass",
        )
        mock_resp = MagicMock()
        mock_resp.text = ")]}'\n{}"
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        kwargs = mock_get.call_args[1]
        assert kwargs["auth"] == ("user", "pass")

    def test_bearer_token_auth(self) -> None:
        config = _make_config(
            auth_type="bearer_token",
            bearer_token="my-token-123",
        )
        mock_resp = MagicMock()
        mock_resp.text = ")]}'\n{}"
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        kwargs = mock_get.call_args[1]
        assert "Authorization" in kwargs.get("headers", {})
        assert kwargs["headers"]["Authorization"] == "Bearer my-token-123"

    def test_ssh_auth_uses_anonymous(self) -> None:
        config = _make_config(auth_type="ssh")
        mock_resp = MagicMock()
        mock_resp.text = ")]}'\n{}"
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        kwargs = mock_get.call_args[1]
        assert "auth" not in kwargs
        assert "headers" not in kwargs

    def test_request_failure_returns_empty(self) -> None:
        config = _make_config()

        with patch(
            "start_instances.requests.get",
            side_effect=requests.RequestException("connection refused"),
        ):
            result = start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        assert result == []

    def test_invalid_json_returns_empty(self) -> None:
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = "not json"
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp):
            result = start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        assert result == []

    def test_xssi_prefix_variant(self) -> None:
        """Handle the variant where the XSSI prefix uses the elif branch."""
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = ')]}\'  \n{"a": {}}'
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp):
            result = start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 100, config
            )

        assert result == ["a"]

    def test_max_projects_in_url(self) -> None:
        config = _make_config()
        mock_resp = MagicMock()
        mock_resp.text = ")]}'\n{}"
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp) as mock_get:
            start_instances.fetch_remote_projects(
                "gerrit.example.org", "", "", 42, config
            )

        url = mock_get.call_args[0][0]
        assert "n=42" in url


# =====================================================================
# generate_replication_config
# =====================================================================


class TestGenerateReplicationConfig:
    """Tests for generate_replication_config()."""

    def test_ssh_auth_url_format(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(auth_type="ssh")

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "/r",
            config,
        )

        content = config_file.read_text()
        assert "ssh://gerrit@gerrit.example.org:29418/${name}.git" in content

    def test_http_basic_url_format(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(auth_type="http_basic")

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "/r",
            config,
        )

        content = config_file.read_text()
        assert "https://gerrit.example.org/r/a/${name}.git" in content

    def test_http_no_api_path(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(auth_type="http_basic")

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "https://gerrit.example.org/a/${name}.git" in content

    def test_fetch_every_present(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(fetch_every="30s")

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "fetchEvery = 30s" in content

    def test_fetch_every_disabled(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(fetch_every="0")

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        # The word "fetchEvery" appears in comments; check the actual setting line is absent
        config_lines = [
            line.strip()
            for line in content.splitlines()
            if not line.strip().startswith("#")
        ]
        assert not any(line.startswith("fetchEvery") for line in config_lines)

    def test_sync_refs_in_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(
            sync_refs="+refs/heads/*:refs/heads/*,+refs/tags/*:refs/tags/*"
        )

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "fetch = +refs/heads/*:refs/heads/*" in content
        assert "fetch = +refs/tags/*:refs/tags/*" in content

    def test_project_filter_present(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config()

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "my-project",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "projects = my-project" in content

    def test_remote_name_matches_slug(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config()

        start_instances.generate_replication_config(
            config_file,
            "my-slug",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert '[remote "my-slug"]' in content

    def test_replication_timeout_and_connection_timeout(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(replication_timeout=60)

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "timeout = 60" in content
        # 60 * 1000 = 60000 < 120000, so connection timeout should be 120000
        assert "connectionTimeout = 120000" in content

    def test_large_replication_timeout(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(replication_timeout=300)

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        # 300 * 1000 = 300000 > 120000, so connectionTimeout = timeout_ms
        assert "connectionTimeout = 300000" in content

    def test_sync_on_startup(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(sync_on_startup=True)

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "replicateOnStartup = true" in content

    def test_sync_on_startup_false(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(sync_on_startup=False)

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "replicateOnStartup = false" in content

    def test_threads_setting(self, tmp_path: Path) -> None:
        config_file = tmp_path / "replication.config"
        config = _make_config(replication_threads=8)

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        content = config_file.read_text()
        assert "threads = 8" in content

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        config_file = tmp_path / "deep" / "nested" / "replication.config"
        config = _make_config()

        start_instances.generate_replication_config(
            config_file,
            "test",
            "gerrit.example.org",
            "",
            "gerrit",
            29418,
            "",
            config,
        )

        assert config_file.exists()


# =====================================================================
# generate_secure_config
# =====================================================================


class TestGenerateSecureConfig:
    """Tests for generate_secure_config()."""

    def test_http_basic(self, tmp_path: Path) -> None:
        config_file = tmp_path / "secure.config"
        config = _make_config(
            auth_type="http_basic",
            http_username="admin",
            http_password="secret123",
        )

        start_instances.generate_secure_config(config_file, "test", config)

        content = config_file.read_text()
        assert '[remote "test"]' in content
        assert "username = admin" in content
        assert "password = secret123" in content

    def test_bearer_token(self, tmp_path: Path) -> None:
        config_file = tmp_path / "secure.config"
        config = _make_config(
            auth_type="bearer_token",
            bearer_token="tok-abc-123",
        )

        start_instances.generate_secure_config(config_file, "test", config)

        content = config_file.read_text()
        assert "[auth]" in content
        assert "bearerToken = tok-abc-123" in content

    def test_ssh_creates_empty(self, tmp_path: Path) -> None:
        config_file = tmp_path / "secure.config"
        config = _make_config(auth_type="ssh")

        start_instances.generate_secure_config(config_file, "test", config)

        content = config_file.read_text()
        assert content == ""

    def test_permissions(self, tmp_path: Path) -> None:
        config_file = tmp_path / "secure.config"
        config = _make_config(auth_type="ssh")

        start_instances.generate_secure_config(config_file, "test", config)

        mode = config_file.stat().st_mode & 0o777
        assert mode == 0o600


# =====================================================================
# download_plugin
# =====================================================================


class TestDownloadPlugin:
    """Tests for download_plugin()."""

    def test_skip_when_flag_set(self, tmp_path: Path) -> None:
        result = start_instances.download_plugin(
            tmp_path / "plugins", "stable-3.13", skip_plugin_install=True
        )
        assert result is True

    def test_uses_cached_plugin(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # Create cached JAR
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cached = cache_dir / "pull-replication-stable-3.13.jar"
        cached.write_bytes(b"fake-jar-content")

        with patch.object(start_instances, "_PLUGIN_CACHE_DIR", cache_dir):
            result = start_instances.download_plugin(
                plugin_dir, "stable-3.13", skip_plugin_install=False
            )

        assert result is True
        assert (plugin_dir / "pull-replication.jar").exists()
        assert (plugin_dir / "pull-replication.jar").read_bytes() == b"fake-jar-content"

    def test_downloads_from_primary(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        cache_dir = tmp_path / "cache"

        def fake_download(url: str, dest: Path) -> bool:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"downloaded")
            return True

        with (
            patch.object(start_instances, "_PLUGIN_CACHE_DIR", cache_dir),
            patch.object(start_instances, "_download_file", side_effect=fake_download),
        ):
            result = start_instances.download_plugin(
                plugin_dir, "stable-3.13", skip_plugin_install=False
            )

        assert result is True

    def test_fallback_to_alternate(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        cache_dir = tmp_path / "cache"

        call_count = 0

        def fake_download(url: str, dest: Path) -> bool:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return False  # Primary fails
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"alt-download")
            return True

        with (
            patch.object(start_instances, "_PLUGIN_CACHE_DIR", cache_dir),
            patch.object(start_instances, "_download_file", side_effect=fake_download),
        ):
            result = start_instances.download_plugin(
                plugin_dir, "stable-3.13", skip_plugin_install=False
            )

        assert result is True
        assert call_count == 2

    def test_failure_when_both_fail(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        cache_dir = tmp_path / "cache"

        with (
            patch.object(start_instances, "_PLUGIN_CACHE_DIR", cache_dir),
            patch.object(start_instances, "_download_file", return_value=False),
        ):
            result = start_instances.download_plugin(
                plugin_dir, "stable-3.13", skip_plugin_install=False
            )

        assert result is False


class TestDownloadAdditionalPlugins:
    """Tests for download_additional_plugins()."""

    def test_empty_string_no_op(self, tmp_path: Path) -> None:
        with patch.object(start_instances, "_download_file") as mock_dl:
            start_instances.download_additional_plugins(tmp_path, "")
            mock_dl.assert_not_called()

    def test_downloads_multiple(self, tmp_path: Path) -> None:
        urls = "https://example.com/a.jar,https://example.com/b.jar"

        with patch.object(
            start_instances, "_download_file", return_value=True
        ) as mock_dl:
            start_instances.download_additional_plugins(tmp_path, urls)

        assert mock_dl.call_count == 2


class TestDownloadFile:
    """Tests for _download_file()."""

    def test_success(self, tmp_path: Path) -> None:
        dest = tmp_path / "output.jar"
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [b"data1", b"data2"]
        mock_resp.raise_for_status.return_value = None

        with patch("start_instances.requests.get", return_value=mock_resp):
            result = start_instances._download_file("https://example.com/f", dest)

        assert result is True
        assert dest.read_bytes() == b"data1data2"

    def test_failure_cleans_up(self, tmp_path: Path) -> None:
        dest = tmp_path / "output.jar"

        with patch(
            "start_instances.requests.get",
            side_effect=requests.RequestException("network error"),
        ):
            result = start_instances._download_file("https://example.com/f", dest)

        assert result is False
        assert not dest.exists()


# =====================================================================
# init_gerrit_site
# =====================================================================


class TestInitGerritSite:
    """Tests for init_gerrit_site()."""

    def test_creates_subdirectories(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.run_ephemeral.return_value = ""
        instance_dir = tmp_path / "instance"

        with patch.object(start_instances, "_chown_tree"):
            start_instances.init_gerrit_site(
                docker,
                instance_dir,
                "test",
                "http://localhost:18080/",
                "test-image:latest",
            )

        for sub in start_instances._GERRIT_SUBDIRS:
            assert (instance_dir / sub).is_dir()

    def test_calls_docker_init(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.run_ephemeral.return_value = ""
        instance_dir = tmp_path / "instance"

        with patch.object(start_instances, "_chown_tree"):
            start_instances.init_gerrit_site(
                docker,
                instance_dir,
                "test",
                "http://localhost:18080/",
                "my-image:1.0",
            )

        docker.run_ephemeral.assert_called_once()
        call_kwargs = docker.run_ephemeral.call_args
        assert call_kwargs[0][0] == "my-image:1.0"
        assert call_kwargs[1]["command"] == ["init"]
        assert "CANONICAL_WEB_URL" in call_kwargs[1]["env"]

    def test_volumes_map_subdirs(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.run_ephemeral.return_value = ""
        instance_dir = tmp_path / "instance"

        with patch.object(start_instances, "_chown_tree"):
            start_instances.init_gerrit_site(
                docker,
                instance_dir,
                "test",
                "http://localhost:18080/",
                "img:latest",
            )

        volumes = docker.run_ephemeral.call_args[1]["volumes"]
        for sub in start_instances._GERRIT_SUBDIRS:
            assert str(instance_dir / sub) in volumes
            assert volumes[str(instance_dir / sub)] == f"/var/gerrit/{sub}"

    def test_raises_on_init_failure(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.run_ephemeral.side_effect = DockerError("init failed")
        instance_dir = tmp_path / "instance"

        with (
            patch.object(start_instances, "_chown_tree"),
            pytest.raises(GerritActionError, match="Failed to initialize"),
        ):
            start_instances.init_gerrit_site(
                docker,
                instance_dir,
                "test",
                "http://localhost:18080/",
                "img:latest",
            )


# =====================================================================
# configure_gerrit
# =====================================================================


class TestConfigureGerrit:
    """Tests for configure_gerrit()."""

    def test_calls_git_config(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        (instance_dir / "etc").mkdir(parents=True)
        # Create a minimal git config file
        (instance_dir / "etc" / "gerrit.config").write_text("")

        with patch("start_instances.subprocess.run") as mock_run:
            mock_run.return_value = _cp()
            start_instances.configure_gerrit(
                instance_dir,
                "test",
                "http://localhost:18080/",
                "http://*:8080/",
                "",
                "localhost:29418",
                False,
            )

        # Should have been called many times for git config
        assert mock_run.call_count > 5

    def test_sets_dev_auth(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        (instance_dir / "etc").mkdir(parents=True)
        (instance_dir / "etc" / "gerrit.config").write_text("")

        calls_made = []

        def record_call(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls_made.append(args[0])
            return _cp()

        with patch("start_instances.subprocess.run", side_effect=record_call):
            start_instances.configure_gerrit(
                instance_dir,
                "test",
                "http://localhost:18080/",
                "http://*:8080/",
                "",
                "localhost:29418",
                False,
            )

        # Find the auth.type call
        auth_calls = [
            c
            for c in calls_made
            if "auth.type" in c and "DEVELOPMENT_BECOME_ANY_ACCOUNT" in c
        ]
        assert len(auth_calls) == 1

    def test_tunnel_mode_disables_remote_admin(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        (instance_dir / "etc").mkdir(parents=True)
        (instance_dir / "etc" / "gerrit.config").write_text("")

        calls_made = []

        def record_call(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls_made.append(args[0])
            return _cp()

        with patch("start_instances.subprocess.run", side_effect=record_call):
            start_instances.configure_gerrit(
                instance_dir,
                "test",
                "http://tunnel.example.com:8080/",
                "http://*:8080/",
                "",
                "tunnel.example.com:12345",
                True,
            )

        admin_calls = [c for c in calls_made if "plugins.allowRemoteAdmin" in c]
        assert any("false" in c for c in admin_calls)

    def test_no_tunnel_enables_remote_admin(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        (instance_dir / "etc").mkdir(parents=True)
        (instance_dir / "etc" / "gerrit.config").write_text("")

        calls_made = []

        def record_call(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls_made.append(args[0])
            return _cp()

        with patch("start_instances.subprocess.run", side_effect=record_call):
            start_instances.configure_gerrit(
                instance_dir,
                "test",
                "http://localhost:18080/",
                "http://*:8080/",
                "",
                "localhost:29418",
                False,
            )

        admin_calls = [c for c in calls_made if "plugins.allowRemoteAdmin" in c]
        assert any("true" in c for c in admin_calls)

    def test_ootb_redirect_includes_api_path(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        (instance_dir / "etc").mkdir(parents=True)
        (instance_dir / "etc" / "gerrit.config").write_text("")

        calls_made: list[list[str]] = []

        def record_call(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls_made.append(args[0])
            return _cp()

        with patch("start_instances.subprocess.run", side_effect=record_call):
            start_instances.configure_gerrit(
                instance_dir,
                "test",
                "http://localhost:18080/r/",
                "http://*:8080/r/",
                "/r",
                "localhost:29418",
                False,
            )

        # Each call is a list like ['git', 'config', '-f', '...', 'httpd.firstTimeRedirectUrl', '/r/login/...']
        redirect_calls = [
            c for c in calls_made if any("firstTimeRedirectUrl" in elem for elem in c)
        ]
        assert len(redirect_calls) == 1
        assert "/r/login/" in redirect_calls[0][-1]


# =====================================================================
# Project pre-creation
# =====================================================================


class TestResolveProjectList:
    """Tests for _resolve_project_list()."""

    def test_no_filter_fetches_all(self) -> None:
        instance = _make_instance(project="")
        config = _make_config()

        with patch.object(
            start_instances, "fetch_remote_projects", return_value=["p1", "p2"]
        ) as mock_fetch:
            result = start_instances._resolve_project_list(instance, "/r", config)

        assert result == ["p1", "p2"]
        mock_fetch.assert_called_once()

    def test_regex_prefix_fetches_filtered(self) -> None:
        instance = _make_instance(project="regex:foo.*")
        config = _make_config()

        with patch.object(
            start_instances, "fetch_remote_projects", return_value=["foo-bar"]
        ) as mock_fetch:
            result = start_instances._resolve_project_list(instance, "", config)

        assert result == ["foo-bar"]
        args = mock_fetch.call_args[0]
        assert args[2] == "foo.*"  # regex_pattern without prefix

    def test_literal_project_names(self) -> None:
        instance = _make_instance(project="proj-a, proj-b , proj-c")
        config = _make_config()

        result = start_instances._resolve_project_list(instance, "", config)

        assert result == ["proj-a", "proj-b", "proj-c"]

    def test_single_literal_project(self) -> None:
        instance = _make_instance(project="my-project")
        config = _make_config()

        result = start_instances._resolve_project_list(instance, "", config)

        assert result == ["my-project"]


class TestFetchAndPrecreateProjects:
    """Tests for fetch_and_precreate_projects()."""

    def test_creates_bare_repos(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        instance_dir.mkdir()
        instance = _make_instance(project="proj-a, proj-b")
        config = _make_config()

        with (
            patch.object(start_instances, "_chown_tree"),
            patch("start_instances.subprocess.run", return_value=_cp()),
        ):
            count = start_instances.fetch_and_precreate_projects(
                instance_dir, instance, "", config
            )

        assert count == 2
        assert (instance_dir / "git" / "proj-a.git").is_dir()
        assert (instance_dir / "git" / "proj-b.git").is_dir()

    def test_filters_system_projects(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        instance_dir.mkdir()
        instance = _make_instance(project="")
        config = _make_config()

        projects = ["All-Projects", "All-Users", "real-project"]

        with (
            patch.object(
                start_instances, "fetch_remote_projects", return_value=projects
            ),
            patch.object(start_instances, "_chown_tree"),
            patch("start_instances.subprocess.run", return_value=_cp()),
        ):
            count = start_instances.fetch_and_precreate_projects(
                instance_dir, instance, "", config
            )

        assert count == 1
        assert (instance_dir / "git" / "real-project.git").is_dir()
        assert not (instance_dir / "git" / "All-Projects.git").exists()

    def test_writes_expected_count_file(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        instance_dir.mkdir()
        instance = _make_instance(project="a, b, c")
        config = _make_config()

        with (
            patch.object(start_instances, "_chown_tree"),
            patch("start_instances.subprocess.run", return_value=_cp()),
        ):
            start_instances.fetch_and_precreate_projects(
                instance_dir, instance, "", config
            )

        count_file = instance_dir / "expected_project_count"
        assert count_file.read_text() == "3"

    def test_does_not_recreate_existing_dirs(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        git_dir = instance_dir / "git" / "existing.git"
        git_dir.mkdir(parents=True)
        # Mark with a sentinel file
        (git_dir / "sentinel").write_text("original")

        instance = _make_instance(project="existing")
        config = _make_config()

        with (
            patch.object(start_instances, "_chown_tree"),
            patch("start_instances.subprocess.run", return_value=_cp()),
        ):
            start_instances.fetch_and_precreate_projects(
                instance_dir, instance, "", config
            )

        # Sentinel should still be there — directory was not recreated
        assert (git_dir / "sentinel").read_text() == "original"

    def test_empty_remote_returns_zero(self, tmp_path: Path) -> None:
        instance_dir = tmp_path / "instance"
        instance_dir.mkdir()
        instance = _make_instance(project="")
        config = _make_config()

        with patch.object(start_instances, "fetch_remote_projects", return_value=[]):
            count = start_instances.fetch_and_precreate_projects(
                instance_dir, instance, "", config
            )

        assert count == 0


# =====================================================================
# capture_ssh_host_keys
# =====================================================================


class TestCaptureSshHostKeys:
    """Tests for capture_ssh_host_keys()."""

    def test_captures_keys(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.exec_cmd.return_value = (
            "/var/gerrit/etc/ssh_host_ed25519_key.pub "
            "/var/gerrit/etc/ssh_host_rsa_key.pub"
        )

        def fake_cp(src: str, dst: str) -> None:
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            if "ed25519" in src:
                Path(dst).write_text("ssh-ed25519 AAAAC3...")
            elif "rsa" in src:
                Path(dst).write_text("ssh-rsa AAAAB3...")

        docker.cp.side_effect = fake_cp

        result = start_instances.capture_ssh_host_keys(
            docker, "abc123", tmp_path, "test"
        )

        assert "ssh_host_ed25519_key" in result
        assert "ssh_host_rsa_key" in result
        assert result["ssh_host_ed25519_key"] == "ssh-ed25519 AAAAC3..."

    def test_handles_exec_failure(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.exec_cmd.side_effect = DockerError("exec failed")

        result = start_instances.capture_ssh_host_keys(
            docker, "abc123", tmp_path, "test"
        )

        assert result == {}

    def test_handles_cp_failure(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.exec_cmd.return_value = "/var/gerrit/etc/ssh_host_rsa_key.pub"
        docker.cp.side_effect = DockerError("cp failed")

        result = start_instances.capture_ssh_host_keys(
            docker, "abc123", tmp_path, "test"
        )

        assert result == {}

    def test_empty_key_list(self, tmp_path: Path) -> None:
        docker = MagicMock()
        docker.exec_cmd.return_value = ""

        result = start_instances.capture_ssh_host_keys(
            docker, "abc123", tmp_path, "test"
        )

        assert result == {}


# =====================================================================
# _resolve_tunnel
# =====================================================================


class TestResolveTunnel:
    """Tests for _resolve_tunnel()."""

    def test_no_tunnel(self) -> None:
        config = _make_config(tunnel_host="", tunnel_ports_json="")

        use_tunnel, host, http, ssh = start_instances._resolve_tunnel("test", config)

        assert use_tunnel is False
        assert host == "localhost"

    def test_with_tunnel(self) -> None:
        ports_json = json.dumps({"test": {"http": 8080, "ssh": 22}})
        config = _make_config(
            tunnel_host="tunnel.example.com", tunnel_ports_json=ports_json
        )

        use_tunnel, host, http, ssh = start_instances._resolve_tunnel("test", config)

        assert use_tunnel is True
        assert host == "tunnel.example.com"
        assert http == 8080
        assert ssh == 22

    def test_tunnel_host_but_no_matching_slug(self) -> None:
        ports_json = json.dumps({"other": {"http": 8080, "ssh": 22}})
        config = _make_config(
            tunnel_host="tunnel.example.com", tunnel_ports_json=ports_json
        )

        use_tunnel, host, http, ssh = start_instances._resolve_tunnel("test", config)

        assert use_tunnel is False
        assert host == "localhost"


# =====================================================================
# _write_env_sh
# =====================================================================


class TestWriteEnvSh:
    """Tests for _write_env_sh()."""

    def test_writes_variables(self, tmp_path: Path) -> None:
        start_instances._write_env_sh(
            tmp_path,
            "http://localhost:18080/",
            "http://*:8080/",
            "localhost:29418",
            False,
        )

        content = (tmp_path / "env.sh").read_text()
        assert "GERRIT_CANONICAL_URL=http://localhost:18080/" in content
        assert "GERRIT_LISTEN_URL=http://*:8080/" in content
        assert "GERRIT_SSH_ADDR=localhost:29418" in content
        assert "GERRIT_TUNNEL_MODE" not in content

    def test_writes_tunnel_mode(self, tmp_path: Path) -> None:
        start_instances._write_env_sh(
            tmp_path,
            "http://t.example.com:8080/",
            "http://*:8080/",
            "t.example.com:22",
            True,
        )

        content = (tmp_path / "env.sh").read_text()
        assert "GERRIT_TUNNEL_MODE=true" in content

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        env_file = tmp_path / "env.sh"
        env_file.write_text("EXISTING=yes\n")

        start_instances._write_env_sh(
            tmp_path,
            "url",
            "listen",
            "addr",
            False,
        )

        content = env_file.read_text()
        assert "EXISTING=yes" in content
        assert "GERRIT_CANONICAL_URL=url" in content


# =====================================================================
# _write_startup_summary
# =====================================================================


class TestWriteStartupSummary:
    """Tests for _write_startup_summary()."""

    def test_writes_markdown_table(self, tmp_path: Path) -> None:
        store = InstanceStore(tmp_path / "instances.json")
        store._data = {
            "alpha": {"http_port": 18080, "ssh_port": 29418},
            "beta": {"http_port": 18081, "ssh_port": 29419},
        }

        with patch.object(start_instances, "write_summary") as mock_ws:
            start_instances._write_startup_summary(store)

        written = mock_ws.call_args[0][0]
        assert "alpha" in written
        assert "beta" in written
        assert "18080" in written
        assert "29419" in written
        assert "Running" in written


# =====================================================================
# _chown_tree
# =====================================================================


class TestChownTree:
    """Tests for _chown_tree()."""

    def test_calls_chown_and_chmod(self, tmp_path: Path) -> None:
        with patch("start_instances.subprocess.run") as mock_run:
            mock_run.return_value = _cp()
            start_instances._chown_tree(tmp_path)

        assert mock_run.call_count == 2
        chown_call = mock_run.call_args_list[0][0][0]
        chmod_call = mock_run.call_args_list[1][0][0]
        assert "chown" in chown_call
        assert "1000:1000" in chown_call
        assert "chmod" in chmod_call

    def test_ignores_errors(self) -> None:
        with patch(
            "start_instances.subprocess.run",
            side_effect=FileNotFoundError("chown not found"),
        ):
            # Should not raise
            start_instances._chown_tree(Path("/nonexistent"))


# =====================================================================
# start_instance (integration-level)
# =====================================================================


class TestStartInstance:
    """Tests for start_instance()."""

    def _setup_mocks(
        self, tmp_path: Path
    ) -> tuple[MagicMock, InstanceConfig, ActionConfig, ApiPathStore, InstanceStore]:
        docker = MagicMock()
        docker.run_ephemeral.return_value = ""
        docker.run_container.return_value = "abc123def456"
        docker.container_ip.return_value = "172.17.0.2"
        docker.exec_cmd.return_value = ""
        docker.ps.return_value = ""

        instance = _make_instance()
        config = _make_config(work_dir=str(tmp_path))

        api_store = ApiPathStore(tmp_path / "api_paths.json")
        api_store._data = {
            "test": {
                "gerrit_host": "gerrit.example.org",
                "api_path": "/r",
                "api_url": "https://gerrit.example.org/r",
            }
        }

        inst_store = InstanceStore(tmp_path / "instances.json")
        inst_store._data = {}
        # Create the file so save() works
        inst_store.save()

        # Create container_ids.txt
        (tmp_path / "container_ids.txt").write_text("")

        return docker, instance, config, api_store, inst_store

    def test_success(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=5
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            ok = start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        assert ok is True
        assert "test" in inst_store.data
        assert inst_store.data["test"]["cid"] == "abc123def456"
        assert inst_store.data["test"]["http_port"] == 18080
        assert inst_store.data["test"]["ssh_port"] == 29418

    def test_plugin_failure_returns_false(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=False),
            patch.object(start_instances, "_write_env_sh"),
        ):
            ok = start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        assert ok is False

    def test_docker_run_failure_returns_false(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)
        docker.run_container.side_effect = DockerError("cannot start")

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "_write_env_sh"),
        ):
            ok = start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        assert ok is False

    def test_port_assignment(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            # Instance at index 2
            start_instances.start_instance(
                docker,
                instance,
                2,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        ports = docker.run_container.call_args[1]["ports"]
        assert 18082 in ports  # base_http + 2
        assert 29420 in ports  # base_ssh + 2

    def test_ssh_auth_not_called_for_http_basic(self, tmp_path: Path) -> None:
        docker, instance, _, api_store, inst_store = self._setup_mocks(tmp_path)
        config = _make_config(
            auth_type="http_basic",
            http_username="user",
            http_password="pass",
            work_dir=str(tmp_path),
        )

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth") as mock_ssh,
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        mock_ssh.assert_not_called()

    def test_removes_bundled_replication_jar(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)

        # Create the bundled jar to be removed
        plugins_dir = tmp_path / "instances" / "test" / "plugins"
        plugins_dir.mkdir(parents=True)
        bundled = plugins_dir / "replication.jar"
        bundled.write_text("bundled")

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        assert not bundled.exists()

    def test_tunnel_mode_urls(self, tmp_path: Path) -> None:
        docker, instance, _, api_store, inst_store = self._setup_mocks(tmp_path)
        ports_json = json.dumps({"test": {"http": 9080, "ssh": 9022}})
        config = _make_config(
            tunnel_host="tunnel.example.com",
            tunnel_ports_json=ports_json,
            work_dir=str(tmp_path),
        )

        written_env_args = {}

        def capture_env_sh(*args: Any, **kwargs: Any) -> None:
            written_env_args["args"] = args

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit") as mock_cfg,
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh", side_effect=capture_env_sh),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        # Check canonical_url includes tunnel host
        cfg_args = mock_cfg.call_args
        canonical_url = cfg_args[0][2]  # 3rd positional arg
        assert "tunnel.example.com" in canonical_url
        assert "9080" in canonical_url

    def test_container_ip_failure_handled(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = self._setup_mocks(tmp_path)
        docker.container_ip.side_effect = DockerError("no ip")

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            ok = start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "test-image:latest",
            )

        assert ok is True
        assert inst_store.data["test"]["ip"] == ""


# =====================================================================
# run()
# =====================================================================


class TestRun:
    """Tests for the top-level run() orchestrator."""

    def test_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        setup_json = json.dumps(
            [
                {"slug": "inst1", "gerrit": "gerrit.example.org"},
            ]
        )
        monkeypatch.setenv("GERRIT_SETUP", setup_json)
        monkeypatch.setenv("WORK_DIR", str(work_dir))
        monkeypatch.setenv("SSH_PRIVATE_KEY", "fake-key")
        monkeypatch.setenv("AUTH_TYPE", "ssh")

        # Create api_paths.json
        api_paths = work_dir / "api_paths.json"
        api_paths.write_text(
            json.dumps(
                {
                    "inst1": {
                        "gerrit_host": "gerrit.example.org",
                        "api_path": "",
                        "api_url": "https://gerrit.example.org",
                    }
                }
            )
        )

        with (
            patch.object(start_instances, "ensure_custom_image", return_value="img:1"),
            patch.object(
                start_instances, "start_instance", return_value=True
            ) as mock_start,
            patch.object(start_instances, "_write_startup_summary"),
            patch.object(
                start_instances,
                "log_group",
                return_value=MagicMock(
                    __enter__=MagicMock(return_value=None),
                    __exit__=MagicMock(return_value=False),
                ),
            ),
        ):
            rc = start_instances.run()

        assert rc == 0
        mock_start.assert_called_once()

    def test_validation_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GERRIT_SETUP", "[]")  # Empty — no instances
        monkeypatch.setenv("WORK_DIR", str(tmp_path))
        monkeypatch.setenv("AUTH_TYPE", "ssh")
        monkeypatch.setenv("SSH_PRIVATE_KEY", "key")

        rc = start_instances.run()

        assert rc == 1  # Validation fails (no instances)

    def test_partial_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        setup_json = json.dumps(
            [
                {"slug": "ok", "gerrit": "gerrit1.example.org"},
                {"slug": "fail", "gerrit": "gerrit2.example.org"},
            ]
        )
        monkeypatch.setenv("GERRIT_SETUP", setup_json)
        monkeypatch.setenv("WORK_DIR", str(work_dir))
        monkeypatch.setenv("SSH_PRIVATE_KEY", "fake-key")
        monkeypatch.setenv("AUTH_TYPE", "ssh")

        api_paths = work_dir / "api_paths.json"
        api_paths.write_text(
            json.dumps(
                {
                    "ok": {
                        "gerrit_host": "g1",
                        "api_path": "",
                        "api_url": "https://g1",
                    },
                    "fail": {
                        "gerrit_host": "g2",
                        "api_path": "",
                        "api_url": "https://g2",
                    },
                }
            )
        )

        # First instance succeeds, second fails
        side_effects = [True, False]

        with (
            patch.object(start_instances, "ensure_custom_image", return_value="img:1"),
            patch.object(start_instances, "start_instance", side_effect=side_effects),
            patch.object(start_instances, "_write_startup_summary"),
            patch.object(
                start_instances,
                "log_group",
                return_value=MagicMock(
                    __enter__=MagicMock(return_value=None),
                    __exit__=MagicMock(return_value=False),
                ),
            ),
        ):
            rc = start_instances.run()

        assert rc == 1  # Partial failure


# =====================================================================
# main()
# =====================================================================


class TestMain:
    """Tests for the main() entry point."""

    def test_gerrit_action_error(self) -> None:
        with patch.object(
            start_instances,
            "run",
            side_effect=GerritActionError("boom"),
        ):
            rc = start_instances.main()

        assert rc == 1

    def test_unexpected_error(self) -> None:
        with patch.object(
            start_instances,
            "run",
            side_effect=RuntimeError("unexpected"),
        ):
            rc = start_instances.main()

        assert rc == 2

    def test_success(self) -> None:
        with patch.object(start_instances, "run", return_value=0):
            rc = start_instances.main()

        assert rc == 0


# =====================================================================
# Edge cases and integration scenarios
# =====================================================================


class TestEdgeCases:
    """Additional edge-case and scenario tests."""

    def test_use_api_path_true_affects_urls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When USE_API_PATH=true, canonical_url includes the api_path."""
        monkeypatch.setenv("USE_API_PATH", "true")

        docker, instance, _, api_store, inst_store = TestStartInstance()._setup_mocks(
            tmp_path
        )

        instance = _make_instance(api_path="/r")
        config = _make_config(use_api_path=True, work_dir=str(tmp_path))

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit") as mock_cfg,
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "img:latest",
            )

        # configure_gerrit is called with the canonical_url
        canonical_url = mock_cfg.call_args[0][2]
        listen_url = mock_cfg.call_args[0][3]
        assert "/r/" in canonical_url
        assert "/r/" in listen_url

    def test_multiple_instances_get_different_ports(self, tmp_path: Path) -> None:
        """Each instance should be assigned incrementing port numbers."""
        docker = MagicMock()
        docker.run_ephemeral.return_value = ""
        docker.run_container.return_value = "cid123"
        docker.container_ip.return_value = "172.17.0.2"
        docker.exec_cmd.return_value = ""

        api_store = ApiPathStore(tmp_path / "api_paths.json")
        api_store._data = {
            "a": {"gerrit_host": "g", "api_path": "", "api_url": "https://g"},
            "b": {"gerrit_host": "g", "api_path": "", "api_url": "https://g"},
        }

        inst_store = InstanceStore(tmp_path / "instances.json")
        inst_store._data = {}
        inst_store.save()
        (tmp_path / "container_ids.txt").write_text("")

        config = _make_config(work_dir=str(tmp_path))
        instances = [
            _make_instance(slug="a"),
            _make_instance(slug="b"),
        ]

        port_maps = []
        for idx, inst in enumerate(instances):
            with (
                patch.object(start_instances, "init_gerrit_site"),
                patch.object(start_instances, "configure_gerrit"),
                patch.object(start_instances, "download_plugin", return_value=True),
                patch.object(start_instances, "download_additional_plugins"),
                patch.object(start_instances, "setup_ssh_auth"),
                patch.object(start_instances, "generate_replication_config"),
                patch.object(start_instances, "generate_secure_config"),
                patch.object(
                    start_instances, "fetch_and_precreate_projects", return_value=0
                ),
                patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
                patch.object(start_instances, "_write_env_sh"),
            ):
                start_instances.start_instance(
                    docker,
                    inst,
                    idx,
                    config,
                    api_store,
                    inst_store,
                    "img:latest",
                )
            port_maps.append(docker.run_container.call_args[1]["ports"])

        # Instance 0: base ports, Instance 1: base + 1
        assert 18080 in port_maps[0]
        assert 29418 in port_maps[0]
        assert 18081 in port_maps[1]
        assert 29419 in port_maps[1]

    def test_debug_mode_adds_env_var(self, tmp_path: Path) -> None:
        docker, instance, _, api_store, inst_store = TestStartInstance()._setup_mocks(
            tmp_path
        )
        config = _make_config(debug=True, work_dir=str(tmp_path))

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "img:latest",
            )

        env = docker.run_container.call_args[1]["env"]
        assert env.get("DEBUG") == "1"

    def test_ssh_volume_mounted_readonly(self, tmp_path: Path) -> None:
        docker, instance, config, api_store, inst_store = (
            TestStartInstance()._setup_mocks(tmp_path)
        )

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=0
            ),
            patch.object(start_instances, "capture_ssh_host_keys", return_value={}),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "img:latest",
            )

        volumes = docker.run_container.call_args[1]["volumes"]
        # Should have an entry with :ro for SSH
        ssh_keys = [k for k in volumes if "ssh" in k and ":ro" in k]
        assert len(ssh_keys) == 1
        assert volumes[ssh_keys[0]] == "/var/gerrit/ssh"

    def test_instance_metadata_structure(self, tmp_path: Path) -> None:
        """Verify the metadata written matches the expected schema."""
        docker, instance, config, api_store, inst_store = (
            TestStartInstance()._setup_mocks(tmp_path)
        )

        with (
            patch.object(start_instances, "init_gerrit_site"),
            patch.object(start_instances, "configure_gerrit"),
            patch.object(start_instances, "download_plugin", return_value=True),
            patch.object(start_instances, "download_additional_plugins"),
            patch.object(start_instances, "setup_ssh_auth"),
            patch.object(start_instances, "generate_replication_config"),
            patch.object(start_instances, "generate_secure_config"),
            patch.object(
                start_instances, "fetch_and_precreate_projects", return_value=7
            ),
            patch.object(
                start_instances,
                "capture_ssh_host_keys",
                return_value={"ssh_host_ed25519_key": "ssh-ed25519 AAAA..."},
            ),
            patch.object(start_instances, "_write_env_sh"),
        ):
            start_instances.start_instance(
                docker,
                instance,
                0,
                config,
                api_store,
                inst_store,
                "img:latest",
            )

        meta = inst_store.data["test"]
        assert meta["cid"] == "abc123def456"
        assert meta["ip"] == "172.17.0.2"
        assert meta["http_port"] == 18080
        assert meta["ssh_port"] == 29418
        assert meta["url"] == "http://172.17.0.2:8080"
        assert meta["gerrit_host"] == "gerrit.example.org"
        assert meta["expected_project_count"] == 7
        assert "ssh_host_ed25519_key" in meta["ssh_host_keys"]
        assert meta["api_path"] == "/r"
        assert meta["api_url"] == "https://gerrit.example.org/r"
