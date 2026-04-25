# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the g2p_setup module."""

from __future__ import annotations

import configparser
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from errors import G2PSetupError
from g2p_config import (
    DEFAULT_COMMENT_MAPPINGS,
    DEFAULT_REMOTE_AUTH_GROUP,
    VALID_HOOKS,
    G2PConfig,
)
from g2p_setup import (
    G2P_CONFIG_DIR,
    G2P_INI_PATH,
    G2P_REPLICATION_SYMLINK,
    GERRIT_HOOKS_DIR,
    GERRIT_REPLICATION_CONFIG,
    GERRIT_TOOLS_VENV_BIN,
    GITHUB_HOST_KEY_ED25519,
    SSH_DIR,
    G2PSetupResult,
    _append_file_in_container,
    _write_file_in_container,
    fetch_github_host_keys,
    generate_g2p_ini,
    generate_g2p_replication_section,
    generate_ssh_keypair,
    setup_g2p,
    setup_g2p_config_dir,
    setup_g2p_hooks,
    setup_g2p_ini,
    setup_g2p_replication_remote,
    setup_g2p_replication_symlink,
    setup_g2p_ssh,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_docker_mock(
    *,
    exec_cmd_return: str = "",
    exec_test_return: bool = True,
) -> MagicMock:
    """Create a mock DockerManager with sensible defaults."""
    docker = MagicMock()
    docker.exec_cmd.return_value = exec_cmd_return
    docker.exec_test.return_value = exec_test_return
    docker.cp.return_value = None
    return docker


def _parse_ini(content: str) -> configparser.ConfigParser:
    """Parse an INI string into a ConfigParser."""
    cp = configparser.ConfigParser()
    cp.optionxform = str  # type: ignore[assignment]
    cp.read_string(content)
    return cp


CID = "abc123container"


# ===================================================================
# G2PSetupResult
# ===================================================================


class TestG2PSetupResult:
    """Tests for the G2PSetupResult dataclass."""

    def test_defaults(self) -> None:
        result = G2PSetupResult()
        assert result.config_path == ""
        assert result.hooks_enabled == []
        assert result.ssh_public_key == ""
        assert result.replication_remote_configured is False

    def test_with_values(self) -> None:
        result = G2PSetupResult(
            config_path="/var/gerrit/.config/gerrit_to_platform/gerrit_to_platform.ini",
            hooks_enabled=["patchset-created", "comment-added"],
            ssh_public_key="ssh-ed25519 AAAA...",
            replication_remote_configured=True,
        )
        assert result.config_path.endswith(".ini")
        assert len(result.hooks_enabled) == 2
        assert result.ssh_public_key.startswith("ssh-ed25519")
        assert result.replication_remote_configured is True


# ===================================================================
# generate_g2p_ini
# ===================================================================


class TestGenerateG2pIni:
    """Tests for INI content generation."""

    def test_default_config(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_test123",
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        assert cp.has_section('mapping "comment-added"')
        assert cp.has_section("github.com")
        assert cp.get("github.com", "token") == "ghp_test123"

    def test_default_comment_mappings(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_tok",
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        section = 'mapping "comment-added"'
        for keyword, wf_filter in DEFAULT_COMMENT_MAPPINGS.items():
            assert cp.get(section, keyword) == wf_filter

    def test_custom_comment_mappings(self) -> None:
        custom = {
            "recheck": "verify",
            "remerge": "merge",
            "rerun-gha": "verify",
            "remerge-gha": "merge",
        }
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            github_token="ghp_tok",
            comment_mappings=custom,
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        section = 'mapping "comment-added"'
        assert cp.get(section, "rerun-gha") == "verify"
        assert cp.get(section, "remerge-gha") == "merge"
        assert len(dict(cp.items(section))) == 4

    def test_no_token_omits_github_section(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="",
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        assert cp.has_section('mapping "comment-added"')
        assert not cp.has_section("github.com")

    def test_preserves_key_case(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_x",
            comment_mappings={"ReCheck": "verify"},
        )
        ini = generate_g2p_ini(config)
        # The key should appear as-is, not lowered
        assert "ReCheck" in ini

    def test_single_mapping(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="tok",
            comment_mappings={"recheck": "verify"},
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        section = 'mapping "comment-added"'
        items = dict(cp.items(section))
        assert items == {"recheck": "verify"}

    def test_empty_mappings(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="tok",
            comment_mappings={},
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        section = 'mapping "comment-added"'
        assert cp.has_section(section)
        assert dict(cp.items(section)) == {}

    def test_ini_is_valid_configparser_format(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            github_token="ghp_token_value",
            comment_mappings=DEFAULT_COMMENT_MAPPINGS,
        )
        ini = generate_g2p_ini(config)
        # Must not raise
        cp = _parse_ini(ini)
        assert len(cp.sections()) >= 2

    def test_production_onap_config(self) -> None:
        """Match the ONAP production Hiera pattern."""
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            github_token="ghp_onap_pat",
            comment_mappings={
                "recheck": "verify",
                "remerge": "merge",
                "rerun-gha": "verify",
                "remerge-gha": "merge",
            },
        )
        ini = generate_g2p_ini(config)
        cp = _parse_ini(ini)
        assert cp.get("github.com", "token") == "ghp_onap_pat"
        section = 'mapping "comment-added"'
        assert cp.get(section, "recheck") == "verify"
        assert cp.get(section, "remerge-gha") == "merge"


# ===================================================================
# generate_g2p_replication_section
# ===================================================================


class TestGenerateG2pReplicationSection:
    """Tests for replication config section generation."""

    def test_standard_config(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            remote_name_style="dash",
            remote_auth_group=DEFAULT_REMOTE_AUTH_GROUP,
        )
        section = generate_g2p_replication_section(config)
        assert '[remote "github-g2p"]' in section
        assert "git@github.com:onap/${name}.git" in section
        assert f"authGroup = {DEFAULT_REMOTE_AUTH_GROUP}" in section
        assert "remoteNameStyle = dash" in section

    def test_underscore_name_style(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="fdio",
            remote_name_style="underscore",
        )
        section = generate_g2p_replication_section(config)
        assert "remoteNameStyle = underscore" in section
        assert "git@github.com:fdio/${name}.git" in section

    def test_slash_name_style(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="opendaylight",
            remote_name_style="slash",
        )
        section = generate_g2p_replication_section(config)
        assert "remoteNameStyle = slash" in section

    def test_custom_url(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="custom",
            remote_url="ssh://git@github.example.com/${name}.git",
        )
        section = generate_g2p_replication_section(config)
        assert "ssh://git@github.example.com/${name}.git" in section

    def test_custom_auth_group(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            remote_auth_group="My Custom Group",
        )
        section = generate_g2p_replication_section(config)
        assert "authGroup = My Custom Group" in section

    def test_empty_url_and_owner_returns_empty(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="",
            remote_url="",
        )
        section = generate_g2p_replication_section(config)
        assert section == ""

    def test_contains_comment_header(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test",
        )
        section = generate_g2p_replication_section(config)
        assert "G2P platform detection" in section
        assert "Auto-generated" in section

    def test_section_is_appendable(self) -> None:
        """Section should start with a newline for clean appending."""
        config = G2PConfig(
            enabled=True,
            github_owner="test",
        )
        section = generate_g2p_replication_section(config)
        assert section.startswith("\n")


# ===================================================================
# generate_ssh_keypair
# ===================================================================


class TestGenerateSshKeypair:
    """Tests for SSH keypair generation."""

    @patch("g2p_setup.subprocess.run")
    def test_successful_generation(self, mock_run: MagicMock, tmp_path: Path) -> None:
        private_key_content = "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----"
        public_key_content = "ssh-ed25519 AAAAC3test gerrit-action-g2p"

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            # Find the -f argument to determine the key path
            f_idx = cmd.index("-f")
            key_path = cmd[f_idx + 1]
            Path(key_path).write_text(private_key_content, encoding="utf-8")
            Path(f"{key_path}.pub").write_text(public_key_content, encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        mock_run.side_effect = fake_run
        private, public = generate_ssh_keypair()
        assert "BEGIN OPENSSH PRIVATE KEY" in private
        assert public.startswith("ssh-ed25519")

        # Verify ssh-keygen was called with correct args
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "ssh-keygen" in call_args
        assert "-t" in call_args
        assert "ed25519" in call_args

    @patch("g2p_setup.subprocess.run")
    def test_keygen_failure_raises(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "ssh-keygen", stderr="keygen error"
        )
        with pytest.raises(G2PSetupError, match="ssh-keygen failed"):
            generate_ssh_keypair()

    @patch("g2p_setup.subprocess.run")
    def test_keygen_timeout_raises(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired("ssh-keygen", 30)
        with pytest.raises(G2PSetupError, match="timed out"):
            generate_ssh_keypair()

    @patch("g2p_setup.subprocess.run")
    def test_keygen_not_found_raises(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("ssh-keygen")
        with pytest.raises(G2PSetupError, match="ssh-keygen not found"):
            generate_ssh_keypair()


# ===================================================================
# fetch_github_host_keys
# ===================================================================


class TestFetchGithubHostKeys:
    """Tests for GitHub host key fetching."""

    @patch("g2p_setup.subprocess.run")
    def test_successful_scan(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["ssh-keyscan"],
            0,
            stdout="github.com ssh-ed25519 AAAAC3scanresult\n",
            stderr="",
        )
        result = fetch_github_host_keys()
        assert "github.com" in result
        assert "AAAAC3scanresult" in result

    @patch("g2p_setup.subprocess.run")
    def test_scan_failure_falls_back(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["ssh-keyscan"], 1, stdout="", stderr="error"
        )
        result = fetch_github_host_keys()
        assert result == GITHUB_HOST_KEY_ED25519

    @patch("g2p_setup.subprocess.run")
    def test_scan_empty_stdout_falls_back(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["ssh-keyscan"], 0, stdout="", stderr=""
        )
        result = fetch_github_host_keys()
        assert result == GITHUB_HOST_KEY_ED25519

    @patch("g2p_setup.subprocess.run")
    def test_scan_timeout_falls_back(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired("ssh-keyscan", 30)
        result = fetch_github_host_keys()
        assert result == GITHUB_HOST_KEY_ED25519

    @patch("g2p_setup.subprocess.run")
    def test_scan_not_found_falls_back(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("ssh-keyscan")
        result = fetch_github_host_keys()
        assert result == GITHUB_HOST_KEY_ED25519

    @patch("g2p_setup.subprocess.run")
    def test_scan_os_error_falls_back(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = OSError("weird error")
        result = fetch_github_host_keys()
        assert result == GITHUB_HOST_KEY_ED25519

    def test_fallback_key_is_valid_format(self) -> None:
        parts = GITHUB_HOST_KEY_ED25519.split()
        assert parts[0] == "github.com"
        assert parts[1] == "ssh-ed25519"
        assert len(parts) == 3


# ===================================================================
# _write_file_in_container
# ===================================================================


class TestWriteFileInContainer:
    """Tests for the container file write helper."""

    def test_writes_file_with_correct_permissions(self) -> None:
        docker = _make_docker_mock()
        _write_file_in_container(
            docker,
            CID,
            "/var/gerrit/test.txt",
            "content",
            mode="0600",
            owner="gerrit:gerrit",
        )

        # Should have called mkdir, cp, chmod, chown
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any("mkdir -p" in c for c in exec_calls)
        assert any("chmod 0600" in c for c in exec_calls)
        assert any("chown gerrit:gerrit" in c for c in exec_calls)
        docker.cp.assert_called_once()

    def test_creates_parent_directory(self) -> None:
        docker = _make_docker_mock()
        _write_file_in_container(
            docker,
            CID,
            "/a/b/c/file.txt",
            "data",
        )
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any("mkdir -p /a/b/c" in c for c in exec_calls)

    def test_cleans_up_temp_file(self) -> None:
        docker = _make_docker_mock()
        _write_file_in_container(
            docker,
            CID,
            "/test.txt",
            "data",
        )
        # The temp file referenced by docker.cp should no longer exist
        cp_call = docker.cp.call_args[0][0]
        assert not os.path.exists(cp_call)

    def test_custom_mode_and_owner(self) -> None:
        docker = _make_docker_mock()
        _write_file_in_container(
            docker,
            CID,
            "/test.txt",
            "data",
            mode="0644",
            owner="root:root",
        )
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any("chmod 0644" in c for c in exec_calls)
        assert any("chown root:root" in c for c in exec_calls)

    def test_runs_mkdir_chmod_chown_as_root(self) -> None:
        """Post-docker-cp ops must run as root (docker cp creates root-owned files)."""
        docker = _make_docker_mock()
        _write_file_in_container(
            docker,
            CID,
            "/var/gerrit/test.txt",
            "content",
            mode="0600",
            owner="gerrit:gerrit",
        )
        for call in docker.exec_cmd.call_args_list:
            cmd_str = call[0][1]
            kwargs = call[1] if len(call) > 1 else {}
            # All exec_cmd calls in _write_file_in_container should
            # pass user="0" so they run as root inside the container.
            if any(op in cmd_str for op in ("mkdir -p", "chmod", "chown")):
                assert kwargs.get("user") == "0", (
                    f"Expected user='0' for command: {cmd_str}"
                )


# ===================================================================
# _append_file_in_container
# ===================================================================


class TestAppendFileInContainer:
    """Tests for the container file append helper."""

    def test_appends_content(self) -> None:
        docker = _make_docker_mock()
        _append_file_in_container(
            docker,
            CID,
            "/var/gerrit/etc/replication.config",
            "extra\n",
        )
        docker.cp.assert_called_once()
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any("cat" in c and ">>" in c for c in exec_calls)

    def test_cleans_up_temp_file(self) -> None:
        docker = _make_docker_mock()
        _append_file_in_container(docker, CID, "/test.txt", "data")
        cp_call = docker.cp.call_args[0][0]
        assert not os.path.exists(cp_call)

    def test_runs_cat_rm_as_root(self) -> None:
        """cat/rm must run as root since docker cp creates root-owned files."""
        docker = _make_docker_mock()
        _append_file_in_container(
            docker,
            CID,
            "/var/gerrit/etc/replication.config",
            "extra\n",
        )
        for call in docker.exec_cmd.call_args_list:
            cmd_str = call[0][1]
            kwargs = call[1] if len(call) > 1 else {}
            if "cat" in cmd_str and ">>" in cmd_str:
                assert kwargs.get("user") == "0", (
                    f"Expected user='0' for command: {cmd_str}"
                )


# ===================================================================
# setup_g2p_config_dir
# ===================================================================


class TestSetupG2pConfigDir:
    """Tests for config directory creation."""

    def test_creates_directory(self) -> None:
        docker = _make_docker_mock()
        setup_g2p_config_dir(docker, CID)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any(f"mkdir -p {G2P_CONFIG_DIR}" in c for c in exec_calls)
        assert any(f"chown -R gerrit:gerrit {G2P_CONFIG_DIR}" in c for c in exec_calls)


# ===================================================================
# setup_g2p_ini
# ===================================================================


class TestSetupG2pIni:
    """Tests for INI deployment to container."""

    def test_returns_ini_path(self) -> None:
        docker = _make_docker_mock()
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_tok",
        )
        path = setup_g2p_ini(docker, CID, config)
        assert path == G2P_INI_PATH

    def test_writes_with_secure_permissions(self) -> None:
        docker = _make_docker_mock()
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_tok",
        )
        setup_g2p_ini(docker, CID, config)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any("chmod 0600" in c for c in exec_calls)
        assert any("chown gerrit:gerrit" in c for c in exec_calls)

    def test_calls_docker_cp(self) -> None:
        docker = _make_docker_mock()
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_tok",
        )
        setup_g2p_ini(docker, CID, config)
        docker.cp.assert_called_once()
        # Second arg should be container path
        assert docker.cp.call_args[0][1] == f"{CID}:{G2P_INI_PATH}"


# ===================================================================
# setup_g2p_replication_symlink
# ===================================================================


class TestSetupG2pReplicationSymlink:
    """Tests for replication config symlink creation."""

    def test_creates_symlink(self) -> None:
        docker = _make_docker_mock()
        setup_g2p_replication_symlink(docker, CID)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any(
            f"ln -sf {GERRIT_REPLICATION_CONFIG} {G2P_REPLICATION_SYMLINK}" in c
            for c in exec_calls
        )

    def test_sets_ownership(self) -> None:
        docker = _make_docker_mock()
        setup_g2p_replication_symlink(docker, CID)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any(
            f"chown -h gerrit:gerrit {G2P_REPLICATION_SYMLINK}" in c for c in exec_calls
        )


# ===================================================================
# setup_g2p_replication_remote
# ===================================================================


class TestSetupG2pReplicationRemote:
    """Tests for appending the g2p detection remote."""

    def test_appends_section(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="missing")
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            remote_name_style="dash",
        )
        result = setup_g2p_replication_remote(docker, CID, config)
        assert result is True
        docker.cp.assert_called_once()

    def test_skips_when_already_present(self) -> None:
        docker = _make_docker_mock()
        # grep -q finds match, returns "found"
        docker.exec_cmd.return_value = "found"
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
        )
        result = setup_g2p_replication_remote(docker, CID, config)
        assert result is True
        docker.cp.assert_not_called()

    def test_returns_false_when_no_url(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="",
            remote_url="",
        )
        docker = _make_docker_mock()
        result = setup_g2p_replication_remote(docker, CID, config)
        assert result is False


# ===================================================================
# setup_g2p_hooks
# ===================================================================


class TestSetupG2pHooks:
    """Tests for Gerrit hook symlink creation."""

    def test_creates_all_hooks(self) -> None:
        docker = _make_docker_mock(exec_test_return=True)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=list(VALID_HOOKS),
        )
        enabled = setup_g2p_hooks(docker, CID, config)
        assert enabled == list(VALID_HOOKS)

    def test_creates_hooks_directory(self) -> None:
        docker = _make_docker_mock(exec_test_return=True)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created"],
        )
        setup_g2p_hooks(docker, CID, config)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any(f"mkdir -p {GERRIT_HOOKS_DIR}" in c for c in exec_calls)

    def test_symlink_target_points_to_venv_bin(self) -> None:
        docker = _make_docker_mock(exec_test_return=True)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created"],
        )
        setup_g2p_hooks(docker, CID, config)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        expected_target = f"{GERRIT_TOOLS_VENV_BIN}/patchset-created"
        expected_path = f"{GERRIT_HOOKS_DIR}/patchset-created"
        assert any(f"ln -sf {expected_target} {expected_path}" in c for c in exec_calls)

    def test_skips_missing_binary(self) -> None:
        docker = _make_docker_mock(exec_test_return=False)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created", "comment-added"],
        )
        enabled = setup_g2p_hooks(docker, CID, config)
        assert enabled == []

    def test_partial_availability(self) -> None:
        docker = _make_docker_mock()
        # exec_test call sequence:
        #   1. hooks.jar present?         -> True
        #   2. patchset-created binary?    -> True
        #   3. comment-added binary?       -> False
        docker.exec_test.side_effect = [True, True, False]
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created", "comment-added"],
        )
        enabled = setup_g2p_hooks(docker, CID, config)
        assert enabled == ["patchset-created"]

    def test_empty_hooks_list(self) -> None:
        docker = _make_docker_mock()
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=[],
        )
        enabled = setup_g2p_hooks(docker, CID, config)
        assert enabled == []

    def test_single_hook(self) -> None:
        docker = _make_docker_mock(exec_test_return=True)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["change-merged"],
        )
        enabled = setup_g2p_hooks(docker, CID, config)
        assert enabled == ["change-merged"]

    def test_sets_hook_ownership(self) -> None:
        docker = _make_docker_mock(exec_test_return=True)
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created"],
        )
        setup_g2p_hooks(docker, CID, config)
        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        hook_path = f"{GERRIT_HOOKS_DIR}/patchset-created"
        assert any(f"chown -h gerrit:gerrit {hook_path}" in c for c in exec_calls)


# ===================================================================
# setup_g2p_ssh
# ===================================================================


class TestSetupG2pSsh:
    """Tests for SSH configuration inside the container."""

    def test_provided_private_key(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nkeydata\n-----END OPENSSH PRIVATE KEY-----",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                0,
                stdout="ssh-ed25519 AAAApubkey gerrit-action-g2p",
                stderr="",
            )
            public_key, private_key = setup_g2p_ssh(docker, CID, config)

        assert public_key.startswith("ssh-ed25519")
        assert "BEGIN OPENSSH PRIVATE KEY" in private_key
        docker.cp.assert_called()

    def test_auto_generates_keypair(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.generate_ssh_keypair") as mock_keygen:
            mock_keygen.return_value = (
                "-----BEGIN KEY-----\nprivate\n-----END KEY-----",
                "ssh-ed25519 AAAAgenerated gerrit-action-g2p",
            )
            public_key, private_key = setup_g2p_ssh(docker, CID, config)

        assert "AAAAgenerated" in public_key
        assert "private" in private_key
        mock_keygen.assert_called_once()

    def test_keygen_failure_is_warning_not_error(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.generate_ssh_keypair") as mock_keygen:
            mock_keygen.side_effect = G2PSetupError("keygen failed")
            # Should not raise
            public_key, private_key = setup_g2p_ssh(docker, CID, config)

        assert public_key == ""
        assert private_key == ""

    def test_creates_ssh_directory(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="key",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                1,
                stdout="",
                stderr="",
            )
            setup_g2p_ssh(docker, CID, config)

        exec_calls = [c[0][1] for c in docker.exec_cmd.call_args_list]
        assert any(f"mkdir -p {SSH_DIR}" in c for c in exec_calls)
        assert any(f"chmod 700 {SSH_DIR}" in c for c in exec_calls)

    def test_provided_known_hosts(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        custom_hosts = "github.com ssh-rsa AAAAcustomkey"
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="key",
            github_known_hosts=custom_hosts,
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                1,
                stdout="",
                stderr="",
            )
            setup_g2p_ssh(docker, CID, config)

        # Should not call fetch_github_host_keys
        # Check that the custom hosts are used (via cp call for known_hosts)
        assert docker.cp.called

    @patch("g2p_setup.fetch_github_host_keys")
    def test_fetches_host_keys_when_not_provided(self, mock_fetch: MagicMock) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        mock_fetch.return_value = GITHUB_HOST_KEY_ED25519
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="key",
            github_known_hosts="",
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                1,
                stdout="",
                stderr="",
            )
            setup_g2p_ssh(docker, CID, config)

        mock_fetch.assert_called_once()

    def test_skips_known_hosts_when_already_present(self) -> None:
        docker = _make_docker_mock()
        # First exec_cmd calls will vary — we handle grep -q returning
        # "found" for github.com presence checks
        call_count = 0

        def side_effect(cid: str, cmd: str, **kwargs: Any) -> str:
            nonlocal call_count
            call_count += 1
            if "grep -q 'github.com'" in cmd and "known_hosts" in cmd:
                return "found"
            if "grep -q 'Host github.com'" in cmd:
                return "found"
            return "missing"

        docker.exec_cmd.side_effect = side_effect
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="key",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                1,
                stdout="",
                stderr="",
            )
            setup_g2p_ssh(docker, CID, config)

        # When github.com is already present, cp should only be called
        # for the private key (not for known_hosts or ssh config)
        assert docker.cp.call_count == 1

    def test_adds_ssh_client_config(self) -> None:
        docker = _make_docker_mock(exec_cmd_return="0")
        config = G2PConfig(
            enabled=True,
            github_owner="test",
            ssh_private_key="key",
            github_known_hosts="github.com ssh-ed25519 AAAA",
        )
        with patch("g2p_setup.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                ["ssh-keygen"],
                1,
                stdout="",
                stderr="",
            )
            setup_g2p_ssh(docker, CID, config)

        # Should add ssh config via append (cp call for config file)
        assert docker.cp.call_count >= 2


# ===================================================================
# setup_g2p (orchestration)
# ===================================================================


class TestSetupG2p:
    """Tests for the full G2P setup orchestration."""

    @patch("g2p_setup.setup_g2p_ssh")
    @patch("g2p_setup.setup_g2p_hooks")
    @patch("g2p_setup.setup_g2p_replication_symlink")
    @patch("g2p_setup.setup_g2p_replication_remote")
    @patch("g2p_setup.setup_g2p_ini")
    @patch("g2p_setup.setup_g2p_config_dir")
    def test_calls_all_steps_in_order(
        self,
        mock_config_dir: MagicMock,
        mock_ini: MagicMock,
        mock_repl_remote: MagicMock,
        mock_repl_symlink: MagicMock,
        mock_hooks: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        mock_ini.return_value = G2P_INI_PATH
        mock_repl_remote.return_value = True
        mock_hooks.return_value = ["patchset-created", "comment-added"]
        mock_ssh.return_value = ("ssh-ed25519 AAAAkey", "-----BEGIN KEY-----")

        docker = _make_docker_mock()
        config = G2PConfig(
            enabled=True,
            github_owner="onap",
            github_token="ghp_tok",
        )

        result = setup_g2p(config, docker, CID)

        # Verify call order
        mock_config_dir.assert_called_once_with(docker, CID)
        mock_ini.assert_called_once_with(docker, CID, config)
        mock_repl_remote.assert_called_once_with(docker, CID, config)
        mock_repl_symlink.assert_called_once_with(docker, CID)
        mock_hooks.assert_called_once_with(docker, CID, config)
        mock_ssh.assert_called_once_with(docker, CID, config)

        # Verify result
        assert result.config_path == G2P_INI_PATH
        assert result.hooks_enabled == ["patchset-created", "comment-added"]
        assert result.ssh_public_key == "ssh-ed25519 AAAAkey"
        assert result.replication_remote_configured is True

    @patch("g2p_setup.setup_g2p_ssh")
    @patch("g2p_setup.setup_g2p_hooks")
    @patch("g2p_setup.setup_g2p_replication_symlink")
    @patch("g2p_setup.setup_g2p_replication_remote")
    @patch("g2p_setup.setup_g2p_ini")
    @patch("g2p_setup.setup_g2p_config_dir")
    def test_result_reflects_no_replication(
        self,
        mock_config_dir: MagicMock,
        mock_ini: MagicMock,
        mock_repl_remote: MagicMock,
        mock_repl_symlink: MagicMock,
        mock_hooks: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        mock_ini.return_value = G2P_INI_PATH
        mock_repl_remote.return_value = False
        mock_hooks.return_value = []
        mock_ssh.return_value = ("", "")

        docker = _make_docker_mock()
        config = G2PConfig(enabled=True, github_owner="test")

        result = setup_g2p(config, docker, CID)
        assert result.replication_remote_configured is False
        assert result.hooks_enabled == []
        assert result.ssh_public_key == ""

    @patch("g2p_setup.setup_g2p_config_dir")
    def test_g2p_setup_error_propagates(self, mock_config_dir: MagicMock) -> None:
        mock_config_dir.side_effect = G2PSetupError("dir creation failed")
        docker = _make_docker_mock()
        config = G2PConfig(enabled=True, github_owner="test")

        with pytest.raises(G2PSetupError, match="dir creation failed"):
            setup_g2p(config, docker, CID)

    @patch("g2p_setup.setup_g2p_config_dir")
    def test_unexpected_error_wrapped_in_g2p_setup_error(
        self, mock_config_dir: MagicMock
    ) -> None:
        mock_config_dir.side_effect = RuntimeError("unexpected")
        docker = _make_docker_mock()
        config = G2PConfig(enabled=True, github_owner="test")

        with pytest.raises(G2PSetupError, match="G2P setup failed"):
            setup_g2p(config, docker, CID)


# ===================================================================
# Constants validation
# ===================================================================


class TestContainerPathConstants:
    """Verify container path constants are sensible."""

    def test_gerrit_home(self) -> None:
        assert G2P_CONFIG_DIR.startswith("/var/gerrit")

    def test_ini_path_under_config_dir(self) -> None:
        assert G2P_INI_PATH.startswith(G2P_CONFIG_DIR)
        assert G2P_INI_PATH.endswith(".ini")

    def test_symlink_under_config_dir(self) -> None:
        assert G2P_REPLICATION_SYMLINK.startswith(G2P_CONFIG_DIR)

    def test_hooks_dir(self) -> None:
        assert GERRIT_HOOKS_DIR == "/var/gerrit/hooks"

    def test_replication_config_path(self) -> None:
        assert GERRIT_REPLICATION_CONFIG == "/var/gerrit/etc/replication.config"

    def test_tools_venv_bin(self) -> None:
        assert GERRIT_TOOLS_VENV_BIN == "/opt/gerrit-tools/bin"

    def test_ssh_dir(self) -> None:
        assert SSH_DIR.endswith(".ssh")
