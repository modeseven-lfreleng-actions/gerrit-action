# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the docker_manager module."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest
from docker_manager import DockerManager
from errors import DockerError

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


# ---------------------------------------------------------------------------
# run_cmd
# ---------------------------------------------------------------------------


class TestRunCmd:
    """Tests for DockerManager.run_cmd."""

    def test_success(self) -> None:
        with patch("subprocess.run", return_value=_cp(stdout="ok\n")) as mock:
            dm = DockerManager()
            result = dm.run_cmd(["ps", "-q"])

        assert result.stdout == "ok\n"
        mock.assert_called_once()
        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "ps", "-q"]

    def test_nonzero_exit_raises(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stderr="not found"),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError, match="failed.*exit 1"):
                dm.run_cmd(["inspect", "missing"])

    def test_nonzero_exit_check_false(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stderr="not found"),
        ):
            dm = DockerManager()
            result = dm.run_cmd(["inspect", "missing"], check=False)
            assert result.returncode == 1

    def test_timeout_raises(self) -> None:
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError, match="timed out"):
                dm.run_cmd(["logs", "cid"], timeout=5)

    def test_docker_not_found_raises(self) -> None:
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError, match="not found"):
                dm.run_cmd(["ps"])

    def test_input_data_forwarded(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_cmd(["exec", "cid", "sh"], input_data="echo hello")

        _, kwargs = mock.call_args
        assert kwargs["input"] == "echo hello"

    def test_timeout_forwarded(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_cmd(["ps"], timeout=42)

        _, kwargs = mock.call_args
        assert kwargs["timeout"] == 42


# ---------------------------------------------------------------------------
# Docker error details
# ---------------------------------------------------------------------------


class TestDockerError:
    """Tests for DockerError exception attributes."""

    def test_attributes(self) -> None:
        err = DockerError("msg", returncode=127, stderr="oops")
        assert err.returncode == 127
        assert err.stderr == "oops"
        assert "oops" in str(err)

    def test_str_without_stderr(self) -> None:
        err = DockerError("just a message")
        assert str(err) == "just a message"


# ---------------------------------------------------------------------------
# Image management
# ---------------------------------------------------------------------------


class TestImageManagement:
    """Tests for image_exists, build_image, pull_image."""

    def test_image_exists_true(self) -> None:
        with patch("subprocess.run", return_value=_cp()):
            dm = DockerManager()
            assert dm.image_exists("my-image:latest") is True

    def test_image_exists_false(self) -> None:
        with patch("subprocess.run", return_value=_cp(returncode=1)):
            dm = DockerManager()
            assert dm.image_exists("missing:latest") is False

    def test_build_image_basic(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.build_image("tag:v1", "/path/to/ctx")

        cmd = mock.call_args[0][0]
        assert "build" in cmd
        assert "-t" in cmd
        assert "tag:v1" in cmd
        assert "/path/to/ctx" in cmd

    def test_build_image_with_build_args(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.build_image(
                "tag:v1",
                "/ctx",
                build_args={"VERSION": "1.0", "DEBUG": "true"},
            )

        cmd = mock.call_args[0][0]
        assert "--build-arg" in cmd
        # Both build args should be present
        arg_indices = [i for i, a in enumerate(cmd) if a == "--build-arg"]
        assert len(arg_indices) == 2

    def test_pull_image(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.pull_image("gerrit:3.13")

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "pull", "gerrit:3.13"]


# ---------------------------------------------------------------------------
# Container lifecycle
# ---------------------------------------------------------------------------


class TestContainerLifecycle:
    """Tests for run_container, stop, kill, remove."""

    def test_run_container_basic(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="abc123def456\n"),
        ) as mock:
            dm = DockerManager()
            cid = dm.run_container("img:v1", "my-container")

        assert cid == "abc123def456"
        cmd = mock.call_args[0][0]
        assert "run" in cmd
        assert "-d" in cmd
        assert "--name" in cmd
        assert "my-container" in cmd
        assert "img:v1" in cmd

    def test_run_container_with_ports(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", ports={8080: 80, 443: 443})

        cmd = mock.call_args[0][0]
        assert "-p" in cmd
        # Should have two port mappings
        port_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-p"]
        assert "8080:80" in port_args
        assert "443:443" in port_args

    def test_run_container_with_volumes(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container(
                "img",
                "c",
                volumes={"/host/data": "/container/data"},
            )

        cmd = mock.call_args[0][0]
        assert "-v" in cmd
        vol_idx = cmd.index("-v")
        assert cmd[vol_idx + 1] == "/host/data:/container/data"

    def test_run_container_with_ro_volumes(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container(
                "img",
                "c",
                volumes={"/host/ssh:ro": "/var/gerrit/ssh"},
            )

        cmd = mock.call_args[0][0]
        vol_idx = cmd.index("-v")
        assert cmd[vol_idx + 1] == "/host/ssh:/var/gerrit/ssh:ro"

    def test_run_container_with_env(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", env={"KEY": "VALUE"})

        cmd = mock.call_args[0][0]
        assert "-e" in cmd
        env_idx = cmd.index("-e")
        assert cmd[env_idx + 1] == "KEY=VALUE"

    def test_run_container_with_cidfile(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", cidfile="/tmp/cid")

        cmd = mock.call_args[0][0]
        assert "--cidfile" in cmd
        idx = cmd.index("--cidfile")
        assert cmd[idx + 1] == "/tmp/cid"

    def test_run_container_with_rm(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", remove=True)

        cmd = mock.call_args[0][0]
        assert "--rm" in cmd

    def test_run_container_no_detach(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="output"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", detach=False)

        cmd = mock.call_args[0][0]
        assert "-d" not in cmd

    def test_run_container_with_command_string(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", command="init")

        cmd = mock.call_args[0][0]
        assert cmd[-1] == "init"

    def test_run_container_with_command_list(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container("img", "c", command=["sh", "-c", "echo hi"])

        cmd = mock.call_args[0][0]
        assert cmd[-3:] == ["sh", "-c", "echo hi"]

    def test_run_container_with_extra_args(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="cid\n"),
        ) as mock:
            dm = DockerManager()
            dm.run_container(
                "img",
                "c",
                extra_args=["--network", "host"],
            )

        cmd = mock.call_args[0][0]
        assert "--network" in cmd
        assert "host" in cmd

    def test_stop(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.stop("abc123", timeout=15)

        cmd = mock.call_args[0][0]
        assert cmd[:2] == ["docker", "stop"]
        assert "--time" in cmd
        assert "15" in cmd
        assert "abc123" in cmd

    def test_kill(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.kill("abc123")

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "kill", "abc123"]

    def test_remove_basic(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.remove("abc123")

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "rm", "abc123"]

    def test_remove_force(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.remove("abc123", force=True)

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "rm", "-f", "abc123"]


# ---------------------------------------------------------------------------
# Container inspection
# ---------------------------------------------------------------------------


class TestContainerInspection:
    """Tests for inspect, container_state, container_ip, container_exists."""

    def test_inspect_plain(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout='[{"Id":"abc"}]\n'),
        ):
            dm = DockerManager()
            result = dm.inspect("abc123")
            assert '"Id"' in result

    def test_inspect_with_format(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="running\n"),
        ) as mock:
            dm = DockerManager()
            result = dm.inspect("abc123", "{{.State.Status}}")

        assert result == "running"
        cmd = mock.call_args[0][0]
        assert "-f" in cmd
        assert "{{.State.Status}}" in cmd

    def test_inspect_missing_container_raises(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stderr="No such container"),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError):
                dm.inspect("missing")

    def test_container_state(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="running\n"),
        ):
            dm = DockerManager()
            assert dm.container_state("abc") == "running"

    def test_container_ip(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="172.17.0.2\n"),
        ):
            dm = DockerManager()
            assert dm.container_ip("abc") == "172.17.0.2"

    def test_container_exists_true(self) -> None:
        with patch("subprocess.run", return_value=_cp()):
            dm = DockerManager()
            assert dm.container_exists("abc") is True

    def test_container_exists_false(self) -> None:
        with patch("subprocess.run", return_value=_cp(returncode=1)):
            dm = DockerManager()
            assert dm.container_exists("abc") is False


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


class TestLogs:
    """Tests for container_logs and grep_logs."""

    def test_container_logs_combines_stdout_stderr(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="line1\n", stderr="line2\n"),
        ):
            dm = DockerManager()
            logs = dm.container_logs("abc", tail=100)

        assert "line1" in logs
        assert "line2" in logs

    def test_container_logs_tail_parameter(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.container_logs("abc", tail=42)

        cmd = mock.call_args[0][0]
        assert "--tail" in cmd
        assert "42" in cmd

    def test_grep_logs_found(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(
                stdout="",
                stderr="2024-01-01 Loaded plugin pull-replication\n",
            ),
        ):
            dm = DockerManager()
            assert dm.grep_logs("abc", "Loaded plugin pull-replication") is True

    def test_grep_logs_not_found(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="some other log\n"),
        ):
            dm = DockerManager()
            assert dm.grep_logs("abc", "Loaded plugin pull-replication") is False

    def test_grep_logs_custom_tail(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.grep_logs("abc", "pattern", tail=5000)

        cmd = mock.call_args[0][0]
        assert "5000" in cmd


# ---------------------------------------------------------------------------
# Exec
# ---------------------------------------------------------------------------


class TestExec:
    """Tests for exec_cmd and exec_test."""

    def test_exec_cmd_success(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="  hello world  \n"),
        ) as mock:
            dm = DockerManager()
            result = dm.exec_cmd("abc", "echo hello world")

        assert result == "hello world"
        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "exec", "abc", "sh", "-c", "echo hello world"]

    def test_exec_cmd_failure_raises(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stderr="command not found"),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError):
                dm.exec_cmd("abc", "bad_command")

    def test_exec_cmd_check_false(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stdout="partial output"),
        ):
            dm = DockerManager()
            result = dm.exec_cmd("abc", "cmd", check=False)
            assert result == "partial output"

    def test_exec_cmd_timeout(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.exec_cmd("abc", "cmd", timeout=99)

        _, kwargs = mock.call_args
        assert kwargs["timeout"] == 99

    def test_exec_test_true(self) -> None:
        with patch("subprocess.run", return_value=_cp(returncode=0)):
            dm = DockerManager()
            assert dm.exec_test("abc", "-f /var/gerrit/etc/config") is True

    def test_exec_test_false(self) -> None:
        with patch("subprocess.run", return_value=_cp(returncode=1)):
            dm = DockerManager()
            assert dm.exec_test("abc", "-f /missing/file") is False

    def test_exec_test_splits_args(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.exec_test("abc", "-f /some/path")

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "exec", "abc", "test", "-f", "/some/path"]


# ---------------------------------------------------------------------------
# Copy
# ---------------------------------------------------------------------------


class TestCopy:
    """Tests for cp."""

    def test_cp(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.cp("abc:/var/gerrit/file", "/tmp/file")

        cmd = mock.call_args[0][0]
        assert cmd == ["docker", "cp", "abc:/var/gerrit/file", "/tmp/file"]


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------


class TestSystem:
    """Tests for ps and system_prune."""

    def test_ps_basic(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="CONTAINER ID  IMAGE\nabc  gerrit\n"),
        ):
            dm = DockerManager()
            result = dm.ps()
            assert "CONTAINER ID" in result

    def test_ps_with_filter(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.ps(filter_name="gerrit-")

        cmd = mock.call_args[0][0]
        assert "-f" in cmd
        assert "name=gerrit-" in cmd

    def test_ps_quiet(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.ps(quiet=True)

        cmd = mock.call_args[0][0]
        assert "-q" in cmd

    def test_system_prune_defaults(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.system_prune()

        cmd = mock.call_args[0][0]
        assert "system" in cmd
        assert "prune" in cmd
        assert "-f" in cmd

    def test_system_prune_with_filters(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.system_prune(filters=["until=24h", "label!=keep"])

        cmd = mock.call_args[0][0]
        filter_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--filter"]
        assert "until=24h" in filter_args
        assert "label!=keep" in filter_args

    def test_system_prune_no_force(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.system_prune(force=False)

        cmd = mock.call_args[0][0]
        assert "-f" not in cmd


# ---------------------------------------------------------------------------
# run_ephemeral
# ---------------------------------------------------------------------------


class TestRunEphemeral:
    """Tests for run_ephemeral."""

    def test_run_ephemeral_basic(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(stdout="output from init\n"),
        ) as mock:
            dm = DockerManager()
            result = dm.run_ephemeral("img:v1", command="init")

        assert "output from init" in result
        cmd = mock.call_args[0][0]
        assert "run" in cmd
        assert "--rm" in cmd
        assert "img:v1" in cmd
        assert "init" in cmd
        # Should NOT have -d since run_ephemeral is synchronous
        assert "-d" not in cmd

    def test_run_ephemeral_with_entrypoint(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_ephemeral("img", entrypoint="")

        cmd = mock.call_args[0][0]
        assert "--entrypoint" in cmd
        ep_idx = cmd.index("--entrypoint")
        assert cmd[ep_idx + 1] == ""

    def test_run_ephemeral_with_volumes(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_ephemeral(
                "img",
                volumes={"/h/git": "/var/gerrit/git"},
            )

        cmd = mock.call_args[0][0]
        assert "-v" in cmd
        vol_idx = cmd.index("-v")
        assert cmd[vol_idx + 1] == "/h/git:/var/gerrit/git"

    def test_run_ephemeral_with_env(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_ephemeral("img", env={"FOO": "bar"})

        cmd = mock.call_args[0][0]
        assert "-e" in cmd
        env_idx = cmd.index("-e")
        assert cmd[env_idx + 1] == "FOO=bar"

    def test_run_ephemeral_with_command_list(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_ephemeral("img", command=["sh", "-c", "echo done"])

        cmd = mock.call_args[0][0]
        assert cmd[-3:] == ["sh", "-c", "echo done"]

    def test_run_ephemeral_failure_raises(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_cp(returncode=1, stderr="init failed"),
        ):
            dm = DockerManager()
            with pytest.raises(DockerError, match="failed"):
                dm.run_ephemeral("img", command="init")

    def test_run_ephemeral_ro_volumes(self) -> None:
        with patch("subprocess.run", return_value=_cp()) as mock:
            dm = DockerManager()
            dm.run_ephemeral(
                "img",
                volumes={"/h/ssh:ro": "/var/gerrit/ssh"},
            )

        cmd = mock.call_args[0][0]
        vol_idx = cmd.index("-v")
        assert cmd[vol_idx + 1] == "/h/ssh:/var/gerrit/ssh:ro"
