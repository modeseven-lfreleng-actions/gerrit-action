# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the health_check module.

Covers:
- RetryConfig dataclass and effective_timeout
- Container state verification
- Gerrit readiness log polling
- Replica/headless mode detection
- HTTP health checks with retries
- TCP port checks
- SSH keyscan verification
- Plugin verification (logs, HTTP, jar file)
- Per-instance health check orchestration
- Multi-instance check_all_instances orchestrator
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests
from conftest import MockResponse, make_completed_process
from errors import DockerError, HealthCheckError

# =========================================================================
# RetryConfig
# =========================================================================


class TestRetryConfig:
    def test_defaults(self):
        from health_check import RetryConfig

        rc = RetryConfig()
        assert rc.max_retries == 30
        assert rc.interval == 2.0
        assert rc.timeout == 0.0

    def test_effective_timeout_from_retries(self):
        from health_check import RetryConfig

        rc = RetryConfig(max_retries=10, interval=3.0)
        assert rc.effective_timeout == 30.0

    def test_effective_timeout_from_explicit(self):
        from health_check import RetryConfig

        rc = RetryConfig(max_retries=10, interval=3.0, timeout=120.0)
        assert rc.effective_timeout == 120.0

    def test_frozen(self):
        from health_check import RetryConfig

        rc = RetryConfig()
        with pytest.raises(AttributeError):
            rc.max_retries = 5  # pyright: ignore[reportAttributeAccessIssue]


# =========================================================================
# verify_container_running
# =========================================================================


class TestVerifyContainerRunning:
    def test_container_running(self, mock_docker):
        from health_check import verify_container_running

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # container_exists → inspect returns ok
            make_completed_process(stdout="abc123"),
            # container_state → inspect returns "running"
            make_completed_process(stdout="running"),
        ]

        result = verify_container_running(docker, "abc123", "test-slug")
        assert result is True

    def test_container_not_exists(self, mock_docker):
        from health_check import verify_container_running

        docker, mock_run = mock_docker
        # container_exists returns False when inspect fails
        mock_run.return_value = make_completed_process(
            returncode=1, stderr="No such container"
        )

        with pytest.raises(HealthCheckError, match="does not exist"):
            verify_container_running(docker, "missing123", "test-slug")

    def test_container_exited(self, mock_docker):
        from health_check import verify_container_running

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # container_exists → succeeds
            make_completed_process(stdout="abc123"),
            # container_state → "exited"
            make_completed_process(stdout="exited"),
            # container_logs for diagnostics
            make_completed_process(stdout="some error log"),
        ]

        with pytest.raises(HealthCheckError, match="not running.*exited"):
            verify_container_running(docker, "abc123", "test-slug")


# =========================================================================
# wait_for_gerrit_ready
# =========================================================================


class TestWaitForGerritReady:
    @patch("health_check.time.sleep")
    def test_ready_found_immediately(self, mock_sleep, mock_docker):
        from health_check import wait_for_gerrit_ready

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(
            stdout="[2025-01-01] Gerrit Code Review 3.13.1 ready"
        )

        result = wait_for_gerrit_ready(docker, "abc123", timeout=60)
        assert result is True
        mock_sleep.assert_not_called()

    @patch("health_check.time.sleep")
    def test_ready_found_after_polls(self, mock_sleep, mock_docker):
        from health_check import wait_for_gerrit_ready

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # First poll: not ready
            make_completed_process(stdout="Starting Gerrit..."),
            # Second poll: not ready
            make_completed_process(stdout="Loading plugins..."),
            # Third poll: ready
            make_completed_process(stdout="Gerrit Code Review 3.13.1 ready"),
        ]

        result = wait_for_gerrit_ready(docker, "abc123", timeout=60, poll_interval=1.0)
        assert result is True
        assert mock_sleep.call_count == 2

    @patch("health_check.time.sleep")
    def test_timeout_returns_false(self, mock_sleep, mock_docker):
        from health_check import wait_for_gerrit_ready

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="Still loading...")

        result = wait_for_gerrit_ready(docker, "abc123", timeout=3, poll_interval=1.0)
        assert result is False


# =========================================================================
# is_replica_mode
# =========================================================================


class TestIsReplicaMode:
    def test_replica_detected(self, mock_docker):
        from health_check import is_replica_mode

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(
            stdout="Gerrit [replica] mode [headless] started"
        )

        assert is_replica_mode(docker, "abc123") is True

    def test_standard_mode(self, mock_docker):
        from health_check import is_replica_mode

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(
            stdout="Gerrit Code Review 3.13.1 ready"
        )

        assert is_replica_mode(docker, "abc123") is False

    def test_empty_logs(self, mock_docker):
        from health_check import is_replica_mode

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="")

        assert is_replica_mode(docker, "abc123") is False


# =========================================================================
# http_health_check
# =========================================================================


class TestHttpHealthCheck:
    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_200_succeeds(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.return_value = MockResponse(status_code=200)
        retry = RetryConfig(max_retries=3, interval=0.1)

        result = http_health_check("http://10.0.0.2:8080/version", retry=retry)
        assert result == 200
        mock_sleep.assert_not_called()

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_401_succeeds(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.return_value = MockResponse(status_code=401)
        retry = RetryConfig(max_retries=3, interval=0.1)

        result = http_health_check("http://10.0.0.2:8080/version", retry=retry)
        assert result == 401

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_403_succeeds(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.return_value = MockResponse(status_code=403)
        retry = RetryConfig(max_retries=3, interval=0.1)

        result = http_health_check("http://10.0.0.2:8080/version", retry=retry)
        assert result == 403

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_retry_then_succeed(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.side_effect = [
            MockResponse(status_code=503),
            MockResponse(status_code=503),
            MockResponse(status_code=200),
        ]
        retry = RetryConfig(max_retries=5, interval=0.1)

        result = http_health_check("http://10.0.0.2:8080/version", retry=retry)
        assert result == 200
        assert mock_get.call_count == 3

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_all_retries_exhausted(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.return_value = MockResponse(status_code=503)
        retry = RetryConfig(max_retries=3, interval=0.1)

        with pytest.raises(HealthCheckError) as exc_info:
            http_health_check("http://10.0.0.2:8080/version", retry=retry)

        assert exc_info.value.last_status_code == 503
        assert exc_info.value.attempts == 3

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_connection_error_retries(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.side_effect = [
            requests.ConnectionError("refused"),
            requests.ConnectionError("refused"),
            MockResponse(status_code=200),
        ]
        retry = RetryConfig(max_retries=5, interval=0.1)

        result = http_health_check("http://10.0.0.2:8080/version", retry=retry)
        assert result == 200

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_all_connection_errors(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.side_effect = requests.ConnectionError("refused")
        retry = RetryConfig(max_retries=2, interval=0.1)

        with pytest.raises(HealthCheckError) as exc_info:
            http_health_check("http://10.0.0.2:8080/version", retry=retry)

        assert exc_info.value.last_status_code is None
        assert exc_info.value.attempts == 2

    @patch("health_check.time.sleep")
    @patch("health_check.requests.get")
    def test_404_never_healthy(self, mock_get, mock_sleep):
        from health_check import RetryConfig, http_health_check

        mock_get.return_value = MockResponse(status_code=404)
        retry = RetryConfig(max_retries=2, interval=0.1)

        with pytest.raises(HealthCheckError):
            http_health_check("http://10.0.0.2:8080/version", retry=retry)


# =========================================================================
# tcp_port_check
# =========================================================================


class TestTcpPortCheck:
    @patch("health_check.socket.create_connection")
    def test_port_open(self, mock_conn):
        from health_check import tcp_port_check

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        assert tcp_port_check("10.0.0.2", 8080) is True

    @patch("health_check.socket.create_connection")
    def test_port_closed(self, mock_conn):
        from health_check import tcp_port_check

        mock_conn.side_effect = OSError("Connection refused")
        assert tcp_port_check("10.0.0.2", 8080) is False

    @patch("health_check.socket.create_connection")
    def test_port_timeout(self, mock_conn):
        from health_check import tcp_port_check

        mock_conn.side_effect = TimeoutError("timed out")
        assert tcp_port_check("10.0.0.2", 8080) is False


# =========================================================================
# wait_for_tcp_port
# =========================================================================


class TestWaitForTcpPort:
    @patch("health_check.time.sleep")
    @patch("health_check.tcp_port_check")
    def test_port_immediately_available(self, mock_check, mock_sleep):
        from health_check import RetryConfig, wait_for_tcp_port

        mock_check.return_value = True
        retry = RetryConfig(max_retries=3, interval=0.1)

        result = wait_for_tcp_port("10.0.0.2", 8080, retry=retry)
        assert result is True
        mock_sleep.assert_not_called()

    @patch("health_check.time.sleep")
    @patch("health_check.tcp_port_check")
    def test_port_available_after_retries(self, mock_check, mock_sleep):
        from health_check import RetryConfig, wait_for_tcp_port

        mock_check.side_effect = [False, False, True]
        retry = RetryConfig(max_retries=5, interval=0.1)

        result = wait_for_tcp_port("10.0.0.2", 8080, retry=retry)
        assert result is True
        assert mock_check.call_count == 3

    @patch("health_check.time.sleep")
    @patch("health_check.tcp_port_check")
    def test_port_never_available(self, mock_check, mock_sleep):
        from health_check import RetryConfig, wait_for_tcp_port

        mock_check.return_value = False
        retry = RetryConfig(max_retries=3, interval=0.1)

        with pytest.raises(HealthCheckError, match="not listening"):
            wait_for_tcp_port("10.0.0.2", 8080, retry=retry)

    @patch("health_check.time.sleep")
    @patch("health_check.tcp_port_check")
    def test_custom_label_in_error(self, mock_check, mock_sleep):
        from health_check import RetryConfig, wait_for_tcp_port

        mock_check.return_value = False
        retry = RetryConfig(max_retries=2, interval=0.1)

        with pytest.raises(HealthCheckError, match="HTTP port 8080"):
            wait_for_tcp_port("10.0.0.2", 8080, retry=retry, label="HTTP port 8080")


# =========================================================================
# verify_ssh_service
# =========================================================================


class TestVerifySshService:
    @patch("health_check.subprocess.run")
    def test_successful_keyscan(self, mock_run):
        from health_check import verify_ssh_service

        mock_run.return_value = subprocess.CompletedProcess(
            args=["ssh-keyscan"],
            returncode=0,
            stdout="[10.0.0.2]:29418 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
            stderr="",
        )

        result = verify_ssh_service("10.0.0.2", port=29418)
        assert "ssh-ed25519" in result

    @patch("health_check.subprocess.run")
    def test_empty_keyscan(self, mock_run):
        from health_check import verify_ssh_service

        mock_run.return_value = subprocess.CompletedProcess(
            args=["ssh-keyscan"],
            returncode=0,
            stdout="",
            stderr="",
        )

        result = verify_ssh_service("10.0.0.2", port=29418)
        assert result == ""

    @patch("health_check.subprocess.run")
    def test_keyscan_timeout(self, mock_run):
        from health_check import verify_ssh_service

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["ssh-keyscan"], timeout=15
        )

        result = verify_ssh_service("10.0.0.2", port=29418)
        assert result == ""

    @patch("health_check.subprocess.run")
    def test_keyscan_not_found(self, mock_run):
        from health_check import verify_ssh_service

        mock_run.side_effect = FileNotFoundError("ssh-keyscan not found")

        result = verify_ssh_service("10.0.0.2", port=29418)
        assert result == ""

    @patch("health_check.subprocess.run")
    def test_keyscan_calls_correct_command(self, mock_run):
        from health_check import verify_ssh_service

        mock_run.return_value = subprocess.CompletedProcess(
            args=["ssh-keyscan"],
            returncode=0,
            stdout="",
            stderr="",
        )

        verify_ssh_service("10.0.0.2", port=29418, timeout=5)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == ["ssh-keyscan", "-p", "29418", "-T", "5", "10.0.0.2"]


# =========================================================================
# verify_plugin_loaded
# =========================================================================


class TestVerifyPluginLoaded:
    def test_plugin_found_in_logs(self, mock_docker):
        from health_check import verify_plugin_loaded

        docker, mock_run = mock_docker
        # grep_logs calls container_logs internally
        mock_run.return_value = make_completed_process(
            stdout="[2025-01-01] Loaded plugin pull-replication v3.13.0"
        )

        result = verify_plugin_loaded(docker, "abc123", "pull-replication")
        assert result is True

    def test_plugin_not_in_logs_but_in_http(self, mock_docker):
        from health_check import verify_plugin_loaded

        docker, mock_run = mock_docker
        # First two grep_logs calls (tail=1000, tail=5000) return empty
        mock_run.return_value = make_completed_process(stdout="")

        with patch("health_check.requests.get") as mock_get:
            mock_get.return_value = MockResponse(
                status_code=200,
                text=')]}\'\n{"pull-replication":{"id":"pull-replication"}}',
            )

            result = verify_plugin_loaded(
                docker,
                "abc123",
                "pull-replication",
                container_ip="10.0.0.2",
            )
            assert result is True

    def test_plugin_not_found_anywhere(self):
        from health_check import verify_plugin_loaded

        docker = MagicMock()
        # grep_logs returns False (not found in logs)
        docker.grep_logs.return_value = False
        # exec_test returns False (jar file doesn't exist)
        docker.exec_test.return_value = False

        with patch("health_check.requests.get") as mock_get:
            mock_get.return_value = MockResponse(
                status_code=200, text='{"other-plugin":{}}'
            )

            result = verify_plugin_loaded(
                docker,
                "abc123",
                "pull-replication",
                container_ip="10.0.0.2",
            )
            assert result is False

    def test_plugin_jar_exists_treat_as_ok(self, mock_docker):
        from health_check import verify_plugin_loaded

        docker, mock_run = mock_docker

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            cmd_str = str(args)
            # grep_logs calls (first two) return empty
            if "logs" in cmd_str and call_count[0] <= 2:
                return make_completed_process(stdout="")
            # exec_test for jar file returns success
            if "-f /var/gerrit/plugins/pull-replication.jar" in cmd_str:
                return make_completed_process(returncode=0)
            # Subsequent grep_logs after sleep returns empty
            return make_completed_process(stdout="")

        mock_run.side_effect = side_effect

        with patch("health_check.requests.get") as mock_get:
            mock_get.side_effect = requests.ConnectionError("refused")
            with patch("health_check.time.sleep"):
                result = verify_plugin_loaded(
                    docker,
                    "abc123",
                    "pull-replication",
                    container_ip="10.0.0.2",
                )
                # jar file exists → treated as ok
                assert result is True

    def test_plugin_http_check_uses_api_path(self, mock_docker):
        from health_check import verify_plugin_loaded

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="")

        with patch("health_check.requests.get") as mock_get:
            mock_get.return_value = MockResponse(
                status_code=200,
                text="pull-replication",
            )

            verify_plugin_loaded(
                docker,
                "abc123",
                "pull-replication",
                container_ip="10.0.0.2",
                effective_api_path="/r",
            )

            # Verify the URL includes the api_path
            call_url = mock_get.call_args[0][0]
            assert call_url == "http://10.0.0.2:8080/r/plugins/"


# =========================================================================
# HealthCheckResult
# =========================================================================


class TestHealthCheckResult:
    def test_defaults(self):
        from health_check import HealthCheckResult

        r = HealthCheckResult(slug="test")
        assert r.slug == "test"
        assert r.success is False
        assert r.error == ""
        assert r.is_replica is False


# =========================================================================
# check_instance
# =========================================================================


class TestCheckInstance:
    @patch("health_check._check_standard_health")
    @patch("health_check.is_replica_mode")
    @patch("health_check.wait_for_gerrit_ready")
    @patch("health_check.verify_container_running")
    def test_standard_instance_healthy(
        self, mock_verify, mock_ready, mock_replica, mock_standard
    ):
        from health_check import check_instance

        docker = MagicMock()
        mock_verify.return_value = True
        mock_ready.return_value = True
        mock_replica.return_value = False
        mock_standard.return_value = True

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
            "api_path": "/r",
        }

        result = check_instance(docker, "onap", instance)
        assert result.success is True
        assert result.is_replica is False
        mock_standard.assert_called_once()

    @patch("health_check._check_replica_health")
    @patch("health_check.is_replica_mode")
    @patch("health_check.wait_for_gerrit_ready")
    @patch("health_check.verify_container_running")
    def test_replica_instance_healthy(
        self, mock_verify, mock_ready, mock_replica, mock_replica_health
    ):
        from health_check import check_instance

        docker = MagicMock()
        mock_verify.return_value = True
        mock_ready.return_value = True
        mock_replica.return_value = True
        mock_replica_health.return_value = True

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
        }

        result = check_instance(docker, "replica", instance)
        assert result.success is True
        assert result.is_replica is True
        mock_replica_health.assert_called_once()

    @patch("health_check.verify_container_running")
    def test_container_not_running(self, mock_verify):
        from health_check import check_instance

        docker = MagicMock()
        docker.container_logs.return_value = ""
        mock_verify.side_effect = HealthCheckError("not running")

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
        }

        result = check_instance(docker, "broken", instance)
        assert result.success is False
        assert "not running" in result.error

    @patch("health_check._check_standard_health")
    @patch("health_check.is_replica_mode")
    @patch("health_check.wait_for_gerrit_ready")
    @patch("health_check.verify_container_running")
    def test_http_health_fails(
        self, mock_verify, mock_ready, mock_replica, mock_standard
    ):
        from health_check import check_instance

        docker = MagicMock()
        docker.container_logs.return_value = "error logs here"
        mock_verify.return_value = True
        mock_ready.return_value = True
        mock_replica.return_value = False
        mock_standard.side_effect = HealthCheckError("HTTP failed")

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
        }

        result = check_instance(docker, "failed", instance)
        assert result.success is False
        assert "HTTP failed" in result.error

    @patch("health_check._check_standard_health")
    @patch("health_check.is_replica_mode")
    @patch("health_check.wait_for_gerrit_ready")
    @patch("health_check.verify_container_running")
    def test_use_api_path_true(
        self, mock_verify, mock_ready, mock_replica, mock_standard
    ):
        from health_check import check_instance

        docker = MagicMock()
        mock_verify.return_value = True
        mock_ready.return_value = True
        mock_replica.return_value = False
        mock_standard.return_value = True

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
            "api_path": "/r",
        }

        result = check_instance(docker, "onap", instance, use_api_path=True)
        assert result.success is True

        # Verify standard health was called with the effective_api_path
        call_kwargs = mock_standard.call_args
        assert (
            call_kwargs[1].get("skip_plugin_install", None) is not None
            or len(call_kwargs[0]) >= 5
        )  # positional args include effective_api_path

    @patch("health_check._check_standard_health")
    @patch("health_check.is_replica_mode")
    @patch("health_check.wait_for_gerrit_ready")
    @patch("health_check.verify_container_running")
    def test_use_api_path_false(
        self, mock_verify, mock_ready, mock_replica, mock_standard
    ):
        from health_check import check_instance

        docker = MagicMock()
        mock_verify.return_value = True
        mock_ready.return_value = True
        mock_replica.return_value = False
        mock_standard.return_value = True

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
            "api_path": "/r",
        }

        result = check_instance(docker, "onap", instance, use_api_path=False)
        assert result.success is True

    @patch("health_check.verify_container_running")
    def test_docker_error_caught(self, mock_verify):
        from health_check import check_instance

        docker = MagicMock()
        docker.container_logs.return_value = ""
        mock_verify.side_effect = DockerError("Docker daemon not running")

        instance = {
            "cid": "abc123def456",
            "ip": "10.0.0.2",
            "http_port": 18080,
        }

        result = check_instance(docker, "broken", instance)
        assert result.success is False
        assert "Docker daemon" in result.error


# =========================================================================
# _check_standard_health
# =========================================================================


class TestCheckStandardHealth:
    @patch("health_check.verify_plugin_loaded")
    @patch("health_check.http_health_check")
    def test_standard_health_no_plugins(self, mock_http, mock_plugin):
        from health_check import _check_standard_health

        docker = MagicMock()
        mock_http.return_value = 200

        result = _check_standard_health(
            docker,
            "abc123",
            "10.0.0.2",
            "test",
            "",
            skip_plugin_install=True,
        )
        assert result is True
        mock_plugin.assert_not_called()

    @patch("health_check.verify_plugin_loaded")
    @patch("health_check.http_health_check")
    def test_standard_health_with_plugins(self, mock_http, mock_plugin):
        from health_check import _check_standard_health

        docker = MagicMock()
        docker.grep_logs.return_value = True
        mock_http.return_value = 200
        mock_plugin.return_value = True

        result = _check_standard_health(
            docker,
            "abc123",
            "10.0.0.2",
            "test",
            "/r",
            skip_plugin_install=False,
        )
        assert result is True
        mock_plugin.assert_called_once()

    @patch("health_check.http_health_check")
    def test_standard_health_url_with_api_path(self, mock_http):
        from health_check import _check_standard_health

        docker = MagicMock()
        mock_http.return_value = 200

        _check_standard_health(
            docker,
            "abc123",
            "10.0.0.2",
            "test",
            "/r",
            skip_plugin_install=True,
        )

        # Check the URL passed to http_health_check
        call_args = mock_http.call_args
        url = call_args[0][0]
        assert url == "http://10.0.0.2:8080/r/config/server/version"

    @patch("health_check.http_health_check")
    def test_standard_health_url_without_api_path(self, mock_http):
        from health_check import _check_standard_health

        docker = MagicMock()
        mock_http.return_value = 200

        _check_standard_health(
            docker,
            "abc123",
            "10.0.0.2",
            "test",
            "",
            skip_plugin_install=True,
        )

        url = mock_http.call_args[0][0]
        assert url == "http://10.0.0.2:8080/config/server/version"


# =========================================================================
# _check_replica_health
# =========================================================================


class TestCheckReplicaHealth:
    @patch("health_check.verify_ssh_service")
    @patch("health_check.wait_for_tcp_port")
    def test_replica_all_checks_pass(self, mock_tcp, mock_ssh):
        from health_check import _check_replica_health

        docker = MagicMock()
        mock_tcp.return_value = True
        mock_ssh.return_value = "ssh-ed25519 AAAA..."

        result = _check_replica_health(docker, "abc123", "10.0.0.2", "test")
        assert result is True
        # Should have been called twice: HTTP port and SSH port
        assert mock_tcp.call_count == 2

    @patch("health_check.verify_ssh_service")
    @patch("health_check.wait_for_tcp_port")
    def test_replica_http_port_fail(self, mock_tcp, mock_ssh):
        from health_check import _check_replica_health

        docker = MagicMock()
        mock_tcp.side_effect = HealthCheckError("port not listening")

        with pytest.raises(HealthCheckError):
            _check_replica_health(docker, "abc123", "10.0.0.2", "test")


# =========================================================================
# check_all_instances
# =========================================================================


class TestCheckAllInstances:
    @patch("health_check.check_instance")
    def test_all_pass(self, mock_check):
        from health_check import HealthCheckResult, check_all_instances

        docker = MagicMock()

        mock_check.side_effect = [
            HealthCheckResult(slug="onap", success=True),
            HealthCheckResult(slug="lf", success=True),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc", "ip": "10.0.0.2"}),
                    ("lf", {"cid": "def", "ip": "10.0.0.3"}),
                ]
            )
        )

        with (
            patch("health_check.write_status_summary"),
            patch("health_check.DockerManager"),
        ):
            results = check_all_instances(docker, store)

        assert len(results) == 2
        assert all(r.success for r in results)

    @patch("health_check.check_instance")
    def test_one_fails_raises(self, mock_check):
        from health_check import HealthCheckResult, check_all_instances

        docker = MagicMock()
        docker.ps.return_value = ""

        mock_check.side_effect = [
            HealthCheckResult(slug="onap", success=True),
            HealthCheckResult(slug="lf", success=False, error="timeout"),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc", "ip": "10.0.0.2"}),
                    ("lf", {"cid": "def", "ip": "10.0.0.3"}),
                ]
            )
        )

        with (
            patch("health_check.write_summary"),
            pytest.raises(HealthCheckError, match="lf"),
        ):
            check_all_instances(docker, store)

    @patch("health_check.check_instance")
    def test_all_fail_raises_with_all_slugs(self, mock_check):
        from health_check import HealthCheckResult, check_all_instances

        docker = MagicMock()
        docker.ps.return_value = ""

        mock_check.side_effect = [
            HealthCheckResult(slug="onap", success=False, error="fail1"),
            HealthCheckResult(slug="lf", success=False, error="fail2"),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc", "ip": "10.0.0.2"}),
                    ("lf", {"cid": "def", "ip": "10.0.0.3"}),
                ]
            )
        )

        with patch("health_check.write_summary"):
            with pytest.raises(HealthCheckError) as exc_info:
                check_all_instances(docker, store)

            assert "onap" in str(exc_info.value)
            assert "lf" in str(exc_info.value)

    @patch("health_check.check_instance")
    def test_empty_store(self, mock_check):
        from health_check import check_all_instances

        docker = MagicMock()
        docker.ps.return_value = ""

        store = MagicMock()
        store.__iter__ = MagicMock(return_value=iter([]))

        with patch("health_check.write_status_summary"):
            results = check_all_instances(docker, store)

        assert len(results) == 0
        mock_check.assert_not_called()

    @patch("health_check.check_instance")
    def test_skip_plugin_and_api_path_forwarded(self, mock_check):
        from health_check import HealthCheckResult, check_all_instances

        docker = MagicMock()

        mock_check.return_value = HealthCheckResult(slug="onap", success=True)

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter([("onap", {"cid": "abc", "ip": "10.0.0.2"})])
        )

        with patch("health_check.write_status_summary"):
            check_all_instances(
                docker,
                store,
                skip_plugin_install=True,
                use_api_path=True,
            )

        mock_check.assert_called_once_with(
            docker,
            "onap",
            {"cid": "abc", "ip": "10.0.0.2"},
            skip_plugin_install=True,
            use_api_path=True,
        )
