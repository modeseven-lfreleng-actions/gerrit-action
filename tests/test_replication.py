# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the replication module.

Covers:
- TriggerResult, VerificationResult, ReplicationSnapshot dataclasses
- _StabilityTracker: steady-state detection
- check_replication_config: file existence check
- show_replication_config: config reading with comment filtering
- check_secure_config: secure.config existence and section display
- check_replication_errors: error pattern detection in logs
- get_completed_repo_count: unique repo counting from log
- get_log_line_count: log line counting for change detection
- get_disk_usage_kb: raw KB disk usage for precise comparison
- take_snapshot: point-in-time replication state capture
- check_pull_replication_log: completion status analysis
- count_repositories: bare git repo counting
- get_git_disk_usage_mb / get_git_disk_usage_human: disk usage
- check_replication_has_content: content size thresholds (per-repo)
- list_repositories: directory listing
- show_pull_replication_log: log tail retrieval
- trigger_replication: per-instance trigger orchestration
- wait_for_replication: polling loop with timeout + steady-state
- verify_single_instance: full verification flow
- trigger_all_instances / verify_all_instances: multi-instance orchestrators
- _parse_int: digit extraction helper
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from conftest import make_completed_process
from errors import DockerError, ReplicationError

# =========================================================================
# Dataclasses
# =========================================================================


class TestTriggerResult:
    def test_defaults(self):
        from replication import TriggerResult

        r = TriggerResult(slug="onap")
        assert r.slug == "onap"
        assert r.success is False
        assert r.replication_started is False
        assert r.error == ""
        assert r.repo_count == 0
        assert r.expected_count == 0

    def test_fields_settable(self):
        from replication import TriggerResult

        r = TriggerResult(slug="test")
        r.success = True
        r.replication_started = True
        r.repo_count = 42
        r.expected_count = 50
        r.error = "some issue"
        assert r.success is True
        assert r.repo_count == 42


class TestVerificationResult:
    def test_defaults(self):
        from replication import VerificationResult

        r = VerificationResult(slug="onap")
        assert r.slug == "onap"
        assert r.success is False
        assert r.error == ""
        assert r.repo_count == 0
        assert r.expected_count == 0
        assert r.completed_count == 0
        assert r.disk_usage == ""
        assert r.disk_usage_mb == 0

    def test_fields_settable(self):
        from replication import VerificationResult

        r = VerificationResult(slug="test")
        r.success = True
        r.repo_count = 36
        r.expected_count = 36
        r.completed_count = 36
        r.disk_usage = "86M"
        r.disk_usage_mb = 86
        assert r.success is True


# =========================================================================
# ReplicationSnapshot and _StabilityTracker
# =========================================================================


class TestReplicationSnapshot:
    def test_defaults(self):
        from replication import ReplicationSnapshot

        snap = ReplicationSnapshot()
        assert snap.timestamp == 0.0
        assert snap.completed_count == 0
        assert snap.disk_usage_kb == 0
        assert snap.log_line_count == 0
        assert snap.repo_count == 0

    def test_is_same_as_identical(self):
        from replication import ReplicationSnapshot

        a = ReplicationSnapshot(
            timestamp=1.0,
            completed_count=10,
            disk_usage_kb=500,
            log_line_count=100,
            repo_count=10,
        )
        b = ReplicationSnapshot(
            timestamp=2.0,
            completed_count=10,
            disk_usage_kb=500,
            log_line_count=100,
            repo_count=10,
        )
        # Timestamps differ but observable state is the same
        assert a.is_same_as(b)

    def test_is_same_as_different_completed(self):
        from replication import ReplicationSnapshot

        a = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=100, repo_count=10
        )
        b = ReplicationSnapshot(
            completed_count=11, disk_usage_kb=500, log_line_count=100, repo_count=10
        )
        assert not a.is_same_as(b)

    def test_is_same_as_different_disk(self):
        from replication import ReplicationSnapshot

        a = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=100, repo_count=10
        )
        b = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=600, log_line_count=100, repo_count=10
        )
        assert not a.is_same_as(b)

    def test_is_same_as_different_log_lines(self):
        from replication import ReplicationSnapshot

        a = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=100, repo_count=10
        )
        b = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=120, repo_count=10
        )
        assert not a.is_same_as(b)

    def test_is_same_as_different_repo_count(self):
        from replication import ReplicationSnapshot

        a = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=100, repo_count=10
        )
        b = ReplicationSnapshot(
            completed_count=10, disk_usage_kb=500, log_line_count=100, repo_count=12
        )
        assert not a.is_same_as(b)


class TestStabilityTracker:
    def test_not_stable_with_no_snapshots(self):
        from replication import _StabilityTracker

        tracker = _StabilityTracker(window=30)
        assert not tracker.is_stable(time.time())

    def test_not_stable_after_single_snapshot(self):
        from replication import ReplicationSnapshot, _StabilityTracker

        tracker = _StabilityTracker(window=30)
        snap = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap)
        # Right after first snapshot, only 0 seconds have passed
        assert not tracker.is_stable(100.0)

    def test_becomes_stable_after_window(self):
        from replication import ReplicationSnapshot, _StabilityTracker

        tracker = _StabilityTracker(window=30)
        snap = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap)
        # Simulate time passing with identical state
        snap2 = ReplicationSnapshot(
            timestamp=131.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap2)
        # 31 seconds since last change
        assert tracker.is_stable(131.0)

    def test_resets_on_state_change(self):
        from replication import ReplicationSnapshot, _StabilityTracker

        tracker = _StabilityTracker(window=30)
        snap1 = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap1)
        # Wait 20 seconds, same state
        snap2 = ReplicationSnapshot(
            timestamp=120.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap2)
        assert not tracker.is_stable(120.0)  # only 20s, need 30

        # State changes at t=125
        snap3 = ReplicationSnapshot(
            timestamp=125.0,
            completed_count=6,
            disk_usage_kb=200,
            log_line_count=55,
            repo_count=6,
        )
        tracker.update(snap3)
        # Clock resets; at t=150 only 25s since change
        assert not tracker.is_stable(150.0)
        # At t=156, 31s since change
        assert tracker.is_stable(156.0)

    def test_seconds_stable_property(self):
        from replication import ReplicationSnapshot, _StabilityTracker

        tracker = _StabilityTracker(window=30)
        assert tracker.seconds_stable == 0.0

        snap1 = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap1)
        assert tracker.seconds_stable == 0.0

        # Same state at t=110
        snap2 = ReplicationSnapshot(
            timestamp=110.0,
            completed_count=5,
            disk_usage_kb=100,
            log_line_count=50,
            repo_count=5,
        )
        tracker.update(snap2)
        assert tracker.seconds_stable == 10.0


# =========================================================================
# _parse_int
# =========================================================================


class TestParseInt:
    def test_plain_number(self):
        from replication import _parse_int

        assert _parse_int("42") == 42

    def test_number_with_whitespace(self):
        from replication import _parse_int

        assert _parse_int("  42  \n") == 42

    def test_number_with_trailing_text(self):
        from replication import _parse_int

        assert _parse_int("42 repos") == 42

    def test_empty_string(self):
        from replication import _parse_int

        assert _parse_int("") == 0

    def test_no_digits(self):
        from replication import _parse_int

        assert _parse_int("no numbers here") == 0

    def test_mixed_digits(self):
        from replication import _parse_int

        # Strips non-digit chars, so "1a2b3" → "123"
        assert _parse_int("1a2b3") == 123

    def test_zero(self):
        from replication import _parse_int

        assert _parse_int("0") == 0


# =========================================================================
# check_replication_config
# =========================================================================


class TestCheckReplicationConfig:
    def test_config_exists(self, mock_docker):
        from replication import check_replication_config

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(returncode=0)

        assert check_replication_config(docker, "abc123") is True

    def test_config_missing(self, mock_docker):
        from replication import check_replication_config

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(returncode=1)

        assert check_replication_config(docker, "abc123") is False


# =========================================================================
# show_replication_config
# =========================================================================


class TestShowReplicationConfig:
    def test_returns_filtered_content(self, mock_docker):
        from replication import show_replication_config

        docker, mock_run = mock_docker
        config_text = (
            "# Comment line\n"
            '[remote "origin"]\n'
            "  url = https://gerrit.example.org/${name}.git\n"
            "\n"
            "# Another comment\n"
            "  fetch = +refs/*:refs/*\n"
        )
        mock_run.return_value = make_completed_process(stdout=config_text)

        result = show_replication_config(docker, "abc123")
        lines = result.splitlines()
        # Comments and blanks should be filtered out
        assert all(not line.strip().startswith("#") for line in lines)
        assert all(line.strip() != "" for line in lines)
        assert '[remote "origin"]' in result
        assert "url = " in result
        assert "fetch = " in result

    def test_returns_empty_on_error(self, mock_docker):
        from replication import show_replication_config

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        result = show_replication_config(docker, "abc123")
        assert result == ""

    def test_returns_empty_for_empty_file(self, mock_docker):
        from replication import show_replication_config

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="")

        result = show_replication_config(docker, "abc123")
        assert result == ""


# =========================================================================
# check_secure_config
# =========================================================================


class TestCheckSecureConfig:
    def test_config_exists_with_sections(self, mock_docker):
        from replication import check_secure_config

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test for file existence: success
            make_completed_process(returncode=0),
            # grep sections
            make_completed_process(stdout='[remote "origin"]\n[http]\n'),
        ]

        assert check_secure_config(docker, "abc123") is True

    def test_config_missing(self, mock_docker):
        from replication import check_secure_config

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(returncode=1)

        assert check_secure_config(docker, "abc123") is False


# =========================================================================
# check_replication_errors
# =========================================================================


class TestCheckReplicationErrors:
    def test_no_errors(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test for log file: exists
            make_completed_process(returncode=0),
            # grep for errors: empty (no matches)
            make_completed_process(stdout=""),
            # container_logs: no error patterns
            make_completed_process(
                stdout="INFO: Replication from origin completed successfully"
            ),
        ]

        assert check_replication_errors(docker, "abc123") is False

    def test_error_in_pull_replication_log(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file exists
            make_completed_process(returncode=0),
            # grep for errors: found
            make_completed_process(stdout="ERROR: Cannot replicate from origin"),
        ]

        assert check_replication_errors(docker, "abc123") is True

    def test_transport_exception_in_log(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file exists
            make_completed_process(returncode=0),
            # grep: found TransportException
            make_completed_process(stdout="TransportException: Connection timed out"),
        ]

        assert check_replication_errors(docker, "abc123") is True

    def test_error_in_container_logs(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file does NOT exist
            make_completed_process(returncode=1),
            # container_logs: has replication-specific error patterns
            make_completed_process(
                stdout="Cannot replicate from origin\n"
                "pull-replication: error fetching refs\n"
            ),
        ]

        assert check_replication_errors(docker, "abc123") is True

    def test_email_error_not_flagged_as_replication_error(self, mock_docker):
        """Email delivery failures must NOT be flagged as replication errors.

        Gerrit logs 'Connection refused' and 'ERROR' when the SMTP server
        is unreachable.  These are completely unrelated to replication and
        caused false positives in CI (see deployment failure 2026-02-22).
        """
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file does NOT exist (replication hasn't started)
            make_completed_process(returncode=1),
            # container_logs: email error — NOT a replication problem
            make_completed_process(
                stdout=(
                    "[2026-02-22T09:42:22.981Z] [HTTP POST /r/a/accounts/1000001/sshkeys] "
                    "ERROR com.google.gerrit.server.restapi.account.AddSshKey : "
                    "Cannot send SSH key added message to user@example.com\n"
                    "com.google.gerrit.exceptions.EmailException: Mail Error: Connection refused\n"
                    "Caused by: java.net.ConnectException: Connection refused\n"
                ),
            ),
        ]

        # Must return False — email errors are not replication errors
        assert check_replication_errors(docker, "abc123") is False

    def test_generic_permission_denied_not_flagged(self, mock_docker):
        """Generic 'Permission denied' in container logs should not trigger.

        Only replication-specific patterns should match container logs.
        """
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file does NOT exist
            make_completed_process(returncode=1),
            # container_logs: generic permission denied (not replication)
            make_completed_process(
                stdout="Permission denied accessing /var/gerrit/cache\n"
            ),
        ]

        assert check_replication_errors(docker, "abc123") is False

    def test_no_log_file_no_container_errors(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file does NOT exist
            make_completed_process(returncode=1),
            # container_logs: clean
            make_completed_process(stdout="INFO: Gerrit Code Review 3.13.1 ready"),
        ]

        assert check_replication_errors(docker, "abc123") is False

    def test_docker_error_treated_as_no_errors(self, mock_docker):
        from replication import check_replication_errors

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: log file exists
            make_completed_process(returncode=0),
            # grep command raises DockerError
            DockerError("exec failed"),
            # container_logs also fails
            DockerError("logs failed"),
        ]

        # DockerError during log reading should not raise; should return False
        assert check_replication_errors(docker, "abc123") is False


# =========================================================================
# get_completed_repo_count
# =========================================================================


class TestGetCompletedRepoCount:
    def test_returns_count(self, mock_docker):
        from replication import get_completed_repo_count

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="15\n")

        assert get_completed_repo_count(docker, "abc123") == 15

    def test_returns_zero_on_empty(self, mock_docker):
        from replication import get_completed_repo_count

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="")

        assert get_completed_repo_count(docker, "abc123") == 0

    def test_returns_zero_on_error(self, mock_docker):
        from replication import get_completed_repo_count

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        assert get_completed_repo_count(docker, "abc123") == 0

    def test_strips_whitespace(self, mock_docker):
        from replication import get_completed_repo_count

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="  42  \n")

        assert get_completed_repo_count(docker, "abc123") == 42


# =========================================================================
# check_pull_replication_log
# =========================================================================


class TestCheckPullReplicationLog:
    def test_log_missing_returns_false(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        # exec_test: file not found
        mock_run.return_value = make_completed_process(returncode=1)

        assert check_pull_replication_log(docker, "abc123") is False

    def test_errors_in_log_returns_false(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: found
            make_completed_process(stdout="Cannot replicate from origin"),
        ]

        assert check_pull_replication_log(docker, "abc123") is False

    def test_expected_count_met(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: none
            make_completed_process(stdout=""),
            # get_completed_repo_count: 10 unique repos
            make_completed_process(stdout="10\n"),
        ]

        # Expected 10, got 10: meets 90% threshold
        assert check_pull_replication_log(docker, "abc123", expected_count=10) is True

    def test_expected_count_90_pct_threshold(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: none
            make_completed_process(stdout=""),
            # completed count: 9 out of 10 (90%)
            make_completed_process(stdout="9\n"),
        ]

        # 90% of 10 = 9, so 9 >= 9 passes
        assert check_pull_replication_log(docker, "abc123", expected_count=10) is True

    def test_expected_count_not_met(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: none
            make_completed_process(stdout=""),
            # completed count: only 5 of 10
            make_completed_process(stdout="5\n"),
        ]

        assert check_pull_replication_log(docker, "abc123", expected_count=10) is False

    def test_no_expected_count_any_completion_ok(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: none
            make_completed_process(stdout=""),
            # completed count: some repos
            make_completed_process(stdout="3\n"),
        ]

        # No expected count, any completion is good
        assert check_pull_replication_log(docker, "abc123", expected_count=0) is True

    def test_no_expected_count_no_completions(self, mock_docker):
        from replication import check_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists
            make_completed_process(returncode=0),
            # grep for errors: none
            make_completed_process(stdout=""),
            # completed count: 0
            make_completed_process(stdout="0\n"),
        ]

        assert check_pull_replication_log(docker, "abc123", expected_count=0) is False


# =========================================================================
# count_repositories
# =========================================================================


class TestCountRepositories:
    def test_returns_count(self, mock_docker):
        from replication import count_repositories

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="25\n")

        assert count_repositories(docker, "abc123") == 25

    def test_returns_zero_on_empty(self, mock_docker):
        from replication import count_repositories

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="0\n")

        assert count_repositories(docker, "abc123") == 0

    def test_returns_zero_on_error(self, mock_docker):
        from replication import count_repositories

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        assert count_repositories(docker, "abc123") == 0


# =========================================================================
# get_git_disk_usage_mb / get_git_disk_usage_human
# =========================================================================


class TestDiskUsage:
    def test_disk_usage_mb(self, mock_docker):
        from replication import get_git_disk_usage_mb

        docker, mock_run = mock_docker
        # du -sk returns KB
        mock_run.return_value = make_completed_process(stdout="1048576\n")

        assert get_git_disk_usage_mb(docker, "abc123") == 1024

    def test_disk_usage_mb_zero(self, mock_docker):
        from replication import get_git_disk_usage_mb

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="0\n")

        assert get_git_disk_usage_mb(docker, "abc123") == 0

    def test_disk_usage_mb_error(self, mock_docker):
        from replication import get_git_disk_usage_mb

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        assert get_git_disk_usage_mb(docker, "abc123") == 0

    def test_disk_usage_human(self, mock_docker):
        from replication import get_git_disk_usage_human

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="1.2G\n")

        assert get_git_disk_usage_human(docker, "abc123") == "1.2G"

    def test_disk_usage_human_error(self, mock_docker):
        from replication import get_git_disk_usage_human

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        assert get_git_disk_usage_human(docker, "abc123") == "?"


# =========================================================================
# check_replication_has_content
# =========================================================================


class TestCheckReplicationHasContent:
    """Tests for check_replication_has_content with per-repo threshold.

    The function now uses _MIN_KB_PER_REPO (200 KB) per expected repo
    instead of a hard-coded 100 MB floor, which was the root cause of
    the 600-second timeout bug with small repositories.
    """

    def test_content_above_default_floor(self, mock_docker):
        """With no expected count, 1 MB is the floor."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # Return 2 MB in KB
        mock_run.return_value = make_completed_process(stdout="2048\n")

        assert check_replication_has_content(docker, "abc123") is True

    def test_content_below_default_floor(self, mock_docker):
        """With no expected count and 0 MB, should fail."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="0\n")

        assert check_replication_has_content(docker, "abc123") is False

    def test_small_repos_above_per_repo_threshold(self, mock_docker):
        """36 repos at 86 MB should pass (86 MB >> 36 * 200 KB = 7 MB)."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 86 MB in KB
        mock_run.return_value = make_completed_process(stdout="88064\n")

        # expected_count=36 → threshold = max(36*200/1024, 1) = max(7, 1) = 7 MB
        assert (
            check_replication_has_content(docker, "abc123", expected_count=36) is True
        )

    def test_small_repos_below_per_repo_threshold(self, mock_docker):
        """36 repos at 4 MB should fail (below 7 MB threshold)."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 4 MB in KB
        mock_run.return_value = make_completed_process(stdout="4096\n")

        assert (
            check_replication_has_content(docker, "abc123", expected_count=36) is False
        )

    def test_large_expected_count_scales_threshold(self, mock_docker):
        """500 repos → threshold = 500*200KB/1024 ≈ 97 MB, so 200 MB passes."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 200 MB in KB
        mock_run.return_value = make_completed_process(stdout="204800\n")

        assert (
            check_replication_has_content(docker, "abc123", expected_count=500) is True
        )

    def test_large_expected_count_not_met(self, mock_docker):
        """500 repos → threshold ≈ 97 MB, so 50 MB fails."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 50 MB in KB
        mock_run.return_value = make_completed_process(stdout="51200\n")

        assert (
            check_replication_has_content(docker, "abc123", expected_count=500) is False
        )

    def test_custom_min_size_overrides(self, mock_docker):
        """Explicit min_size_mb=50 with no expected count."""
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 50 MB in KB
        mock_run.return_value = make_completed_process(stdout="51200\n")

        assert check_replication_has_content(docker, "abc123", min_size_mb=50) is True

    def test_content_zero(self, mock_docker):
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="0\n")

        assert check_replication_has_content(docker, "abc123") is False

    def test_regression_86mb_36repos(self, mock_docker):
        """Regression: the exact scenario from the bug report.

        36 ansible-role repos totalling 86 MB should be detected as
        having real content.  Previously the 100 MB floor blocked this.
        """
        from replication import check_replication_has_content

        docker, mock_run = mock_docker
        # 86 MB in KB
        mock_run.return_value = make_completed_process(stdout="88064\n")

        assert (
            check_replication_has_content(docker, "abc123", expected_count=36) is True
        )


# =========================================================================
# New helper functions: get_log_line_count, get_disk_usage_kb, take_snapshot
# =========================================================================


class TestGetLogLineCount:
    def test_returns_count(self, mock_docker):
        from replication import get_log_line_count

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="150\n")

        assert get_log_line_count(docker, "abc123") == 150

    def test_returns_zero_on_empty(self, mock_docker):
        from replication import get_log_line_count

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="0\n")

        assert get_log_line_count(docker, "abc123") == 0

    def test_returns_zero_on_error(self, mock_docker):
        from replication import get_log_line_count

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("cmd failed")

        assert get_log_line_count(docker, "abc123") == 0


class TestGetDiskUsageKb:
    def test_returns_kb(self, mock_docker):
        from replication import get_disk_usage_kb

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="88064\n")

        assert get_disk_usage_kb(docker, "abc123") == 88064

    def test_returns_zero_on_error(self, mock_docker):
        from replication import get_disk_usage_kb

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("cmd failed")

        assert get_disk_usage_kb(docker, "abc123") == 0


class TestTakeSnapshot:
    @patch("replication.get_log_line_count", return_value=150)
    @patch("replication.get_disk_usage_kb", return_value=88064)
    @patch("replication.get_completed_repo_count", return_value=36)
    @patch("replication.count_repositories", return_value=36)
    def test_captures_all_fields(self, mock_count, mock_completed, mock_disk, mock_log):
        from replication import take_snapshot

        docker = MagicMock()
        snap = take_snapshot(docker, "abc123")

        assert snap.completed_count == 36
        assert snap.disk_usage_kb == 88064
        assert snap.log_line_count == 150
        assert snap.repo_count == 36
        assert snap.timestamp > 0


# =========================================================================
# list_repositories
# =========================================================================


class TestListRepositories:
    def test_returns_listing(self, mock_docker):
        from replication import list_repositories

        docker, mock_run = mock_docker
        listing = "/var/gerrit/git/project-a.git\n/var/gerrit/git/project-b.git\n"
        mock_run.return_value = make_completed_process(stdout=listing)

        result = list_repositories(docker, "abc123")
        assert "project-a.git" in result
        assert "project-b.git" in result

    def test_returns_fallback_on_error(self, mock_docker):
        from replication import list_repositories

        docker, mock_run = mock_docker
        mock_run.side_effect = DockerError("exec failed")

        result = list_repositories(docker, "abc123")
        assert result == "(none found)"

    def test_max_items_forwarded(self, mock_docker):
        from replication import list_repositories

        docker, mock_run = mock_docker
        mock_run.return_value = make_completed_process(stdout="")

        list_repositories(docker, "abc123", max_items=5)

        # Verify the command includes head -5
        call_args = mock_run.call_args
        cmd_list = call_args[0][0]
        cmd_str = " ".join(cmd_list)
        assert "head -5" in cmd_str


# =========================================================================
# show_pull_replication_log
# =========================================================================


class TestShowPullReplicationLog:
    def test_returns_log_content(self, mock_docker):
        from replication import show_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test: file exists (non-empty, -f passes)
            make_completed_process(returncode=0),
            # tail command
            make_completed_process(
                stdout="[2025-01-01] Replication from origin completed\n"
            ),
        ]

        result = show_pull_replication_log(docker, "abc123")
        assert "Replication from origin completed" in result

    def test_returns_empty_for_empty_file(self, mock_docker):
        from replication import show_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test -f: fails (empty file or not regular)
            make_completed_process(returncode=1),
            # exec_test -e: file exists but empty
            make_completed_process(returncode=0),
        ]

        result = show_pull_replication_log(docker, "abc123")
        assert result == "(empty)"

    def test_returns_not_found_if_missing(self, mock_docker):
        from replication import show_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test -f: fails
            make_completed_process(returncode=1),
            # exec_test -e: also fails (file doesn't exist at all)
            make_completed_process(returncode=1),
        ]

        result = show_pull_replication_log(docker, "abc123")
        assert result == "(file not found)"

    def test_returns_error_on_docker_error(self, mock_docker):
        from replication import show_pull_replication_log

        docker, mock_run = mock_docker
        mock_run.side_effect = [
            # exec_test -f: success
            make_completed_process(returncode=0),
            # tail: DockerError
            DockerError("exec failed"),
        ]

        result = show_pull_replication_log(docker, "abc123")
        assert result == "(error reading log)"


# =========================================================================
# wait_for_replication (core polling loop)
# =========================================================================


class TestWaitForReplication:
    """Tests for wait_for_replication with steady-state detection.

    The function now uses three success signals:
    1. Classic: repo count + content threshold + log completions
    2. Steady-state: unchanging snapshot for stability_window seconds
    3. Error detection: requires 2 consecutive error hits
    """

    @patch("replication.get_git_disk_usage_human", return_value="500M")
    @patch("replication.check_pull_replication_log", return_value=True)
    @patch("replication.check_replication_has_content", return_value=True)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories")
    @patch("replication.time.sleep")
    def test_completes_when_count_meets_expected(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_has_content,
        mock_log_ok,
        mock_disk_human,
    ):
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        # Initial count
        mock_count.return_value = 5
        # Snapshot returns matching count on second poll
        mock_snap.side_effect = [
            ReplicationSnapshot(
                timestamp=100.0,
                completed_count=5,
                disk_usage_kb=50000,
                log_line_count=50,
                repo_count=5,
            ),
            ReplicationSnapshot(
                timestamp=105.0,
                completed_count=10,
                disk_usage_kb=500000,
                log_line_count=100,
                repo_count=10,
            ),
        ]

        result = wait_for_replication(
            docker,
            "abc123",
            "onap",
            timeout=30,
            expected_count=10,
            stability_window=60,
        )
        assert result is True

    @patch("replication.show_pull_replication_log", return_value="error log")
    @patch("replication.list_repositories", return_value="/var/gerrit/git/a.git")
    @patch("replication.check_replication_errors", return_value=True)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories", return_value=5)
    @patch("replication.time.sleep")
    def test_raises_on_persistent_replication_errors(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_list,
        mock_show_log,
    ):
        """Errors must appear on 2 consecutive polls to fail fast."""
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        mock_snap.return_value = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=0,
            disk_usage_kb=100,
            log_line_count=5,
            repo_count=2,
        )

        with pytest.raises(ReplicationError, match="errors detected"):
            wait_for_replication(
                docker,
                "abc123",
                "onap",
                timeout=30,
                expected_count=10,
                stability_window=60,
            )

    @patch("replication.check_replication_errors")
    @patch("replication.check_pull_replication_log", return_value=True)
    @patch("replication.check_replication_has_content", return_value=True)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories", return_value=5)
    @patch("replication.time.sleep")
    def test_transient_error_does_not_fail(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_has_content,
        mock_log_ok,
        mock_errors,
    ):
        """A single error followed by success should not fail fast."""
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        # Error on first poll, then clears, then repo count matches
        mock_errors.side_effect = [True, False, False]
        mock_snap.side_effect = [
            ReplicationSnapshot(
                timestamp=100.0,
                completed_count=5,
                disk_usage_kb=50000,
                log_line_count=50,
                repo_count=5,
            ),
            ReplicationSnapshot(
                timestamp=105.0,
                completed_count=10,
                disk_usage_kb=500000,
                log_line_count=100,
                repo_count=10,
            ),
            ReplicationSnapshot(
                timestamp=110.0,
                completed_count=10,
                disk_usage_kb=500000,
                log_line_count=100,
                repo_count=10,
            ),
        ]

        result = wait_for_replication(
            docker,
            "abc123",
            "onap",
            timeout=30,
            expected_count=10,
            stability_window=60,
        )
        assert result is True

    @patch("replication.show_pull_replication_log", return_value="log tail")
    @patch("replication.list_repositories", return_value="repos")
    @patch("replication.get_git_disk_usage_human", return_value="100M")
    @patch("replication.check_pull_replication_log", return_value=False)
    @patch("replication.check_replication_has_content", return_value=False)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories", return_value=2)
    @patch("replication.time.sleep")
    def test_raises_on_timeout(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_has_content,
        mock_log_ok,
        mock_disk_human,
        mock_list,
        mock_show_log,
    ):
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        # Each poll returns a slightly different snapshot (still growing)
        call_count = [0]

        def make_snap(d, c):
            call_count[0] += 1
            return ReplicationSnapshot(
                timestamp=100.0 + call_count[0] * 5,
                completed_count=2,
                disk_usage_kb=100000 + call_count[0] * 100,
                log_line_count=50 + call_count[0],
                repo_count=2,
            )

        mock_snap.side_effect = make_snap

        with pytest.raises(ReplicationError, match="timed out") as exc_info:
            wait_for_replication(
                docker,
                "abc123",
                "onap",
                timeout=10,
                expected_count=50,
                stability_window=60,
            )

        assert exc_info.value.expected_count == 50
        assert exc_info.value.elapsed == 10

    @patch("replication.get_git_disk_usage_human", return_value="200M")
    @patch("replication.check_pull_replication_log", return_value=True)
    @patch("replication.check_replication_has_content", return_value=True)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories")
    @patch("replication.time.sleep")
    def test_no_expected_count_uses_content_check(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_has_content,
        mock_log_ok,
        mock_disk_human,
    ):
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        # Initial count then poll
        mock_count.side_effect = [0, 5]
        mock_snap.return_value = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=5,
            disk_usage_kb=200000,
            log_line_count=100,
            repo_count=5,
        )

        result = wait_for_replication(
            docker,
            "abc123",
            "onap",
            timeout=30,
            expected_count=0,
            stability_window=60,
        )
        assert result is True

    @patch("replication.get_git_disk_usage_human", return_value="86M")
    @patch("replication.check_pull_replication_log", return_value=True)
    @patch("replication.check_replication_has_content", return_value=True)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories", return_value=36)
    @patch("replication.time.sleep")
    def test_regression_36_repos_86mb_succeeds_immediately(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_has_content,
        mock_log_ok,
        mock_disk_human,
    ):
        """Regression: 36 repos at 86 MB must succeed via classic check.

        This is the exact scenario from the bug report — previously the
        100 MB floor in check_replication_has_content prevented success,
        causing a 600-second timeout.
        """
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        mock_snap.return_value = ReplicationSnapshot(
            timestamp=100.0,
            completed_count=36,
            disk_usage_kb=88064,
            log_line_count=200,
            repo_count=36,
        )

        result = wait_for_replication(
            docker,
            "abc123",
            "lf",
            timeout=600,
            expected_count=36,
            stability_window=45,
        )
        assert result is True
        # Should complete on first poll, not wait the full timeout
        assert mock_sleep.call_count == 1

    @patch("replication.get_git_disk_usage_human", return_value="86M")
    @patch("replication.check_pull_replication_log", return_value=False)
    @patch("replication.check_replication_has_content", return_value=False)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.take_snapshot")
    @patch("replication.count_repositories", return_value=36)
    @patch("replication.time.sleep")
    def test_steady_state_detection_completes_early(
        self,
        mock_sleep,
        mock_count,
        mock_snap,
        mock_errors,
        mock_has_content,
        mock_log_ok,
        mock_disk_human,
    ):
        """When classic checks fail but state is stable, steady-state kicks in."""
        from replication import ReplicationSnapshot, wait_for_replication

        docker = MagicMock()
        base_time = 1000.0
        call_idx = [0]

        def make_stable_snap(d, c):
            call_idx[0] += 1
            return ReplicationSnapshot(
                timestamp=base_time + call_idx[0] * 5,
                completed_count=36,
                disk_usage_kb=88064,
                log_line_count=200,
                repo_count=36,
            )

        mock_snap.side_effect = make_stable_snap

        result = wait_for_replication(
            docker,
            "abc123",
            "lf",
            timeout=600,
            expected_count=36,
            # Use a short window so the test completes quickly
            stability_window=10,
        )
        assert result is True
        # Should NOT wait 600 seconds; should exit after stability detected
        assert mock_sleep.call_count < 120  # 600s / 5s interval = 120 max


# =========================================================================
# trigger_replication (per-instance)
# =========================================================================


class TestTriggerReplication:
    @patch("replication.list_repositories", return_value="")
    @patch("replication.show_pull_replication_log", return_value="(empty)")
    @patch("replication.count_repositories", return_value=0)
    @patch("replication.verify_plugin_loaded", return_value=True)
    @patch("replication.show_replication_config", return_value="[remote]\n  url=...")
    @patch("replication.check_replication_config", return_value=True)
    @patch("replication.time.sleep")
    def test_trigger_basic_flow(
        self,
        mock_sleep,
        mock_config,
        mock_show_config,
        mock_plugin,
        mock_count,
        mock_show_log,
        mock_list,
    ):
        from replication import trigger_replication

        docker = MagicMock()
        docker.container_logs.return_value = "Loaded plugin pull-replication"
        docker.exec_test.return_value = False  # log file not found during wait
        docker.exec_cmd.return_value = ""

        config = MagicMock()
        config.skip_plugin_install = False
        config.auth_type = "http_basic"
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60
        config.sync_on_startup = True
        config.debug = False

        instance = {
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 10,
        }

        result = trigger_replication(docker, "abc123", "test", instance, config)
        assert result.slug == "test"
        assert result.success is True

    @patch("replication.check_replication_config", return_value=False)
    def test_trigger_no_config(self, mock_config):
        from replication import trigger_replication

        docker = MagicMock()
        config = MagicMock()

        instance = {
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = trigger_replication(docker, "abc123", "test", instance, config)
        assert result.success is False
        assert "replication.config not found" in result.error

    @patch("replication.list_repositories", return_value="")
    @patch("replication.show_pull_replication_log", return_value="(empty)")
    @patch("replication.count_repositories", return_value=0)
    @patch("replication.show_replication_config", return_value="[remote]")
    @patch("replication.check_replication_config", return_value=True)
    @patch("replication.time.sleep")
    def test_trigger_skip_plugin_check(
        self,
        mock_sleep,
        mock_config,
        mock_show_config,
        mock_count,
        mock_show_log,
        mock_list,
    ):
        from replication import trigger_replication

        docker = MagicMock()
        docker.container_logs.return_value = ""
        docker.exec_test.return_value = False
        docker.exec_cmd.return_value = ""

        config = MagicMock()
        config.skip_plugin_install = True
        config.auth_type = "http_basic"
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60
        config.sync_on_startup = True
        config.debug = False

        instance = {
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = trigger_replication(docker, "abc123", "test", instance, config)
        # Should succeed even without plugin check
        assert result.success is True

    @patch("replication.list_repositories", return_value="")
    @patch("replication.show_pull_replication_log", return_value="log data")
    @patch("replication.count_repositories", return_value=5)
    @patch("replication.verify_plugin_loaded", return_value=True)
    @patch("replication.show_replication_config", return_value="[remote]")
    @patch("replication.check_replication_config", return_value=True)
    @patch("replication.time.sleep")
    def test_trigger_ssh_mode_attempts_trigger(
        self,
        mock_sleep,
        mock_config,
        mock_show_config,
        mock_plugin,
        mock_count,
        mock_show_log,
        mock_list,
    ):
        from replication import trigger_replication

        docker = MagicMock()
        docker.container_logs.return_value = "Loaded plugin pull-replication\n"
        docker.exec_test.return_value = True
        docker.exec_cmd.return_value = "Replication triggered"

        config = MagicMock()
        config.skip_plugin_install = False
        config.auth_type = "ssh"
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60
        config.sync_on_startup = True
        config.debug = False

        instance = {
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 5,
        }

        result = trigger_replication(docker, "abc123", "test", instance, config)
        assert result.success is True


# =========================================================================
# verify_single_instance
# =========================================================================


class TestVerifySingleInstance:
    @patch("replication.get_git_disk_usage_mb", return_value=500)
    @patch("replication.get_git_disk_usage_human", return_value="500M")
    @patch("replication.get_completed_repo_count", return_value=10)
    @patch("replication.count_repositories", return_value=10)
    @patch("replication.wait_for_replication", return_value=True)
    @patch("replication.check_replication_errors", return_value=False)
    @patch("replication.check_secure_config", return_value=True)
    @patch("replication.show_replication_config", return_value="[remote]")
    @patch("replication.check_replication_config", return_value=True)
    @patch("replication.verify_plugin_loaded", return_value=True)
    def test_full_success_flow(
        self,
        mock_plugin,
        mock_config,
        mock_show_config,
        mock_secure,
        mock_errors,
        mock_wait,
        mock_count,
        mock_completed,
        mock_disk_human,
        mock_disk_mb,
    ):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = True
        docker.container_state.return_value = "running"
        docker.exec_cmd.return_value = "/var/gerrit/git/a.git\n/var/gerrit/git/b.git"

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 10,
        }

        result = verify_single_instance(docker, "onap", instance, timeout=60)
        assert result.success is True
        assert result.slug == "onap"
        assert result.repo_count == 10
        assert result.disk_usage == "500M"

    @patch("replication.verify_plugin_loaded", return_value=False)
    def test_plugin_not_loaded(self, mock_plugin):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = True
        docker.container_state.return_value = "running"

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 10,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "plugin not loaded" in result.error.lower()

    @patch("replication.verify_plugin_loaded", return_value=True)
    @patch("replication.check_replication_config", return_value=False)
    def test_config_missing(self, mock_config, mock_plugin):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = True
        docker.container_state.return_value = "running"

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "replication.config not found" in result.error

    def test_container_not_found(self):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = False

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_container_not_running(self):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = True
        docker.container_state.return_value = "exited"

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "not running" in result.error.lower()

    @patch("replication.get_git_disk_usage_mb", return_value=0)
    @patch("replication.get_git_disk_usage_human", return_value="0")
    @patch("replication.get_completed_repo_count", return_value=0)
    @patch("replication.count_repositories", return_value=0)
    @patch("replication.check_secure_config", return_value=True)
    @patch("replication.show_replication_config", return_value="[remote]")
    @patch("replication.check_replication_config", return_value=True)
    @patch("replication.verify_plugin_loaded", return_value=True)
    @patch("replication.check_replication_errors", return_value=True)
    def test_replication_errors_detected(
        self,
        mock_errors,
        mock_plugin,
        mock_config,
        mock_show_config,
        mock_secure,
        mock_count,
        mock_completed,
        mock_disk_human,
        mock_disk_mb,
    ):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.return_value = True
        docker.container_state.return_value = "running"
        docker.exec_test.return_value = True
        docker.exec_cmd.return_value = "Cannot replicate from origin"
        docker.container_logs.return_value = "Cannot replicate from origin"

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 10,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "error" in result.error.lower()

    def test_docker_error_during_container_check(self):
        from replication import verify_single_instance

        docker = MagicMock()
        docker.container_exists.side_effect = DockerError("daemon not running")

        instance = {
            "cid": "abc123def456",
            "gerrit_host": "gerrit.example.org",
            "project": "",
            "expected_project_count": 0,
        }

        result = verify_single_instance(docker, "onap", instance)
        assert result.success is False
        assert "daemon" in result.error.lower()


# =========================================================================
# trigger_all_instances
# =========================================================================


class TestTriggerAllInstances:
    @patch("replication.trigger_replication")
    @patch("replication.write_summary")
    def test_triggers_all(self, mock_summary, mock_trigger):
        from replication import TriggerResult, trigger_all_instances

        docker = MagicMock()
        config = MagicMock()
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60

        mock_trigger.side_effect = [
            TriggerResult(slug="onap", success=True),
            TriggerResult(slug="lf", success=True),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc", "gerrit_host": "gerrit.onap.org"}),
                    ("lf", {"cid": "def", "gerrit_host": "gerrit.lf.org"}),
                ]
            )
        )

        results = trigger_all_instances(docker, store, config)
        assert len(results) == 2
        assert all(r.success for r in results)

    @patch("replication.trigger_replication")
    @patch("replication.write_summary")
    def test_partial_failure_returns_all_results(self, mock_summary, mock_trigger):
        from replication import TriggerResult, trigger_all_instances

        docker = MagicMock()
        config = MagicMock()
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60

        mock_trigger.side_effect = [
            TriggerResult(slug="onap", success=True),
            TriggerResult(slug="lf", success=False, error="plugin missing"),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc", "gerrit_host": "gerrit.onap.org"}),
                    ("lf", {"cid": "def", "gerrit_host": "gerrit.lf.org"}),
                ]
            )
        )

        results = trigger_all_instances(docker, store, config)
        assert len(results) == 2
        # trigger_all_instances does NOT raise on failure
        failed = [r for r in results if not r.success]
        assert len(failed) == 1
        assert failed[0].slug == "lf"

    @patch("replication.write_summary")
    def test_empty_store(self, mock_summary):
        from replication import trigger_all_instances

        docker = MagicMock()
        config = MagicMock()
        config.fetch_every = "60s"
        config.fetch_interval_seconds = 60

        store = MagicMock()
        store.__iter__ = MagicMock(return_value=iter([]))

        results = trigger_all_instances(docker, store, config)
        assert len(results) == 0


# =========================================================================
# verify_all_instances
# =========================================================================


class TestVerifyAllInstances:
    @patch("replication.verify_single_instance")
    @patch("replication.write_summary")
    def test_all_pass(self, mock_summary, mock_verify):
        from replication import VerificationResult, verify_all_instances

        docker = MagicMock()

        mock_verify.side_effect = [
            VerificationResult(
                slug="onap",
                success=True,
                repo_count=10,
                disk_usage="500M",
            ),
            VerificationResult(
                slug="lf",
                success=True,
                repo_count=5,
                disk_usage="200M",
            ),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc"}),
                    ("lf", {"cid": "def"}),
                ]
            )
        )

        results = verify_all_instances(docker, store, timeout=60)
        assert len(results) == 2
        assert all(r.success for r in results)

    @patch("replication.verify_single_instance")
    @patch("replication.write_summary")
    def test_one_fails_raises(self, mock_summary, mock_verify):
        from replication import VerificationResult, verify_all_instances

        docker = MagicMock()

        mock_verify.side_effect = [
            VerificationResult(slug="onap", success=True, repo_count=10),
            VerificationResult(
                slug="lf",
                success=False,
                error="timeout",
                expected_count=5,
                repo_count=2,
            ),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc"}),
                    ("lf", {"cid": "def"}),
                ]
            )
        )

        with pytest.raises(ReplicationError, match="lf") as exc_info:
            verify_all_instances(docker, store, timeout=60)

        assert exc_info.value.expected_count == 5
        assert exc_info.value.actual_count == 2

    @patch("replication.verify_single_instance")
    @patch("replication.write_summary")
    def test_all_fail_raises_with_totals(self, mock_summary, mock_verify):
        from replication import VerificationResult, verify_all_instances

        docker = MagicMock()

        mock_verify.side_effect = [
            VerificationResult(
                slug="onap",
                success=False,
                error="timeout",
                expected_count=10,
                repo_count=3,
            ),
            VerificationResult(
                slug="lf",
                success=False,
                error="errors",
                expected_count=5,
                repo_count=1,
            ),
        ]

        store = MagicMock()
        store.__iter__ = MagicMock(
            return_value=iter(
                [
                    ("onap", {"cid": "abc"}),
                    ("lf", {"cid": "def"}),
                ]
            )
        )

        with pytest.raises(ReplicationError) as exc_info:
            verify_all_instances(docker, store, timeout=60)

        # Totals should be summed
        assert exc_info.value.expected_count == 15  # 10 + 5
        assert exc_info.value.actual_count == 4  # 3 + 1
        assert "onap" in str(exc_info.value)
        assert "lf" in str(exc_info.value)

    @patch("replication.write_summary")
    def test_empty_store(self, mock_summary):
        from replication import verify_all_instances

        docker = MagicMock()

        store = MagicMock()
        store.__iter__ = MagicMock(return_value=iter([]))

        # Empty store: no failures, returns empty list
        results = verify_all_instances(docker, store, timeout=60)
        assert len(results) == 0

    @patch("replication.verify_single_instance")
    @patch("replication.write_summary")
    def test_timeout_forwarded(self, mock_summary, mock_verify):
        from replication import VerificationResult, verify_all_instances

        docker = MagicMock()

        mock_verify.return_value = VerificationResult(
            slug="onap", success=True, repo_count=10, disk_usage="1G"
        )

        store = MagicMock()
        store.__iter__ = MagicMock(return_value=iter([("onap", {"cid": "abc"})]))

        verify_all_instances(docker, store, timeout=300, debug=True)

        mock_verify.assert_called_once_with(
            docker,
            "onap",
            {"cid": "abc"},
            timeout=300,
            debug=True,
            stability_window=45,
        )
