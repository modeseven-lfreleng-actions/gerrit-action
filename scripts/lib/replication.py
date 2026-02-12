# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Replication trigger and verification for Gerrit pull-replication.

Replaces ``trigger-replication.sh`` (353 lines) and
``verify-replication.sh`` (740 lines) with a testable Python
implementation.

The pull-replication plugin is configured with ``fetchEvery`` which
polls the source Gerrit at regular intervals to fetch new/changed refs.

This module provides:

- Plugin and configuration verification
- SSH-based replication trigger (optional, for faster initial sync)
- Polling-based wait for replication activity
- Repository count and disk usage verification
- Detailed progress reporting

Usage::

    from docker_manager import DockerManager
    from replication import (
        trigger_replication,
        verify_replication,
        check_all_instances_replication,
    )

    docker = DockerManager()
    trigger_replication(docker, container_id, config)
    verify_replication(docker, container_id, slug, timeout=180)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from config import ActionConfig, InstanceStore
from docker_manager import DockerManager
from errors import DockerError, ReplicationError
from health_check import verify_plugin_loaded
from outputs import write_summary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum wait time for replication regardless of fetch interval
_MIN_WAIT_SECONDS = 60

# Default number of seconds with no state change before declaring
# replication "stable" (i.e. nothing new is being fetched).
_STABILITY_WINDOW_SECONDS = 45

# Minimum per-repo disk size in KB that indicates real content.
# An empty bare git repo is ~150 KB; anything above ~200 KB/repo
# means actual refs/objects were fetched.
_MIN_KB_PER_REPO = 200

# Patterns for detecting replication errors in the pull_replication_log.
# These are safe to use against the replication-specific log because every
# line in that file is replication-related.
_REPLICATION_ERROR_PATTERNS = [
    "Cannot replicate",
    "TransportException",
    "git-upload-pack not permitted",
    "Authentication.*failed",
    "Permission denied",
    "Connection refused",
]

# Patterns for detecting replication errors in the **container** logs.
#
# These must be much more selective than the pull_replication_log patterns
# because container logs contain ALL of Gerrit's output (web UI, email,
# account management, etc.).  Generic patterns like "Connection refused"
# or "Permission denied" cause false positives when e.g. the email
# subsystem cannot reach an SMTP server.
#
# Only patterns that unambiguously indicate a replication failure belong
# here.
_CONTAINER_ERROR_PATTERNS = [
    "Cannot replicate",
    r"pull-replication.*(?:error|failed|exception)",
    r"TransportException.*(?:fetch|replicate|remote)",
    "git-upload-pack not permitted",
]

# Pattern to extract unique completed repo names from pull_replication_log
# Log format: "[timestamp] [id] Replication from <url> completed in ..."
# URL formats:
#   - HTTPS: https://gerrit.example.org/r/a/<project>.git
#   - SSH:   ssh://gerrit.example.org:29418/<project>.git
#
# Extraction: strip prefix through "Replication from ", strip ".git completed..."
# suffix, strip /a/ path for HTTP, strip scheme://authority/ for SSH.
_COMPLETED_COUNT_CMD = (
    "grep 'Replication from .* completed' "
    "/var/gerrit/logs/pull_replication_log 2>/dev/null | "
    "sed -E '"
    "s|.*Replication from ||; "
    "s|\\.git completed.*||; "
    "s|.*/a/||; "
    "s|^[^:]+://[^/]+/||"
    "' | "
    "grep -v -E '^All-Projects$|^All-Users$' | "
    "sort -u | wc -l"
)

# Command to count bare git repos excluding system repos
_COUNT_REPOS_CMD = (
    "find /var/gerrit/git -name '*.git' -type d -prune 2>/dev/null | "
    "while read -r dir; do "
    '  if [ -f "$dir/HEAD" ]; then echo "$dir"; fi; '
    "done | "
    "grep -v -E 'All-Projects|All-Users' | wc -l"
)

# Command to get git directory disk usage in KB
_DISK_USAGE_CMD = "du -sk /var/gerrit/git 2>/dev/null | cut -f1"

# Command to get human-readable disk usage
_DISK_USAGE_HUMAN_CMD = "du -sh /var/gerrit/git 2>/dev/null | cut -f1"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TriggerResult:
    """Result of a replication trigger for a single instance."""

    slug: str
    success: bool = False
    replication_started: bool = False
    error: str = ""
    repo_count: int = 0
    expected_count: int = 0


@dataclass
class VerificationResult:
    """Result of replication verification for a single instance."""

    slug: str
    success: bool = False
    error: str = ""
    repo_count: int = 0
    expected_count: int = 0
    completed_count: int = 0
    disk_usage: str = ""
    disk_usage_mb: int = 0


@dataclass
class ReplicationSnapshot:
    """Point-in-time snapshot of replication progress.

    Used by the wait loop to detect whether replication is still making
    progress or has reached a steady state (no new fetches, no disk
    growth, no new log entries).
    """

    timestamp: float = 0.0
    completed_count: int = 0
    disk_usage_kb: int = 0
    log_line_count: int = 0
    repo_count: int = 0

    def is_same_as(self, other: ReplicationSnapshot) -> bool:
        """Return *True* if all observable counters are unchanged."""
        return (
            self.completed_count == other.completed_count
            and self.disk_usage_kb == other.disk_usage_kb
            and self.log_line_count == other.log_line_count
            and self.repo_count == other.repo_count
        )


@dataclass
class _StabilityTracker:
    """Track how long replication state has been unchanging.

    The tracker records the timestamp at which the state last changed.
    Callers push new snapshots via :meth:`update` and query whether the
    state has been stable for at least *window* seconds.
    """

    window: float = _STABILITY_WINDOW_SECONDS
    _last_change_time: float = field(default=0.0, init=False)
    _prev_snapshot: ReplicationSnapshot | None = field(default=None, init=False)

    def update(self, snap: ReplicationSnapshot) -> None:
        """Record a new snapshot; reset the clock if state changed."""
        if self._prev_snapshot is None or not snap.is_same_as(self._prev_snapshot):
            self._last_change_time = snap.timestamp
        self._prev_snapshot = snap

    def is_stable(self, now: float) -> bool:
        """Return *True* if the state has not changed for *window* seconds."""
        if self._prev_snapshot is None:
            return False
        return (now - self._last_change_time) >= self.window

    @property
    def seconds_stable(self) -> float:
        """Seconds since the last state change (0 if no snapshot yet)."""
        if self._prev_snapshot is None:
            return 0.0
        return self._prev_snapshot.timestamp - self._last_change_time


# ---------------------------------------------------------------------------
# Plugin and configuration checks
# ---------------------------------------------------------------------------


def check_replication_config(docker: DockerManager, cid: str) -> bool:
    """Verify that ``replication.config`` exists in the container.

    Returns *True* if the file exists.
    """
    result: bool = docker.exec_test(cid, "-f /var/gerrit/etc/replication.config")
    return result


def show_replication_config(docker: DockerManager, cid: str) -> str:
    """Read and return the replication config (excluding comments/blanks).

    Returns the config content or an empty string.
    """
    try:
        raw = docker.exec_cmd(
            cid,
            "cat /var/gerrit/etc/replication.config 2>/dev/null",
            check=False,
        )
        # Filter out comments and blank lines
        lines = [
            line
            for line in raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return "\n".join(lines)
    except DockerError:
        return ""


def check_secure_config(docker: DockerManager, cid: str) -> bool:
    """Check if secure.config exists and log its sections.

    Returns *True* if the file exists.
    """
    if not docker.exec_test(cid, "-f /var/gerrit/etc/secure.config"):
        logger.warning("secure.config not found")
        return False

    logger.info("  secure.config exists ✅")
    try:
        sections = docker.exec_cmd(
            cid,
            "grep '^\\[' /var/gerrit/etc/secure.config 2>/dev/null",
            check=False,
        )
        if sections:
            logger.info("  secure.config sections:")
            for line in sections.splitlines():
                logger.info("    %s", line)
    except DockerError:
        pass
    return True


# ---------------------------------------------------------------------------
# Replication log analysis
# ---------------------------------------------------------------------------


def check_replication_errors(docker: DockerManager, cid: str) -> bool:
    """Check for replication errors in logs.

    The pull_replication_log is the **primary** source of truth.  We
    also do a narrowly-scoped scan of container logs for replication-
    specific patterns, but intentionally skip generic terms like
    ``Connection refused`` or ``ERROR`` that frequently appear for
    non-replication reasons (e.g. email delivery failures).

    Returns *True* if errors were found (i.e. replication is failing).
    """
    # --- 1. pull_replication_log (authoritative) ---
    if docker.exec_test(cid, "-f /var/gerrit/logs/pull_replication_log"):
        try:
            # Build a grep pattern from the replication-specific patterns.
            grep_pattern = "|".join(_REPLICATION_ERROR_PATTERNS)
            result = docker.exec_cmd(
                cid,
                f"tail -n 500 /var/gerrit/logs/pull_replication_log 2>/dev/null | "
                f"grep -iE '{grep_pattern}'",
                check=False,
            )
            if result.strip():
                return True
        except DockerError:
            pass

    # --- 2. Container logs (narrow, replication-specific patterns only) ---
    try:
        logs = docker.container_logs(cid, tail=2000)
        for pattern in _CONTAINER_ERROR_PATTERNS:
            if re.search(pattern, logs, re.IGNORECASE):
                return True
    except DockerError:
        pass

    return False


def get_completed_repo_count(docker: DockerManager, cid: str) -> int:
    """Count UNIQUE repos that have completed replication.

    Parses the pull_replication_log, extracting project names from URLs
    and counting unique entries (excluding system repos).
    """
    try:
        raw = docker.exec_cmd(cid, _COMPLETED_COUNT_CMD, check=False, timeout=15)
        count = _parse_int(raw)
        return count
    except DockerError:
        return 0


def get_log_line_count(docker: DockerManager, cid: str) -> int:
    """Return the number of lines in the pull_replication_log.

    Used by steady-state detection to tell whether new log entries
    are still being written.
    """
    try:
        raw = docker.exec_cmd(
            cid,
            "wc -l < /var/gerrit/logs/pull_replication_log 2>/dev/null || echo 0",
            check=False,
            timeout=10,
        )
        return _parse_int(raw)
    except DockerError:
        return 0


def get_disk_usage_kb(docker: DockerManager, cid: str) -> int:
    """Return the git directory disk usage in kilobytes.

    Unlike :func:`get_git_disk_usage_mb` this returns the raw KB value,
    which is needed for precise change detection in the steady-state
    tracker.
    """
    try:
        raw = docker.exec_cmd(cid, _DISK_USAGE_CMD, check=False, timeout=10)
        return _parse_int(raw)
    except DockerError:
        return 0


def take_snapshot(docker: DockerManager, cid: str) -> ReplicationSnapshot:
    """Capture a point-in-time snapshot of all replication indicators."""
    return ReplicationSnapshot(
        timestamp=time.time(),
        completed_count=get_completed_repo_count(docker, cid),
        disk_usage_kb=get_disk_usage_kb(docker, cid),
        log_line_count=get_log_line_count(docker, cid),
        repo_count=count_repositories(docker, cid),
    )


def check_pull_replication_log(
    docker: DockerManager,
    cid: str,
    expected_count: int = 0,
    debug: bool = False,
) -> bool:
    """Check if replication has completed successfully.

    Returns *True* ONLY if replication completed WITHOUT errors and
    the completed count meets the threshold.
    """
    # Check if log file exists
    if not docker.exec_test(cid, "-f /var/gerrit/logs/pull_replication_log"):
        if debug:
            logger.debug("    pull_replication_log not found")
        return False

    # Check for errors in recent entries
    try:
        error_grep = "|".join(_REPLICATION_ERROR_PATTERNS)
        recent_errors = docker.exec_cmd(
            cid,
            f"tail -n 200 /var/gerrit/logs/pull_replication_log 2>/dev/null | "
            f"grep -iE '{error_grep}'",
            check=False,
        )
        if recent_errors.strip():
            if debug:
                logger.debug("    Found replication errors in log")
            return False
    except DockerError:
        pass

    completed_count = get_completed_repo_count(docker, cid)
    if debug:
        logger.debug(
            "    check_pull_replication_log: completed=%d, expected=%d",
            completed_count,
            expected_count,
        )

    if expected_count > 0:
        # Require at least 90% of expected repos
        min_completed = expected_count * 9 // 10
        if debug:
            logger.debug("    min_completed (90%%)=%d", min_completed)
        if completed_count >= min_completed:
            if debug:
                logger.debug("    Success: %d >= %d", completed_count, min_completed)
            return True
        if debug:
            logger.debug("    Not enough: %d < %d", completed_count, min_completed)
        return False
    else:
        # No expected count — any completion is good
        if completed_count > 0:
            if debug:
                logger.debug(
                    "    No expected count, found %d completions", completed_count
                )
            return True

    return False


# ---------------------------------------------------------------------------
# Repository counting and disk usage
# ---------------------------------------------------------------------------


def count_repositories(docker: DockerManager, cid: str) -> int:
    """Count replicated repositories (excludes All-Projects and All-Users).

    Uses ``-prune`` to avoid descending into .git directories and
    verifies each directory is a bare repo by checking for HEAD file.
    """
    try:
        raw = docker.exec_cmd(cid, _COUNT_REPOS_CMD, check=False, timeout=15)
        return _parse_int(raw)
    except DockerError:
        return 0


def get_git_disk_usage_mb(docker: DockerManager, cid: str) -> int:
    """Return the git directory disk usage in megabytes."""
    try:
        raw = docker.exec_cmd(cid, _DISK_USAGE_CMD, check=False, timeout=10)
        size_kb = _parse_int(raw)
        return size_kb // 1024
    except DockerError:
        return 0


def get_git_disk_usage_human(docker: DockerManager, cid: str) -> str:
    """Return human-readable git directory disk usage."""
    try:
        result: str = docker.exec_cmd(
            cid, _DISK_USAGE_HUMAN_CMD, check=False, timeout=10
        )
        return result
    except DockerError:
        return "?"


def check_replication_has_content(
    docker: DockerManager,
    cid: str,
    expected_count: int = 0,
    min_size_mb: int = 0,
) -> bool:
    """Check if replication has fetched substantial content.

    An empty bare git repo created by ``createMissingRepositories`` is
    roughly 150 KB.  We consider a repository to have *real* content
    when its average size exceeds :data:`_MIN_KB_PER_REPO` (200 KB).

    The previous hard-coded 100 MB floor caused false negatives for
    collections of small repositories (e.g. 36 ansible-role repos
    totalling 86 MB — well above empty, but below the old threshold).

    Parameters
    ----------
    docker, cid:
        Docker manager / container ID.
    expected_count:
        Number of repositories expected.  When > 0 we estimate a
        per-repo minimum; otherwise we fall back to *min_size_mb*.
    min_size_mb:
        Absolute minimum MB.  Defaults to 0 so the per-repo heuristic
        is the primary check.  Callers may pass a value for cases
        where no expected count is available.
    """
    current_kb = get_disk_usage_kb(docker, cid)
    current_mb = current_kb // 1024

    if expected_count > 0:
        # Scale the threshold to the actual number of repos.
        # _MIN_KB_PER_REPO (200 KB) is ~33% above the size of an
        # empty bare repo, so exceeding this means real objects exist.
        estimated_min_kb = expected_count * _MIN_KB_PER_REPO
        estimated_min_mb = max(estimated_min_kb // 1024, 1)
        threshold_mb = max(estimated_min_mb, min_size_mb)
    else:
        # No expected count — use 1 MB as a sanity floor.
        threshold_mb = max(1, min_size_mb)

    return current_mb >= threshold_mb


def list_repositories(
    docker: DockerManager,
    cid: str,
    max_items: int = 20,
) -> str:
    """List repositories in the git directory.

    Returns a newline-separated string of repository paths.
    """
    try:
        result: str = docker.exec_cmd(
            cid,
            f"find /var/gerrit/git -name '*.git' -type d -prune 2>/dev/null | "
            f"head -{max_items}",
            check=False,
            timeout=15,
        )
        return result
    except DockerError:
        return "(none found)"


def show_pull_replication_log(
    docker: DockerManager,
    cid: str,
    lines: int = 50,
) -> str:
    """Return the last N lines of the pull_replication_log."""
    if not docker.exec_test(cid, "-f /var/gerrit/logs/pull_replication_log"):
        if docker.exec_test(cid, "-e /var/gerrit/logs/pull_replication_log"):
            return "(empty)"
        return "(file not found)"

    try:
        content = docker.exec_cmd(
            cid,
            f"tail -n {lines} /var/gerrit/logs/pull_replication_log 2>/dev/null",
            check=False,
            timeout=10,
        )
        return content if content.strip() else "(empty)"
    except DockerError:
        return "(error reading log)"


# ---------------------------------------------------------------------------
# Trigger replication
# ---------------------------------------------------------------------------


def trigger_replication(
    docker: DockerManager,
    cid: str,
    slug: str,
    instance: dict[str, Any],
    config: ActionConfig,
) -> TriggerResult:
    """Trigger initial replication for a single instance.

    This replaces the per-instance loop in ``trigger-replication.sh``.

    Steps:
    1. Verify replication.config exists
    2. Verify pull-replication plugin is loaded
    3. Show replication configuration
    4. Optionally trigger via SSH
    5. Wait for fetchEvery polling to show activity
    """
    result = TriggerResult(slug=slug)

    gerrit_host = instance.get("gerrit_host", "")
    project = instance.get("project", "")
    expected_count = int(instance.get("expected_project_count", 0))
    result.expected_count = expected_count

    logger.info("========================================")
    logger.info("Triggering replication: %s", slug)
    logger.info("========================================")
    logger.info("Container ID: %s", cid[:12] if cid else "(none)")
    logger.info("Source: %s", gerrit_host)
    if project:
        logger.info("Project filter: %s", project)
    if expected_count > 0:
        logger.info("Expected repositories: %d", expected_count)
    logger.info("")

    # Check replication config
    if not check_replication_config(docker, cid):
        logger.warning("replication.config not found, skipping replication trigger")
        result.error = "replication.config not found"
        return result

    # Check plugin
    if not config.skip_plugin_install:
        logger.info("Verifying pull-replication plugin is loaded…")
        if verify_plugin_loaded(docker, cid, "pull-replication"):
            logger.info("Pull-replication plugin is active ✅")
            # Show plugin version from logs
            try:
                logs = docker.container_logs(cid, tail=200)
                for line in logs.splitlines():
                    if "Loaded plugin pull-replication" in line:
                        logger.info("  %s", line.strip())
                        break
            except DockerError:
                pass
        else:
            # Check if jar file exists
            if docker.exec_test(cid, "-f /var/gerrit/plugins/pull-replication.jar"):
                logger.info("  Plugin file exists, may still be loading…")
            else:
                logger.warning("Plugin file not found in container")
                result.error = "pull-replication plugin not found"
                return result
        logger.info("")

    # Show replication config
    logger.info("Replication configuration:")
    config_content = show_replication_config(docker, cid)
    if config_content:
        logger.info("--- replication.config ---")
        for line in config_content.splitlines():
            logger.info("  %s", line)
        logger.info("---")
    else:
        logger.warning("replication.config not found or empty")
    logger.info("")

    # SSH trigger (optional, for faster initial sync)
    if config.auth_type == "ssh":
        logger.info("Attempting to trigger replication via SSH…")
        try:
            ssh_result = docker.exec_cmd(
                cid,
                "ssh -p 29418 -o StrictHostKeyChecking=no admin@localhost "
                "gerrit pull-replication start --wait --all 2>&1",
                timeout=30,
                check=False,
            )
            if any(
                err in ssh_result
                for err in ("ssh_failed", "Connection refused", "Permission denied")
            ):
                logger.warning(
                    "SSH trigger not available (expected for new installations)"
                )
                logger.info("Replication will occur based on configured schedule")
            else:
                logger.info("SSH trigger response: %s", ssh_result)
                logger.info("✅ Replication triggered via SSH")
        except DockerError:
            logger.warning("SSH trigger failed, relying on fetchEvery polling")

    # Wait for fetchEvery polling
    logger.info("")
    logger.info("Waiting for fetchEvery polling to trigger replication…")
    logger.info(
        "(First poll occurs within the configured fetch interval: %s)",
        config.fetch_every,
    )

    # Calculate wait timeout: 1.5× fetch interval, minimum 60s
    fetch_seconds = config.fetch_interval_seconds
    max_wait = max(fetch_seconds * 3 // 2, _MIN_WAIT_SECONDS)
    logger.info("Wait timeout: %ds (1.5× fetch interval)", max_wait)

    waited = 0
    replication_started = False

    while waited < max_wait:
        # Check pull_replication_log for activity
        if docker.exec_test(cid, "-f /var/gerrit/logs/pull_replication_log"):
            try:
                log_content = docker.exec_cmd(
                    cid,
                    "tail -n 50 /var/gerrit/logs/pull_replication_log 2>/dev/null",
                    check=False,
                    timeout=10,
                )
                if log_content.strip():
                    replication_started = True
                    if "completed" in log_content:
                        logger.info("✅ Replication activity detected and completed")
                        break
            except DockerError:
                pass

        time.sleep(5)
        waited += 5
        if waited % 15 == 0:
            logger.info("  Still waiting… %ds elapsed", waited)

    if not replication_started and waited >= max_wait:
        logger.warning(
            "No replication activity detected after %ds. "
            "This may be normal if the fetch interval is longer. "
            "Replication will continue in background via fetchEvery polling.",
            max_wait,
        )

    result.replication_started = replication_started

    # Show pull_replication_log content
    logger.info("")
    logger.info("Pull replication log (last 20 lines):")
    log_tail = show_pull_replication_log(docker, cid, lines=20)
    for line in log_tail.splitlines():
        logger.info("  %s", line)
    logger.info("")

    # Show container log replication activity
    logger.info("Container log replication activity:")
    try:
        logs = docker.container_logs(cid, tail=5000)
        repl_lines = [
            line
            for line in logs.splitlines()
            if re.search(r"pull-replication|fetch|FetchAll", line, re.IGNORECASE)
        ]
        for line in repl_lines[-10:]:
            logger.info("  %s", line.strip())
        if not repl_lines:
            logger.info("  (none)")
    except DockerError:
        logger.info("  (could not read logs)")
    logger.info("")

    # Count repositories
    result.repo_count = count_repositories(docker, cid)
    logger.info("Replicated repositories: %d", result.repo_count)

    # Show repository listing
    debug = config.debug
    if debug:
        logger.info("(DEBUG=true: showing full repository list)")
        repos = list_repositories(docker, cid, max_items=9999)
    else:
        logger.info("(showing first 50 repositories; set DEBUG=true for full list)")
        repos = list_repositories(docker, cid, max_items=50)
    for line in repos.splitlines():
        logger.info("  %s", line)
    logger.info("")

    # Compare against expected
    if expected_count > 0:
        logger.info("Expected repositories: %d", expected_count)
        if result.repo_count >= expected_count and replication_started:
            logger.info(
                "✅ Replication complete: %d/%d repositories (log indicates activity)",
                result.repo_count,
                expected_count,
            )
        elif result.repo_count >= expected_count:
            logger.info(
                "⏳ Repo count matches but awaiting replication log confirmation: %d/%d",
                result.repo_count,
                expected_count,
            )
        elif result.repo_count > 2:
            logger.info(
                "⏳ Replication in progress: %d/%d repositories",
                result.repo_count,
                expected_count,
            )
        else:
            logger.warning("Replication may still be starting")
    elif result.repo_count > 0 and replication_started:
        logger.info(
            "✅ Replication appears to be working (%d repositories, log indicates activity)",
            result.repo_count,
        )
    elif result.repo_count > 0:
        logger.info(
            "⏳ Repositories found (%d) but awaiting replication log confirmation",
            result.repo_count,
        )
    elif config.sync_on_startup:
        logger.warning(
            "No replicated repositories detected. Replication may still be in progress."
        )

    logger.info("")
    logger.info("Replication trigger completed for %s", slug)
    logger.info("")

    result.success = True
    return result


# ---------------------------------------------------------------------------
# Verify replication (wait for completion)
# ---------------------------------------------------------------------------


def wait_for_replication(
    docker: DockerManager,
    cid: str,
    slug: str,
    timeout: int,
    expected_count: int = 0,
    project: str = "",
    debug: bool = False,
    stability_window: int = _STABILITY_WINDOW_SECONDS,
) -> bool:
    """Wait for replication to complete for a single instance.

    The function uses **three complementary signals** to decide when
    replication is finished:

    1. **Repo count + log completions + content size** — the "classic"
       check.  If the repository count on disk meets the expected count,
       the pull-replication log shows completions for ≥ 90 % of repos,
       and disk usage exceeds the per-repo content threshold, we
       declare success immediately.

    2. **Steady-state detection** — a :class:`ReplicationSnapshot` is
       taken every poll cycle.  When the snapshot (completed count,
       disk usage in KB, log line count, repo count) has not changed
       for *stability_window* seconds **and** there is meaningful
       content, we declare success.  This handles the case where all
       repos are small (total < old 100 MB floor) or when the log
       shows periodic no-op fetch cycles that keep the file growing
       even though nothing is actually changing.

    3. **Error detection** — if ``check_replication_errors`` fires
       on *two consecutive* polls (to avoid transient false positives)
       we fail fast.

    Returns *True* on success.
    Raises :class:`ReplicationError` on timeout or persistent errors.
    """
    elapsed = 0
    interval = 5
    consecutive_errors = 0  # require 2 in a row before failing fast
    initial_count = count_repositories(docker, cid)

    logger.info("  Initial repository count: %d", initial_count)
    if project:
        logger.info("  Project filter: %s", project)
    if expected_count > 0:
        logger.info("  Expected from remote: %d", expected_count)
        logger.info("  Waiting up to %ds for all repositories…", timeout)
    else:
        logger.info("  No expected count available, waiting for replication activity…")
    logger.info(
        "  Stability window: %ds (declare done when state is unchanging)",
        stability_window,
    )
    logger.info("")

    tracker = _StabilityTracker(window=stability_window)

    while elapsed < timeout:
        time.sleep(interval)
        elapsed += interval

        # ---- 1. Error check (require 2 consecutive hits) ----
        if check_replication_errors(docker, cid):
            consecutive_errors += 1
            if consecutive_errors >= 2:
                logger.error("")
                logger.error("  ❌ Persistent replication errors detected!")
                logger.error("")
                logger.error("  Debugging info:")
                repos = list_repositories(docker, cid, max_items=10)
                for line in repos.splitlines():
                    logger.error("    %s", line)
                logger.error("")
                log_tail = show_pull_replication_log(docker, cid)
                for line in log_tail.splitlines():
                    logger.error("    %s", line)

                raise ReplicationError(
                    f"Replication errors detected for {slug}",
                    expected_count=expected_count,
                    actual_count=count_repositories(docker, cid),
                    elapsed=elapsed,
                )
            elif debug:
                logger.debug(
                    "  Transient replication error (attempt %d/2), will recheck",
                    consecutive_errors,
                )
        else:
            consecutive_errors = 0

        # ---- 2. Take a snapshot for steady-state tracking ----
        snap = take_snapshot(docker, cid)
        tracker.update(snap)

        current_count = snap.repo_count
        current_size_mb = snap.disk_usage_kb // 1024

        # ---- 3. Classic completion check ----
        if expected_count > 0 and current_count >= expected_count:
            has_content = check_replication_has_content(docker, cid, expected_count)
            log_ok = check_pull_replication_log(
                docker, cid, expected_count, debug=debug
            )

            if debug:
                logger.debug(
                    "  has_content=%s, log_ok=%s, count=%d, expected=%d",
                    has_content,
                    log_ok,
                    current_count,
                    expected_count,
                )

            if has_content and log_ok:
                logger.info("")
                logger.info(
                    "  ✅ Replication complete: %d/%d repositories",
                    current_count,
                    expected_count,
                )
                logger.info("  ✅ Content verified: %dMB fetched", current_size_mb)
                return True

        # No expected count — check for content growth and log activity
        if (
            expected_count <= 0
            and check_replication_has_content(docker, cid, 0)
            and check_pull_replication_log(docker, cid, debug=debug)
        ):
            logger.info("")
            logger.info(
                "  ✅ Replication complete: %d repositories (%dMB)",
                current_count,
                current_size_mb,
            )
            return True

        # ---- 4. Steady-state detection ----
        now = time.time()
        if tracker.is_stable(now):
            # State hasn't changed for stability_window seconds.
            # Check whether we have anything meaningful at all.
            has_any_content = snap.disk_usage_kb > 0 and snap.completed_count > 0

            # For expected-count scenarios: accept if count matches
            # even if the classic threshold didn't pass (covers the
            # "small repos" case where total disk < per-repo threshold).
            count_ok = (
                expected_count <= 0
                or current_count >= expected_count
                or snap.completed_count >= expected_count
            )

            if has_any_content and count_ok:
                logger.info("")
                logger.info(
                    "  ✅ Replication stable for %ds — declaring complete",
                    stability_window,
                )
                logger.info(
                    "     repos=%d, completed=%d, disk=%dMB, log_lines=%d",
                    snap.repo_count,
                    snap.completed_count,
                    current_size_mb,
                    snap.log_line_count,
                )
                return True

            if debug:
                logger.debug(
                    "  Stable for %ds but not enough content "
                    "(has_any_content=%s, count_ok=%s)",
                    stability_window,
                    has_any_content,
                    count_ok,
                )

        # ---- 5. Progress reporting every 15 seconds ----
        if elapsed % 15 == 0:
            disk_human = get_git_disk_usage_human(docker, cid)
            completed = snap.completed_count
            stable_secs = int(tracker.seconds_stable)

            if expected_count > 0:
                pct = (
                    completed * 100 // expected_count
                    if expected_count > 0 and completed > 0
                    else 0
                )
                logger.info(
                    "  [%ds/%ds] %d/%d unique repos completed (%d%%) "
                    "disk=%s stable=%ds",
                    elapsed,
                    timeout,
                    completed,
                    expected_count,
                    pct,
                    disk_human,
                    stable_secs,
                )
            else:
                logger.info(
                    "  [%ds/%ds] %d unique repos completed disk=%s stable=%ds",
                    elapsed,
                    timeout,
                    completed,
                    disk_human,
                    stable_secs,
                )

            # Log the reason we're still waiting (helps debugging)
            if debug and expected_count > 0:
                has_content = check_replication_has_content(docker, cid, expected_count)
                log_ok = check_pull_replication_log(
                    docker, cid, expected_count, debug=False
                )
                pending: list[str] = []
                if current_count < expected_count:
                    pending.append(f"repo_count ({current_count}<{expected_count})")
                if not has_content:
                    pending.append("content_threshold")
                if not log_ok:
                    pending.append("log_completions")
                if not tracker.is_stable(now):
                    pending.append(f"stability ({stable_secs}s<{stability_window}s)")
                if pending:
                    logger.debug("    Waiting on: %s", ", ".join(pending))

    # ---- Timeout ----
    final_snap = take_snapshot(docker, cid)
    final_count = final_snap.repo_count
    final_stable = int(tracker.seconds_stable)

    logger.error("")
    logger.error("  ❌ Timeout after %ds", timeout)
    logger.error("  Final: %d repositories", final_count)
    if expected_count > 0:
        logger.error("  Expected: %d", expected_count)

    disk_human = get_git_disk_usage_human(docker, cid)
    logger.error("  Disk usage: %s", disk_human)
    logger.error(
        "  State was stable for %ds (window=%ds)",
        final_stable,
        stability_window,
    )
    if final_stable >= stability_window:
        logger.error(
            "  ⚠️ Replication appears idle — the data above may be "
            "the final state.  Check whether the content threshold "
            "is appropriate for your repository sizes."
        )
    else:
        logger.error(
            "  ℹ️ Replication was still active at timeout — "
            "consider increasing REPLICATION_WAIT_TIMEOUT."
        )
    logger.error("")

    # Debugging info
    logger.error("  Debugging info:")
    repos = list_repositories(docker, cid, max_items=10)
    for line in repos.splitlines():
        logger.error("    %s", line)
    logger.error("")
    log_tail = show_pull_replication_log(docker, cid)
    for line in log_tail.splitlines():
        logger.error("    %s", line)

    raise ReplicationError(
        f"Replication timed out for {slug} after {timeout}s "
        f"(got {final_count}/{expected_count} repositories)",
        expected_count=expected_count,
        actual_count=final_count,
        elapsed=timeout,
    )


def verify_single_instance(
    docker: DockerManager,
    slug: str,
    instance: dict[str, Any],
    timeout: int = 180,
    debug: bool = False,
    stability_window: int = _STABILITY_WINDOW_SECONDS,
) -> VerificationResult:
    """Verify replication for a single instance.

    This runs the full verification flow from ``verify-replication.sh``:
    1. Verify plugin loaded
    2. Verify replication config
    3. Check for errors
    4. Wait for replication
    5. Report final stats
    """
    result = VerificationResult(slug=slug)

    cid = instance.get("cid", "")
    gerrit_host = instance.get("gerrit_host", "")
    project = instance.get("project", "")
    expected_count = int(instance.get("expected_project_count", 0))
    result.expected_count = expected_count

    logger.info("========================================")
    logger.info("Verifying replication: %s", slug)
    logger.info("========================================")
    logger.info("Container ID: %s", cid[:12] if cid else "(none)")
    logger.info("Source: %s", gerrit_host)
    if project:
        logger.info("Project filter: %s", project)
    logger.info("")

    # Verify container is running
    try:
        if not docker.container_exists(cid):
            result.error = f"Container {cid[:12]} not found"
            logger.error("%s ❌", result.error)
            return result

        state = docker.container_state(cid)
        if state != "running":
            result.error = f"Container not running (state: {state})"
            logger.error("%s ❌", result.error)
            return result
        logger.info("Container state: %s ✅", state)
    except DockerError as exc:
        result.error = str(exc)
        logger.error("Container check failed: %s", exc)
        return result

    # Step 1: Plugin check
    logger.info("")
    logger.info("Step 1: Verifying pull-replication plugin…")
    if not verify_plugin_loaded(docker, cid, "pull-replication"):
        result.error = "Pull-replication plugin not loaded"
        logger.error("%s ❌", result.error)
        return result

    # Step 2: Config check
    logger.info("")
    logger.info("Step 2: Verifying replication configuration…")
    if check_replication_config(docker, cid):
        logger.info("  replication.config found ✅")
        config_content = show_replication_config(docker, cid)
        if config_content:
            logger.info("  Configuration content:")
            for line in config_content.splitlines():
                logger.info("    %s", line)
    else:
        result.error = "replication.config not found"
        logger.error("%s ❌", result.error)
        return result

    logger.info("")
    logger.info("Step 2b: Verifying authentication configuration…")
    check_secure_config(docker, cid)

    # Step 3: Error check
    logger.info("")
    logger.info("Step 3: Checking for replication errors…")
    if check_replication_errors(docker, cid):
        result.error = "Replication errors detected"
        logger.error("Replication errors detected! ❌")
        log_tail = show_pull_replication_log(docker, cid)
        logger.error("  Pull replication log (recent):")
        for line in log_tail.splitlines():
            logger.error("    %s", line)

        # Show only replication-specific error lines from container logs.
        # Use the same narrow patterns as check_replication_errors() to
        # avoid dumping unrelated Gerrit errors (email, account mgmt, etc.)
        try:
            container_logs = docker.container_logs(cid, tail=3000)
            repl_error_pattern = "|".join(_CONTAINER_ERROR_PATTERNS)
            error_lines = [
                line
                for line in container_logs.splitlines()
                if re.search(repl_error_pattern, line, re.IGNORECASE)
            ]
            if error_lines:
                logger.error("  Replication-related container log errors:")
                for line in error_lines[-20:]:
                    logger.error("    %s", line.strip())
        except DockerError:
            pass
        return result

    logger.info("  No replication errors detected ✅")

    # Step 4: Wait for replication
    logger.info("")
    logger.info("Step 4: Waiting for replicated repositories…")
    try:
        wait_for_replication(
            docker,
            cid,
            slug,
            timeout=timeout,
            expected_count=expected_count,
            project=project,
            debug=debug,
            stability_window=stability_window,
        )
        logger.info("  Replication verified ✅")

        # List sample repos
        logger.info("")
        logger.info("  Sample replicated repositories:")
        try:
            sample = docker.exec_cmd(
                cid,
                "find /var/gerrit/git -name '*.git' -type d -prune 2>/dev/null | "
                "grep -v 'All-Projects\\|All-Users' | head -5",
                check=False,
                timeout=10,
            )
            for line in sample.splitlines():
                logger.info("    %s", line)
        except DockerError:
            pass

    except ReplicationError as exc:
        result.error = str(exc)
        logger.error("Replication verification failed: %s", exc)

        # Show recent logs
        try:
            container_logs = docker.container_logs(cid, tail=3000)
            repl_lines = [
                line
                for line in container_logs.splitlines()
                if re.search(
                    r"replication|pull-replication|fetch|remote",
                    line,
                    re.IGNORECASE,
                )
            ]
            if repl_lines:
                logger.error("  Recent replication logs:")
                for line in repl_lines[-20:]:
                    logger.error("    %s", line.strip())
        except DockerError:
            pass
        return result

    # Step 5: Final stats
    logger.info("")
    logger.info("Step 5: Final replication statistics…")
    result.repo_count = count_repositories(docker, cid)
    result.completed_count = get_completed_repo_count(docker, cid)
    result.disk_usage = get_git_disk_usage_human(docker, cid)
    result.disk_usage_mb = get_git_disk_usage_mb(docker, cid)

    logger.info("  Replicated repositories: %d", result.repo_count)
    if expected_count > 0:
        logger.info("  Expected from remote: %d", expected_count)

        # Validate count with tolerance
        min_required = expected_count * 95 // 100
        if result.repo_count >= min_required:
            logger.info("  ✅ Project count matches expected (within 5%% tolerance)")
        elif expected_count > 0:
            pct = result.repo_count * 100 // expected_count
            logger.warning(
                "  ⚠️ Project count mismatch: got %d%% of expected projects",
                pct,
            )

    logger.info("  Disk usage: %s", result.disk_usage)
    logger.info("")
    logger.info("✅ Instance %s verification passed", slug)
    logger.info("")

    result.success = True
    return result


# ---------------------------------------------------------------------------
# Multi-instance orchestrators
# ---------------------------------------------------------------------------


def trigger_all_instances(
    docker: DockerManager,
    instance_store: InstanceStore,
    config: ActionConfig,
) -> list[TriggerResult]:
    """Trigger replication for all instances.

    This is the top-level entry point replacing ``trigger-replication.sh``.
    """
    logger.info("Triggering initial replication…")
    logger.info("")

    fetch_seconds = config.fetch_interval_seconds
    logger.info("Fetch interval: %s (%d seconds)", config.fetch_every, fetch_seconds)
    max_wait = max(fetch_seconds * 3 // 2, _MIN_WAIT_SECONDS)
    logger.info("Wait timeout: %ds (1.5× fetch interval)", max_wait)
    logger.info("")

    results: list[TriggerResult] = []

    for slug, instance in instance_store:
        cid = instance.get("cid", "")
        result = trigger_replication(docker, cid, slug, instance, config)
        results.append(result)

    # Summary
    failed = [r for r in results if not r.success]

    logger.info("========================================")
    if not failed:
        logger.info("Replication triggered for all instances ✅")
        logger.info("========================================")
        logger.info("")

        lines = [
            "**Replication Status** 🔄",
            "",
            "Replication has been triggered for all instances.",
            "",
            "_Note: Initial replication may take several minutes "
            "depending on repository sizes._",
            "",
        ]
        write_summary("\n".join(lines))
    else:
        logger.warning("Some replication triggers failed ⚠️")
        logger.info("========================================")
        logger.info("")

        lines = [
            "**Replication Trigger Status** ⚠️",
            "",
            "Some replication triggers encountered issues.",
            "Check logs for details.",
            "",
        ]
        write_summary("\n".join(lines))

    # Monitoring instructions
    monitor_lines = [
        "To monitor ongoing replication, check container logs:",
        "```bash",
    ]
    for _slug, instance in instance_store:
        cid = instance.get("cid", "")
        monitor_lines.append(f"docker logs -f {cid} | grep replication")
    monitor_lines.extend(["```", ""])
    write_summary("\n".join(monitor_lines))

    return results


def verify_all_instances(
    docker: DockerManager,
    instance_store: InstanceStore,
    timeout: int = 180,
    debug: bool = False,
    stability_window: int = _STABILITY_WINDOW_SECONDS,
) -> list[VerificationResult]:
    """Verify replication for all instances.

    This is the top-level entry point replacing ``verify-replication.sh``.

    Raises :class:`ReplicationError` if any instance fails.
    """
    logger.info("Verifying replication success…")
    logger.info("")

    results: list[VerificationResult] = []
    total = 0

    for slug, instance in instance_store:
        total += 1
        r = verify_single_instance(
            docker,
            slug,
            instance,
            timeout=timeout,
            debug=debug,
            stability_window=stability_window,
        )
        results.append(r)

    # Summary
    failed = [r for r in results if not r.success]

    logger.info("========================================")
    logger.info("Verification Summary")
    logger.info("========================================")
    logger.info("Total instances: %d", total)
    logger.info("Failed: %d", len(failed))
    logger.info("")

    if not failed:
        logger.info("All replication verifications passed! ✅")
        logger.info("")

        # Disk usage summary
        logger.info("========================================")
        logger.info("Disk Usage Summary")
        logger.info("========================================")
        for r in results:
            logger.info("")
            logger.info("Instance: %s", r.slug)
            logger.info("  Disk usage: %s", r.disk_usage)
        logger.info("")

        # Step summary
        summary_lines = [
            "## Replication Verification ✅",
            "",
            "All instances successfully replicated from source Gerrit servers.",
            "",
            "### Instance Details",
            "",
            "| Instance | Repos | Expected | Disk Usage |",
            "|----------|-------|----------|------------|",
        ]
        for r in results:
            expected_display = str(r.expected_count) if r.expected_count > 0 else "N/A"
            summary_lines.append(
                f"| {r.slug} | {r.repo_count} | {expected_display} | {r.disk_usage} |"
            )
        summary_lines.append("")
        write_summary("\n".join(summary_lines))
    else:
        logger.error("Some verifications failed ❌")
        logger.info("")

        lines = [
            "**Replication Verification** ❌",
            "",
            f"{len(failed)} of {total} instances failed verification.",
            "",
            "Check the workflow logs for detailed error information.",
            "",
        ]
        write_summary("\n".join(lines))

        slugs = ", ".join(r.slug for r in failed)
        raise ReplicationError(
            f"Replication verification failed for: {slugs}",
            expected_count=sum(r.expected_count for r in failed),
            actual_count=sum(r.repo_count for r in failed),
        )

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_int(raw: str) -> int:
    """Parse a string to int, stripping non-digit characters.

    Returns 0 if the string contains no digits.
    """
    digits = re.sub(r"[^0-9]", "", raw.strip())
    return int(digits) if digits else 0
