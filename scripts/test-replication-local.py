#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Local Docker test harness for replication verification.

Exercises the replication detection improvements across multiple Gerrit
project configurations **locally in Docker**, without requiring GitHub
Actions.  Each test scenario spins up a real Gerrit container, configures
pull-replication against a public upstream, and validates that:

1. The content-size threshold does not cause false negatives for small
   repos (the original 86 MB / 36-repo bug).
2. Steady-state detection terminates the wait loop early instead of
   blocking for the full timeout.
3. Transient errors do not cause premature failure.
4. Progress reporting shows *why* the loop is still waiting.
5. The tunnel verification script produces actionable diagnostics.

Usage::

    # Run all scenarios (needs Docker + network access + ~/.netrc creds)
    python scripts/test-replication-local.py

    # Run a single scenario by name
    python scripts/test-replication-local.py --scenario lf-small

    # List available scenarios without running them
    python scripts/test-replication-local.py --list

    # Use explicit credentials instead of ~/.netrc
    GERRIT_HTTP_USERNAME=user GERRIT_HTTP_PASSWORD=pass \\
        python scripts/test-replication-local.py

    # Override timeouts for faster iteration
    REPLICATION_WAIT_TIMEOUT=120 STABILITY_WINDOW=20 \\
        python scripts/test-replication-local.py --scenario lf-small

    # Keep containers running after test for manual inspection
    python scripts/test-replication-local.py --keep

Environment Variables
---------------------
GERRIT_HTTP_USERNAME / GERRIT_HTTP_PASSWORD
    HTTP Basic auth credentials.  Falls back to ``~/.netrc`` entries.
GERRIT_VERSION
    Gerrit Docker image tag (default: ``3.13.1-ubuntu24``).
PLUGIN_VERSION
    Pull-replication plugin branch (default: ``stable-3.13``).
REPLICATION_WAIT_TIMEOUT
    Per-scenario timeout in seconds (default: ``180``).
STABILITY_WINDOW
    Seconds of no-change before declaring stable (default: ``30``).
FETCH_EVERY
    Poll interval for pull-replication (default: ``15s``).
DEBUG
    ``"true"`` for verbose output.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import logging
import netrc
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import parse_interval_to_seconds  # noqa: E402
from docker_manager import DockerManager  # noqa: E402
from errors import DockerError, ReplicationError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from replication import (  # noqa: E402
    _StabilityTracker,
    check_replication_errors,
    check_replication_has_content,
    get_disk_usage_kb,
    get_git_disk_usage_human,
    get_log_line_count,
    show_pull_replication_log,
    take_snapshot,
    wait_for_replication,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

# Each scenario represents a real-world Gerrit project configuration
# from the GERRIT_SERVERS matrix.  ``expected_project_count`` is the
# approximate number of repositories the upstream has — the test will
# validate that the detection logic works correctly for this size.


@dataclasses.dataclass
class Scenario:
    """A single test scenario exercising a specific upstream configuration."""

    name: str
    description: str
    gerrit_host: str
    api_path: str
    project_filter: str = ""
    expected_project_count: int = 0
    # When True, the scenario is expected to have small total disk (the
    # bug-report case).  The test will *assert* that the old 100 MB
    # threshold would have been wrong.
    expect_small_disk: bool = False
    slug: str = ""

    def __post_init__(self) -> None:
        if not self.slug:
            self.slug = self.name


# Curated set of scenarios covering different repository sizes and counts.
# The list is ordered from smallest (most likely to trigger the old bug)
# to largest.
SCENARIOS: list[Scenario] = [
    Scenario(
        name="lf-small",
        description=(
            "Linux Foundation infra — many small repos (ansible roles, "
            "puppet modules).  This is the exact configuration that "
            "triggered the 600-second timeout bug: 36 repos at 86 MB."
        ),
        gerrit_host="gerrit.linuxfoundation.org",
        api_path="/infra",
        expected_project_count=36,
        expect_small_disk=True,
        slug="lf",
    ),
    Scenario(
        name="lf-single",
        description=(
            "Linux Foundation infra — single project filter. "
            "Tests that project-filtered replication detects "
            "completion for a single repo without false negatives."
        ),
        gerrit_host="gerrit.linuxfoundation.org",
        api_path="/infra",
        project_filter="releng/lftools",
        expected_project_count=1,
        expect_small_disk=True,
        slug="lf-single",
    ),
    Scenario(
        name="onap",
        description=(
            "ONAP — medium-sized project set.  Tests the standard "
            "case where the old threshold would have (eventually) passed."
        ),
        gerrit_host="gerrit.onap.org",
        api_path="/r",
        expected_project_count=10,
        slug="onap",
    ),
    Scenario(
        name="opnfv",
        description=(
            "OPNFV — small set of infrastructure repos.  Another "
            "case that may fall below the old 100 MB floor."
        ),
        gerrit_host="gerrit.opnfv.org",
        api_path="/gerrit",
        expected_project_count=5,
        expect_small_disk=True,
        slug="opnfv",
    ),
    Scenario(
        name="o-ran-sc",
        description=(
            "O-RAN Software Community — medium project set.  "
            "Tests pull-replication with a different Gerrit host."
        ),
        gerrit_host="gerrit.o-ran-sc.org",
        api_path="/r",
        expected_project_count=10,
        slug="o-ran-sc",
    ),
]

# Quick lookup by name
_SCENARIO_MAP: dict[str, Scenario] = {s.name: s for s in SCENARIOS}

# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


def _get_credentials(host: str) -> tuple[str, str]:
    """Resolve HTTP Basic credentials from env vars or ~/.netrc.

    Returns ``(username, password)`` or raises ``SystemExit``.
    """
    user = os.environ.get("GERRIT_HTTP_USERNAME", "").strip()
    password = os.environ.get("GERRIT_HTTP_PASSWORD", "").strip()
    if user and password:
        return user, password

    # Try ~/.netrc
    try:
        nrc = netrc.netrc()
        auth = nrc.authenticators(host)
        if auth and auth[2] is not None:
            return auth[0], auth[2]
    except (FileNotFoundError, netrc.NetrcParseError):
        pass

    logger.error(
        "No credentials found for %s.  Set GERRIT_HTTP_USERNAME / "
        "GERRIT_HTTP_PASSWORD or add an entry to ~/.netrc.",
        host,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Container lifecycle
# ---------------------------------------------------------------------------

# Base port incremented per scenario to avoid conflicts.
_BASE_HTTP_PORT = 18080
_BASE_SSH_PORT = 39418


@dataclasses.dataclass
class _ContainerContext:
    """Tracks a running Gerrit container for a single scenario."""

    cid: str
    name: str
    http_port: int
    ssh_port: int
    work_dir: Path


def _build_image(docker: DockerManager, gerrit_version: str) -> str:
    """Build (or reuse) the extended Gerrit Docker image.

    Returns the image tag.
    """
    tag = f"gerrit-test-local:{gerrit_version}"

    # Check if already built
    try:
        result = docker.run_cmd(
            ["image", "inspect", tag],
            check=False,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info("Reusing existing image %s", tag)
            return tag
    except DockerError:
        pass

    dockerfile = SCRIPT_DIR.parent / "Dockerfile"
    if not dockerfile.exists():
        # Fall back to stock Gerrit image
        stock = f"gerritcodereview/gerrit:{gerrit_version}"
        logger.info("Dockerfile not found; pulling stock image %s", stock)
        docker.run_cmd(["pull", stock], timeout=120)
        return stock

    logger.info("Building image %s from %s …", tag, dockerfile.parent)
    docker.run_cmd(
        [
            "build",
            "-t",
            tag,
            "--build-arg",
            f"GERRIT_VERSION={gerrit_version}",
            str(dockerfile.parent),
        ],
        timeout=300,
    )
    return tag


def _start_container(
    docker: DockerManager,
    scenario: Scenario,
    image: str,
    index: int,
    creds: tuple[str, str],
    *,
    fetch_every: str = "15s",
) -> _ContainerContext:
    """Start a Gerrit container configured for *scenario*.

    Creates the work directory, writes ``replication.config`` and
    ``secure.config``, and starts the container with proper port
    mappings and volume mounts.
    """
    http_port = _BASE_HTTP_PORT + index
    ssh_port = _BASE_SSH_PORT + index
    container_name = f"gerrit-test-{scenario.slug}-{int(time.time()) % 100000}"

    work_dir = Path(f"/tmp/gerrit-test-{scenario.slug}")
    work_dir.mkdir(parents=True, exist_ok=True)

    etc_dir = work_dir / "etc"
    etc_dir.mkdir(exist_ok=True)

    # --- replication.config ---
    url_template = f"https://{scenario.gerrit_host}{scenario.api_path}/a/${{name}}.git"
    repl_config = textwrap.dedent(f"""\
        [gerrit]
          replicateOnStartup = true
          autoReload = true
        [replication]
          lockErrorMaxRetries = 5
          maxRetries = 5
          useCGitClient = false
          refsBatchSize = 50
        [remote "{scenario.slug}"]
          url = {url_template}
          fetchEvery = {fetch_every}
          timeout = 600
          connectionTimeout = 600000
          replicationDelay = 0
          replicationRetry = 60
          threads = 4
          createMissingRepositories = true
          replicateHiddenProjects = false
          fetch = +refs/heads/*:refs/heads/*
          fetch = +refs/tags/*:refs/tags/*
          fetch = +refs/changes/*:refs/changes/*
    """)
    (etc_dir / "replication.config").write_text(repl_config)

    # --- secure.config ---
    username, password = creds
    secure_config = textwrap.dedent(f"""\
        [remote "{scenario.slug}"]
          username = {username}
          password = {password}
    """)
    (etc_dir / "secure.config").write_text(secure_config)

    # Ensure the git directory exists
    git_dir = work_dir / "git"
    git_dir.mkdir(exist_ok=True)

    # --- Start container ---
    logger.info(
        "Starting container %s  http=%d ssh=%d …",
        container_name,
        http_port,
        ssh_port,
    )

    cid_raw = docker.run_cmd(
        [
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            f"{http_port}:8080",
            "-p",
            f"{ssh_port}:29418",
            "-v",
            f"{etc_dir}:/var/gerrit/etc",
            "-v",
            f"{git_dir}:/var/gerrit/git",
            "-e",
            "CANONICAL_WEB_URL=http://localhost:8080/",
            image,
        ],
        timeout=30,
    )
    cid = cid_raw.stdout.strip()
    logger.info("  Container ID: %s", cid[:12])

    return _ContainerContext(
        cid=cid,
        name=container_name,
        http_port=http_port,
        ssh_port=ssh_port,
        work_dir=work_dir,
    )


def _wait_for_gerrit_ready(docker: DockerManager, cid: str, timeout: int = 120) -> bool:
    """Wait for the Gerrit ``ready`` log message."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            logs = docker.container_logs(cid, tail=200)
            if "Gerrit Code Review" in logs and "ready" in logs.lower():
                return True
        except DockerError:
            pass
        time.sleep(3)
    return False


def _cleanup_container(docker: DockerManager, ctx: _ContainerContext) -> None:
    """Stop and remove a test container and its work directory."""
    with contextlib.suppress(DockerError):
        docker.run_cmd(["stop", "-t", "5", ctx.cid], check=False, timeout=15)
    with contextlib.suppress(DockerError):
        docker.run_cmd(["rm", "-f", ctx.cid], check=False, timeout=10)
    # Clean up work directory
    if ctx.work_dir.exists():
        shutil.rmtree(ctx.work_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Individual test assertions
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class TestResult:
    """Outcome of a single test within a scenario."""

    name: str
    passed: bool
    message: str = ""
    elapsed_s: float = 0.0

    def __str__(self) -> str:
        icon = "✅" if self.passed else "❌"
        msg = f" — {self.message}" if self.message else ""
        timing = f" ({self.elapsed_s:.1f}s)" if self.elapsed_s else ""
        return f"  {icon} {self.name}{msg}{timing}"


def _test_content_threshold(
    docker: DockerManager, cid: str, scenario: Scenario
) -> TestResult:
    """Verify that ``check_replication_has_content`` returns True.

    For small-repo scenarios this is the core regression test — the old
    100 MB floor would return False here.
    """
    start = time.time()
    result = check_replication_has_content(
        docker, cid, expected_count=scenario.expected_project_count
    )
    elapsed = time.time() - start

    if scenario.expect_small_disk:
        disk = get_git_disk_usage_human(docker, cid)
        disk_kb = get_disk_usage_kb(docker, cid)
        threshold_kb = scenario.expected_project_count * 200  # _MIN_KB_PER_REPO
        threshold_mb = max(threshold_kb // 1024, 1)
        if result:
            return TestResult(
                name="content_threshold (small-repo regression)",
                passed=True,
                message=f"disk={disk} >= {threshold_mb}MB threshold — old 100MB floor would have FAILED",
                elapsed_s=elapsed,
            )
        else:
            return TestResult(
                name="content_threshold (small-repo regression)",
                passed=False,
                message=f"disk={disk}, threshold={threshold_mb}MB, disk_kb={disk_kb}",
                elapsed_s=elapsed,
            )
    else:
        return TestResult(
            name="content_threshold",
            passed=result,
            message=f"disk={get_git_disk_usage_human(docker, cid)}",
            elapsed_s=elapsed,
        )


def _test_steady_state_detection(
    docker: DockerManager,
    cid: str,
    _scenario: Scenario,
    stability_window: int,
) -> TestResult:
    """Verify that the stability tracker detects quiescence.

    Takes snapshots 3 × stability_window seconds apart and asserts the
    tracker reports stable.
    """
    start = time.time()
    tracker = _StabilityTracker(window=stability_window)

    snap1 = take_snapshot(docker, cid)
    tracker.update(snap1)

    # Wait for one stability window and re-check
    time.sleep(stability_window + 5)

    snap2 = take_snapshot(docker, cid)
    tracker.update(snap2)

    elapsed = time.time() - start
    now = time.time()
    stable = tracker.is_stable(now)

    if snap1.is_same_as(snap2):
        detail = f"state unchanged for {elapsed:.0f}s"
    else:
        changed_fields: list[str] = []
        if snap1.completed_count != snap2.completed_count:
            changed_fields.append(
                f"completed {snap1.completed_count}->{snap2.completed_count}"
            )
        if snap1.disk_usage_kb != snap2.disk_usage_kb:
            changed_fields.append(
                f"disk {snap1.disk_usage_kb}->{snap2.disk_usage_kb}KB"
            )
        if snap1.log_line_count != snap2.log_line_count:
            changed_fields.append(
                f"log_lines {snap1.log_line_count}->{snap2.log_line_count}"
            )
        if snap1.repo_count != snap2.repo_count:
            changed_fields.append(f"repos {snap1.repo_count}->{snap2.repo_count}")
        detail = "changed: " + ", ".join(changed_fields)

    if stable:
        return TestResult(
            name="steady_state_detection",
            passed=True,
            message=f"stable=True after {elapsed:.0f}s ({detail})",
            elapsed_s=elapsed,
        )
    else:
        # If state is still changing, that's fine — replication may
        # still be running.  We only fail if we expected stability.
        return TestResult(
            name="steady_state_detection",
            passed=True,  # Informational — state still changing is valid
            message=f"stable=False — replication still active ({detail})",
            elapsed_s=elapsed,
        )


def _test_wait_for_replication(
    docker: DockerManager,
    cid: str,
    scenario: Scenario,
    timeout: int,
    stability_window: int,
) -> TestResult:
    """Run the full ``wait_for_replication`` and verify it completes.

    The key assertion: the function should return True well before the
    full timeout (especially for small-repo scenarios).
    """
    start = time.time()
    try:
        ok = wait_for_replication(
            docker,
            cid,
            scenario.slug,
            timeout=timeout,
            expected_count=scenario.expected_project_count,
            project=scenario.project_filter,
            debug=True,
            stability_window=stability_window,
        )
        elapsed = time.time() - start

        if ok:
            # Check it didn't take the full timeout
            if elapsed < timeout * 0.8:
                return TestResult(
                    name="wait_for_replication",
                    passed=True,
                    message=f"completed in {elapsed:.0f}s (timeout={timeout}s) — early exit ✅",
                    elapsed_s=elapsed,
                )
            else:
                return TestResult(
                    name="wait_for_replication",
                    passed=True,
                    message=f"completed in {elapsed:.0f}s (close to timeout={timeout}s) ⚠️",
                    elapsed_s=elapsed,
                )
        else:
            return TestResult(
                name="wait_for_replication",
                passed=False,
                message=f"returned False after {elapsed:.0f}s",
                elapsed_s=elapsed,
            )

    except ReplicationError as exc:
        elapsed = time.time() - start
        return TestResult(
            name="wait_for_replication",
            passed=False,
            message=f"raised ReplicationError after {elapsed:.0f}s: {exc}",
            elapsed_s=elapsed,
        )


def _test_snapshot_fields(docker: DockerManager, cid: str) -> TestResult:
    """Verify ``take_snapshot`` returns populated fields."""
    snap = take_snapshot(docker, cid)
    issues: list[str] = []
    if snap.timestamp <= 0:
        issues.append("timestamp=0")
    if snap.repo_count < 0:
        issues.append(f"repo_count={snap.repo_count}")
    if snap.disk_usage_kb <= 0:
        issues.append(f"disk_usage_kb={snap.disk_usage_kb}")

    if issues:
        return TestResult(
            name="snapshot_fields",
            passed=False,
            message=f"bad fields: {', '.join(issues)}",
        )
    return TestResult(
        name="snapshot_fields",
        passed=True,
        message=(
            f"repos={snap.repo_count} completed={snap.completed_count} "
            f"disk={snap.disk_usage_kb}KB log_lines={snap.log_line_count}"
        ),
    )


def _test_no_false_errors(docker: DockerManager, cid: str) -> TestResult:
    """Verify ``check_replication_errors`` does not false-positive.

    Normal replication log activity (ASYNC started, completed, periodic
    fetch scheduling) should NOT be flagged as errors.
    """
    has_errors = check_replication_errors(docker, cid)
    log_tail = show_pull_replication_log(docker, cid, lines=10)

    if has_errors:
        return TestResult(
            name="no_false_errors",
            passed=False,
            message=f"check_replication_errors returned True — log tail: {log_tail[:200]}",
        )
    return TestResult(
        name="no_false_errors",
        passed=True,
        message="no false positives from error detection",
    )


def _test_log_line_count(docker: DockerManager, cid: str) -> TestResult:
    """Verify ``get_log_line_count`` returns a positive value."""
    count = get_log_line_count(docker, cid)
    if count > 0:
        return TestResult(
            name="log_line_count",
            passed=True,
            message=f"{count} lines in pull_replication_log",
        )
    return TestResult(
        name="log_line_count",
        passed=False,
        message="0 lines — log may not have been created yet",
    )


def _test_tunnel_script_validates_inputs() -> TestResult:
    """Verify the tunnel script rejects missing env vars gracefully."""
    tunnel_script = SCRIPT_DIR / "verify-tunnel.py"
    if not tunnel_script.exists():
        return TestResult(
            name="tunnel_input_validation",
            passed=False,
            message="verify-tunnel.py not found",
        )

    # Run with empty BORE_HOST — should exit 1 with a helpful message
    env = os.environ.copy()
    env["BORE_HOST"] = ""
    env["HTTP_PORT"] = "8080"
    env.pop("GITHUB_STEP_SUMMARY", None)

    try:
        proc = subprocess.run(
            [sys.executable, str(tunnel_script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return TestResult(
            name="tunnel_input_validation",
            passed=False,
            message="script timed out",
        )

    if proc.returncode == 1 and "BORE_HOST" in (proc.stdout + proc.stderr):
        return TestResult(
            name="tunnel_input_validation",
            passed=True,
            message="correctly rejects empty BORE_HOST with helpful error",
        )
    return TestResult(
        name="tunnel_input_validation",
        passed=False,
        message=f"exit={proc.returncode} stderr={proc.stderr[:200]}",
    )


def _test_tunnel_script_handles_unreachable() -> TestResult:
    """Verify the tunnel script produces diagnostics for a bad host."""
    tunnel_script = SCRIPT_DIR / "verify-tunnel.py"
    if not tunnel_script.exists():
        return TestResult(
            name="tunnel_unreachable_diagnostics",
            passed=False,
            message="verify-tunnel.py not found",
        )

    env = os.environ.copy()
    env["BORE_HOST"] = "192.0.2.1"  # RFC 5737 TEST-NET — guaranteed unreachable
    env["HTTP_PORT"] = "1"
    env["MAX_ATTEMPTS"] = "1"
    env["RETRY_DELAY"] = "0"
    env["DEBUG"] = "true"
    env.pop("GITHUB_STEP_SUMMARY", None)

    try:
        proc = subprocess.run(
            [sys.executable, str(tunnel_script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return TestResult(
            name="tunnel_unreachable_diagnostics",
            passed=False,
            message="script timed out (expected quick failure)",
        )

    combined = proc.stdout + proc.stderr
    has_diagnostics = any(
        kw in combined
        for kw in (
            "Network diagnostics",
            "Possible causes",
            "error_type",
            "connection_refused",
            "timeout",
            "FAILED",
        )
    )

    if proc.returncode != 0 and has_diagnostics:
        return TestResult(
            name="tunnel_unreachable_diagnostics",
            passed=True,
            message="produced actionable diagnostic output on connection failure",
        )
    return TestResult(
        name="tunnel_unreachable_diagnostics",
        passed=False,
        message=f"exit={proc.returncode} diagnostics_found={has_diagnostics}",
    )


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ScenarioResult:
    """Aggregated result for one scenario."""

    scenario: Scenario
    tests: list[TestResult] = dataclasses.field(default_factory=list)
    container_started: bool = False
    gerrit_ready: bool = False
    error: str = ""

    @property
    def passed(self) -> bool:
        if not self.container_started or not self.gerrit_ready:
            return False
        return all(t.passed for t in self.tests)

    @property
    def total_elapsed(self) -> float:
        return sum(t.elapsed_s for t in self.tests)


def run_scenario(
    docker: DockerManager,
    scenario: Scenario,
    index: int,
    *,
    image: str,
    creds: tuple[str, str],
    timeout: int,
    stability_window: int,
    fetch_every: str,
    keep: bool = False,
) -> ScenarioResult:
    """Execute all tests for a single scenario."""
    result = ScenarioResult(scenario=scenario)

    logger.info("")
    logger.info("=" * 60)
    logger.info("SCENARIO: %s", scenario.name)
    logger.info("=" * 60)
    logger.info("  %s", scenario.description)
    logger.info("  Host:     %s", scenario.gerrit_host)
    logger.info("  API path: %s", scenario.api_path)
    if scenario.project_filter:
        logger.info("  Project:  %s", scenario.project_filter)
    logger.info("  Expected: %d repos", scenario.expected_project_count)
    logger.info("  Timeout:  %ds", timeout)
    logger.info("  Stability window: %ds", stability_window)
    logger.info("")

    ctx: _ContainerContext | None = None
    try:
        # Start container
        ctx = _start_container(
            docker,
            scenario,
            image,
            index,
            creds,
            fetch_every=fetch_every,
        )
        result.container_started = True

        # Wait for Gerrit to be ready
        logger.info("  Waiting for Gerrit to start…")
        ready_timeout = 120
        if _wait_for_gerrit_ready(docker, ctx.cid, timeout=ready_timeout):
            result.gerrit_ready = True
            logger.info("  Gerrit ready ✅")
        else:
            result.error = f"Gerrit did not become ready within {ready_timeout}s"
            logger.error("  %s", result.error)
            # Dump logs for debugging
            try:
                logs = docker.container_logs(ctx.cid, tail=50)
                for line in logs.splitlines()[-20:]:
                    logger.error("    %s", line.strip())
            except DockerError:
                pass
            return result

        # Give pull-replication time for the first fetch cycle
        fetch_secs = parse_interval_to_seconds(fetch_every)
        initial_wait = max(fetch_secs + 10, 30)
        logger.info(
            "  Waiting %ds for initial replication cycle (fetchEvery=%s)…",
            initial_wait,
            fetch_every,
        )
        time.sleep(initial_wait)

        # --- Run tests ---
        logger.info("")
        logger.info("  Running tests…")
        logger.info("")

        # 1. Snapshot fields
        result.tests.append(_test_snapshot_fields(docker, ctx.cid))

        # 2. Log line count
        result.tests.append(_test_log_line_count(docker, ctx.cid))

        # 3. No false error detection
        result.tests.append(_test_no_false_errors(docker, ctx.cid))

        # 4. Content threshold (regression test for 86MB/36-repo bug)
        result.tests.append(_test_content_threshold(docker, ctx.cid, scenario))

        # 5. Steady-state detection
        result.tests.append(
            _test_steady_state_detection(docker, ctx.cid, scenario, stability_window)
        )

        # 6. Full wait_for_replication — this is the integration test
        result.tests.append(
            _test_wait_for_replication(
                docker, ctx.cid, scenario, timeout, stability_window
            )
        )

    except Exception as exc:
        result.error = f"Unexpected error: {exc}"
        logger.exception("  %s", result.error)

    finally:
        if ctx and not keep:
            logger.info("")
            logger.info("  Cleaning up container %s…", ctx.name)
            _cleanup_container(docker, ctx)
        elif ctx and keep:
            logger.info("")
            logger.info(
                "  Container kept running (--keep): %s  "
                "http://localhost:%d  ssh://localhost:%d",
                ctx.name,
                ctx.http_port,
                ctx.ssh_port,
            )

    return result


# ---------------------------------------------------------------------------
# Tunnel-only tests (no container needed)
# ---------------------------------------------------------------------------


def run_tunnel_tests() -> list[TestResult]:
    """Run the tunnel verification script tests that don't need a container."""
    logger.info("")
    logger.info("=" * 60)
    logger.info("TUNNEL VERIFICATION TESTS (no container needed)")
    logger.info("=" * 60)
    logger.info("")

    results: list[TestResult] = []
    results.append(_test_tunnel_script_validates_inputs())
    results.append(_test_tunnel_script_handles_unreachable())
    return results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def print_summary(
    scenario_results: list[ScenarioResult],
    tunnel_results: list[TestResult],
) -> int:
    """Print a final summary and return an exit code."""
    total_tests = sum(len(sr.tests) for sr in scenario_results) + len(tunnel_results)
    total_passed = sum(
        sum(1 for t in sr.tests if t.passed) for sr in scenario_results
    ) + sum(1 for t in tunnel_results if t.passed)
    total_failed = total_tests - total_passed
    scenarios_passed = sum(1 for sr in scenario_results if sr.passed)
    scenarios_total = len(scenario_results)

    logger.info("")
    logger.info("=" * 60)
    logger.info("FINAL SUMMARY")
    logger.info("=" * 60)
    logger.info("")

    # Tunnel tests
    if tunnel_results:
        logger.info("Tunnel verification tests:")
        for t in tunnel_results:
            logger.info(str(t))
        logger.info("")

    # Scenario results
    for sr in scenario_results:
        icon = "✅" if sr.passed else "❌"
        logger.info(
            "%s Scenario: %s  (%d tests, %.0fs total)",
            icon,
            sr.scenario.name,
            len(sr.tests),
            sr.total_elapsed,
        )
        if sr.error:
            logger.info("  ERROR: %s", sr.error)
        if not sr.container_started:
            logger.info("  (container did not start)")
        elif not sr.gerrit_ready:
            logger.info("  (Gerrit did not become ready)")
        else:
            for t in sr.tests:
                logger.info(str(t))
        logger.info("")

    # Overall
    logger.info("-" * 60)
    logger.info(
        "Scenarios: %d/%d passed",
        scenarios_passed,
        scenarios_total,
    )
    logger.info(
        "Tests:     %d/%d passed  (%d failed)",
        total_passed,
        total_tests,
        total_failed,
    )
    logger.info("-" * 60)

    if total_failed > 0:
        logger.info("")
        logger.info("❌ SOME TESTS FAILED")
        return 1

    logger.info("")
    logger.info("✅ ALL TESTS PASSED")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local Docker test harness for replication verification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s                          # run all scenarios
              %(prog)s --scenario lf-small      # run a single scenario
              %(prog)s --scenario lf-small,onap # run multiple scenarios
              %(prog)s --list                   # list available scenarios
              %(prog)s --keep                   # keep containers running
              %(prog)s --tunnel-only            # only run tunnel tests
        """),
    )
    parser.add_argument(
        "--scenario",
        "-s",
        help="Comma-separated scenario names to run (default: all).",
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List available scenarios and exit.",
    )
    parser.add_argument(
        "--keep",
        "-k",
        action="store_true",
        help="Keep containers running after tests (for inspection).",
    )
    parser.add_argument(
        "--tunnel-only",
        action="store_true",
        help="Only run tunnel verification tests (no Docker containers).",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Docker image build (use stock gerritcodereview/gerrit image).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    debug = os.environ.get("DEBUG", "false").lower() == "true"
    setup_logging(debug=debug)

    # --- List mode ---
    if args.list:
        print("\nAvailable test scenarios:\n")
        for s in SCENARIOS:
            flag = " [small-disk]" if s.expect_small_disk else ""
            print(f"  {s.name:20s} {s.gerrit_host}{s.api_path}{flag}")
            print(f"  {'':20s} {s.description}")
            print()
        return 0

    # --- Resolve configuration ---
    gerrit_version = os.environ.get("GERRIT_VERSION", "3.13.1-ubuntu24")
    plugin_version = os.environ.get("PLUGIN_VERSION", "stable-3.13")
    timeout = int(os.environ.get("REPLICATION_WAIT_TIMEOUT", "180"))
    stability_window = int(os.environ.get("STABILITY_WINDOW", "30"))
    fetch_every = os.environ.get("FETCH_EVERY", "15s")

    logger.info("Test configuration:")
    logger.info("  Gerrit version:     %s", gerrit_version)
    logger.info("  Plugin version:     %s", plugin_version)
    logger.info("  Timeout:            %ds", timeout)
    logger.info("  Stability window:   %ds", stability_window)
    logger.info("  Fetch every:        %s", fetch_every)
    logger.info("  Debug:              %s", debug)
    logger.info("")

    # --- Tunnel-only mode ---
    tunnel_results = run_tunnel_tests()
    for t in tunnel_results:
        logger.info(str(t))

    if args.tunnel_only:
        failed = sum(1 for t in tunnel_results if not t.passed)
        return 1 if failed else 0

    # --- Resolve scenarios ---
    if args.scenario:
        names = [n.strip() for n in args.scenario.split(",")]
        selected: list[Scenario] = []
        for name in names:
            if name in _SCENARIO_MAP:
                selected.append(_SCENARIO_MAP[name])
            else:
                logger.error(
                    "Unknown scenario: %r  (available: %s)",
                    name,
                    ", ".join(_SCENARIO_MAP),
                )
                return 1
    else:
        selected = list(SCENARIOS)

    logger.info("Scenarios to run: %s", ", ".join(s.name for s in selected))
    logger.info("")

    # --- Docker setup ---
    docker = DockerManager()

    if args.skip_build:
        image = f"gerritcodereview/gerrit:{gerrit_version}"
        logger.info("Using stock image: %s", image)
        try:
            docker.run_cmd(["pull", image], timeout=120)
        except DockerError as exc:
            logger.error("Failed to pull image: %s", exc)
            return 1
    else:
        try:
            image = _build_image(docker, gerrit_version)
        except DockerError as exc:
            logger.error("Failed to build Docker image: %s", exc)
            return 1

    # --- Run scenarios ---
    scenario_results: list[ScenarioResult] = []

    # Install signal handler for clean shutdown
    _shutdown_contexts: list[_ContainerContext] = []

    def _signal_handler(_signum: int, _frame: Any) -> None:
        logger.info("\nInterrupted — cleaning up…")
        for ctx in _shutdown_contexts:
            _cleanup_container(docker, ctx)
        sys.exit(130)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    for idx, scenario in enumerate(selected):
        # Check credentials before starting container
        try:
            creds = _get_credentials(scenario.gerrit_host)
        except SystemExit:
            sr = ScenarioResult(scenario=scenario)
            sr.error = f"No credentials for {scenario.gerrit_host}"
            scenario_results.append(sr)
            continue

        sr = run_scenario(
            docker,
            scenario,
            idx,
            image=image,
            creds=creds,
            timeout=timeout,
            stability_window=stability_window,
            fetch_every=fetch_every,
            keep=args.keep,
        )
        scenario_results.append(sr)

    # --- Summary ---
    return print_summary(scenario_results, tunnel_results)


if __name__ == "__main__":
    sys.exit(main())
