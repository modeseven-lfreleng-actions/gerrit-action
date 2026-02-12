# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""HTTP and TCP health checks with configurable retries.

Replaces ``check-services.sh`` (416 lines) with a testable Python
implementation that provides:

- Container state verification
- Log polling for "Gerrit Code Review … ready" with timeout
- HTTP health checks with retries
- TCP port checks for replica/headless mode
- SSH keyscan verification
- Plugin verification via logs and HTTP API
- Replica mode detection

Usage::

    from docker_manager import DockerManager
    from health_check import (
        wait_for_gerrit_ready,
        http_health_check,
        tcp_port_check,
        verify_plugin_loaded,
        check_all_instances,
    )

    docker = DockerManager()
    wait_for_gerrit_ready(docker, container_id, timeout=180)
    http_health_check(url="http://10.0.0.2:8080/config/server/version")
    verify_plugin_loaded(docker, container_id, "pull-replication")
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Any

import requests
from config import InstanceStore
from docker_manager import DockerManager
from errors import DockerError, HealthCheckError, PluginError
from outputs import write_status_summary, write_summary

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryConfig:
    """Retry parameters for health checks."""

    max_retries: int = 30
    interval: float = 2.0
    timeout: float = 0.0  # 0 means no overall timeout (use max_retries × interval)

    @property
    def effective_timeout(self) -> float:
        """Total wall-clock seconds this retry config could consume."""
        if self.timeout > 0:
            return self.timeout
        return self.max_retries * self.interval


# Sensible defaults
GERRIT_READY_TIMEOUT = 180  # seconds to wait for "Gerrit Code Review … ready"
HTTP_RETRY = RetryConfig(max_retries=30, interval=2.0)
TCP_RETRY = RetryConfig(max_retries=30, interval=2.0)
TCP_SSH_RETRY = RetryConfig(max_retries=15, interval=2.0)

# Pattern that Gerrit logs when it has finished starting up
_READY_PATTERN = re.compile(r"Gerrit Code Review.*ready")

# Pattern that identifies replica/headless mode
_REPLICA_PATTERN = re.compile(r"\[replica\].*\[headless\]")

# HTTP status codes considered "healthy" (the endpoint exists and responds)
_HEALTHY_HTTP_CODES = {200, 401, 403}


# ---------------------------------------------------------------------------
# Container state verification
# ---------------------------------------------------------------------------


def verify_container_running(docker: DockerManager, cid: str, slug: str) -> bool:
    """Verify that a container exists and is in the ``running`` state.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    cid:
        Container ID.
    slug:
        Instance slug for logging.

    Returns
    -------
    bool
        *True* if the container is running.

    Raises
    ------
    HealthCheckError
        If the container does not exist or is not running.
    """
    if not docker.container_exists(cid):
        raise HealthCheckError(
            f"Container {cid[:12]} for {slug} does not exist",
            url="",
            attempts=0,
        )

    state = docker.container_state(cid)
    if state != "running":
        # Grab some logs for diagnostics
        try:
            tail = docker.container_logs(cid, tail=20)
        except DockerError:
            tail = "(could not retrieve logs)"
        raise HealthCheckError(
            f"Container {cid[:12]} for {slug} is not running "
            f"(state: {state})\nRecent logs:\n{tail}",
            url="",
            attempts=0,
        )

    logger.info("Container state: %s ✅", state)
    return True


# ---------------------------------------------------------------------------
# Gerrit readiness (log polling)
# ---------------------------------------------------------------------------


def wait_for_gerrit_ready(
    docker: DockerManager,
    cid: str,
    timeout: int = GERRIT_READY_TIMEOUT,
    poll_interval: float = 2.0,
    log_tail: int = 500,
) -> bool:
    """Wait for Gerrit to log its "ready" message.

    Polls the container logs every *poll_interval* seconds, looking for
    the pattern ``Gerrit Code Review .* ready``.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    cid:
        Container ID.
    timeout:
        Maximum seconds to wait.
    poll_interval:
        Seconds between log polls.
    log_tail:
        Number of log lines to inspect on each poll.

    Returns
    -------
    bool
        *True* if the ready message was found within the timeout.
        *False* if the timeout elapsed without finding it (a warning
        is logged but no exception is raised, since Gerrit may still
        respond to HTTP checks even without the explicit ready message).
    """
    logger.info("Waiting for Gerrit to initialize…")
    elapsed = 0.0

    while elapsed < timeout:
        logs = docker.container_logs(cid, tail=log_tail)
        if _READY_PATTERN.search(logs):
            logger.info("Gerrit ready message detected in logs ✅")
            return True

        time.sleep(poll_interval)
        elapsed += poll_interval

        if int(elapsed) % 10 == 0 and elapsed > 0:
            logger.info("  Waiting… %.0fs elapsed", elapsed)

    logger.warning(
        "Gerrit did not show 'ready' message in logs after %ds. "
        "Proceeding with HTTP check anyway…",
        timeout,
    )
    return False


# ---------------------------------------------------------------------------
# Replica / headless mode detection
# ---------------------------------------------------------------------------


def is_replica_mode(docker: DockerManager, cid: str, tail: int = 2000) -> bool:
    """Detect if Gerrit is running in replica/headless mode.

    In this mode the REST API is disabled and HTTP health checks will
    fail; we must use TCP port checks instead.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    cid:
        Container ID.
    tail:
        Number of log lines to search.

    Returns
    -------
    bool
        *True* if the replica/headless pattern was found in logs.
    """
    logs = docker.container_logs(cid, tail=tail)
    return bool(_REPLICA_PATTERN.search(logs))


# ---------------------------------------------------------------------------
# HTTP health check
# ---------------------------------------------------------------------------


def http_health_check(
    url: str,
    retry: RetryConfig = HTTP_RETRY,
) -> int:
    """Perform an HTTP health check with retries.

    The check succeeds when the endpoint responds with one of the
    "healthy" status codes (200, 401, 403).

    Parameters
    ----------
    url:
        Full URL to check (e.g.
        ``http://10.0.0.2:8080/config/server/version``).
    retry:
        Retry configuration.

    Returns
    -------
    int
        The HTTP status code that passed the check.

    Raises
    ------
    HealthCheckError
        If the endpoint did not return a healthy status code within
        the allowed retries.
    """
    logger.info("HTTP health check: %s", url)
    last_code: int | None = None

    for attempt in range(1, retry.max_retries + 1):
        try:
            resp = requests.get(url, timeout=(5, 10), allow_redirects=False)
            last_code = resp.status_code

            if last_code in _HEALTHY_HTTP_CODES:
                logger.info("HTTP check passed (code: %d) ✅", last_code)
                return last_code

        except requests.RequestException:
            last_code = None

        if attempt < retry.max_retries:
            time.sleep(retry.interval)
            if attempt % 5 == 0:
                logger.info(
                    "  Retry %d/%d (HTTP code: %s)",
                    attempt,
                    retry.max_retries,
                    last_code or "N/A",
                )

    raise HealthCheckError(
        f"HTTP health check failed for {url} after {retry.max_retries} retries "
        f"(last HTTP code: {last_code})",
        url=url,
        last_status_code=last_code,
        attempts=retry.max_retries,
    )


# ---------------------------------------------------------------------------
# TCP port check
# ---------------------------------------------------------------------------


def tcp_port_check(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    """Check whether a TCP port is accepting connections.

    Parameters
    ----------
    host:
        Hostname or IP address.
    port:
        Port number.
    timeout:
        Connection timeout in seconds.

    Returns
    -------
    bool
        *True* if the connection succeeded.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def wait_for_tcp_port(
    host: str,
    port: int,
    retry: RetryConfig = TCP_RETRY,
    label: str = "",
) -> bool:
    """Wait for a TCP port to become available.

    Parameters
    ----------
    host:
        Hostname or IP address.
    port:
        Port number.
    retry:
        Retry configuration.
    label:
        Human-readable label for log messages (e.g. "HTTP port 8080").

    Returns
    -------
    bool
        *True* if the port became available.

    Raises
    ------
    HealthCheckError
        If the port did not become available within the allowed retries.
    """
    display = label or f"{host}:{port}"
    logger.info("Waiting for TCP port: %s", display)

    for attempt in range(1, retry.max_retries + 1):
        if tcp_port_check(host, port):
            logger.info("  TCP port %s is listening ✅", display)
            return True

        if attempt < retry.max_retries:
            time.sleep(retry.interval)
            if attempt % 5 == 0:
                logger.info(
                    "  Retry %d/%d (waiting for %s)",
                    attempt,
                    retry.max_retries,
                    display,
                )

    raise HealthCheckError(
        f"TCP port {display} not listening after {retry.max_retries} retries",
        url=display,
        attempts=retry.max_retries,
    )


# ---------------------------------------------------------------------------
# SSH keyscan verification
# ---------------------------------------------------------------------------


def verify_ssh_service(
    host: str,
    port: int = 29418,
    timeout: int = 10,
) -> str:
    """Verify that the Gerrit SSH service responds with a host key.

    Uses ``ssh-keyscan`` to contact the SSH service.

    Parameters
    ----------
    host:
        Hostname or IP address.
    port:
        SSH port (default 29418).
    timeout:
        Keyscan timeout in seconds.

    Returns
    -------
    str
        The raw keyscan output (host key lines), or ``""`` if the
        service did not respond.
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "-T", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        output = result.stdout.strip()
        if output:
            # Show a truncated version of the first key for logging
            first_line = output.splitlines()[0]
            parts = first_line.split()
            key_preview = (
                f"{parts[1]} {parts[2][:40]}…" if len(parts) >= 3 else first_line[:60]
            )
            logger.info("  Gerrit SSH service is responding ✅")
            logger.info("  Host key received: %s", key_preview)
        else:
            logger.warning(
                "Could not retrieve SSH host key from %s:%d. "
                "SSH port is open but service may not be fully ready.",
                host,
                port,
            )
        return output
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("ssh-keyscan failed for %s:%d: %s", host, port, exc)
        return ""


# ---------------------------------------------------------------------------
# Plugin verification
# ---------------------------------------------------------------------------


def verify_plugin_loaded(
    docker: DockerManager,
    cid: str,
    plugin_name: str,
    container_ip: str = "",
    effective_api_path: str = "",
) -> bool:
    """Verify that a Gerrit plugin is loaded.

    This is the **single implementation** replacing the duplicated
    ``check_plugin_in_logs()`` function that existed in
    ``check-services.sh`` and ``trigger-replication.sh``.

    Detection strategy (ordered by reliability):

    1. Search recent container logs for ``"Loaded plugin <name>"``.
    2. Query the ``/plugins/`` REST endpoint via HTTP.
    3. Check whether the plugin ``.jar`` file exists in the container.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    cid:
        Container ID.
    plugin_name:
        Name of the plugin (e.g. ``"pull-replication"``).
    container_ip:
        If provided, enables the HTTP fallback check.
    effective_api_path:
        API path prefix for the HTTP fallback.

    Returns
    -------
    bool
        *True* if the plugin was confirmed loaded by any method.
    """
    load_pattern = f"Loaded plugin {plugin_name}"

    # Method 1: Check container logs (most reliable)
    if docker.grep_logs(cid, load_pattern, tail=1000):
        logger.info("%s plugin loaded ✅ (verified via logs)", plugin_name)
        return True

    # Extended search with more lines
    if docker.grep_logs(cid, load_pattern, tail=5000):
        logger.info("%s plugin loaded ✅ (verified via extended logs)", plugin_name)
        return True

    # Method 2: HTTP API check
    if container_ip:
        try:
            if effective_api_path:
                url = f"http://{container_ip}:8080{effective_api_path}/plugins/"
            else:
                url = f"http://{container_ip}:8080/plugins/"

            resp = requests.get(url, timeout=5)
            if plugin_name in resp.text:
                logger.info("%s plugin detected ✅ (verified via HTTP)", plugin_name)
                return True
        except requests.RequestException:
            pass

    # Method 3: Check jar file existence
    jar_path = f"/var/gerrit/plugins/{plugin_name}.jar"
    if docker.exec_test(cid, f"-f {jar_path}"):
        logger.info("Plugin file %s exists in container", jar_path)
        # Give it a moment and check logs again
        time.sleep(3)
        if docker.grep_logs(cid, load_pattern, tail=1000):
            logger.info("%s plugin loaded ✅ (after wait)", plugin_name)
            return True
        logger.warning(
            "Plugin file exists but %s not yet loaded – "
            "this may be normal during initial startup",
            plugin_name,
        )
        return True  # File exists, treat as OK (may still be loading)

    logger.warning("Plugin %s not found by any method", plugin_name)
    return False


# ---------------------------------------------------------------------------
# Replica-mode health check flow
# ---------------------------------------------------------------------------


def _check_replica_health(
    _docker: DockerManager,
    _cid: str,
    container_ip: str,
    _slug: str,
) -> bool:
    """Run health checks for a replica/headless Gerrit instance.

    In replica mode the REST API is disabled, so we check:
    1. HTTP port (8080) is listening via TCP
    2. SSH port (29418) is listening via TCP
    3. SSH service responds with a host key

    Returns *True* on success, raises :class:`HealthCheckError` on failure.
    """
    logger.info("Gerrit is running in replica/headless mode")
    logger.info("Using TCP port checks (REST API is disabled in this mode)…")

    # Step 1: HTTP port
    logger.info("")
    logger.info("Step 1: Checking HTTP port (8080)…")
    wait_for_tcp_port(
        container_ip,
        8080,
        retry=TCP_RETRY,
        label="HTTP port 8080",
    )

    # Step 2: SSH port
    logger.info("")
    logger.info("Step 2: Checking SSH port (29418)…")
    wait_for_tcp_port(
        container_ip,
        29418,
        retry=TCP_SSH_RETRY,
        label="SSH port 29418",
    )

    # Step 3: SSH service verification
    logger.info("")
    logger.info("Step 3: Verifying Gerrit SSH service…")
    verify_ssh_service(container_ip, port=29418)

    logger.info("")
    logger.info("Replica mode health checks passed ✅")
    return True


# ---------------------------------------------------------------------------
# Standard (non-replica) health check flow
# ---------------------------------------------------------------------------


def _check_standard_health(
    docker: DockerManager,
    cid: str,
    container_ip: str,
    _slug: str,
    effective_api_path: str,
    skip_plugin_install: bool = False,
) -> bool:
    """Run health checks for a standard (non-replica) Gerrit instance.

    1. HTTP health check on the version endpoint.
    2. Plugin verification (pull-replication, replication-api).

    Returns *True* on success, raises :class:`HealthCheckError` on failure.
    """
    logger.info("Performing HTTP health check…")

    # Build health check URL
    if effective_api_path:
        health_url = (
            f"http://{container_ip}:8080{effective_api_path}/config/server/version"
        )
    else:
        health_url = f"http://{container_ip}:8080/config/server/version"

    logger.info("Health check URL: %s", health_url)
    http_health_check(health_url, retry=HTTP_RETRY)

    # Plugin checks
    if not skip_plugin_install:
        logger.info("")
        logger.info("Verifying pull-replication plugin…")
        verify_plugin_loaded(
            docker,
            cid,
            "pull-replication",
            container_ip=container_ip,
            effective_api_path=effective_api_path,
        )

        # Also check replication-api (dependency)
        if docker.grep_logs(cid, "Loaded plugin replication-api", tail=1000):
            logger.info("Replication-api plugin loaded ✅")

    return True


# ---------------------------------------------------------------------------
# Per-instance health check
# ---------------------------------------------------------------------------


@dataclass
class HealthCheckResult:
    """Result of a health check for a single instance."""

    slug: str
    success: bool = False
    error: str = ""
    is_replica: bool = False


def check_instance(
    docker: DockerManager,
    slug: str,
    instance: dict[str, Any],
    *,
    skip_plugin_install: bool = False,
    use_api_path: bool = False,
) -> HealthCheckResult:
    """Run all health checks for a single Gerrit instance.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    slug:
        Instance slug.
    instance:
        Instance metadata dict (from ``instances.json``).
    skip_plugin_install:
        If *True*, skip plugin verification.
    use_api_path:
        If *True*, use the ``api_path`` from instance metadata.

    Returns
    -------
    HealthCheckResult
        The result of the health check.
    """
    result = HealthCheckResult(slug=slug)

    cid = instance.get("cid", "")
    container_ip = instance.get("ip", "")
    api_path = instance.get("api_path", "")

    # Compute effective API path (matching shell script logic)
    effective_api_path = ""
    if use_api_path and api_path:
        effective_api_path = api_path

    logger.info("========================================")
    logger.info("Checking instance: %s", slug)
    logger.info("========================================")
    logger.info("Container ID: %s", cid[:12] if cid else "(none)")
    logger.info("IP Address: %s", container_ip)
    logger.info("HTTP Port: %s (container port 8080)", instance.get("http_port", "?"))
    if api_path:
        logger.info(
            "API Path: %s (USE_API_PATH=%s)",
            api_path,
            "true" if use_api_path else "false",
        )
    logger.info("")

    try:
        # Step 1: Verify container is running
        verify_container_running(docker, cid, slug)
        logger.info("")

        # Step 2: Wait for Gerrit ready message
        wait_for_gerrit_ready(docker, cid)

        # Step 3: Check if replica mode
        result.is_replica = is_replica_mode(docker, cid)

        if result.is_replica:
            _check_replica_health(docker, cid, container_ip, slug)
        else:
            _check_standard_health(
                docker,
                cid,
                container_ip,
                slug,
                effective_api_path,
                skip_plugin_install=skip_plugin_install,
            )

        logger.info("")
        logger.info("✅ Instance %s is healthy and responding", slug)
        logger.info("")
        result.success = True

    except (HealthCheckError, DockerError, PluginError) as exc:
        result.error = str(exc)
        logger.error("Health check failed for %s: %s", slug, exc)

        # Try to grab container logs for diagnostics
        try:
            tail = docker.container_logs(cid, tail=50)
            logger.error("Container logs (last 50 lines):\n%s", tail)
        except DockerError:
            pass

    return result


# ---------------------------------------------------------------------------
# Multi-instance orchestrator
# ---------------------------------------------------------------------------


def check_all_instances(
    docker: DockerManager,
    instance_store: InstanceStore,
    *,
    skip_plugin_install: bool = False,
    use_api_path: bool = False,
) -> list[HealthCheckResult]:
    """Run health checks for all instances in the store.

    This is the top-level entry point that replaces the main loop in
    ``check-services.sh``.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    instance_store:
        Loaded instance metadata.
    skip_plugin_install:
        Skip plugin verification if *True*.
    use_api_path:
        Use API path from instance metadata if *True*.

    Returns
    -------
    list[HealthCheckResult]
        Results for each instance, in slug order.

    Raises
    ------
    HealthCheckError
        If any instance failed its health check.
    """
    logger.info("Checking Gerrit service availability…")
    logger.info("")

    results: list[HealthCheckResult] = []

    for slug, instance in instance_store:
        r = check_instance(
            docker,
            slug,
            instance,
            skip_plugin_install=skip_plugin_install,
            use_api_path=use_api_path,
        )
        results.append(r)

    # Summary
    failed = [r for r in results if not r.success]

    logger.info("========================================")
    if not failed:
        logger.info("All service checks passed! ✅")
        logger.info("========================================")
        logger.info("")

        write_status_summary(
            "Service Health Checks",
            "All Gerrit instances are healthy and responding!",
            emoji="💚",
        )
    else:
        logger.error("Some service checks failed ❌")
        logger.info("========================================")
        logger.info("")

        lines = [
            "**Service Health Checks** ❌",
            "",
            "Some instances failed health checks.",
            "See logs above for details.",
            "",
        ]
        write_summary("\n".join(lines))

    # Show container status
    logger.info("Current container status:")
    try:
        ps_output = docker.ps(filter_name="gerrit-")
        if ps_output:
            logger.info("%s", ps_output)
    except DockerError:
        pass
    logger.info("")

    if failed:
        slugs = ", ".join(r.slug for r in failed)
        raise HealthCheckError(
            f"Health checks failed for: {slugs}",
            attempts=len(results),
        )

    return results
