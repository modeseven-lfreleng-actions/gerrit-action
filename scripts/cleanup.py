#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Cleanup Gerrit containers and working directories.

This script gracefully terminates all Gerrit instances started by the
action, removes containers, cleans up instance directories, and
optionally prunes Docker caches.

Replaces ``cleanup.sh`` (162 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/cleanup.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action python scripts/cleanup.py
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import ActionConfig, InstanceStore  # noqa: E402
from docker_manager import DockerManager  # noqa: E402
from errors import DockerError, GerritActionError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from outputs import write_status_summary  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-instance cleanup
# ---------------------------------------------------------------------------


def cleanup_instance(
    docker: DockerManager,
    slug: str,
    cid: str,
    work_dir: Path,
) -> bool:
    """Stop and remove a single Gerrit container and its local files.

    Parameters
    ----------
    docker:
        Docker CLI wrapper.
    slug:
        Instance slug (used for logging and directory names).
    cid:
        Container ID or name.
    work_dir:
        Root working directory (e.g. ``/tmp/gerrit-action``).

    Returns
    -------
    bool
        *True* if cleanup completed without critical errors.
    """
    logger.info("========================================")
    logger.info("Cleaning up instance: %s", slug)
    logger.info("========================================")
    logger.info("Container ID: %s", cid)

    success = True

    # ------------------------------------------------------------------
    # 1. Check if container exists
    # ------------------------------------------------------------------
    if not docker.container_exists(cid):
        logger.info("Container %s does not exist (already removed)", cid[:12])
    else:
        # Get container state
        try:
            state = docker.container_state(cid)
        except DockerError:
            state = "unknown"

        logger.info("Container state: %s", state)

        if state == "running":
            # Attempt graceful shutdown via Gerrit's own stop command
            logger.info("Attempting graceful shutdown…")
            try:
                docker.exec_cmd(cid, "gerrit stop", timeout=10, check=False)
            except DockerError:
                logger.info(
                    "Graceful stop command not available, proceeding with container kill"
                )

            # Give the process a moment to wind down
            time.sleep(3)

            # Re-check state after graceful stop attempt
            try:
                state = docker.container_state(cid)
            except DockerError:
                state = "stopped"

            if state == "running":
                logger.info("Killing container…")
                try:
                    docker.kill(cid)
                    logger.info("Container killed ✅")
                except DockerError as exc:
                    logger.warning("Failed to kill container %s: %s", cid[:12], exc)
                    success = False
            else:
                logger.info("Container stopped gracefully ✅")

            # Remove the container
            logger.info("Removing container…")
            try:
                docker.remove(cid)
                logger.info("Container removed ✅")
            except DockerError:
                logger.warning(
                    "Failed to remove container %s (may already be removed)",
                    cid[:12],
                )
        else:
            # Container exists but is not running — force remove
            logger.info("Container not running, removing…")
            try:
                docker.remove(cid, force=True)
                logger.info("Container removed ✅")
            except DockerError:
                logger.warning("Failed to remove container %s", cid[:12])
                success = False

    # ------------------------------------------------------------------
    # 2. Clean up instance directory
    # ------------------------------------------------------------------
    instance_dir = work_dir / "instances" / slug
    if instance_dir.is_dir():
        logger.info("Cleaning up instance directory…")
        try:
            shutil.rmtree(instance_dir)
            logger.info("Instance directory removed ✅")
        except OSError as exc:
            logger.warning("Failed to remove instance directory: %s", exc)

    # ------------------------------------------------------------------
    # 3. Clean up CID file
    # ------------------------------------------------------------------
    cidfile = work_dir / f"gerrit-{slug}.cid"
    if cidfile.exists():
        with contextlib.suppress(OSError):
            cidfile.unlink()

    logger.info("✅ Cleanup completed for %s", slug)
    logger.info("")

    return success


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def run() -> int:
    """Clean up all Gerrit containers and the working directory.

    Reads ``instances.json`` from ``$WORK_DIR``, stops and removes each
    container, deletes instance directories, optionally prunes Docker
    caches, and removes the working directory.

    Returns
    -------
    int
        Exit code: 0 on success, 1 if some cleanup operations failed,
        2 on unexpected errors.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)
    docker = DockerManager()

    logger.info("Cleaning up Gerrit containers…")
    logger.info("")

    work_dir = config.work_path

    # ------------------------------------------------------------------
    # Load instances metadata (if it exists)
    # ------------------------------------------------------------------
    instances_path = config.instances_json_path
    if not instances_path.exists():
        logger.warning("No instances metadata found, nothing to cleanup")
        return 0

    store = InstanceStore(instances_path)
    store.load()

    # ------------------------------------------------------------------
    # Clean up each instance
    # ------------------------------------------------------------------
    cleanup_failed = 0

    for slug, instance in store:
        cid = instance.get("cid", "")
        if not cid:
            logger.warning("No container ID for %s, skipping", slug)
            continue

        ok = cleanup_instance(docker, slug, cid, work_dir)
        if not ok:
            cleanup_failed += 1

    # ------------------------------------------------------------------
    # Clean up the working directory
    # ------------------------------------------------------------------
    if work_dir.is_dir():
        logger.info("Cleaning up working directory: %s", work_dir)
        try:
            shutil.rmtree(work_dir)
            logger.info("Working directory removed ✅")
        except OSError as exc:
            logger.warning("Failed to remove working directory: %s", exc)

    # ------------------------------------------------------------------
    # Optional Docker cache pruning
    # ------------------------------------------------------------------
    if config.enable_cache:
        logger.info("Preserving Docker layers in cache…")
        try:
            docker.system_prune(
                force=True,
                filters=["until=24h", "label!=keep-cache"],
            )
        except DockerError:
            logger.warning("Docker cleanup skipped")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    logger.info("========================================")
    if cleanup_failed == 0:
        logger.info("All containers cleaned up! ✅")
        logger.info("========================================")
        logger.info("")

        write_status_summary(
            "Cleanup Complete",
            "All Gerrit containers have been stopped and cleaned up.",
            emoji="🧹",
        )
    else:
        logger.warning("Some cleanup operations failed ⚠️")
        logger.info("========================================")
        logger.info("")

        write_status_summary(
            "Cleanup Status",
            "Some cleanup operations encountered issues.\n"
            "Manual cleanup may be required.",
            emoji="⚠️",
        )

    # ------------------------------------------------------------------
    # Check for remaining containers
    # ------------------------------------------------------------------
    try:
        remaining = docker.ps(filter_name="gerrit-", quiet=True)
        if remaining.strip():
            logger.warning("Some Gerrit containers are still running:")
            ps_output = docker.ps(filter_name="gerrit-")
            logger.warning("%s", ps_output)
        else:
            logger.info("No Gerrit containers remaining ✅")
    except DockerError:
        pass
    logger.info("")

    return 1 if cleanup_failed > 0 else 0


def main() -> int:
    """Entry point with structured error handling."""
    try:
        return run()
    except GerritActionError as exc:
        logger.error(str(exc))
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
