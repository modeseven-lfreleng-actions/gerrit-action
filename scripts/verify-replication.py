#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Verify Gerrit replication success for all configured instances.

This script waits for and validates that replication has completed
successfully for all configured instances.  It is the enforcement
counterpart to ``trigger-replication.py`` — while the trigger script
kicks off replication on a best-effort basis, *this* script gates the
workflow by returning a non-zero exit code if replication does not
complete within the configured timeout.

Verification flow per instance:

1. Verify pull-replication plugin is loaded.
2. Verify ``replication.config`` and ``secure.config`` exist.
3. Check for replication errors in ``pull_replication_log`` — fail fast.
4. Wait for replication to complete (repository count matches expected,
   log shows completion, disk usage indicates real content).
5. Report final statistics (repo count, disk usage, project count
   validation).

Replaces ``verify-replication.sh`` (740 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/verify-replication.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action \
    REPLICATION_WAIT_TIMEOUT=180 \
    FETCH_EVERY=60s \
        python scripts/verify-replication.py
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import ActionConfig, InstanceStore  # noqa: E402
from docker_manager import DockerManager  # noqa: E402
from errors import GerritActionError, ReplicationError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from replication import verify_all_instances  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Verify replication for all Gerrit instances.

    Reads ``instances.json`` from ``$WORK_DIR``, runs the full
    verification flow for each instance (plugin check, config check,
    error check, wait-for-replication, final stats), and writes a
    Markdown summary.

    Environment Variables
    ---------------------
    WORK_DIR
        Working directory containing ``instances.json``.
    REPLICATION_WAIT_TIMEOUT
        Maximum seconds to wait for replication to complete per instance
        (default: ``180``).
    FETCH_EVERY
        Fetch interval for pull-replication (e.g. ``"60s"``, ``"5m"``).
        Used for informational logging only — the actual interval is
        configured in ``replication.config`` by ``start-instances``.
    STABILITY_WINDOW
        Seconds with no observable state change before declaring
        replication complete (default: ``45``).  Helps avoid waiting
        the full timeout when replication has genuinely finished but
        the classic size/count thresholds are not met (e.g. many
        small repositories).
    DEBUG
        If ``"true"``, enable debug-level logging (shows internal
        counters and decision points during the wait loop).

    Returns
    -------
    int
        Exit code: 0 if all verifications passed, 1 if any failed, 2 on
        unexpected errors.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    docker = DockerManager()

    # Load instances metadata
    instance_store = InstanceStore(config.instances_json_path)
    instance_store.load()

    if len(instance_store) == 0:
        logger.warning(
            "No instances found in %s, nothing to verify",
            config.instances_json_path,
        )
        return 0

    # Resolve timeout — the action.yaml step may pass this directly as
    # an env var, so check the env first before falling back to
    # ActionConfig (which also reads the env, but this allows for
    # per-step overrides).
    timeout_str = os.environ.get(
        "REPLICATION_WAIT_TIMEOUT",
        str(config.replication_wait_timeout),
    )
    try:
        timeout = int(timeout_str)
    except ValueError:
        logger.warning(
            "Invalid REPLICATION_WAIT_TIMEOUT '%s', using default 180",
            timeout_str,
        )
        timeout = 180

    # Resolve stability window
    stability_str = os.environ.get("STABILITY_WINDOW", "45")
    try:
        stability_window = int(stability_str)
    except ValueError:
        logger.warning(
            "Invalid STABILITY_WINDOW '%s', using default 45",
            stability_str,
        )
        stability_window = 45

    # Log configuration
    logger.info("Replication verification configuration:")
    logger.info("  Wait timeout:       %ds", timeout)
    logger.info("  Stability window:   %ds", stability_window)
    logger.info("  Fetch interval:     %s", config.fetch_every)
    logger.info("  Debug:              %s", config.debug)
    logger.info("  Instances:          %d", len(instance_store))
    logger.info("")

    try:
        results = verify_all_instances(
            docker,
            instance_store,
            timeout=timeout,
            debug=config.debug,
            stability_window=stability_window,
        )

        # All passed — log a brief summary
        for r in results:
            logger.info(
                "  %s: %d repos, %s disk",
                r.slug,
                r.repo_count,
                r.disk_usage or "?",
            )

        return 0

    except ReplicationError as exc:
        # verify_all_instances already logged detailed error info and
        # wrote the step summary; just propagate the non-zero exit code.
        logger.error("Replication verification failed: %s", exc)
        return 1


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
