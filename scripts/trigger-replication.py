#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Trigger initial replication for all configured Gerrit instances.

This script monitors pull-replication for all configured instances.
The pull-replication plugin is configured with ``fetchEvery`` which
polls the source Gerrit at regular intervals (default: 60s) to fetch
new/changed refs.

This script:

1. Verifies the pull-replication plugin is loaded for each instance.
2. Shows current replication configuration.
3. Optionally attempts SSH trigger for faster initial sync.
4. Waits for first poll cycle to show activity.

Replaces ``trigger-replication.sh`` (353 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/trigger-replication.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action \
    AUTH_TYPE=ssh \
    SYNC_ON_STARTUP=true \
    FETCH_EVERY=60s \
        python scripts/trigger-replication.py
"""

from __future__ import annotations

import logging
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
from errors import GerritActionError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from replication import trigger_all_instances  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Trigger replication for all Gerrit instances.

    Reads ``instances.json`` from ``$WORK_DIR``, verifies the
    pull-replication plugin is loaded for each instance, shows the
    replication configuration, optionally triggers replication via SSH,
    and waits for the first fetchEvery poll cycle to show activity.

    Environment Variables
    ---------------------
    WORK_DIR
        Working directory containing ``instances.json``.
    AUTH_TYPE
        Authentication type (``ssh``, ``http_basic``, ``bearer_token``).
    SYNC_ON_STARTUP
        If ``"true"``, replication is expected on startup.
    FETCH_EVERY
        Fetch interval for pull-replication (e.g. ``"60s"``, ``"5m"``).
    SKIP_PLUGIN_INSTALL
        If ``"true"``, skip plugin verification.
    REQUIRE_REPLICATION_SUCCESS
        If ``"true"``, require replication to succeed (informational here;
        actual enforcement is in ``verify-replication.py``).
    REPLICATION_WAIT_TIMEOUT
        Maximum seconds to wait for replication activity.
    DEBUG
        If ``"true"``, enable debug-level logging.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on anticipated error, 2 on
        unexpected error.

    Note
    ----
    The actual pass/fail decision for replication is delegated to
    ``verify-replication.py``, which runs after this script when
    ``require_replication_success`` is true.  This script only
    **triggers** replication; verification is separate.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    docker = DockerManager()

    # Load instances metadata
    instance_store = InstanceStore(config.instances_json_path)
    instance_store.load()

    if len(instance_store) == 0:
        logger.warning(
            "No instances found in %s, nothing to trigger",
            config.instances_json_path,
        )
        return 0

    # Log configuration for context
    logger.info("Replication trigger configuration:")
    logger.info("  Auth type:          %s", config.auth_type)
    logger.info("  Sync on startup:    %s", config.sync_on_startup)
    logger.info("  Fetch interval:     %s", config.fetch_every)
    logger.info("  Skip plugin:        %s", config.skip_plugin_install)
    logger.info("  Debug:              %s", config.debug)
    logger.info("")

    # Run trigger for all instances
    results = trigger_all_instances(docker, instance_store, config)

    # Count failures (note: trigger failures are non-fatal; the actual
    # pass/fail decision is made by verify-replication.py)
    failed = [r for r in results if not r.success]

    if failed:
        logger.warning(
            "%d of %d replication trigger(s) encountered issues",
            len(failed),
            len(results),
        )
        for r in failed:
            if r.error:
                logger.warning("  %s: %s", r.slug, r.error)

    # Note: We do NOT exit with failure here.  The trigger step is
    # best-effort — it kicks off replication but does not gate the
    # workflow.  The verify-replication step (if enabled) is the one
    # that enforces success.
    return 0


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
