#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Check Gerrit service availability for all configured instances.

This script verifies that all Gerrit instances are responding correctly
by running health checks appropriate to each instance's mode:

- **Standard mode:** HTTP health check on the version endpoint, plugin
  verification (pull-replication, replication-api).
- **Replica/headless mode:** TCP port checks for HTTP (8080) and SSH
  (29418), plus SSH keyscan verification.

Both modes first verify that the container is running and wait for
Gerrit's "ready" log message before proceeding.

Replaces ``check-services.sh`` (416 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/check-services.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action python scripts/check-services.py

    # With options
    SKIP_PLUGIN_INSTALL=true USE_API_PATH=true \
        python scripts/check-services.py
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
from errors import GerritActionError, HealthCheckError  # noqa: E402
from health_check import check_all_instances  # noqa: E402
from logging_utils import setup_logging  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Run health checks for all Gerrit instances.

    Reads ``instances.json`` from ``$WORK_DIR``, iterates over each
    instance, runs the appropriate health checks (standard or replica
    mode), and reports results.

    Environment Variables
    ---------------------
    WORK_DIR
        Working directory containing ``instances.json``.
    SKIP_PLUGIN_INSTALL
        If ``"true"``, skip plugin verification.
    USE_API_PATH
        If ``"true"``, use the ``api_path`` from instance metadata
        when constructing health check URLs.
    DEBUG
        If ``"true"``, enable debug-level logging.

    Returns
    -------
    int
        Exit code: 0 if all checks passed, 1 if any failed, 2 on
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
            "No instances found in %s, nothing to check",
            config.instances_json_path,
        )
        return 0

    # Resolve flags from environment (these may be passed directly as
    # env vars without going through ActionConfig for backwards compat
    # with the action.yaml steps that set them individually).
    skip_plugin = _str_to_bool(
        os.environ.get("SKIP_PLUGIN_INSTALL", str(config.skip_plugin_install))
    )
    use_api_path = _str_to_bool(
        os.environ.get("USE_API_PATH", str(config.use_api_path))
    )

    logger.info("Checking Gerrit service availability…")
    logger.info("")
    logger.info("  Instances:           %d", len(instance_store))
    logger.info("  Skip plugin install: %s", skip_plugin)
    logger.info("  Use API path:        %s", use_api_path)
    logger.info("")

    try:
        check_all_instances(
            docker,
            instance_store,
            skip_plugin_install=skip_plugin,
            use_api_path=use_api_path,
        )
    except HealthCheckError:
        # check_all_instances already logged details and wrote the
        # step summary; just propagate the non-zero exit code.
        return 1

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _str_to_bool(value: str) -> bool:
    """Convert a string to bool (``"true"`` → True, anything else → False)."""
    return value.strip().lower() == "true"


if __name__ == "__main__":
    sys.exit(main())
