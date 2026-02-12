#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Collect outputs from Gerrit instances and export to GitHub Actions.

This script aggregates instance metadata from ``instances.json`` and
``api_paths.json``, builds the output structure, writes it to
``$GITHUB_OUTPUT``, and generates a Markdown step summary.

Replaces ``collect-outputs.sh`` (172 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/collect-outputs.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action python scripts/collect-outputs.py
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

from config import ActionConfig, ApiPathStore, InstanceStore  # noqa: E402
from errors import GerritActionError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from outputs import emit_collected_outputs  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Collect and emit outputs for all Gerrit instances.

    Reads ``instances.json`` and ``api_paths.json`` from
    ``$WORK_DIR``, aggregates the metadata, writes to
    ``$GITHUB_OUTPUT``, and generates the step summary.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on anticipated error, 2 on
        unexpected error.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    logger.info("Collecting outputs…")
    logger.info("")

    # Load instances metadata
    instance_store = InstanceStore(config.instances_json_path)
    instances = instance_store.load()

    if not instances:
        logger.warning("No instances found in %s", config.instances_json_path)
        return 0

    # Load API paths (optional — may not exist)
    api_path_store = ApiPathStore(config.api_paths_json_path)
    api_paths = api_path_store.load()

    # Collect and emit outputs
    emit_collected_outputs(instances, api_paths or None)

    logger.info("")
    logger.info("Outputs collected ✅")
    logger.info(
        "Processed %d instance(s), %d API path(s)",
        len(instances),
        len(api_paths),
    )

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
