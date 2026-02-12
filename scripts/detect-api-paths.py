#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Detect Gerrit API paths via redirect detection.

This script queries each Gerrit server to determine its API path prefix
(e.g., /r/, /infra/, /gerrit/) and stores results for use in replication
config.

Replaces ``detect-api-paths.sh`` (213 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/detect-api-paths.py

    # Locally with environment variables
    GERRIT_SETUP='[{"slug":"onap","gerrit":"gerrit.onap.org"}]' \
    WORK_DIR=/tmp/gerrit-action \
        python scripts/detect-api-paths.py
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

from api_paths import detect_and_record_api_paths  # noqa: E402
from config import ActionConfig, ApiPathStore  # noqa: E402
from errors import GerritActionError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402
from outputs import write_summary  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run() -> int:
    """Detect API paths for all configured Gerrit instances.

    Reads the ``GERRIT_SETUP`` environment variable (JSON array of
    instance configs), detects the API path for each server, and writes
    the results to ``$WORK_DIR/api_paths.json``.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on anticipated error, 2 on
        unexpected error.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    logger.info("Detecting Gerrit API paths…")
    logger.info("")

    # Build the list of dicts that detect_and_record_api_paths expects
    instances = [
        {
            "slug": inst.slug,
            "gerrit": inst.gerrit_host,
            "api_path": inst.api_path or None,
        }
        for inst in config.instances
    ]

    if not instances:
        logger.warning("No instances configured in GERRIT_SETUP")
        return 0

    # Run detection
    results = detect_and_record_api_paths(instances)

    # Persist to api_paths.json
    store = ApiPathStore(config.api_paths_json_path)
    for slug, entry in results.items():
        store.set_path(
            slug,
            gerrit_host=entry["gerrit_host"],
            api_path=entry["api_path"],
            api_url=entry["api_url"],
        )
    store.save()

    # Console summary
    logger.info("========================================")
    logger.info("API Path Detection Complete ✅")
    logger.info("========================================")
    logger.info("")
    logger.info("Detected paths:")
    for slug, entry in sorted(results.items()):
        logger.info(
            "  %s: %s -> %s",
            slug,
            entry["api_path"] or "(root)",
            entry["api_url"],
        )
    logger.info("")

    # Step summary
    summary_lines = [
        "**Gerrit API Paths** 🔗",
        "",
        "| Instance | API Path | API URL |",
        "|----------|----------|---------|",
    ]
    for slug in sorted(results.keys()):
        entry = results[slug]
        api_path_display = f"`{entry['api_path']}`" if entry["api_path"] else "`(root)`"
        summary_lines.append(f"| {slug} | {api_path_display} | {entry['api_url']} |")
    summary_lines.append("")
    write_summary("\n".join(summary_lines))

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
