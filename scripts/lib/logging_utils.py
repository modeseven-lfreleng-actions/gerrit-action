# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Structured logging setup for gerrit-action scripts.

Provides a single :func:`setup_logging` entry point that configures the
root logger with a consistent format, optional GitHub Actions grouping
syntax, and ``DEBUG`` environment variable support.

Usage::

    from logging_utils import setup_logging
    setup_logging()          # reads DEBUG from env
    setup_logging(debug=True)  # force debug level
"""

from __future__ import annotations

import logging
import os
import sys


class _GitHubActionsFormatter(logging.Formatter):
    """Formatter that emits GitHub Actions workflow commands for warnings/errors.

    Regular messages use the standard ``%(asctime)s [%(levelname)s] …`` format.
    Messages at WARNING or above are *additionally* prefixed with the
    ``::warning::`` / ``::error::`` annotations that GitHub Actions renders
    inline in the workflow UI.
    """

    _GH_LEVEL_MAP = {
        logging.WARNING: "warning",
        logging.ERROR: "error",
        logging.CRITICAL: "error",
    }

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        gh_level = self._GH_LEVEL_MAP.get(record.levelno)
        if gh_level:
            # Prepend the GitHub Actions annotation so it appears in the UI
            return f"::{gh_level}::{record.getMessage()}\n{formatted}"
        return formatted


class _PlainFormatter(logging.Formatter):
    """Simple formatter for non-CI environments."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def setup_logging(debug: bool | None = None) -> None:
    """Configure logging for gerrit-action scripts.

    Parameters
    ----------
    debug:
        If *True*, set the root logger to ``DEBUG``.  If *False*, set it
        to ``INFO``.  If *None* (the default), read the ``DEBUG``
        environment variable — ``"true"`` (case-insensitive) selects
        debug level, anything else selects info level.

    The function is idempotent: calling it multiple times replaces any
    previously-installed handler rather than adding duplicates.
    """
    if debug is None:
        debug = os.environ.get("DEBUG", "false").lower() == "true"

    level = logging.DEBUG if debug else logging.INFO

    # Detect GitHub Actions environment
    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"

    handler = logging.StreamHandler(sys.stderr)
    if is_ci:
        handler.setFormatter(_GitHubActionsFormatter())
    else:
        handler.setFormatter(_PlainFormatter())

    root = logging.getLogger()
    # Remove any existing handlers to make this idempotent
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)


def log_group(title: str) -> _LogGroup:
    """Context manager that emits GitHub Actions log grouping commands.

    Usage::

        with log_group("Starting Gerrit containers"):
            logger.info("container 1 started")
            logger.info("container 2 started")

    Outside GitHub Actions the title is printed as a plain header.
    """
    return _LogGroup(title)


class _LogGroup:
    """Context manager for GitHub Actions collapsible log groups."""

    def __init__(self, title: str) -> None:
        self._title = title
        self._is_ci = os.environ.get("GITHUB_ACTIONS") == "true"

    def __enter__(self) -> None:
        if self._is_ci:
            print(f"::group::{self._title}", file=sys.stderr)
        else:
            print(f"\n{'=' * 40}", file=sys.stderr)
            print(f"  {self._title}", file=sys.stderr)
            print(f"{'=' * 40}", file=sys.stderr)

    def __exit__(self, *_args: object) -> None:
        if self._is_ci:
            print("::endgroup::", file=sys.stderr)
