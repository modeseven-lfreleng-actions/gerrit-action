#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Reindex changes and flush caches after pull-replication completes.

Pull-replication writes refs directly into the bare git repositories
inside the Gerrit container; it never goes through the
``ChangeUpdate`` plumbing that keeps Gerrit's Lucene secondary index
in sync with NoteDb.  After replication finishes, the change refs
(``refs/changes/*``) are on disk but the UI dashboard, REST
``/changes/?q=…`` queries and ``gerrit query`` all return empty
because they read from Lucene, not NoteDb.

This script closes that gap by:

1. Connecting to each instance over its mapped HTTP port (the action
   already runs Gerrit in DEVELOPMENT_BECOME_ANY_ACCOUNT mode), and
   becoming an admin account.
2. Flushing a curated allow-list of caches (see
   ``_CACHES_TO_FLUSH``) covering the account, group, external-id,
   change-note and project caches, so newly replicated
   ``All-Users`` / ``All-Projects`` refs become visible without a
   container restart.
3. Listing every project Gerrit knows about and POSTing
   ``/a/projects/<name>/index.changes`` on each one (skipping
   ``All-Users`` and ``All-Projects``, which have no changes of
   their own).  The endpoint is asynchronous on the Gerrit side, so
   this script returns as soon as every project has been *enqueued*
   for reindexing.

Failures on individual projects are logged but do not abort the run;
the action's overall verify-replication step is the authoritative
pass/fail gate.

Usage::

    # Triggered from action.yaml after verify-replication
    REINDEX_AFTER_SYNC=true \\
    WORK_DIR=/tmp/gerrit-action \\
    USE_API_PATH=false \\
        python scripts/reindex.py

Environment Variables
---------------------
WORK_DIR
    Working directory containing ``instances.json``.
REINDEX_AFTER_SYNC
    Must be ``"true"`` for the script to do work; any other value
    makes it a no-op (so the action step can be cheap to keep
    enabled by default).
USE_API_PATH
    When ``"true"``, the per-instance ``api_path`` is appended to
    the local Gerrit URL.  Must match the value used by the rest of
    the action.
REINDEX_TIMEOUT
    Per-instance overall wall-clock budget in seconds (default
    ``900``).
DEBUG
    If ``"true"``, enable debug-level logging.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import ActionConfig, InstanceStore  # noqa: E402
from errors import GerritActionError  # noqa: E402
from logging_utils import setup_logging  # noqa: E402

from gerrit_api import GerritAPIError, GerritDevClient  # noqa: E402

logger = logging.getLogger(__name__)


# Caches that pull-replication writes around (so they need explicit
# flushing once we've landed new refs in All-Users / All-Projects).
# We list them by name rather than calling ``FLUSH_ALL`` so we leave
# unrelated runtime caches (e.g. ``web_sessions``) intact and don't
# evict the admin session we're using to issue the flush itself.
_CACHES_TO_FLUSH: tuple[str, ...] = (
    "accounts",
    "accounts_byemail",
    "accounts_byname",
    "groups",
    "groups_byname",
    "groups_byuuid",
    "groups_members",
    "groups_external",
    "external_ids_map",
    "change_notes",
    "projects",
    "project_list",
)

# Gerrit special projects that have no user changes and should be
# skipped when iterating for ``index.changes``.
_SKIP_PROJECTS: frozenset[str] = frozenset(
    {"All-Users", "All-Projects", "All-External-IDs", "Sequences"}
)


def _build_url(http_port: int, api_path: str, use_api_path: bool) -> str:
    """Build the local Gerrit base URL for an instance."""
    effective = api_path if (use_api_path and api_path) else ""
    return f"http://localhost:{http_port}{effective}"


def _flush_caches(client: GerritDevClient, slug: str) -> int:
    """Flush the caches that pull-replication bypasses.

    Returns the number of caches successfully flushed.
    """
    logger.info("[%s] Flushing %d caches…", slug, len(_CACHES_TO_FLUSH))
    flushed = 0
    for cache_name in _CACHES_TO_FLUSH:
        endpoint = f"config/server/caches/{cache_name}/flush"
        try:
            # The flush endpoint takes no body.  Pass ``data=None``
            # so the client sends a true zero-byte request, and
            # ``content_type=""`` to suppress the default
            # ``Content-Type: application/json`` header — otherwise
            # Gerrit sees ``Content-Type: application/json`` with an
            # empty body, tries to parse ``""`` as JSON, and rejects
            # the call with ``HTTP 400: Expected JSON object``.
            client.post(endpoint, data=None, content_type="")
            flushed += 1
            logger.debug("[%s]   flushed cache: %s", slug, cache_name)
        except GerritAPIError as exc:
            # Not every Gerrit version exposes every cache name listed
            # above (e.g. ``groups_external`` was renamed across 3.x
            # minor releases).  Gerrit's REST handler returns 404 for
            # an unknown cache name on the
            # ``POST /a/config/server/caches/<name>/flush`` endpoint;
            # we treat that single status as benign and continue with
            # the rest of the curated cache list.  Other 4xx / 5xx
            # status codes — including 400 ``Expected JSON object``,
            # which we hit on an earlier round of this branch before
            # we suppressed the request's Content-Type header — are
            # genuine errors and must be logged at WARNING, never
            # silently downgraded.  Narrowing to 404-only here keeps
            # the next regression of that shape from disappearing
            # into debug noise.
            if exc.status_code == 404:
                logger.debug(
                    "[%s]   skip cache %s (HTTP 404, not present on this Gerrit)",
                    slug,
                    cache_name,
                )
                continue
            logger.warning("[%s]   failed to flush %s: %s", slug, cache_name, exc)
    logger.info("[%s]   flushed %d / %d caches", slug, flushed, len(_CACHES_TO_FLUSH))
    return flushed


def _list_projects(client: GerritDevClient, slug: str) -> list[str]:
    """Return the list of project names Gerrit knows about.

    Uses ``/a/projects/`` which respects the caller's read ACLs.  We
    are authenticated as an admin so all projects are returned.
    """
    try:
        # ``?type=ALL`` includes the magic projects; we filter them
        # out below.  We only need the project names (the response
        # keys), so we don't request descriptions (``&d``) — keeping
        # the response small and cheap to parse.
        result = client.get("projects/?type=ALL")
    except GerritAPIError as exc:
        logger.error("[%s] failed to list projects: %s", slug, exc)
        return []

    if not isinstance(result, dict):
        logger.error(
            "[%s] unexpected projects/ response type: %s", slug, type(result).__name__
        )
        return []

    # The endpoint returns a JSON object keyed by project name.
    names = sorted(result.keys())
    logger.info("[%s] Gerrit knows about %d projects", slug, len(names))
    return names


def _reindex_project(client: GerritDevClient, slug: str, project: str) -> bool:
    """Trigger an asynchronous changes-index rebuild for one project.

    Returns *True* on success, *False* on any error.
    """
    encoded = quote(project, safe="")
    endpoint = f"projects/{encoded}/index.changes"
    try:
        # The index.changes endpoint takes no body.  Pass
        # ``data=None`` so the client sends a zero-byte request,
        # and ``content_type=""`` so the default
        # ``Content-Type: application/json`` header is suppressed:
        # if it is sent alongside an empty body Gerrit tries to
        # parse ``""`` as JSON and rejects with
        # ``HTTP 400: Expected JSON object`` (observed against
        # every project of the previous two dispatches even with
        # ``data=None`` alone).
        client.post(endpoint, data=None, content_type="")
    except GerritAPIError as exc:
        # Projects with no changes return 204 No Content which the
        # client treats as success; an actual error here is genuinely
        # noteworthy.
        logger.warning(
            "[%s]   reindex failed for %s (HTTP %s): %s",
            slug,
            project,
            exc.status_code,
            exc,
        )
        return False
    return True


def reindex_instance(
    slug: str,
    instance: dict[str, Any],
    use_api_path: bool,
    timeout: int,
) -> tuple[int, int]:
    """Reindex one Gerrit instance.

    Returns a tuple ``(successes, failures)`` for per-project reindex
    calls.  The cache-flush step's outcome is logged but does not
    contribute to either counter.
    """
    cid = instance.get("cid")
    http_port = instance.get("http_port", 8080)
    api_path = instance.get("api_path", "")

    if not cid or cid == "null":
        logger.warning("[%s] No container ID; skipping reindex", slug)
        return 0, 0

    url = _build_url(http_port, api_path, use_api_path)
    logger.info("[%s] Reindexing via %s", slug, url)

    start = time.monotonic()

    client = GerritDevClient(url, timeout=min(timeout, 60))
    try:
        admin_id = client.become_admin()
    except GerritAPIError as exc:
        logger.error("[%s] could not authenticate as admin: %s", slug, exc)
        return 0, 0
    logger.info("[%s] Authenticated as admin account %s", slug, admin_id)

    # 1. Flush stale caches so newly replicated All-Users / All-Projects
    #    refs become visible to subsequent REST calls.
    _flush_caches(client, slug)

    # 2. Enumerate projects after the cache flush so the project list
    #    reflects any projects that arrived during pull-replication.
    projects = _list_projects(client, slug)
    projects = [p for p in projects if p not in _SKIP_PROJECTS]

    # 3. Per-project reindex.  We respect the overall timeout budget
    #    to keep the action step bounded on huge instances.
    successes = 0
    failures = 0
    for project in projects:
        if time.monotonic() - start > timeout:
            remaining = len(projects) - (successes + failures)
            logger.warning(
                "[%s] reindex timeout (%ds) reached; %d project(s) not enqueued",
                slug,
                timeout,
                remaining,
            )
            break
        if _reindex_project(client, slug, project):
            successes += 1
        else:
            failures += 1

    elapsed = int(time.monotonic() - start)
    logger.info(
        "[%s] Reindex enqueued: %d ok, %d failed, %ds elapsed",
        slug,
        successes,
        failures,
        elapsed,
    )
    return successes, failures


def run() -> int:
    """Reindex every instance listed in ``$WORK_DIR/instances.json``.

    Per-project reindex failures are logged but never propagate to
    the exit code: the action's overall verify-replication step is
    the authoritative pass/fail gate, and a partially reindexed
    Gerrit is more useful than a workflow that aborts on the first
    HTTP hiccup.  Missing or empty ``instances.json``, disabled
    ``REINDEX_AFTER_SYNC``, and disabled ``SYNC_ON_STARTUP`` are
    all treated as no-op success cases.

    Returns
    -------
    int
        Always ``0`` under normal operation.  Unhandled exceptions
        (caught by :func:`main`) map to ``1`` via
        ``GerritActionError`` or ``2`` via the generic exception
        handler; ``run`` itself does not return a non-zero code.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    if not config.reindex_after_sync:
        logger.info("REINDEX_AFTER_SYNC is not 'true'; nothing to do (no-op).")
        return 0

    if not config.sync_on_startup:
        logger.info("SYNC_ON_STARTUP is false; skipping reindex (no replication ran).")
        return 0

    instance_store = InstanceStore(config.instances_json_path)
    if not config.instances_json_path.exists():
        # Only the *missing-file* case is a benign no-op (no
        # deployment ran).  If the file exists but contains invalid
        # JSON, ``load()`` raises ``ConfigError`` and we let it
        # propagate so corrupt metadata fails the step instead of
        # silently skipping the reindex.
        logger.warning(
            "No instances.json at %s; nothing to reindex",
            config.instances_json_path,
        )
        return 0

    instance_store.load()

    if len(instance_store) == 0:
        logger.warning("instances.json is empty; nothing to reindex")
        return 0

    # Parse the per-instance timeout budget defensively: a
    # non-integer REINDEX_TIMEOUT (e.g. a typo or unexpanded
    # template) falls back to the 900s default with a warning
    # rather than crashing the whole reindex step with a bare
    # ValueError that surfaces only via the generic handler.
    _timeout_raw = os.environ.get("REINDEX_TIMEOUT", "900")
    try:
        timeout = int(_timeout_raw)
    except ValueError:
        logger.warning(
            "REINDEX_TIMEOUT=%r is not a valid integer; using default 900s",
            _timeout_raw,
        )
        timeout = 900
    use_api_path = os.environ.get("USE_API_PATH", "false").lower() == "true"

    logger.info("Post-replication reindex configuration:")
    logger.info("  Per-instance timeout: %ds", timeout)
    logger.info("  Use API path:         %s", use_api_path)
    logger.info("  Instances:            %d", len(instance_store))
    logger.info("")

    total_ok = 0
    total_fail = 0
    instances = instance_store.data
    for slug in sorted(instances.keys()):
        ok, fail = reindex_instance(
            slug=slug,
            instance=instances[slug],
            use_api_path=use_api_path,
            timeout=timeout,
        )
        total_ok += ok
        total_fail += fail

    logger.info("")
    logger.info(
        "Reindex summary: %d project(s) enqueued, %d failure(s)",
        total_ok,
        total_fail,
    )

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write("\n## Post-replication reindex\n\n")
                fh.write(
                    f"- Projects enqueued for reindex: **{total_ok}**\n"
                    f"- Reindex failures: **{total_fail}**\n"
                )
        except OSError as exc:
            logger.debug("could not append to step summary: %s", exc)

    # Per-project failures are non-fatal; the verify-replication step
    # already gated the overall success of the workflow.
    return 0


def main() -> int:
    """Entry point with structured error handling."""
    # Configure logging up-front so the _GitHubActionsFormatter is
    # active even if run() raises before it reaches its own
    # setup_logging() call (e.g. a ConfigError from
    # ActionConfig.from_environment()).  The formatter already
    # prepends a single ``::error::`` annotation to ERROR records,
    # so we must not print a second one by hand.
    setup_logging()
    try:
        return run()
    except GerritActionError as exc:
        logger.error(str(exc))
        return 1
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
