# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the post-replication reindex.py script.

Covers the helpers that drive the cache-flush + per-project
``index.changes`` orchestration with a mocked
:class:`GerritDevClient`:

- ``_build_url`` URL construction (with / without API path)
- ``_flush_caches`` zero-body POST contract, 404-benign handling,
  non-404 warning path and the flushed-count return value
- ``_list_projects`` JSON parsing and error handling
- ``_reindex_project`` zero-body POST contract and error handling
- ``reindex_instance`` skip-list, missing-cid and timeout
  short-circuit behaviour
- ``run`` no-op gating on ``REINDEX_AFTER_SYNC`` / ``SYNC_ON_STARTUP``
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup – ensure scripts and lib are importable
# ---------------------------------------------------------------------------
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
LIB_DIR = SCRIPTS_DIR / "lib"
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(LIB_DIR))

from gerrit_api import GerritAPIError  # noqa: E402  # isort: skip

import reindex  # noqa: E402  # isort: skip


# ---------------------------------------------------------------------------
# _build_url
# ---------------------------------------------------------------------------


class TestBuildUrl:
    """Tests for the local Gerrit base-URL builder."""

    def test_no_api_path(self) -> None:
        """Without an API path the URL is just host:port."""
        assert reindex._build_url(8080, "", False) == "http://localhost:8080"

    def test_api_path_disabled(self) -> None:
        """An API path is ignored when use_api_path is False."""
        assert reindex._build_url(8080, "/r", False) == "http://localhost:8080"

    def test_api_path_enabled(self) -> None:
        """The API path is appended when use_api_path is True."""
        assert reindex._build_url(8081, "/r", True) == "http://localhost:8081/r"

    def test_api_path_enabled_but_empty(self) -> None:
        """An empty API path produces no suffix even when enabled."""
        assert reindex._build_url(8082, "", True) == "http://localhost:8082"


# ---------------------------------------------------------------------------
# _flush_caches
# ---------------------------------------------------------------------------


class TestFlushCaches:
    """Tests for the curated cache-flush loop."""

    def test_flushes_every_cache_with_empty_body_post(self) -> None:
        """All caches flush via a zero-body POST suppressing Content-Type."""
        client = MagicMock()
        flushed = reindex._flush_caches(client, "demo")

        assert flushed == len(reindex._CACHES_TO_FLUSH)
        assert client.post.call_count == len(reindex._CACHES_TO_FLUSH)
        # Every call must use data=None and content_type="" so Gerrit
        # does not try to parse an empty body as JSON.
        for call in client.post.call_args_list:
            assert call.kwargs["data"] is None
            assert call.kwargs["content_type"] == ""
            endpoint = call.args[0]
            assert endpoint.startswith("config/server/caches/")
            assert endpoint.endswith("/flush")

    def test_404_is_benign_and_loop_continues(self) -> None:
        """A 404 on one cache is skipped; the rest still flush."""
        client = MagicMock()
        # First cache 404s (not present on this Gerrit), rest succeed.
        client.post.side_effect = [GerritAPIError("nope", status_code=404)] + [None] * (
            len(reindex._CACHES_TO_FLUSH) - 1
        )

        flushed = reindex._flush_caches(client, "demo")

        # The 404 cache is not counted, but the loop did not abort.
        assert flushed == len(reindex._CACHES_TO_FLUSH) - 1
        assert client.post.call_count == len(reindex._CACHES_TO_FLUSH)

    def test_non_404_error_is_warned_not_counted(self) -> None:
        """A non-404 error is logged and does not increment the count."""
        client = MagicMock()
        client.post.side_effect = [GerritAPIError("boom", status_code=400)] + [None] * (
            len(reindex._CACHES_TO_FLUSH) - 1
        )

        flushed = reindex._flush_caches(client, "demo")

        assert flushed == len(reindex._CACHES_TO_FLUSH) - 1
        assert client.post.call_count == len(reindex._CACHES_TO_FLUSH)


# ---------------------------------------------------------------------------
# _list_projects
# ---------------------------------------------------------------------------


class TestListProjects:
    """Tests for project enumeration."""

    def test_returns_sorted_keys(self) -> None:
        """Project names are returned sorted."""
        client = MagicMock()
        client.get.return_value = {"zebra": {}, "alpha": {}, "mango": {}}

        assert reindex._list_projects(client, "demo") == ["alpha", "mango", "zebra"]

    def test_non_dict_response_returns_empty(self) -> None:
        """A non-dict response is treated as an error (empty list)."""
        client = MagicMock()
        client.get.return_value = ["not", "a", "dict"]

        assert reindex._list_projects(client, "demo") == []

    def test_api_error_returns_empty(self) -> None:
        """A GerritAPIError during listing yields an empty list."""
        client = MagicMock()
        client.get.side_effect = GerritAPIError("fail", status_code=500)

        assert reindex._list_projects(client, "demo") == []


# ---------------------------------------------------------------------------
# _reindex_project
# ---------------------------------------------------------------------------


class TestReindexProject:
    """Tests for the per-project index.changes trigger."""

    def test_success_uses_empty_body_post(self) -> None:
        """A successful reindex posts a zero-body request."""
        client = MagicMock()

        assert reindex._reindex_project(client, "demo", "my/project") is True

        client.post.assert_called_once()
        endpoint = client.post.call_args.args[0]
        # The project name is URL-encoded into the path.
        assert endpoint == "projects/my%2Fproject/index.changes"
        assert client.post.call_args.kwargs["data"] is None
        assert client.post.call_args.kwargs["content_type"] == ""

    def test_api_error_returns_false(self) -> None:
        """An API error is swallowed and reported as failure."""
        client = MagicMock()
        client.post.side_effect = GerritAPIError("nope", status_code=500)

        assert reindex._reindex_project(client, "demo", "proj") is False


# ---------------------------------------------------------------------------
# reindex_instance
# ---------------------------------------------------------------------------


class TestReindexInstance:
    """Tests for the per-instance orchestration."""

    def test_missing_cid_skips(self) -> None:
        """An instance without a container ID is skipped."""
        result = reindex.reindex_instance("demo", {"cid": None}, False, 900)
        assert result == (0, 0)

    def test_skip_list_projects_not_reindexed(self) -> None:
        """All-Users / All-Projects are never reindexed."""
        client = MagicMock()
        client.become_admin.return_value = "1000000"
        client.get.return_value = {
            "All-Users": {},
            "All-Projects": {},
            "All-External-IDs": {},
            "Sequences": {},
            "team/repo-a": {},
            "team/repo-b": {},
        }

        with patch.object(reindex, "GerritDevClient", return_value=client):
            successes, failures = reindex.reindex_instance(
                "demo",
                {"cid": "abc123", "http_port": 8080},
                False,
                900,
            )

        assert (successes, failures) == (2, 0)
        # Only the two real projects trigger index.changes POSTs.
        reindexed = {call.args[0] for call in client.post.call_args_list}
        assert "projects/team%2Frepo-a/index.changes" in reindexed
        assert "projects/team%2Frepo-b/index.changes" in reindexed
        assert not any("All-Users" in e for e in reindexed)
        assert not any("All-Projects" in e for e in reindexed)

    def test_become_admin_failure_returns_zero(self) -> None:
        """Failure to authenticate as admin aborts the instance cleanly."""
        client = MagicMock()
        client.become_admin.side_effect = GerritAPIError("denied", status_code=403)

        with patch.object(reindex, "GerritDevClient", return_value=client):
            result = reindex.reindex_instance(
                "demo",
                {"cid": "abc123", "http_port": 8080},
                False,
                900,
            )

        assert result == (0, 0)
        client.post.assert_not_called()

    def test_timeout_short_circuits_remaining_projects(self) -> None:
        """The per-instance timeout stops enqueuing further projects."""
        client = MagicMock()
        client.become_admin.return_value = "1000000"
        client.get.return_value = {"p1": {}, "p2": {}, "p3": {}}

        # monotonic() drives the start marker, each per-loop check and
        # the final elapsed calculation.  p1's check is within budget
        # (enqueued); p2's check jumps past the timeout so p2/p3 are
        # skipped.
        times = iter([100.0, 100.0, 1000.0, 1000.0])

        with (
            patch.object(reindex, "GerritDevClient", return_value=client),
            patch.object(reindex.time, "monotonic", lambda: next(times)),
        ):
            successes, failures = reindex.reindex_instance(
                "demo",
                {"cid": "abc123", "http_port": 8080},
                False,
                300,
            )

        # Only the first project was enqueued before the timeout hit.
        assert successes == 1
        assert failures == 0
        reindex_calls = [
            c for c in client.post.call_args_list if c.args[0].endswith("index.changes")
        ]
        assert len(reindex_calls) == 1


# ---------------------------------------------------------------------------
# run() gating
# ---------------------------------------------------------------------------


class TestRunGating:
    """Tests for the top-level no-op gating in run()."""

    def test_noop_when_reindex_disabled(self) -> None:
        """run() is a no-op when REINDEX_AFTER_SYNC is not true."""
        cfg = MagicMock()
        cfg.reindex_after_sync = False
        cfg.debug = False

        with (
            patch.object(reindex.ActionConfig, "from_environment", return_value=cfg),
            patch.object(reindex, "setup_logging"),
        ):
            assert reindex.run() == 0

    def test_noop_when_sync_on_startup_disabled(self) -> None:
        """run() is a no-op when SYNC_ON_STARTUP is false."""
        cfg = MagicMock()
        cfg.reindex_after_sync = True
        cfg.sync_on_startup = False
        cfg.debug = False

        with (
            patch.object(reindex.ActionConfig, "from_environment", return_value=cfg),
            patch.object(reindex, "setup_logging"),
        ):
            assert reindex.run() == 0
