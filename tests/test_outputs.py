# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the outputs module.

Covers:
- write_output: single-line and multi-line values, heredoc syntax,
  missing GITHUB_OUTPUT env var
- write_summary: append to GITHUB_STEP_SUMMARY, trailing newline,
  missing env var
- write_json_output / write_pretty_json_output: JSON serialisation
- collect_instance_outputs: aggregation of instance metadata
- emit_collected_outputs: full pipeline (collect + write + summary)
- write_instance_table_summary: Markdown table generation
- write_status_summary: titled status block
- _truncate helper
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from outputs import (
    _truncate,
    collect_instance_outputs,
    emit_collected_outputs,
    write_instance_table_summary,
    write_json_output,
    write_output,
    write_pretty_json_output,
    write_status_summary,
    write_summary,
)

# =========================================================================
# write_output
# =========================================================================


class TestWriteOutput:
    def test_single_line_value(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_output("container_ids", '["abc123"]')

        content = github_output.read_text()
        assert content == 'container_ids=["abc123"]\n'

    def test_multi_line_value_uses_heredoc(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        value = "line1\nline2\nline3"
        write_output("instances", value)

        content = github_output.read_text()
        assert content == "instances<<EOF\nline1\nline2\nline3\nEOF\n"

    def test_multiple_writes_append(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_output("key1", "val1")
        write_output("key2", "val2")

        content = github_output.read_text()
        assert "key1=val1\n" in content
        assert "key2=val2\n" in content

    def test_missing_env_var_silently_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        # Should not raise
        write_output("key", "value")

    def test_empty_value(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_output("empty", "")

        content = github_output.read_text()
        assert content == "empty=\n"

    def test_value_with_special_chars(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_output("url", "https://gerrit.example.org/r?q=status:open")

        content = github_output.read_text()
        assert content == "url=https://gerrit.example.org/r?q=status:open\n"

    def test_write_to_nonexistent_path_logs_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad_path = tmp_path / "nonexistent_dir" / "output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(bad_path))

        # Should not raise, just log a warning
        write_output("key", "value")


# =========================================================================
# write_summary
# =========================================================================


class TestWriteSummary:
    def test_append_markdown(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_summary("### Heading\n\nSome content.")

        content = github_summary.read_text()
        assert "### Heading" in content
        assert "Some content." in content

    def test_trailing_newline_ensured(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_summary("No trailing newline")

        content = github_summary.read_text()
        assert content.endswith("\n")

    def test_already_has_trailing_newline(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_summary("Has newline\n")

        content = github_summary.read_text()
        assert content == "Has newline\n"
        # Should not double the newline
        assert not content.endswith("\n\n")

    def test_multiple_writes_append(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_summary("First block\n")
        write_summary("Second block\n")

        content = github_summary.read_text()
        assert "First block" in content
        assert "Second block" in content

    def test_missing_env_var_silently_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        # Should not raise
        write_summary("Some markdown")

    def test_empty_markdown(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_summary("")

        content = github_summary.read_text()
        assert content == "\n"


# =========================================================================
# write_json_output
# =========================================================================


class TestWriteJsonOutput:
    def test_compact_json(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_json_output("ids", ["abc", "def"])

        content = github_output.read_text()
        assert content == 'ids=["abc","def"]\n'

    def test_dict_value(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_json_output("meta", {"key": "value"})

        content = github_output.read_text()
        assert content == 'meta={"key":"value"}\n'

    def test_numeric_value(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_json_output("count", 42)

        content = github_output.read_text()
        assert content == "count=42\n"

    def test_empty_list(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_json_output("empty", [])

        content = github_output.read_text()
        assert content == "empty=[]\n"


# =========================================================================
# write_pretty_json_output
# =========================================================================


class TestWritePrettyJsonOutput:
    def test_indented_json_uses_heredoc(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_pretty_json_output("data", {"a": 1, "b": 2})

        content = github_output.read_text()
        # Multi-line JSON uses heredoc syntax
        assert "data<<EOF\n" in content
        assert "EOF\n" in content
        # Indented
        assert '"a": 1' in content

    def test_list_value(
        self, github_output: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

        write_pretty_json_output("items", [1, 2, 3])

        content = github_output.read_text()
        assert "items<<EOF\n" in content
        # Each item on its own line
        assert "  1" in content


# =========================================================================
# collect_instance_outputs
# =========================================================================


class TestCollectInstanceOutputs:
    def test_basic_aggregation(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
    ) -> None:
        result = collect_instance_outputs(sample_instances, sample_api_paths)

        assert "container_ids" in result
        assert "container_ips" in result
        assert "gerrit_urls" in result
        assert "instances" in result
        assert "api_paths" in result
        assert "ssh_host_keys" in result

    def test_container_ids_sorted_by_slug(
        self, sample_instances: dict[str, dict[str, Any]]
    ) -> None:
        result = collect_instance_outputs(sample_instances)

        # Slugs sorted: "lf" < "onap"
        assert result["container_ids"] == [
            "789ghi012jkl",  # lf
            "abc123def456",  # onap
        ]

    def test_container_ips_sorted_by_slug(
        self, sample_instances: dict[str, dict[str, Any]]
    ) -> None:
        result = collect_instance_outputs(sample_instances)

        assert result["container_ips"] == [
            "172.17.0.3",  # lf
            "172.17.0.2",  # onap
        ]

    def test_gerrit_urls_comma_separated(
        self, sample_instances: dict[str, dict[str, Any]]
    ) -> None:
        result = collect_instance_outputs(sample_instances)

        urls = result["gerrit_urls"].split(",")
        assert len(urls) == 2
        # Sorted by slug: lf, onap
        assert "172.17.0.3" in urls[0]
        assert "172.17.0.2" in urls[1]

    def test_ssh_host_keys_extracted(
        self, sample_instances: dict[str, dict[str, Any]]
    ) -> None:
        result = collect_instance_outputs(sample_instances)

        keys = result["ssh_host_keys"]
        assert "onap" in keys
        assert "lf" in keys
        assert "ssh_host_ed25519_key" in keys["onap"]
        assert keys["lf"] == {}

    def test_api_paths_passthrough(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
    ) -> None:
        result = collect_instance_outputs(sample_instances, sample_api_paths)

        assert result["api_paths"] == sample_api_paths

    def test_no_api_paths(self, sample_instances: dict[str, dict[str, Any]]) -> None:
        result = collect_instance_outputs(sample_instances, None)

        assert result["api_paths"] == {}

    def test_instances_passthrough(
        self, sample_instances: dict[str, dict[str, Any]]
    ) -> None:
        result = collect_instance_outputs(sample_instances)

        assert result["instances"] is sample_instances

    def test_single_instance(self) -> None:
        instances = {
            "solo": {
                "cid": "solo123",
                "ip": "10.0.0.1",
                "url": "http://10.0.0.1:8080",
                "http_port": 18080,
                "ssh_port": 29418,
            }
        }
        result = collect_instance_outputs(instances)

        assert result["container_ids"] == ["solo123"]
        assert result["container_ips"] == ["10.0.0.1"]
        assert result["gerrit_urls"] == "http://10.0.0.1:8080"

    def test_empty_instances(self) -> None:
        result = collect_instance_outputs({})

        assert result["container_ids"] == []
        assert result["container_ips"] == []
        assert result["gerrit_urls"] == ""
        assert result["ssh_host_keys"] == {}

    def test_missing_url_key(self) -> None:
        instances = {
            "test": {
                "cid": "abc",
                "ip": "10.0.0.1",
                "http_port": 18080,
                "ssh_port": 29418,
            }
        }
        result = collect_instance_outputs(instances)

        # Missing "url" should default to ""
        assert result["gerrit_urls"] == ""

    def test_missing_ssh_host_keys(self) -> None:
        instances = {
            "test": {
                "cid": "abc",
                "ip": "10.0.0.1",
                "url": "http://10.0.0.1:8080",
                "http_port": 18080,
                "ssh_port": 29418,
            }
        }
        result = collect_instance_outputs(instances)

        assert result["ssh_host_keys"]["test"] == {}


# =========================================================================
# emit_collected_outputs
# =========================================================================


class TestEmitCollectedOutputs:
    def test_writes_all_outputs(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
        github_output: Path,
        github_summary: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        result = emit_collected_outputs(sample_instances, sample_api_paths)

        # Verify return value
        assert "container_ids" in result
        assert "gerrit_urls" in result

        # Verify GITHUB_OUTPUT was written to
        output_content = github_output.read_text()
        assert "container_ids" in output_content
        assert "container_ips" in output_content
        assert "gerrit_urls" in output_content
        assert "instances" in output_content
        assert "api_paths" in output_content
        assert "ssh_host_keys" in output_content

    def test_writes_step_summary(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
        github_output: Path,
        github_summary: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        emit_collected_outputs(sample_instances, sample_api_paths)

        summary = github_summary.read_text()
        # Should contain JSON blocks
        assert "```json" in summary or "```" in summary
        # Should contain section headers
        assert "Outputs" in summary
        assert "API Paths" in summary
        assert "SSH Host Keys" in summary
        assert "Access URLs" in summary

    def test_summary_contains_instance_details(
        self,
        sample_instances: dict[str, dict[str, Any]],
        github_output: Path,
        github_summary: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        emit_collected_outputs(sample_instances)

        summary = github_summary.read_text()
        assert "onap" in summary
        assert "lf" in summary

    def test_without_api_paths(
        self,
        sample_instances: dict[str, dict[str, Any]],
        github_output: Path,
        github_summary: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        result = emit_collected_outputs(sample_instances, None)

        assert result["api_paths"] == {}

    def test_return_value_structure(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
        github_output: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        result = emit_collected_outputs(sample_instances, sample_api_paths)

        assert isinstance(result["container_ids"], list)
        assert isinstance(result["container_ips"], list)
        assert isinstance(result["gerrit_urls"], str)
        assert isinstance(result["instances"], dict)
        assert isinstance(result["api_paths"], dict)
        assert isinstance(result["ssh_host_keys"], dict)


# =========================================================================
# write_instance_table_summary
# =========================================================================


class TestWriteInstanceTableSummary:
    def test_table_format(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        rows = [
            ("onap", "Healthy ✅"),
            ("lf", "Failed ❌"),
        ]
        write_instance_table_summary("Service Health", rows)

        content = github_summary.read_text()
        assert "### Service Health" in content
        assert "| Instance | Status |" in content
        assert "|----------|--------|" in content
        assert "| onap | Healthy ✅ |" in content
        assert "| lf | Failed ❌ |" in content

    def test_table_with_emoji(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        rows = [("test", "OK")]
        write_instance_table_summary("Check", rows, emoji="💚")

        content = github_summary.read_text()
        assert "### Check 💚" in content

    def test_table_without_emoji(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        rows = [("test", "OK")]
        write_instance_table_summary("Check", rows)

        content = github_summary.read_text()
        assert "### Check\n" in content

    def test_empty_rows(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_instance_table_summary("Empty", [])

        content = github_summary.read_text()
        assert "### Empty" in content
        assert "| Instance | Status |" in content


# =========================================================================
# write_status_summary
# =========================================================================


class TestWriteStatusSummary:
    def test_basic_status(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_status_summary("Cleanup Complete", "All containers removed.")

        content = github_summary.read_text()
        assert "**Cleanup Complete**" in content
        assert "All containers removed." in content

    def test_status_with_emoji(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_status_summary("Done", "All good.", emoji="🧹")

        content = github_summary.read_text()
        assert "**Done** 🧹" in content

    def test_status_without_emoji(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_status_summary("Title", "Body text.")

        content = github_summary.read_text()
        assert "**Title**\n" in content

    def test_multiline_body(
        self, github_summary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(github_summary))

        write_status_summary(
            "Status",
            "Line 1\nLine 2\nLine 3",
        )

        content = github_summary.read_text()
        assert "Line 1\nLine 2\nLine 3" in content


# =========================================================================
# _truncate
# =========================================================================


class TestTruncate:
    def test_short_string_unchanged(self) -> None:
        assert _truncate("hello") == "hello"

    def test_exact_length_unchanged(self) -> None:
        text = "x" * 120
        assert _truncate(text) == text

    def test_long_string_truncated(self) -> None:
        text = "x" * 200
        result = _truncate(text)
        assert len(result) == 121  # 120 + "…"
        assert result.endswith("…")

    def test_custom_maxlen(self) -> None:
        text = "abcdef"
        result = _truncate(text, maxlen=3)
        assert result == "abc…"

    def test_empty_string(self) -> None:
        assert _truncate("") == ""

    def test_maxlen_zero(self) -> None:
        result = _truncate("hello", maxlen=0)
        assert result == "…"


# =========================================================================
# Integration: collect + emit round-trip
# =========================================================================


class TestOutputIntegration:
    def test_json_round_trip_via_output_file(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
        github_output: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify that JSON written to GITHUB_OUTPUT can be parsed back."""
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        emit_collected_outputs(sample_instances, sample_api_paths)

        output_content = github_output.read_text()

        # Extract the gerrit_urls line (single-line)
        for line in output_content.splitlines():
            if line.startswith("gerrit_urls="):
                urls = line.split("=", 1)[1]
                parts = urls.split(",")
                assert len(parts) == 2
                break

        # Extract container_ids (compact JSON, single-line)
        for line in output_content.splitlines():
            if line.startswith("container_ids="):
                ids_json = line.split("=", 1)[1]
                ids = json.loads(ids_json)
                assert isinstance(ids, list)
                assert len(ids) == 2
                break

    def test_collect_then_verify_json_structure(
        self,
        sample_instances: dict[str, dict[str, Any]],
        sample_api_paths: dict[str, dict[str, str]],
    ) -> None:
        """Verify the collected dict has valid JSON-serialisable values."""
        result = collect_instance_outputs(sample_instances, sample_api_paths)

        # Everything should be JSON-serialisable
        serialised = json.dumps(result)
        parsed = json.loads(serialised)

        assert parsed["container_ids"] == result["container_ids"]
        assert parsed["gerrit_urls"] == result["gerrit_urls"]
