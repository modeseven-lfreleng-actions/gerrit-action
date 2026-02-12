# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub Actions output and step summary helpers.

Centralises all interaction with ``$GITHUB_OUTPUT`` and
``$GITHUB_STEP_SUMMARY``, replacing the 26+ occurrences of
``>> "$GITHUB_STEP_SUMMARY"`` and ``>> "$GITHUB_OUTPUT"`` scattered
across the shell scripts.

Usage::

    from outputs import write_output, write_summary

    write_output("container_ids", '["abc123"]')
    write_summary("### Gerrit Started ✅\\n\\nAll instances healthy.")
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def write_output(name: str, value: str) -> None:
    """Append a ``name=value`` pair to ``$GITHUB_OUTPUT``.

    Multi-line values are written using the heredoc syntax that GitHub
    Actions requires::

        name<<EOF
        line 1
        line 2
        EOF

    If the ``GITHUB_OUTPUT`` environment variable is not set (e.g. when
    running locally), the call is silently ignored and a debug message
    is logged instead.
    """
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        logger.debug("GITHUB_OUTPUT not set; would write %s=%s", name, _truncate(value))
        return

    try:
        with open(output_file, "a", encoding="utf-8") as fh:
            if "\n" in value:
                # Multi-line value – use heredoc delimiter
                fh.write(f"{name}<<EOF\n{value}\nEOF\n")
            else:
                fh.write(f"{name}={value}\n")
        logger.debug("Wrote output %s (%d chars)", name, len(value))
    except OSError as exc:
        logger.warning("Failed to write to GITHUB_OUTPUT: %s", exc)


def write_summary(markdown: str) -> None:
    """Append *markdown* content to ``$GITHUB_STEP_SUMMARY``.

    A trailing newline is ensured so that consecutive calls don't run
    together.  If the environment variable is unset the call is silently
    ignored.
    """
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        logger.debug("GITHUB_STEP_SUMMARY not set; would write %s", _truncate(markdown))
        return

    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown)
            if not markdown.endswith("\n"):
                fh.write("\n")
        logger.debug("Wrote %d chars to step summary", len(markdown))
    except OSError as exc:
        logger.warning("Failed to write to GITHUB_STEP_SUMMARY: %s", exc)


# ---------------------------------------------------------------------------
# JSON output helpers
# ---------------------------------------------------------------------------


def write_json_output(name: str, value: Any) -> None:
    """Serialise *value* as compact JSON and write it as a GitHub output."""
    write_output(name, json.dumps(value, separators=(",", ":")))


def write_pretty_json_output(name: str, value: Any) -> None:
    """Serialise *value* as indented JSON and write it as a GitHub output.

    Because the result is multi-line, the heredoc syntax is used
    automatically by :func:`write_output`.
    """
    write_output(name, json.dumps(value, indent=2))


# ---------------------------------------------------------------------------
# Instance output collection
# ---------------------------------------------------------------------------


def collect_instance_outputs(
    instances: dict[str, dict[str, Any]],
    api_paths: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Aggregate per-instance metadata into the output structure.

    Parameters
    ----------
    instances:
        Mapping of ``slug → instance metadata dict``.  Each metadata
        dict is expected to have at least ``cid``, ``ip``, ``url``,
        ``http_port``, ``ssh_port``, and optionally ``ssh_host_keys``.
    api_paths:
        Optional mapping of ``slug → {gerrit_host, api_path, api_url}``.

    Returns
    -------
    dict
        A dictionary with the following keys:

        * ``container_ids`` – JSON array of container IDs
        * ``container_ips`` – JSON array of container IP addresses
        * ``gerrit_urls`` – comma-separated URL string
        * ``instances`` – the full *instances* dict (pass-through)
        * ``api_paths`` – the full *api_paths* dict (pass-through)
        * ``ssh_host_keys`` – ``slug → host-keys`` mapping
    """
    slugs = sorted(instances.keys())

    container_ids = [instances[s]["cid"] for s in slugs]
    container_ips = [instances[s]["ip"] for s in slugs]
    gerrit_urls = ",".join(instances[s].get("url", "") for s in slugs)
    ssh_host_keys = {s: instances[s].get("ssh_host_keys", {}) for s in slugs}

    return {
        "container_ids": container_ids,
        "container_ips": container_ips,
        "gerrit_urls": gerrit_urls,
        "instances": instances,
        "api_paths": api_paths or {},
        "ssh_host_keys": ssh_host_keys,
    }


def emit_collected_outputs(
    instances: dict[str, dict[str, Any]],
    api_paths: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Collect outputs and write them to ``$GITHUB_OUTPUT`` and the step summary.

    This is the high-level entry point that replaces ``collect-outputs.sh``.
    It:

    1. Calls :func:`collect_instance_outputs` to build the aggregated dict.
    2. Writes each key to ``$GITHUB_OUTPUT``.
    3. Writes a Markdown summary table to ``$GITHUB_STEP_SUMMARY``.

    Returns the collected outputs dict for callers that need it.
    """
    collected = collect_instance_outputs(instances, api_paths)

    # --- Write to GITHUB_OUTPUT ---
    write_json_output("container_ids", collected["container_ids"])
    write_json_output("container_ips", collected["container_ips"])
    write_output("gerrit_urls", collected["gerrit_urls"])
    write_pretty_json_output("instances", collected["instances"])
    write_pretty_json_output("api_paths", collected["api_paths"])
    write_pretty_json_output("ssh_host_keys", collected["ssh_host_keys"])

    # --- Console output ---
    logger.info("Outputs collected ✅")
    logger.info("Container IDs: %s", json.dumps(collected["container_ids"]))
    logger.info("Container IPs: %s", json.dumps(collected["container_ips"]))
    logger.info("Gerrit URLs: %s", collected["gerrit_urls"])

    # --- Step summary ---
    lines = [
        "**Outputs** 📤",
        "",
        "```json",
        json.dumps(collected["instances"], indent=2),
        "```",
        "",
        "**API Paths** 🔗",
        "",
        "```json",
        json.dumps(collected["api_paths"], indent=2),
        "```",
        "",
        "**SSH Host Keys** 🔑",
        "",
        "```json",
        json.dumps(collected["ssh_host_keys"], indent=2),
        "```",
        "",
        "**Access URLs** 🔗",
        "",
    ]

    slugs = sorted(instances.keys())
    for slug in slugs:
        inst = instances[slug]
        http_port = inst.get("http_port", "?")
        ssh_port = inst.get("ssh_port", "?")
        api_url = inst.get("api_url", "N/A")
        lines.append(f"- **{slug}**")
        lines.append(f"  - HTTP: `http://localhost:{http_port}`")
        lines.append(f"  - SSH: `ssh://localhost:{ssh_port}`")
        lines.append(f"  - Source API: `{api_url}`")

    lines.append("")
    write_summary("\n".join(lines))

    return collected


# ---------------------------------------------------------------------------
# Summary table helpers
# ---------------------------------------------------------------------------


def write_instance_table_summary(
    title: str,
    rows: list[tuple[str, str]],
    *,
    emoji: str = "",
) -> None:
    """Write a two-column Markdown table to the step summary.

    Parameters
    ----------
    title:
        The ``### heading`` text (without the ``###`` prefix).
    rows:
        List of ``(instance_slug, status_text)`` tuples.
    emoji:
        Optional emoji appended to the title.
    """
    heading = f"### {title}"
    if emoji:
        heading = f"{heading} {emoji}"

    lines = [
        heading,
        "",
        "| Instance | Status |",
        "|----------|--------|",
    ]
    for slug, status in rows:
        lines.append(f"| {slug} | {status} |")
    lines.append("")
    write_summary("\n".join(lines))


def write_status_summary(
    title: str,
    body: str,
    *,
    emoji: str = "",
) -> None:
    """Write a titled status block to the step summary.

    Parameters
    ----------
    title:
        Heading text (rendered as ``**title**``).
    body:
        Markdown body content.
    emoji:
        Optional emoji appended to the title.
    """
    heading = f"**{title}**"
    if emoji:
        heading = f"{heading} {emoji}"
    lines = [heading, "", body, ""]
    write_summary("\n".join(lines))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, maxlen: int = 120) -> str:
    """Return *text* truncated to *maxlen* characters for log messages."""
    if len(text) <= maxlen:
        return text
    return text[:maxlen] + "…"
