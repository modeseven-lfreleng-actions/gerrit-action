#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Configure gerrit_to_platform inside running Gerrit containers.

This script is the entry point for the G2P configuration step in
``action.yaml``.  It reads ``G2P_*`` environment variables, validates
the configuration, optionally checks the target GitHub organisation,
and then sets up each running Gerrit container with the files and
symlinks that ``gerrit_to_platform`` needs to dispatch workflows.

Steps:

1. Parse ``G2PConfig`` from environment variables.
2. Validate the configuration (fatal errors abort).
3. Run GitHub-side checks (unless ``validation_mode=skip``).
4. Load running instances from ``instances.json``.
5. For each container: deploy INI, hooks, SSH, replication remote.
6. Write G2P outputs to ``$GITHUB_OUTPUT``.

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python scripts/configure-g2p.py

    # Locally with environment variables
    G2P_ENABLE=true G2P_GITHUB_OWNER=onap python scripts/configure-g2p.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import ActionConfig, InstanceStore  # noqa: E402
from docker_manager import DockerManager  # noqa: E402
from errors import (  # noqa: E402
    G2PCheckError,
    G2PConfigError,
    G2PSetupError,
    GerritActionError,
)
from g2p_config import G2PConfig  # noqa: E402
from g2p_github import (  # noqa: E402
    G2PCheckResult,
    check_github_config,
    check_org_secrets,
    check_org_variables,
    format_check_results,
    format_check_results_summary,
    provision_org_config,
    results_to_json,
)
from g2p_setup import (  # noqa: E402
    G2PSelfTestReport,
    G2PSetupResult,
    selftest_g2p_plumbing,
    setup_g2p,
)
from logging_utils import log_group, setup_logging  # noqa: E402
from outputs import write_output, write_summary  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _emit_g2p_outputs(
    config: G2PConfig,
    results: list[G2PSetupResult],
    check_json: str,
    org_audit_json: str = "[]",
    org_provisioned: bool = False,
) -> None:
    """Write G2P outputs to ``$GITHUB_OUTPUT``.

    Parameters
    ----------
    config:
        The validated G2P configuration.
    results:
        Setup results from each container.
    check_json:
        JSON string of GitHub check results.
    org_audit_json:
        JSON string of org-level audit check results.
    org_provisioned:
        Whether any org-level items were actually provisioned.
    """
    write_output("g2p_enabled", "true")
    write_output("g2p_github_owner", config.github_owner)
    write_output("g2p_remote_name_style", config.remote_name_style)
    write_output("g2p_token_provided", str(config.token_provided).lower())
    write_output("g2p_validation_results", check_json)

    # Aggregate hooks from all containers
    all_hooks: list[str] = []
    for r in results:
        for h in r.hooks_enabled:
            if h not in all_hooks:
                all_hooks.append(h)
    write_output("g2p_hooks_enabled", json.dumps(all_hooks))

    # Use the first container's config path (they're all the same)
    if results:
        write_output("g2p_config_path", results[0].config_path)

    # Use the first container's SSH public key
    for r in results:
        if r.ssh_public_key:
            write_output("g2p_ssh_public_key", r.ssh_public_key)
            break

    write_output("g2p_org_audit_results", org_audit_json)
    write_output("g2p_org_provisioned", str(org_provisioned).lower())


# ---------------------------------------------------------------------------
# Gerrit info builder (for org provisioning)
# ---------------------------------------------------------------------------


def _build_gerrit_info(
    instances: dict[str, dict[str, Any]],
    setup_results: list[G2PSetupResult],
    action_config: ActionConfig,
) -> dict[str, str]:
    """Build the ``gerrit_info`` dict for org provisioning.

    Extracts connection metadata from the first running instance
    and the G2P setup results so that ``provision_org_config`` can
    populate org-level secrets and variables.

    The host and port values are derived from the same tunnel /
    localhost logic used by ``start-instances.py`` so they point
    at the *running container*, not the source Gerrit server.

    Parameters
    ----------
    instances:
        Loaded ``instances.json`` data.
    setup_results:
        Results from :func:`setup_g2p` for each container.
    action_config:
        The global :class:`ActionConfig`.

    Returns
    -------
    dict[str, str]
        Keys: ``ssh_private_key``, ``ssh_host``, ``ssh_port``,
        ``ssh_user``, ``known_hosts``, ``http_url``.
    """
    info: dict[str, str] = {}

    # Use first instance for connection metadata
    if instances:
        first_slug = sorted(instances.keys())[0]
        meta = instances[first_slug]

        # Resolve effective host/ports using the same logic as
        # _resolve_tunnel() in start-instances.py: tunnel host +
        # tunnel ports when configured, otherwise localhost +
        # the container's mapped ports.
        tunnel_host = action_config.tunnel_host
        tunnel_ports = action_config.tunnel_ports
        tc = tunnel_ports.get(first_slug) if tunnel_host else None

        if tunnel_host and tc:
            ssh_host = tunnel_host
            ssh_port = str(tc.ssh_port)
            http_port = str(tc.http_port)
        else:
            ssh_host = "localhost"
            ssh_port = str(meta.get("ssh_port", ""))
            http_port = str(meta.get("http_port", ""))

        info["ssh_host"] = ssh_host
        info["ssh_port"] = ssh_port
        info["ssh_user"] = action_config.ssh_auth_username or "admin"

        # HTTP URL: construct from effective host/port, optionally
        # appending the API path when USE_API_PATH is enabled.
        api_path = meta.get("api_path", "")
        if action_config.use_api_path and api_path:
            # Normalise: ensure leading /, strip trailing /
            if not api_path.startswith("/"):
                api_path = f"/{api_path}"
            api_path = api_path.rstrip("/")
            info["http_url"] = f"http://{ssh_host}:{http_port}{api_path}/"
        else:
            info["http_url"] = f"http://{ssh_host}:{http_port}/"

        # Build known_hosts from captured SSH host keys
        host_keys = meta.get("ssh_host_keys", {})
        kh_lines: list[str] = []
        for _key_type, key_data in sorted(host_keys.items()):
            if key_data and ssh_host:
                kh_lines.append(f"{ssh_host} {key_data}")
        info["known_hosts"] = "\n".join(kh_lines)

    # SSH private key from the first setup result
    for r in setup_results:
        if r.ssh_private_key:
            info["ssh_private_key"] = r.ssh_private_key
            break

    return info


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _emit_final_status(success: bool, reason: str = "") -> None:
    """Print a single ✅/❌ summary line to stdout.

    Bypasses the logger deliberately so this final status always
    appears as plain stdout regardless of earlier warnings, and is
    easy for a human to spot in the workflow console.
    """
    if success:
        print("✅ Gerrit2Platform configuration succeeded")
    else:
        suffix = f": {reason}" if reason else ""
        print(f"❌ Gerrit2Platform configuration failed{suffix}")


def _pynacl_available() -> bool:
    """Return True when PyNaCl can be imported."""
    try:
        import nacl.public  # noqa: F401  # pyright: ignore[reportMissingImports]
    except ImportError:
        return False
    return True


def run() -> int:
    """Configure G2P for all running Gerrit instances.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on anticipated error, 2 on
        unexpected error.
    """
    # -- Step 1: Parse config --------------------------------------------
    g2p_config = G2PConfig.from_environment()

    if not g2p_config.enabled:
        logger.info("G2P integration is disabled (g2p_enable=false)")
        write_output("g2p_enabled", "false")
        return 0

    logger.info("G2P integration enabled for '%s'", g2p_config.github_owner)

    # -- Step 1b: PyNaCl precheck (provision mode only) ------------------
    # Provisioning org-level secrets requires PyNaCl for sealed-box
    # encryption.  Check early so we fail fast rather than after all
    # the setup work.  Other modes (verify / skip) never touch PyNaCl
    # so we do not import it or warn about it.
    if g2p_config.org_setup == "provision" and not _pynacl_available():
        logger.error(
            "PyNaCl is required for org provisioning but is not "
            "available; install it on the runner with "
            "'python3 -m pip install --user PyNaCl' before "
            "enabling g2p_org_setup=provision",
        )
        _emit_final_status(False, "PyNaCl missing (provision mode)")
        return 1

    # -- Step 2: Validate config -----------------------------------------
    with log_group("G2P configuration validation"):
        errors = g2p_config.check()
        if errors:
            for err in errors:
                # logger.error routes through _GitHubActionsFormatter
                # which emits the ::error:: annotation exactly once.
                logger.error("G2P config error: %s", err)
            raise G2PConfigError(f"G2P configuration has {len(errors)} error(s)")
        logger.info("G2P configuration valid ✅")

    # -- Step 3: GitHub checks -------------------------------------------
    # These are the generic GitHub-side checks (token, org access,
    # .github magic repo, workflow presence).  Org-level secret and
    # variable audits are performed separately in step 3b so that
    # provisioning (when enabled) happens *before* the final audit.
    check_json = "[]"
    check_results: list[G2PCheckResult] = []
    if g2p_config.validation_mode != "skip":
        with log_group("G2P GitHub checks"):
            check_results = check_github_config(g2p_config)
            check_json = results_to_json(check_results)

            # format_check_results logs warnings/errors through the
            # standard logger (which emits ::warning::/::error::
            # annotations exactly once); we do not re-print the
            # returned annotation strings.
            _, has_fatal = format_check_results(
                check_results, g2p_config.validation_mode
            )

            if has_fatal:
                raise G2PCheckError(
                    "GitHub-side checks failed in strict mode",
                    failed_checks=[
                        r.check_name
                        for r in check_results
                        if not r.passed and r.severity == "error"
                    ],
                )

            passed = sum(1 for r in check_results if r.passed)
            total = len(check_results)
            logger.info("GitHub checks: %d/%d passed ✅", passed, total)
    else:
        logger.info("GitHub checks skipped (validation_mode=skip)")

    # -- Step 3b: Org-level audit (initial snapshot) ---------------------
    # This phase only *reports* the initial state. Provisioning (when
    # requested) happens in step 5b after containers are running, and
    # step 5c re-audits so the final ``org_audit_json`` reflects the
    # post-provisioning state instead of flagging items we were about
    # to create.
    org_audit_json = "[]"
    org_provisioned = False
    provisioned_items: list[str] = []
    org_results: list[G2PCheckResult] = []

    if g2p_config.org_setup != "skip":
        with log_group("G2P org-level audit (initial)"):
            # Use the same token resolution as provisioning so the
            # audit's read scope matches the elevated token a caller
            # supplied via ``g2p_org_token_map``.  Without this, a
            # least-privileged ``g2p_github_token`` would 403 the
            # /orgs/.../actions/{secrets,variables} reads even when
            # the operator carefully scoped an elevated org token
            # for provisioning — making provision_org_config()
            # blind to which items already exist.
            audit_token = g2p_config.resolve_org_token()
            if audit_token:
                org_results.append(
                    check_org_secrets(
                        audit_token,
                        g2p_config.github_owner,
                    )
                )
                org_results.append(
                    check_org_variables(
                        audit_token,
                        g2p_config.github_owner,
                    )
                )
            else:
                msg = "Org audit requires a GitHub token; skipping org checks"
                logger.warning(msg)
                org_results.append(
                    G2PCheckResult(
                        check_name="org_audit",
                        passed=False,
                        message=msg,
                        severity="warning",
                    )
                )

            org_audit_json = results_to_json(org_results)
            logger.info(
                "Initial org audit complete (mode=%s)",
                g2p_config.org_setup,
            )
    else:
        logger.info(
            "Org audit skipped (org_setup=%s)",
            g2p_config.org_setup,
        )

    # -- Step 4: Load running instances ----------------------------------
    action_config = ActionConfig.from_environment()
    setup_logging(debug=action_config.debug)

    instance_store = InstanceStore(action_config.instances_json_path)
    instances = instance_store.load()

    if not instances:
        logger.warning(
            "No running instances found in %s — "
            "G2P config will be generated but not deployed",
            action_config.instances_json_path,
        )
        _emit_g2p_outputs(g2p_config, [], check_json, org_audit_json, org_provisioned)
        return 0

    # -- Step 5: Configure each container --------------------------------
    docker = DockerManager()
    setup_results: list[G2PSetupResult] = []
    selftest_reports: list[G2PSelfTestReport] = []
    selftest_had_errors = False

    for slug, meta in instances.items():
        cid = meta.get("cid", "")
        if not cid:
            logger.warning("Instance '%s' has no container ID — skipping", slug)
            continue

        with log_group(f"G2P setup: {slug} ({cid[:12]})"):
            result = setup_g2p(g2p_config, docker, cid)
            setup_results.append(result)

            logger.info(
                "Instance '%s': config=%s, hooks=%s",
                slug,
                result.config_path,
                result.hooks_enabled,
            )

        # Run plumbing self-test immediately after setup so any
        # broken wiring (missing hooks.jar, non-executable hook
        # target, empty token, missing github-g2p remote, import
        # error in the entry-point script) is surfaced now rather
        # than discovered later when a real patchset upload silently
        # fails to dispatch a workflow.
        with log_group(f"G2P self-test: {slug} ({cid[:12]})"):
            report = selftest_g2p_plumbing(docker, cid, g2p_config)
            selftest_reports.append(report)
            if report.has_errors:
                selftest_had_errors = True
                failed = [
                    c.name
                    for c in report.checks
                    if (not c.passed) and c.severity == "error"
                ]
                logger.error(
                    "G2P self-test for instance '%s' failed: %s",
                    slug,
                    ", ".join(failed),
                )
            else:
                passed = sum(1 for c in report.checks if c.passed)
                total = len(report.checks)
                logger.info(
                    "G2P self-test for instance '%s': %d/%d checks passed",
                    slug,
                    passed,
                    total,
                )

    # -- Step 5b: Org provisioning (after containers are configured) ------
    # Always run provisioning when the mode requests it, regardless
    # of the initial audit outcome.  Each Gerrit container build
    # produces a fresh ephemeral SSH key and may bind to different
    # tunnel host/ports, so we cannot rely on the audit reporting
    # items as missing — we must overwrite required org secrets
    # and variables on every provision run to keep them in sync
    # with the live Gerrit instance.
    provision_had_fatal = False
    if g2p_config.org_setup == "provision":
        with log_group("G2P org provisioning"):
            # Build gerrit_info from instances + setup results
            gerrit_info = _build_gerrit_info(
                instances,
                setup_results,
                action_config,
            )
            org_token = g2p_config.resolve_org_token()

            if not org_token:
                msg = (
                    "Cannot provision: no token available "
                    "(set g2p_github_token or g2p_org_token_map)"
                )
                logger.error(msg)
                provision_had_fatal = True
                org_results.append(
                    G2PCheckResult(
                        check_name="org_provision",
                        passed=False,
                        message=msg,
                        severity="error",
                    )
                )
            else:
                prov_results = provision_org_config(
                    g2p_config,
                    org_results,
                    gerrit_info,
                    org_token=org_token,
                )
                for pr in prov_results:
                    if pr.passed:
                        provisioned_items.append(pr.message)
                        logger.info("Provisioned: %s", pr.message)
                    else:
                        logger.error(
                            "Provisioning failed: %s",
                            pr.message,
                        )
                        provision_had_fatal = True
                org_results.extend(prov_results)
                org_provisioned = bool(provisioned_items)

    # -- Step 5c: Re-audit org state after provisioning -----------------
    # Replace the initial audit entries with fresh results so the
    # final JSON and summary reflect post-provisioning reality.
    #
    # The re-audit runs unconditionally whenever ``provision`` mode is
    # active (not just when ``org_provisioned`` is true): provisioning
    # always overwrites required items, and the initial audit may have
    # used the wrong token / hit a permission error, leaving stale or
    # missing entries in ``org_results``.  Running the audit again with
    # the same elevated token used for provisioning guarantees the
    # final output reflects the true post-provision state.
    if g2p_config.org_setup == "provision":
        reaudit_token = g2p_config.resolve_org_token()
        if reaudit_token:
            with log_group("G2P org-level audit (post-provision)"):
                fresh_secrets = check_org_secrets(
                    reaudit_token,
                    g2p_config.github_owner,
                )
                fresh_variables = check_org_variables(
                    reaudit_token,
                    g2p_config.github_owner,
                )
                # Keep any non-secret/variable entries (e.g. error
                # breadcrumbs) and replace the original org_secrets /
                # org_variables entries with the refreshed ones.
                preserved = [
                    r
                    for r in org_results
                    if r.check_name not in ("org_secrets", "org_variables")
                ]
                org_results = [fresh_secrets, fresh_variables, *preserved]
        else:
            logger.warning(
                "Skipping post-provision re-audit: no GitHub token "
                "available; final g2p_org_audit_results reflects the "
                "pre-provision state.",
            )

    # Recompute audit JSON after any provisioning / re-audit work
    if g2p_config.org_setup != "skip":
        org_audit_json = results_to_json(org_results)

    # -- Step 6: Write step summary --------------------------------------
    if check_results or org_results:
        seen_names: set[str] = set()
        all_summary_results: list[G2PCheckResult] = []
        for r in check_results + org_results:
            if r.check_name not in seen_names:
                seen_names.add(r.check_name)
                all_summary_results.append(r)
        summary_md = format_check_results_summary(
            results=all_summary_results,
            owner=g2p_config.github_owner,
            mode=g2p_config.org_setup,
            provisioned=provisioned_items or None,
        )
        write_summary(summary_md)

    # -- Step 7: Emit outputs --------------------------------------------
    with log_group("G2P outputs"):
        _emit_g2p_outputs(
            g2p_config,
            setup_results,
            check_json,
            org_audit_json,
            org_provisioned,
        )

        logger.info(
            "G2P configured %d instance(s)",
            len(setup_results),
        )

    # -- Step 8: Final single-line status -------------------------------
    if provision_had_fatal:
        _emit_final_status(False, "org provisioning failed")
        return 1

    # A failed plumbing self-test means hooks won't fire or the
    # script can't run — dispatch will silently never happen.
    # Surface this as a failure so the deploy step itself goes red,
    # rather than letting the user discover it later when no CI
    # runs appear in the target org.
    if selftest_had_errors:
        _emit_final_status(
            False,
            "G2P plumbing self-test reported error(s); see preceding logs",
        )
        return 1

    # In provision mode, any remaining absent required secrets or
    # variables mean the caller's downstream workflows will still be
    # broken — surface that as a failure.
    if g2p_config.org_setup == "provision":
        # Only error-severity results indicate required items are
        # still absent.  Warning-severity results (e.g. optional
        # recommended secrets missing) are informational and must
        # not fail the step.
        post_failures = [
            r
            for r in org_results
            if r.check_name in ("org_secrets", "org_variables")
            and not r.passed
            and r.severity == "error"
        ]
        if post_failures:
            names = ", ".join(r.check_name for r in post_failures)
            _emit_final_status(
                False,
                f"required org config still absent ({names})",
            )
            return 1

        # Surface any non-fatal warnings for visibility without
        # failing the overall step.
        post_warnings = [
            r
            for r in org_results
            if r.check_name in ("org_secrets", "org_variables")
            and not r.passed
            and r.severity == "warning"
        ]
        for r in post_warnings:
            logger.warning(
                "Post-provision audit advisory (%s): %s",
                r.check_name,
                r.message,
            )

    _emit_final_status(True)
    return 0


def main() -> int:
    """Entry point with structured error handling."""
    setup_logging()
    try:
        return run()
    except G2PConfigError as exc:
        logger.error("G2P configuration error: %s", exc)
        return 1
    except G2PCheckError as exc:
        logger.error(
            "G2P GitHub check failure: %s (checks: %s)",
            exc,
            exc.failed_checks,
        )
        return 1
    except G2PSetupError as exc:
        logger.error("G2P setup error: %s", exc)
        return 1
    except GerritActionError as exc:
        logger.error("Gerrit action error: %s", exc)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error during G2P configuration: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
