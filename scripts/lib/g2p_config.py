# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""G2P (gerrit_to_platform) configuration model.

Provides the frozen :class:`G2PConfig` dataclass that captures every
``g2p_*`` action input, validates it, and exposes derived properties
used by downstream setup and check modules.

Usage::

    from g2p_config import G2PConfig

    config = G2PConfig.from_environment()
    errors = config.check()
    if errors:
        for msg in errors:
            print(f"Config error: {msg}")
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from errors import ConfigError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_NAME_STYLES: tuple[str, ...] = ("dash", "underscore", "slash")
"""Allowed values for ``remote_name_style``."""

VALID_VALIDATION_MODES: tuple[str, ...] = ("error", "warn", "skip")
"""Allowed values for ``validation_mode``."""

VALID_ORG_SETUP_MODES: tuple[str, ...] = ("provision", "verify", "skip")
"""Allowed values for ``org_setup``."""

VALID_HOOKS: tuple[str, ...] = (
    "patchset-created",
    "comment-added",
    "change-merged",
)
"""Gerrit hook names that g2p can handle."""

DEFAULT_COMMENT_MAPPINGS: dict[str, str] = {
    "recheck": "verify",
    "reverify": "verify",
    "remerge": "merge",
}
"""Standard LF keyword-to-workflow-filter mappings."""

DEFAULT_REMOTE_AUTH_GROUP: str = "GitHub Replication"
"""Default Gerrit auth group for the GitHub replication remote."""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _str_to_bool(value: str) -> bool:
    """Convert a string to a boolean (case-insensitive)."""
    return value.strip().lower() in ("true", "1", "yes")


def _parse_csv(value: str) -> list[str]:
    """Split a comma-separated string into a trimmed, non-empty list."""
    return [item.strip() for item in value.split(",") if item.strip()]


def decode_org_tokens(
    b64_value: str,
) -> dict[str, str]:
    """Decode a Base64-encoded JSON array of org-token mappings.

    The expected inner JSON schema is::

        [{"github_org": "org-name", "token": "ghp_xxx"}, ...]

    Parameters
    ----------
    b64_value:
        Base64-encoded string.

    Returns
    -------
    dict[str, str]
        Mapping of ``github_org`` to ``token``.

    Raises
    ------
    ConfigError
        If the value cannot be decoded or parsed.
    """
    import base64
    import binascii

    if not b64_value.strip():
        return {}

    # Normalize input: remove all whitespace so wrapped base64
    # (e.g. line-wrapped by macOS/Linux or GitHub secrets) still
    # decodes correctly with validate=True.
    normalized = "".join(b64_value.split())

    try:
        raw = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(
            f"Failed to decode g2p_org_token_map — bad base64: {exc}"
        ) from exc

    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            "Failed to decode g2p_org_token_map — "
            f"decoded bytes are not valid UTF-8: {exc}"
        ) from exc

    try:
        entries = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Failed to parse g2p_org_token_map — bad JSON: {exc}"
        ) from exc

    if not isinstance(entries, list):
        raise ConfigError(
            f"g2p_org_token_map must be a JSON array, got {type(entries).__name__}"
        )

    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigError(
                f"g2p_org_token_map entries must be objects, got {type(entry).__name__}"
            )
        org = entry.get("github_org", "")
        token = entry.get("token", "")
        if not org or not token:
            raise ConfigError(
                "g2p_org_token_map entries must have 'github_org' and 'token' fields"
            )
        result[org] = token

    return result


def _parse_comment_mappings(raw: str) -> dict[str, str]:
    """Parse a JSON string into a comment-keyword mapping dict.

    Parameters
    ----------
    raw:
        JSON object string, e.g. ``'{"recheck": "verify"}'``.

    Returns
    -------
    dict[str, str]
        Parsed mapping.

    Raises
    ------
    ConfigError
        If *raw* is not valid JSON or not a flat string→string object.
    """
    if not raw.strip():
        return dict(DEFAULT_COMMENT_MAPPINGS)

    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"g2p_comment_mappings is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ConfigError(
            f"g2p_comment_mappings must be a JSON object, got {type(parsed).__name__}"
        )

    for key, value in parsed.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ConfigError(
                "g2p_comment_mappings values must all be strings; "
                f"found {key!r}: {value!r}"
            )

    return dict(parsed)


# ---------------------------------------------------------------------------
# G2PConfig dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class G2PConfig:
    """Configuration for gerrit_to_platform integration.

    Every field corresponds to a ``g2p_*`` action input.  The canonical
    constructor is :meth:`from_environment`, which reads ``G2P_*``
    environment variables set by the composite action step.
    """

    # -- Master toggle ---------------------------------------------------
    enabled: bool = False

    # -- GitHub credentials ----------------------------------------------
    github_token: str = ""
    github_owner: str = ""

    # -- Replication mapping ---------------------------------------------
    remote_name_style: str = "dash"
    remote_url: str = ""
    remote_auth_group: str = DEFAULT_REMOTE_AUTH_GROUP

    # -- Comment-added mappings ------------------------------------------
    comment_mappings: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_COMMENT_MAPPINGS)
    )

    # -- Hook selection --------------------------------------------------
    hooks: list[str] = field(default_factory=lambda: list(VALID_HOOKS))

    # -- Validation behaviour --------------------------------------------
    validation_mode: str = "warn"
    validate_workflows: bool = True
    validate_repos: list[str] = field(default_factory=list)

    # -- SSH configuration -----------------------------------------------
    ssh_private_key: str = ""
    github_known_hosts: str = ""

    # -- Org verification/provisioning -----------------------------------
    org_setup: str = "verify"
    org_token_map: str = ""

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_environment(cls) -> G2PConfig:
        """Build a :class:`G2PConfig` from ``G2P_*`` environment variables.

        Variable names follow the convention used elsewhere in
        ``gerrit-action``: the action input ``g2p_github_token`` is
        exposed as ``G2P_GITHUB_TOKEN``.

        Returns
        -------
        G2PConfig
            A frozen configuration instance constructed from environment
            variables. Required-field validation is performed separately
            by :meth:`G2PConfig.check`.

        Raises
        ------
        ConfigError
            If an environment value is unparsable (e.g. invalid JSON in
            ``G2P_COMMENT_MAPPINGS``).
        """
        env = os.environ.get

        enabled = _str_to_bool(env("G2P_ENABLE", "false"))

        # Short-circuit: when disabled, return defaults immediately so
        # that callers never need to guard every field access.
        if not enabled:
            return cls(enabled=False)

        raw_mappings = env("G2P_COMMENT_MAPPINGS", "")
        comment_mappings = _parse_comment_mappings(raw_mappings)

        raw_hooks = env("G2P_HOOKS", ",".join(VALID_HOOKS))
        hooks = _parse_csv(raw_hooks)

        raw_validate_repos = env("G2P_VALIDATE_REPOS", "")
        validate_repos = _parse_csv(raw_validate_repos)

        return cls(
            enabled=True,
            github_token=env("G2P_GITHUB_TOKEN", ""),
            github_owner=env("G2P_GITHUB_OWNER", ""),
            remote_name_style=env("G2P_REMOTE_NAME_STYLE", "dash").strip().lower(),
            remote_url=env("G2P_REMOTE_URL", ""),
            remote_auth_group=env(
                "G2P_REMOTE_AUTH_GROUP", DEFAULT_REMOTE_AUTH_GROUP
            ).strip(),
            comment_mappings=comment_mappings,
            hooks=hooks,
            validation_mode=env("G2P_VALIDATION_MODE", "warn").strip().lower(),
            validate_workflows=_str_to_bool(env("G2P_VALIDATE_WORKFLOWS", "true")),
            validate_repos=validate_repos,
            ssh_private_key=env("G2P_SSH_PRIVATE_KEY", ""),
            github_known_hosts=env("G2P_GITHUB_KNOWN_HOSTS", ""),
            org_setup=env("G2P_ORG_SETUP", "verify").strip().lower(),
            org_token_map=env("G2P_ORG_TOKEN_MAP", ""),
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def check(self) -> list[str]:
        """Validate the configuration and return error messages.

        Returns an empty list when the configuration is valid.  Each
        string in the returned list describes one problem.  Fatal
        problems (those that would prevent any useful work) are always
        included; advisory issues (e.g. a missing token) are logged as
        warnings but **not** added to the error list, because the
        action should still be able to generate config files without a
        token.

        Returns
        -------
        list[str]
            Human-readable error messages; empty when valid.
        """
        errors: list[str] = []

        if not self.enabled:
            # Nothing to validate when g2p is off.
            return errors

        # -- Required fields ---------------------------------------------
        if not self.github_owner:
            errors.append("g2p_github_owner is required when g2p_enable is true")

        # -- Enum fields -------------------------------------------------
        if self.remote_name_style not in VALID_NAME_STYLES:
            errors.append(
                f"g2p_remote_name_style must be one of "
                f"{VALID_NAME_STYLES!r}, got {self.remote_name_style!r}"
            )

        if self.validation_mode not in VALID_VALIDATION_MODES:
            errors.append(
                f"g2p_validation_mode must be one of "
                f"{VALID_VALIDATION_MODES!r}, got {self.validation_mode!r}"
            )

        if self.org_setup not in VALID_ORG_SETUP_MODES:
            errors.append(
                f"g2p_org_setup must be one of "
                f"{VALID_ORG_SETUP_MODES!r}, got {self.org_setup!r}"
            )

        # -- Hook names --------------------------------------------------
        invalid_hooks = [h for h in self.hooks if h not in VALID_HOOKS]
        if invalid_hooks:
            errors.append(
                f"g2p_hooks contains unknown hook(s): "
                f"{invalid_hooks!r}; valid hooks are {VALID_HOOKS!r}"
            )

        # -- Comment mappings values -------------------------------------
        valid_filters = {"verify", "merge"}
        bad_filters = {
            k: v for k, v in self.comment_mappings.items() if v not in valid_filters
        }
        if bad_filters:
            errors.append(
                f"g2p_comment_mappings has invalid filter value(s): "
                f"{bad_filters!r}; allowed filters are {valid_filters!r}"
            )

        # -- Advisory warnings (not errors) ------------------------------
        if not self.github_token:
            logger.warning(
                "No g2p_github_token provided — g2p config will be "
                "generated without a token; workflow dispatch will not "
                "work until a token is configured"
            )

        if not self.remote_auth_group:
            logger.warning(
                "g2p_remote_auth_group is empty; platform detection "
                "may not work correctly"
            )
        elif "github" not in self.remote_auth_group.lower():
            logger.warning(
                "g2p_remote_auth_group %r does not contain 'github'; "
                "platform detection may not work correctly",
                self.remote_auth_group,
            )

        if self.org_setup == "provision" and not self.org_token_map:
            logger.warning(
                "g2p_org_setup is 'provision' but no "
                "g2p_org_token_map provided; will fall "
                "back to g2p_github_token for org operations"
            )

        return errors

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def effective_remote_url(self) -> str:
        """Return the replication remote URL, auto-generating if empty.

        When ``remote_url`` was not explicitly provided, the URL is
        derived from ``github_owner``::

            git@github.com:<owner>/${name}.git

        Returns an empty string when neither ``remote_url`` nor
        ``github_owner`` is set (this condition is caught by
        :meth:`check`).
        """
        if self.remote_url:
            return self.remote_url
        if self.github_owner:
            return f"git@github.com:{self.github_owner}/${{name}}.git"
        return ""

    @property
    def token_provided(self) -> bool:
        """Whether a GitHub token was supplied."""
        return bool(self.github_token)

    def resolve_org_token(self) -> str:
        """Resolve the token for org-level operations.

        Priority:
        1. ``org_token_map`` entry for this ``github_owner``
        2. ``github_token`` (fallback)

        Returns
        -------
        str
            The resolved token string.
        """
        if self.org_token_map:
            try:
                tokens = decode_org_tokens(self.org_token_map)
            except ConfigError:
                logger.warning(
                    "Failed to decode org_token_map; falling back to github_token"
                )
                return self.github_token
            token = tokens.get(self.github_owner)
            if token:
                return token
            logger.warning(
                "No entry for '%s' in g2p_org_token_map; "
                "falling back to g2p_github_token",
                self.github_owner,
            )
        return self.github_token
