# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the g2p_config module."""

from __future__ import annotations

import json
import logging

import pytest
from errors import ConfigError
from g2p_config import (
    DEFAULT_COMMENT_MAPPINGS,
    DEFAULT_REMOTE_AUTH_GROUP,
    VALID_HOOKS,
    VALID_NAME_STYLES,
    VALID_ORG_SETUP_MODES,
    VALID_VALIDATION_MODES,
    G2PConfig,
    _parse_comment_mappings,
    _parse_csv,
    _str_to_bool,
    decode_org_tokens,
)

# ---------------------------------------------------------------------------
# Helper constants
# ---------------------------------------------------------------------------

ALL_G2P_ENV_VARS = [
    "G2P_ENABLE",
    "G2P_GITHUB_TOKEN",
    "G2P_GITHUB_OWNER",
    "G2P_REMOTE_NAME_STYLE",
    "G2P_REMOTE_URL",
    "G2P_REMOTE_AUTH_GROUP",
    "G2P_COMMENT_MAPPINGS",
    "G2P_HOOKS",
    "G2P_VALIDATION_MODE",
    "G2P_VALIDATE_WORKFLOWS",
    "G2P_VALIDATE_REPOS",
    "G2P_SSH_PRIVATE_KEY",
    "G2P_GITHUB_KNOWN_HOSTS",
    "G2P_ORG_SETUP",
    "G2P_ORG_TOKEN_MAP",
]


@pytest.fixture()
def clean_g2p_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove all G2P environment variables."""
    for var in ALL_G2P_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


@pytest.fixture()
def minimal_g2p_env(
    clean_g2p_env: pytest.MonkeyPatch,
) -> pytest.MonkeyPatch:
    """Set the minimum viable G2P environment (enabled + owner)."""
    clean_g2p_env.setenv("G2P_ENABLE", "true")
    clean_g2p_env.setenv("G2P_GITHUB_OWNER", "onap")
    clean_g2p_env.setenv("G2P_ORG_SETUP", "verify")
    return clean_g2p_env


@pytest.fixture()
def full_g2p_env(
    minimal_g2p_env: pytest.MonkeyPatch,
) -> pytest.MonkeyPatch:
    """Set a complete G2P environment with all inputs populated."""
    minimal_g2p_env.setenv("G2P_GITHUB_TOKEN", "ghp_testtoken123")
    minimal_g2p_env.setenv("G2P_REMOTE_NAME_STYLE", "underscore")
    minimal_g2p_env.setenv(
        "G2P_REMOTE_URL",
        "git@github.com:custom-org/${name}.git",
    )
    minimal_g2p_env.setenv("G2P_REMOTE_AUTH_GROUP", "Custom Group")
    minimal_g2p_env.setenv(
        "G2P_COMMENT_MAPPINGS",
        json.dumps({"recheck": "verify", "remerge": "merge"}),
    )
    minimal_g2p_env.setenv("G2P_HOOKS", "patchset-created,comment-added")
    minimal_g2p_env.setenv("G2P_VALIDATION_MODE", "error")
    minimal_g2p_env.setenv("G2P_VALIDATE_WORKFLOWS", "false")
    minimal_g2p_env.setenv("G2P_VALIDATE_REPOS", "ci-management,releng-lftools")
    minimal_g2p_env.setenv("G2P_SSH_PRIVATE_KEY", "-----BEGIN KEY-----")
    minimal_g2p_env.setenv(
        "G2P_GITHUB_KNOWN_HOSTS",
        "github.com ssh-ed25519 AAAAC3...",
    )
    minimal_g2p_env.setenv("G2P_ORG_SETUP", "verify")
    minimal_g2p_env.setenv("G2P_ORG_TOKEN_MAP", "")
    return minimal_g2p_env


# ===================================================================
# Helper function tests
# ===================================================================


class TestStrToBool:
    """Tests for _str_to_bool."""

    @pytest.mark.parametrize(
        "value",
        ["true", "True", "TRUE", "1", "yes", "YES", " true ", " 1 "],
    )
    def test_truthy_values(self, value: str) -> None:
        assert _str_to_bool(value) is True

    @pytest.mark.parametrize(
        "value",
        ["false", "False", "0", "no", "", "anything", "2"],
    )
    def test_falsy_values(self, value: str) -> None:
        assert _str_to_bool(value) is False


class TestParseCsv:
    """Tests for _parse_csv."""

    def test_simple_list(self) -> None:
        assert _parse_csv("a,b,c") == ["a", "b", "c"]

    def test_trims_whitespace(self) -> None:
        assert _parse_csv(" a , b , c ") == ["a", "b", "c"]

    def test_filters_empty_items(self) -> None:
        assert _parse_csv("a,,b,,,c") == ["a", "b", "c"]

    def test_single_item(self) -> None:
        assert _parse_csv("only-one") == ["only-one"]

    def test_empty_string(self) -> None:
        assert _parse_csv("") == []

    def test_only_commas(self) -> None:
        assert _parse_csv(",,,") == []

    def test_whitespace_only_items(self) -> None:
        assert _parse_csv(" , , ") == []


class TestParseCommentMappings:
    """Tests for _parse_comment_mappings."""

    def test_valid_json(self) -> None:
        raw = '{"recheck": "verify", "remerge": "merge"}'
        result = _parse_comment_mappings(raw)
        assert result == {"recheck": "verify", "remerge": "merge"}

    def test_empty_string_returns_defaults(self) -> None:
        result = _parse_comment_mappings("")
        assert result == DEFAULT_COMMENT_MAPPINGS

    def test_whitespace_only_returns_defaults(self) -> None:
        result = _parse_comment_mappings("   ")
        assert result == DEFAULT_COMMENT_MAPPINGS

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(ConfigError, match="not valid JSON"):
            _parse_comment_mappings("{bad json")

    def test_non_object_raises(self) -> None:
        with pytest.raises(ConfigError, match="must be a JSON object"):
            _parse_comment_mappings('["a", "b"]')

    def test_non_string_values_raise(self) -> None:
        with pytest.raises(ConfigError, match="values must all be strings"):
            _parse_comment_mappings('{"recheck": 42}')

    def test_non_string_keys_raise(self) -> None:
        # JSON keys are always strings, but values could be non-string
        with pytest.raises(ConfigError, match="values must all be strings"):
            _parse_comment_mappings('{"recheck": true}')

    def test_single_mapping(self) -> None:
        result = _parse_comment_mappings('{"recheck": "verify"}')
        assert result == {"recheck": "verify"}

    def test_extended_production_mappings(self) -> None:
        raw = json.dumps(
            {
                "recheck": "verify",
                "remerge": "merge",
                "rerun-gha": "verify",
                "remerge-gha": "merge",
            }
        )
        result = _parse_comment_mappings(raw)
        assert len(result) == 4
        assert result["rerun-gha"] == "verify"


# ===================================================================
# G2PConfig defaults
# ===================================================================


class TestG2PConfigDefaults:
    """Tests for G2PConfig default field values."""

    def test_default_disabled(self) -> None:
        cfg = G2PConfig()
        assert cfg.enabled is False

    def test_default_tokens_empty(self) -> None:
        cfg = G2PConfig()
        assert cfg.github_token == ""
        assert cfg.github_owner == ""

    def test_default_remote_name_style(self) -> None:
        cfg = G2PConfig()
        assert cfg.remote_name_style == "dash"

    def test_default_remote_url_empty(self) -> None:
        cfg = G2PConfig()
        assert cfg.remote_url == ""

    def test_default_remote_auth_group(self) -> None:
        cfg = G2PConfig()
        assert cfg.remote_auth_group == DEFAULT_REMOTE_AUTH_GROUP

    def test_default_comment_mappings(self) -> None:
        cfg = G2PConfig()
        assert cfg.comment_mappings == DEFAULT_COMMENT_MAPPINGS

    def test_default_hooks(self) -> None:
        cfg = G2PConfig()
        assert cfg.hooks == list(VALID_HOOKS)

    def test_default_validation_mode(self) -> None:
        cfg = G2PConfig()
        assert cfg.validation_mode == "warn"

    def test_default_validate_workflows_true(self) -> None:
        cfg = G2PConfig()
        assert cfg.validate_workflows is True

    def test_default_validate_repos_empty(self) -> None:
        cfg = G2PConfig()
        assert cfg.validate_repos == []

    def test_default_ssh_fields_empty(self) -> None:
        cfg = G2PConfig()
        assert cfg.ssh_private_key == ""
        assert cfg.github_known_hosts == ""

    def test_frozen(self) -> None:
        cfg = G2PConfig()
        with pytest.raises(AttributeError):
            cfg.enabled = True  # pyright: ignore[reportAttributeAccessIssue]

    def test_default_comment_mappings_is_copy(self) -> None:
        """Each instance gets its own copy of the default dict."""
        cfg1 = G2PConfig()
        cfg2 = G2PConfig()
        assert cfg1.comment_mappings is not cfg2.comment_mappings

    def test_default_hooks_is_copy(self) -> None:
        """Each instance gets its own copy of the default list."""
        cfg1 = G2PConfig()
        cfg2 = G2PConfig()
        assert cfg1.hooks is not cfg2.hooks


# ===================================================================
# G2PConfig.from_environment — disabled path
# ===================================================================


class TestG2PConfigFromEnvironmentDisabled:
    """Tests for from_environment when G2P is disabled."""

    def test_disabled_by_default(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        cfg = G2PConfig.from_environment()
        assert cfg.enabled is False

    def test_disabled_explicitly(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "false")
        cfg = G2PConfig.from_environment()
        assert cfg.enabled is False

    def test_disabled_ignores_other_vars(
        self, clean_g2p_env: pytest.MonkeyPatch
    ) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "false")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "should-be-ignored")
        cfg = G2PConfig.from_environment()
        assert cfg.enabled is False
        assert cfg.github_owner == ""

    def test_disabled_returns_all_defaults(
        self, clean_g2p_env: pytest.MonkeyPatch
    ) -> None:
        cfg = G2PConfig.from_environment()
        default = G2PConfig()
        assert cfg.enabled == default.enabled
        assert cfg.github_token == default.github_token
        assert cfg.remote_name_style == default.remote_name_style
        assert cfg.hooks == default.hooks


# ===================================================================
# G2PConfig.from_environment — enabled path
# ===================================================================


class TestG2PConfigFromEnvironmentEnabled:
    """Tests for from_environment when G2P is enabled."""

    def test_minimal_config(self, minimal_g2p_env: pytest.MonkeyPatch) -> None:
        cfg = G2PConfig.from_environment()
        assert cfg.enabled is True
        assert cfg.github_owner == "onap"
        assert cfg.github_token == ""
        assert cfg.remote_name_style == "dash"
        assert cfg.hooks == list(VALID_HOOKS)
        assert cfg.comment_mappings == DEFAULT_COMMENT_MAPPINGS
        assert cfg.validation_mode == "warn"
        assert cfg.validate_workflows is True
        assert cfg.validate_repos == []

    def test_full_config(self, full_g2p_env: pytest.MonkeyPatch) -> None:
        cfg = G2PConfig.from_environment()
        assert cfg.enabled is True
        assert cfg.github_owner == "onap"
        assert cfg.github_token == "ghp_testtoken123"
        assert cfg.remote_name_style == "underscore"
        assert cfg.remote_url == "git@github.com:custom-org/${name}.git"
        assert cfg.remote_auth_group == "Custom Group"
        assert cfg.comment_mappings == {
            "recheck": "verify",
            "remerge": "merge",
        }
        assert cfg.hooks == ["patchset-created", "comment-added"]
        assert cfg.validation_mode == "error"
        assert cfg.validate_workflows is False
        assert cfg.validate_repos == [
            "ci-management",
            "releng-lftools",
        ]
        assert cfg.ssh_private_key == "-----BEGIN KEY-----"
        assert cfg.github_known_hosts == "github.com ssh-ed25519 AAAAC3..."

    def test_name_style_normalised_to_lowercase(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_REMOTE_NAME_STYLE", "  DASH  ")
        cfg = G2PConfig.from_environment()
        assert cfg.remote_name_style == "dash"

    def test_validation_mode_normalised_to_lowercase(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_VALIDATION_MODE", "  ERROR  ")
        cfg = G2PConfig.from_environment()
        assert cfg.validation_mode == "error"

    def test_auth_group_trimmed(self, minimal_g2p_env: pytest.MonkeyPatch) -> None:
        minimal_g2p_env.setenv("G2P_REMOTE_AUTH_GROUP", "  My Group  ")
        cfg = G2PConfig.from_environment()
        assert cfg.remote_auth_group == "My Group"

    def test_hooks_single(self, minimal_g2p_env: pytest.MonkeyPatch) -> None:
        minimal_g2p_env.setenv("G2P_HOOKS", "patchset-created")
        cfg = G2PConfig.from_environment()
        assert cfg.hooks == ["patchset-created"]

    def test_hooks_with_spaces(self, minimal_g2p_env: pytest.MonkeyPatch) -> None:
        minimal_g2p_env.setenv("G2P_HOOKS", " patchset-created , change-merged ")
        cfg = G2PConfig.from_environment()
        assert cfg.hooks == ["patchset-created", "change-merged"]

    def test_validate_repos_parsed(self, minimal_g2p_env: pytest.MonkeyPatch) -> None:
        minimal_g2p_env.setenv("G2P_VALIDATE_REPOS", "ci-management, releng-lftools")
        cfg = G2PConfig.from_environment()
        assert cfg.validate_repos == [
            "ci-management",
            "releng-lftools",
        ]

    def test_validate_repos_empty_string(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_VALIDATE_REPOS", "")
        cfg = G2PConfig.from_environment()
        assert cfg.validate_repos == []

    def test_validate_workflows_false(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_VALIDATE_WORKFLOWS", "false")
        cfg = G2PConfig.from_environment()
        assert cfg.validate_workflows is False

    def test_enable_truthy_variants(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        for value in ("true", "True", "1", "yes"):
            clean_g2p_env.setenv("G2P_ENABLE", value)
            clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test")
            cfg = G2PConfig.from_environment()
            assert cfg.enabled is True, f"Failed for G2P_ENABLE={value!r}"

    def test_invalid_comment_mappings_raises(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_COMMENT_MAPPINGS", "{not valid json")
        with pytest.raises(ConfigError, match="not valid JSON"):
            G2PConfig.from_environment()

    def test_empty_comment_mappings_uses_defaults(
        self, minimal_g2p_env: pytest.MonkeyPatch
    ) -> None:
        minimal_g2p_env.setenv("G2P_COMMENT_MAPPINGS", "")
        cfg = G2PConfig.from_environment()
        assert cfg.comment_mappings == DEFAULT_COMMENT_MAPPINGS


# ===================================================================
# G2PConfig.check — validation
# ===================================================================


class TestG2PConfigCheck:
    """Tests for G2PConfig.check validation."""

    def test_disabled_config_always_valid(self) -> None:
        cfg = G2PConfig(enabled=False)
        assert cfg.check() == []

    def test_valid_minimal_config(self) -> None:
        cfg = G2PConfig(enabled=True, github_owner="onap")
        assert cfg.check() == []

    def test_valid_full_config(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="onap",
            github_token="ghp_test",
            remote_name_style="dash",
            remote_auth_group=DEFAULT_REMOTE_AUTH_GROUP,
            comment_mappings={"recheck": "verify"},
            hooks=["patchset-created"],
            validation_mode="warn",
        )
        assert cfg.check() == []

    def test_missing_github_owner(self) -> None:
        cfg = G2PConfig(enabled=True, github_owner="")
        errors = cfg.check()
        assert any("g2p_github_owner" in e for e in errors)

    def test_invalid_name_style(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            remote_name_style="camelCase",
        )
        errors = cfg.check()
        assert any("g2p_remote_name_style" in e for e in errors)
        assert any("camelCase" in e for e in errors)

    @pytest.mark.parametrize("style", list(VALID_NAME_STYLES))
    def test_all_valid_name_styles(self, style: str) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            remote_name_style=style,
        )
        errors = cfg.check()
        assert not any("g2p_remote_name_style" in e for e in errors)

    def test_invalid_validation_mode(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            validation_mode="strict",
        )
        errors = cfg.check()
        assert any("g2p_validation_mode" in e for e in errors)
        assert any("strict" in e for e in errors)

    @pytest.mark.parametrize("mode", list(VALID_VALIDATION_MODES))
    def test_all_valid_validation_modes(self, mode: str) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            validation_mode=mode,
        )
        errors = cfg.check()
        assert not any("g2p_validation_mode" in e for e in errors)

    def test_invalid_hook_name(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=["patchset-created", "nonexistent-hook"],
        )
        errors = cfg.check()
        assert any("nonexistent-hook" in e for e in errors)

    def test_all_valid_hooks_accepted(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=list(VALID_HOOKS),
        )
        errors = cfg.check()
        assert not any("g2p_hooks" in e for e in errors)

    def test_empty_hooks_list_valid(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            hooks=[],
        )
        errors = cfg.check()
        assert not any("g2p_hooks" in e for e in errors)

    def test_invalid_comment_mapping_filter(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            comment_mappings={"recheck": "build"},
        )
        errors = cfg.check()
        assert any("g2p_comment_mappings" in e for e in errors)
        assert any("build" in e for e in errors)

    def test_valid_comment_mapping_filters(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            comment_mappings={
                "recheck": "verify",
                "remerge": "merge",
            },
        )
        errors = cfg.check()
        assert not any("g2p_comment_mappings" in e for e in errors)

    def test_multiple_errors_returned(self) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="",
            remote_name_style="invalid",
            validation_mode="invalid",
            hooks=["bad-hook"],
        )
        errors = cfg.check()
        assert len(errors) >= 4

    def test_missing_token_is_warning_not_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        cfg = G2PConfig(enabled=True, github_owner="test")
        with caplog.at_level(logging.WARNING):
            errors = cfg.check()
        # No error about the token — it should be a warning only
        assert not any("token" in e.lower() for e in errors)
        assert any("g2p_github_token" in record.message for record in caplog.records)

    def test_token_present_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_valid",
        )
        with caplog.at_level(logging.WARNING):
            errors = cfg.check()
        assert errors == []
        assert not any(
            "g2p_github_token" in record.message for record in caplog.records
        )

    def test_empty_auth_group_is_warning_not_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_valid",
            remote_auth_group="",
        )
        with caplog.at_level(logging.WARNING):
            errors = cfg.check()
        assert not any("auth_group" in e for e in errors)
        assert any(
            "g2p_remote_auth_group" in record.message for record in caplog.records
        )

    def test_auth_group_without_github_is_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Non-empty auth group missing 'github' warns about detection."""
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_valid",
            remote_auth_group="Some Other Group",
        )
        with caplog.at_level(logging.WARNING):
            errors = cfg.check()
        assert not any("auth_group" in e for e in errors)
        assert any(
            "does not contain 'github'" in record.message for record in caplog.records
        )

    def test_auth_group_with_github_no_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Auth group containing 'github' should not warn."""
        cfg = G2PConfig(
            enabled=True,
            github_owner="test",
            github_token="ghp_valid",
            remote_auth_group="GitHub Replication",
        )
        with caplog.at_level(logging.WARNING):
            errors = cfg.check()
        assert not any("auth_group" in e for e in errors)
        assert not any(
            "does not contain 'github'" in record.message for record in caplog.records
        )


# ===================================================================
# G2PConfig.effective_remote_url
# ===================================================================


class TestEffectiveRemoteUrl:
    """Tests for the effective_remote_url property."""

    def test_explicit_url_returned_as_is(self) -> None:
        cfg = G2PConfig(remote_url="git@github.com:custom/${name}.git")
        assert cfg.effective_remote_url == "git@github.com:custom/${name}.git"

    def test_auto_generated_from_owner(self) -> None:
        cfg = G2PConfig(github_owner="onap")
        assert cfg.effective_remote_url == "git@github.com:onap/${name}.git"

    def test_explicit_url_takes_precedence_over_owner(self) -> None:
        cfg = G2PConfig(
            github_owner="onap",
            remote_url="git@github.com:override/${name}.git",
        )
        assert cfg.effective_remote_url == "git@github.com:override/${name}.git"

    def test_empty_url_and_owner(self) -> None:
        cfg = G2PConfig(remote_url="", github_owner="")
        assert cfg.effective_remote_url == ""

    def test_url_contains_name_placeholder(self) -> None:
        cfg = G2PConfig(github_owner="fdio")
        assert "${name}" in cfg.effective_remote_url

    def test_url_uses_ssh_format(self) -> None:
        cfg = G2PConfig(github_owner="opendaylight")
        url = cfg.effective_remote_url
        assert url.startswith("git@github.com:")
        assert url.endswith(".git")


# ===================================================================
# G2PConfig.token_provided
# ===================================================================


class TestTokenProvided:
    """Tests for the token_provided property."""

    def test_true_when_token_set(self) -> None:
        cfg = G2PConfig(github_token="ghp_abc123")
        assert cfg.token_provided is True

    def test_false_when_token_empty(self) -> None:
        cfg = G2PConfig(github_token="")
        assert cfg.token_provided is False

    def test_false_by_default(self) -> None:
        cfg = G2PConfig()
        assert cfg.token_provided is False


# ===================================================================
# from_environment integration scenarios
# ===================================================================


class TestG2PConfigIntegrationScenarios:
    """End-to-end scenarios matching real-world usage patterns."""

    def test_onap_production_pattern(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        """Simulate the ONAP production Hiera configuration."""
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "onap")
        clean_g2p_env.setenv("G2P_GITHUB_TOKEN", "ghp_onap_token")
        clean_g2p_env.setenv("G2P_REMOTE_NAME_STYLE", "dash")
        clean_g2p_env.setenv(
            "G2P_COMMENT_MAPPINGS",
            json.dumps(
                {
                    "recheck": "verify",
                    "remerge": "merge",
                    "rerun-gha": "verify",
                    "remerge-gha": "merge",
                }
            ),
        )
        cfg = G2PConfig.from_environment()
        assert cfg.check() == []
        assert cfg.enabled is True
        assert cfg.github_owner == "onap"
        assert cfg.effective_remote_url == ("git@github.com:onap/${name}.git")
        assert len(cfg.comment_mappings) == 4
        assert cfg.comment_mappings["rerun-gha"] == "verify"

    def test_fdio_production_pattern(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        """Simulate the FD.io production Hiera configuration."""
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "fdio")
        clean_g2p_env.setenv("G2P_GITHUB_TOKEN", "ghp_fdio_token")
        clean_g2p_env.setenv("G2P_REMOTE_NAME_STYLE", "dash")
        clean_g2p_env.setenv(
            "G2P_COMMENT_MAPPINGS",
            json.dumps(
                {
                    "recheck": "verify",
                    "remerge": "merge",
                    "rerun-gha": "verify",
                }
            ),
        )
        cfg = G2PConfig.from_environment()
        assert cfg.check() == []
        assert cfg.github_owner == "fdio"

    def test_deferred_config_no_token(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        """Simulate deferred GitHub org configuration (no token)."""
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "my-org")
        clean_g2p_env.setenv("G2P_VALIDATION_MODE", "skip")
        cfg = G2PConfig.from_environment()
        # Should have no hard errors — token absence is a warning
        assert cfg.check() == []
        assert cfg.token_provided is False
        assert cfg.validation_mode == "skip"

    def test_custom_remote_url_override(
        self, clean_g2p_env: pytest.MonkeyPatch
    ) -> None:
        """Simulate a non-standard URL pattern."""
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "custom")
        clean_g2p_env.setenv(
            "G2P_REMOTE_URL",
            "ssh://git@github.example.com/${name}.git",
        )
        cfg = G2PConfig.from_environment()
        assert cfg.check() == []
        assert cfg.effective_remote_url == ("ssh://git@github.example.com/${name}.git")

    def test_single_hook_selection(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        """Simulate enabling only one hook."""
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test")
        clean_g2p_env.setenv("G2P_HOOKS", "patchset-created")
        cfg = G2PConfig.from_environment()
        assert cfg.check() == []
        assert cfg.hooks == ["patchset-created"]


# ===================================================================
# Constants validation
# ===================================================================


class TestConstants:
    """Verify module-level constants are well-formed."""

    def test_valid_name_styles_tuple(self) -> None:
        assert isinstance(VALID_NAME_STYLES, tuple)
        assert "dash" in VALID_NAME_STYLES
        assert "underscore" in VALID_NAME_STYLES
        assert "slash" in VALID_NAME_STYLES

    def test_valid_validation_modes_tuple(self) -> None:
        assert isinstance(VALID_VALIDATION_MODES, tuple)
        assert "error" in VALID_VALIDATION_MODES
        assert "warn" in VALID_VALIDATION_MODES
        assert "skip" in VALID_VALIDATION_MODES

    def test_valid_hooks_tuple(self) -> None:
        assert isinstance(VALID_HOOKS, tuple)
        assert "patchset-created" in VALID_HOOKS
        assert "comment-added" in VALID_HOOKS
        assert "change-merged" in VALID_HOOKS

    def test_default_comment_mappings_values(self) -> None:
        """All default mapping values should be valid filters."""
        valid_filters = {"verify", "merge"}
        for value in DEFAULT_COMMENT_MAPPINGS.values():
            assert value in valid_filters

    def test_default_remote_auth_group_contains_github(self) -> None:
        """Auth group must contain 'github' for platform detection."""
        assert "github" in DEFAULT_REMOTE_AUTH_GROUP.lower()

    def test_valid_org_setup_modes_tuple(self) -> None:
        assert isinstance(VALID_ORG_SETUP_MODES, tuple)
        assert len(VALID_ORG_SETUP_MODES) == 3
        assert "provision" in VALID_ORG_SETUP_MODES
        assert "verify" in VALID_ORG_SETUP_MODES
        assert "skip" in VALID_ORG_SETUP_MODES


# ===================================================================
# Org setup configuration
# ===================================================================


class TestOrgSetupConfig:
    """Tests for org_setup and org_token_map fields."""

    def test_default_org_setup(self) -> None:
        config = G2PConfig()
        assert config.org_setup == "verify"

    def test_default_org_token_map(self) -> None:
        config = G2PConfig()
        assert config.org_token_map == ""

    def test_org_setup_from_env(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test-org")
        clean_g2p_env.setenv("G2P_ORG_SETUP", "provision")
        config = G2PConfig.from_environment()
        assert config.org_setup == "provision"

    def test_org_setup_normalised_to_lowercase(
        self, clean_g2p_env: pytest.MonkeyPatch
    ) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test-org")
        clean_g2p_env.setenv("G2P_ORG_SETUP", "VERIFY")
        config = G2PConfig.from_environment()
        assert config.org_setup == "verify"

    def test_org_setup_default_when_unset(
        self, clean_g2p_env: pytest.MonkeyPatch
    ) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test-org")
        config = G2PConfig.from_environment()
        assert config.org_setup == "verify"

    def test_org_token_map_from_env(self, clean_g2p_env: pytest.MonkeyPatch) -> None:
        clean_g2p_env.setenv("G2P_ENABLE", "true")
        clean_g2p_env.setenv("G2P_GITHUB_OWNER", "test-org")
        clean_g2p_env.setenv("G2P_ORG_TOKEN_MAP", "dGVzdA==")
        config = G2PConfig.from_environment()
        assert config.org_token_map == "dGVzdA=="

    def test_invalid_org_setup_check(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            org_setup="invalid",
        )
        errors = config.check()
        assert any("g2p_org_setup" in e for e in errors)

    def test_all_valid_org_setup_modes(self) -> None:
        for mode in ("provision", "verify", "skip"):
            config = G2PConfig(
                enabled=True,
                github_owner="test-org",
                org_setup=mode,
            )
            errors = config.check()
            assert not any("g2p_org_setup" in e for e in errors)

    def test_provision_without_token_map_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            github_token="ghp_test",
            org_setup="provision",
            org_token_map="",
        )
        with caplog.at_level(logging.WARNING):
            config.check()
        assert any("g2p_org_token_map" in r.message for r in caplog.records)


# ===================================================================
# decode_org_tokens
# ===================================================================


class TestDecodeOrgTokens:
    """Tests for the decode_org_tokens helper function."""

    def test_valid_input(self) -> None:
        import base64

        data = json.dumps(
            [
                {"github_org": "org-a", "token": "ghp_aaa"},
                {"github_org": "org-b", "token": "ghp_bbb"},
            ]
        )
        b64 = base64.b64encode(data.encode()).decode()
        result = decode_org_tokens(b64)
        assert result == {"org-a": "ghp_aaa", "org-b": "ghp_bbb"}

    def test_empty_string(self) -> None:
        result = decode_org_tokens("")
        assert result == {}

    def test_whitespace_only(self) -> None:
        result = decode_org_tokens("   ")
        assert result == {}

    def test_bad_base64(self) -> None:
        with pytest.raises(ConfigError, match="bad base64"):
            decode_org_tokens("not-valid-base64!!!")

    def test_non_utf8_bytes(self) -> None:
        """Valid base64 that decodes to non-UTF-8 bytes is reported as such."""
        import base64

        # 0xff is never a valid UTF-8 lead byte, so this is valid
        # base64 but cannot be decoded as UTF-8.
        b64 = base64.b64encode(b"\xff\xfe").decode()
        with pytest.raises(ConfigError, match="not valid UTF-8"):
            decode_org_tokens(b64)

    def test_bad_json(self) -> None:
        import base64

        b64 = base64.b64encode(b"not json").decode()
        with pytest.raises(ConfigError, match="bad JSON"):
            decode_org_tokens(b64)

    def test_not_array(self) -> None:
        import base64

        b64 = base64.b64encode(b'{"key": "value"}').decode()
        with pytest.raises(ConfigError, match="JSON array"):
            decode_org_tokens(b64)

    def test_missing_fields(self) -> None:
        import base64

        data = json.dumps([{"github_org": "org-a"}])
        b64 = base64.b64encode(data.encode()).decode()
        with pytest.raises(ConfigError, match="github_org.*token"):
            decode_org_tokens(b64)

    def test_empty_array(self) -> None:
        import base64

        b64 = base64.b64encode(b"[]").decode()
        result = decode_org_tokens(b64)
        assert result == {}

    def test_wrapped_base64(self) -> None:
        """Line-wrapped base64 (e.g. from macOS/Linux) decodes."""
        import base64

        data = json.dumps([{"github_org": "org-a", "token": "ghp_aaa"}])
        raw_b64 = base64.b64encode(data.encode()).decode()
        # Simulate line-wrapping every 20 chars
        wrapped = "\n".join(raw_b64[i : i + 20] for i in range(0, len(raw_b64), 20))
        result = decode_org_tokens(wrapped)
        assert result == {"org-a": "ghp_aaa"}


# ===================================================================
# resolve_org_token
# ===================================================================


class TestResolveOrgToken:
    """Tests for the G2PConfig.resolve_org_token method."""

    def test_found_in_map(self) -> None:
        import base64

        data = json.dumps(
            [
                {"github_org": "test-org", "token": "ghp_org_token"},
            ]
        )
        b64 = base64.b64encode(data.encode()).decode()
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            github_token="ghp_fallback",
            org_token_map=b64,
        )
        assert config.resolve_org_token() == "ghp_org_token"

    def test_not_found_falls_back(self) -> None:
        import base64

        data = json.dumps(
            [
                {"github_org": "other-org", "token": "ghp_other"},
            ]
        )
        b64 = base64.b64encode(data.encode()).decode()
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            github_token="ghp_fallback",
            org_token_map=b64,
        )
        assert config.resolve_org_token() == "ghp_fallback"

    def test_no_map_falls_back(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            github_token="ghp_fallback",
            org_token_map="",
        )
        assert config.resolve_org_token() == "ghp_fallback"

    def test_bad_map_falls_back(self) -> None:
        config = G2PConfig(
            enabled=True,
            github_owner="test-org",
            github_token="ghp_fallback",
            org_token_map="bad-base64!!!",
        )
        assert config.resolve_org_token() == "ghp_fallback"
