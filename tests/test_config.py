# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the config module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from config import (
    ActionConfig,
    ApiPathStore,
    ConfigError,
    InstanceConfig,
    InstanceStore,
    TunnelConfig,
    parse_interval_to_seconds,
)

# ---------------------------------------------------------------------------
# InstanceConfig
# ---------------------------------------------------------------------------


class TestInstanceConfig:
    """Tests for InstanceConfig dataclass."""

    def test_from_dict_minimal(self) -> None:
        data = {"slug": "onap", "gerrit": "gerrit.onap.org"}
        ic = InstanceConfig.from_dict(data)
        assert ic.slug == "onap"
        assert ic.gerrit_host == "gerrit.onap.org"
        assert ic.project == ""
        assert ic.api_path == ""
        assert ic.ssh_user == "gerrit"
        assert ic.ssh_port == 29418
        assert ic.max_projects == 500

    def test_from_dict_all_fields(self) -> None:
        data = {
            "slug": "lf",
            "gerrit": "gerrit.lf.org",
            "project": "releng/lftools",
            "api_path": "/infra",
            "ssh_user": "myuser",
            "ssh_port": "12345",
            "max_projects": "200",
        }
        ic = InstanceConfig.from_dict(data)
        assert ic.slug == "lf"
        assert ic.gerrit_host == "gerrit.lf.org"
        assert ic.project == "releng/lftools"
        assert ic.api_path == "/infra"
        assert ic.ssh_user == "myuser"
        assert ic.ssh_port == 12345
        assert ic.max_projects == 200

    def test_from_dict_with_defaults(self) -> None:
        data = {"slug": "test", "gerrit": "g.example.com"}
        ic = InstanceConfig.from_dict(
            data,
            default_ssh_user="admin",
            default_ssh_port=2222,
            default_max_projects=100,
        )
        assert ic.ssh_user == "admin"
        assert ic.ssh_port == 2222
        assert ic.max_projects == 100

    def test_from_dict_per_instance_ssh_overrides_defaults(self) -> None:
        data = {
            "slug": "test",
            "gerrit": "g.example.com",
            "ssh_user": "custom",
            "ssh_port": 9999,
        }
        ic = InstanceConfig.from_dict(
            data,
            default_ssh_user="admin",
            default_ssh_port=2222,
        )
        assert ic.ssh_user == "custom"
        assert ic.ssh_port == 9999

    def test_from_dict_missing_slug(self) -> None:
        with pytest.raises(ConfigError, match="missing required 'slug'"):
            InstanceConfig.from_dict({"gerrit": "g.example.com"})

    def test_from_dict_empty_slug(self) -> None:
        with pytest.raises(ConfigError, match="missing required 'slug'"):
            InstanceConfig.from_dict({"slug": "", "gerrit": "g.example.com"})

    def test_from_dict_missing_gerrit(self) -> None:
        with pytest.raises(ConfigError, match="missing required 'gerrit'"):
            InstanceConfig.from_dict({"slug": "test"})

    def test_effective_api_path_use_api_path_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "false")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="/r")
        assert ic.effective_api_path == ""

    def test_effective_api_path_use_api_path_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "true")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="/r")
        assert ic.effective_api_path == "/r"

    def test_effective_api_path_normalises_missing_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "true")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="r")
        assert ic.effective_api_path == "/r"

    def test_effective_api_path_strips_trailing_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "true")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="/r/")
        assert ic.effective_api_path == "/r"

    def test_effective_api_path_root_normalises_to_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "true")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="/")
        assert ic.effective_api_path == ""

    def test_effective_api_path_empty_when_no_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("USE_API_PATH", "true")
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="")
        assert ic.effective_api_path == ""

    def test_effective_api_path_unset_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("USE_API_PATH", raising=False)
        ic = InstanceConfig(slug="t", gerrit_host="g", api_path="/r")
        assert ic.effective_api_path == ""

    def test_frozen(self) -> None:
        ic = InstanceConfig(slug="t", gerrit_host="g")
        with pytest.raises(AttributeError):
            ic.slug = "other"  # pyright: ignore[reportAttributeAccessIssue]


# ---------------------------------------------------------------------------
# ActionConfig
# ---------------------------------------------------------------------------


class TestActionConfig:
    """Tests for ActionConfig dataclass."""

    def test_from_environment_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Clear everything first
        for key in [
            "GERRIT_SETUP",
            "AUTH_TYPE",
            "SSH_PRIVATE_KEY",
            "SSH_KNOWN_HOSTS",
            "HTTP_USERNAME",
            "HTTP_PASSWORD",
            "BEARER_TOKEN",
            "REMOTE_SSH_USER",
            "REMOTE_SSH_PORT",
            "GERRIT_VERSION",
            "PLUGIN_VERSION",
            "BASE_HTTP_PORT",
            "BASE_SSH_PORT",
            "SYNC_ON_STARTUP",
            "SYNC_REFS",
            "REPLICATION_THREADS",
            "REPLICATION_TIMEOUT",
            "FETCH_EVERY",
            "SKIP_PLUGIN_INSTALL",
            "ADDITIONAL_PLUGINS",
            "GERRIT_INIT_ARGS",
            "DEBUG",
            "USE_API_PATH",
            "TUNNEL_HOST",
            "TUNNEL_PORTS",
            "MAX_PROJECTS",
            "ENABLE_CACHE",
            "CACHE_KEY_SUFFIX",
            "CHECK_SERVICE",
            "EXIT",
            "REQUIRE_REPLICATION_SUCCESS",
            "REPLICATION_WAIT_TIMEOUT",
            "SSH_AUTH_KEYS",
            "SSH_AUTH_USERNAME",
            "WORK_DIR",
        ]:
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setenv("GERRIT_SETUP", "[]")

        config = ActionConfig.from_environment()
        assert config.auth_type == "ssh"
        assert config.gerrit_version == "3.13.1-ubuntu24"
        assert config.plugin_version == "stable-3.13"
        assert config.base_http_port == 18080
        assert config.base_ssh_port == 29418
        assert config.debug is False
        assert config.instances == []

    def test_from_environment_with_instances(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = json.dumps(
            [
                {"slug": "test1", "gerrit": "g1.example.com"},
                {"slug": "test2", "gerrit": "g2.example.com", "project": "proj"},
            ]
        )
        monkeypatch.setenv("GERRIT_SETUP", setup)
        monkeypatch.setenv("DEBUG", "true")
        monkeypatch.setenv("AUTH_TYPE", "http_basic")
        monkeypatch.setenv("HTTP_USERNAME", "user")
        monkeypatch.setenv("HTTP_PASSWORD", "pass")

        config = ActionConfig.from_environment()
        assert len(config.instances) == 2
        assert config.instances[0].slug == "test1"
        assert config.instances[1].project == "proj"
        assert config.debug is True
        assert config.auth_type == "http_basic"

    def test_from_environment_invalid_json(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GERRIT_SETUP", "not json")
        with pytest.raises(ConfigError, match="not valid JSON"):
            ActionConfig.from_environment()

    def test_from_environment_not_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GERRIT_SETUP", '{"key": "val"}')
        with pytest.raises(ConfigError, match="must be a JSON array"):
            ActionConfig.from_environment()

    def test_work_path(self) -> None:
        config = ActionConfig(work_dir="/tmp/test-dir")
        assert config.work_path == Path("/tmp/test-dir")
        assert config.instances_json_path == Path("/tmp/test-dir/instances.json")
        assert config.api_paths_json_path == Path("/tmp/test-dir/api_paths.json")

    def test_custom_image(self) -> None:
        config = ActionConfig(gerrit_version="3.12.0-ubuntu22")
        assert config.custom_image == "gerrit-extended:3.12.0-ubuntu22"

    def test_fetch_every_enabled_true(self) -> None:
        config = ActionConfig(fetch_every="60s")
        assert config.fetch_every_enabled is True

    def test_fetch_every_enabled_false_zero(self) -> None:
        config = ActionConfig(fetch_every="0")
        assert config.fetch_every_enabled is False

    def test_fetch_every_enabled_false_zero_with_unit(self) -> None:
        config = ActionConfig(fetch_every="0s")
        assert config.fetch_every_enabled is False

    def test_fetch_interval_seconds(self) -> None:
        config = ActionConfig(fetch_every="5m")
        assert config.fetch_interval_seconds == 300

    def test_tunnel_ports_empty(self) -> None:
        config = ActionConfig(tunnel_ports_json="")
        assert config.tunnel_ports == {}

    def test_tunnel_ports_valid(self) -> None:
        tp = json.dumps({"onap": {"http": 8080, "ssh": 29418}})
        config = ActionConfig(tunnel_ports_json=tp)
        result = config.tunnel_ports
        assert "onap" in result
        assert result["onap"].http_port == 8080
        assert result["onap"].ssh_port == 29418

    def test_tunnel_ports_invalid_json(self) -> None:
        config = ActionConfig(tunnel_ports_json="not json")
        assert config.tunnel_ports == {}

    def test_tunnel_ports_out_of_range(self) -> None:
        tp = json.dumps({"bad": {"http": 99999, "ssh": 29418}})
        config = ActionConfig(tunnel_ports_json=tp)
        assert "bad" not in config.tunnel_ports

    def test_tunnel_ports_missing_fields(self) -> None:
        tp = json.dumps({"partial": {"http": 8080}})
        config = ActionConfig(tunnel_ports_json=tp)
        assert "partial" not in config.tunnel_ports


class TestActionConfigValidation:
    """Tests for ActionConfig.validate()."""

    def test_valid_ssh_config(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key-content",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        assert config.validate() == []

    def test_valid_http_basic_config(self) -> None:
        config = ActionConfig(
            auth_type="http_basic",
            http_username="user",
            http_password="pass",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        assert config.validate() == []

    def test_valid_bearer_token_config(self) -> None:
        config = ActionConfig(
            auth_type="bearer_token",
            bearer_token="my-token",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        assert config.validate() == []

    def test_empty_instances(self) -> None:
        config = ActionConfig(auth_type="ssh", ssh_private_key="key")
        errors = config.validate()
        assert any("at least one instance" in e for e in errors)

    def test_ssh_missing_key(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("ssh_private_key required" in e for e in errors)

    def test_http_basic_missing_username(self) -> None:
        config = ActionConfig(
            auth_type="http_basic",
            http_username="",
            http_password="pass",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("http_username" in e for e in errors)

    def test_http_basic_missing_password(self) -> None:
        config = ActionConfig(
            auth_type="http_basic",
            http_username="user",
            http_password="",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("http_password" in e for e in errors)

    def test_bearer_token_missing(self) -> None:
        config = ActionConfig(
            auth_type="bearer_token",
            bearer_token="",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("bearer_token required" in e for e in errors)

    def test_invalid_auth_type(self) -> None:
        config = ActionConfig(
            auth_type="magic",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("Invalid auth_type" in e for e in errors)

    def test_port_out_of_range(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key",
            base_http_port=99999,
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("base_http_port out of range" in e for e in errors)

    def test_invalid_fetch_every(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key",
            fetch_every="badvalue",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("fetch_every" in e for e in errors)

    def test_invalid_ssh_auth_username_chars(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key",
            ssh_auth_username="bad user!",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("Invalid ssh_auth_username" in e for e in errors)

    def test_ssh_auth_username_too_long(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key",
            ssh_auth_username="a" * 65,
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert any("too long" in e for e in errors)

    def test_valid_ssh_auth_username(self) -> None:
        config = ActionConfig(
            auth_type="ssh",
            ssh_private_key="key",
            ssh_auth_username="test-user.01_x",
            instances=[InstanceConfig(slug="t", gerrit_host="g")],
        )
        errors = config.validate()
        assert not any("ssh_auth_username" in e for e in errors)


# ---------------------------------------------------------------------------
# parse_interval_to_seconds
# ---------------------------------------------------------------------------


class TestParseInterval:
    """Tests for parse_interval_to_seconds."""

    def test_plain_seconds(self) -> None:
        assert parse_interval_to_seconds("60") == 60

    def test_seconds_suffix(self) -> None:
        assert parse_interval_to_seconds("60s") == 60

    def test_seconds_suffix_uppercase(self) -> None:
        assert parse_interval_to_seconds("60S") == 60

    def test_minutes(self) -> None:
        assert parse_interval_to_seconds("5m") == 300

    def test_minutes_uppercase(self) -> None:
        assert parse_interval_to_seconds("5M") == 300

    def test_hours(self) -> None:
        assert parse_interval_to_seconds("1h") == 3600

    def test_hours_uppercase(self) -> None:
        assert parse_interval_to_seconds("2H") == 7200

    def test_zero(self) -> None:
        assert parse_interval_to_seconds("0") == 0

    def test_zero_with_unit(self) -> None:
        assert parse_interval_to_seconds("0s") == 0

    def test_whitespace_stripped(self) -> None:
        assert parse_interval_to_seconds("  60s  ") == 60

    def test_invalid_format(self) -> None:
        with pytest.raises(ConfigError, match="Invalid interval"):
            parse_interval_to_seconds("abc")

    def test_invalid_unit(self) -> None:
        with pytest.raises(ConfigError, match="Invalid interval"):
            parse_interval_to_seconds("60x")

    def test_empty_string(self) -> None:
        with pytest.raises(ConfigError, match="Invalid interval"):
            parse_interval_to_seconds("")

    def test_negative_not_matched(self) -> None:
        with pytest.raises(ConfigError, match="Invalid interval"):
            parse_interval_to_seconds("-60s")


# ---------------------------------------------------------------------------
# InstanceStore
# ---------------------------------------------------------------------------


class TestInstanceStore:
    """Tests for InstanceStore."""

    def test_load_and_iterate(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        data = {
            "beta": {"cid": "b", "ip": "10.0.0.2"},
            "alpha": {"cid": "a", "ip": "10.0.0.1"},
        }
        path.write_text(json.dumps(data))

        store = InstanceStore(path)
        store.load()

        # Iteration should be sorted by slug
        slugs = [s for s, _ in store]
        assert slugs == ["alpha", "beta"]

    def test_load_missing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.json"
        store = InstanceStore(path)
        with pytest.raises(ConfigError, match="not found"):
            store.load()

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json")
        store = InstanceStore(path)
        with pytest.raises(ConfigError, match="Invalid JSON"):
            store.load()

    def test_get_existing_slug(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        data = {"test": {"cid": "c123"}}
        path.write_text(json.dumps(data))

        store = InstanceStore(path)
        store.load()
        assert store.get("test")["cid"] == "c123"

    def test_get_missing_slug(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({"test": {}}))

        store = InstanceStore(path)
        store.load()
        with pytest.raises(ConfigError, match="not found"):
            store.get("missing")

    def test_len(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({"a": {}, "b": {}, "c": {}}))

        store = InstanceStore(path)
        store.load()
        assert len(store) == 3

    def test_set_instance_and_save(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({}))

        store = InstanceStore(path)
        store.load()
        store.set_instance("new", {"cid": "n123", "ip": "10.0.0.5"})
        store.save()

        # Re-read and verify
        reloaded = json.loads(path.read_text())
        assert "new" in reloaded
        assert reloaded["new"]["cid"] == "n123"

    def test_update_field(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({"test": {"cid": "c1"}}))

        store = InstanceStore(path)
        store.load()
        store.update_field("test", "ip", "10.0.0.9")
        assert store.get("test")["ip"] == "10.0.0.9"

    def test_update_field_creates_slug_if_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({}))

        store = InstanceStore(path)
        store.load()
        store.update_field("new_slug", "key", "value")
        assert store.data["new_slug"]["key"] == "value"

    def test_save_creates_parent_dir(self, tmp_path: Path) -> None:
        path = tmp_path / "subdir" / "instances.json"
        store = InstanceStore(path)
        store.set_instance("test", {"cid": "c1"})
        store.save()
        assert path.exists()

    def test_slugs_returns_sorted(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        path.write_text(json.dumps({"z": {}, "a": {}, "m": {}}))

        store = InstanceStore(path)
        store.load()
        assert store.slugs() == ["a", "m", "z"]

    def test_data_property(self, tmp_path: Path) -> None:
        path = tmp_path / "instances.json"
        data = {"test": {"key": "val"}}
        path.write_text(json.dumps(data))

        store = InstanceStore(path)
        store.load()
        assert store.data == data


# ---------------------------------------------------------------------------
# ApiPathStore
# ---------------------------------------------------------------------------


class TestApiPathStore:
    """Tests for ApiPathStore."""

    def test_load_existing(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        data = {
            "onap": {
                "gerrit_host": "gerrit.onap.org",
                "api_path": "/r",
                "api_url": "https://gerrit.onap.org/r",
            }
        }
        path.write_text(json.dumps(data))

        store = ApiPathStore(path)
        result = store.load()
        assert "onap" in result
        assert result["onap"]["api_path"] == "/r"

    def test_load_missing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.json"
        store = ApiPathStore(path)
        result = store.load()
        assert result == {}

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json")
        store = ApiPathStore(path)
        result = store.load()
        assert result == {}

    def test_set_path_and_save(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        store = ApiPathStore(path)
        store.set_path(
            "test",
            gerrit_host="g.example.com",
            api_path="/r",
            api_url="https://g.example.com/r",
        )
        store.save()

        reloaded = json.loads(path.read_text())
        assert reloaded["test"]["api_path"] == "/r"
        assert reloaded["test"]["api_url"] == "https://g.example.com/r"

    def test_get_api_path_existing(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        data = {"s": {"api_path": "/infra", "api_url": "u"}}
        path.write_text(json.dumps(data))

        store = ApiPathStore(path)
        store.load()
        assert store.get_api_path("s") == "/infra"

    def test_get_api_path_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        path.write_text(json.dumps({}))

        store = ApiPathStore(path)
        store.load()
        assert store.get_api_path("missing") == ""

    def test_get_api_url_existing(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        data = {"s": {"api_path": "/r", "api_url": "https://g.org/r"}}
        path.write_text(json.dumps(data))

        store = ApiPathStore(path)
        store.load()
        assert store.get_api_url("s") == "https://g.org/r"

    def test_get_api_url_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        path.write_text(json.dumps({}))

        store = ApiPathStore(path)
        store.load()
        assert store.get_api_url("nope") == ""

    def test_save_creates_parent_dir(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "dir" / "api_paths.json"
        store = ApiPathStore(path)
        store.set_path("t", gerrit_host="g", api_path="/x", api_url="u")
        store.save()
        assert path.exists()

    def test_data_property(self, tmp_path: Path) -> None:
        path = tmp_path / "api_paths.json"
        path.write_text(json.dumps({"k": {"api_path": "/a", "api_url": "b"}}))

        store = ApiPathStore(path)
        store.load()
        assert store.data == {"k": {"api_path": "/a", "api_url": "b"}}


# ---------------------------------------------------------------------------
# TunnelConfig
# ---------------------------------------------------------------------------


class TestTunnelConfig:
    """Tests for TunnelConfig dataclass."""

    def test_creation(self) -> None:
        tc = TunnelConfig(http_port=8080, ssh_port=29418)
        assert tc.http_port == 8080
        assert tc.ssh_port == 29418

    def test_frozen(self) -> None:
        tc = TunnelConfig(http_port=8080, ssh_port=29418)
        with pytest.raises(AttributeError):
            tc.http_port = 9090  # pyright: ignore[reportAttributeAccessIssue]
