# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Configuration parsing and validation for gerrit-action.

Replaces the ``jq`` pipelines and repeated environment variable reads
scattered across the shell scripts with typed, validated dataclasses.

Usage::

    from config import ActionConfig

    config = ActionConfig.from_environment()
    for instance in config.instances:
        print(instance.slug, instance.effective_api_path)
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from errors import ConfigError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-instance configuration
# ---------------------------------------------------------------------------

# Default work directory (matches the shell scripts' convention)
DEFAULT_WORK_DIR = "/tmp/gerrit-action"


@dataclass(frozen=True)
class InstanceConfig:
    """Configuration for a single Gerrit instance.

    Typically parsed from one element of the ``gerrit_setup`` JSON array.
    """

    slug: str
    gerrit_host: str
    project: str = ""
    api_path: str = ""
    ssh_user: str = ""
    ssh_port: int = 29418
    max_projects: int = 500

    @property
    def effective_api_path(self) -> str:
        """Resolve *api_path*, respecting the ``USE_API_PATH`` flag.

        When ``USE_API_PATH`` is not ``"true"`` the API path is ignored
        (returns ``""``).  Otherwise the stored path is normalised:

        * A leading ``/`` is ensured.
        * A trailing ``/`` is stripped.
        * The bare ``"/"`` is collapsed to ``""``.
        """
        if os.environ.get("USE_API_PATH", "false").lower() != "true":
            return ""
        return _normalise_path(self.api_path)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        default_ssh_user: str = "gerrit",
        default_ssh_port: int = 29418,
        default_max_projects: int = 500,
    ) -> InstanceConfig:
        """Create an :class:`InstanceConfig` from a JSON-decoded dict.

        Missing keys fall back to sensible defaults so that callers do
        not need to specify every field.
        """
        slug = data.get("slug", "")
        if not slug:
            raise ConfigError("Instance config missing required 'slug' field")

        gerrit_host = data.get("gerrit", "")
        if not gerrit_host:
            raise ConfigError(f"Instance '{slug}' missing required 'gerrit' field")

        ssh_user = data.get("ssh_user", "") or default_ssh_user
        raw_ssh_port = data.get("ssh_port", "") or default_ssh_port

        return cls(
            slug=slug,
            gerrit_host=gerrit_host,
            project=data.get("project", ""),
            api_path=data.get("api_path", ""),
            ssh_user=ssh_user,
            ssh_port=int(raw_ssh_port),
            max_projects=int(data.get("max_projects", default_max_projects)),
        )


# ---------------------------------------------------------------------------
# Tunnel configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TunnelConfig:
    """Tunnel port mapping for a single instance."""

    http_port: int
    ssh_port: int


# ---------------------------------------------------------------------------
# Global action configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionConfig:
    """Global configuration for the gerrit-action.

    Aggregates environment variables and the ``gerrit_setup`` JSON input
    into a single validated object.
    """

    # Authentication
    auth_type: str = "ssh"
    ssh_private_key: str = ""
    ssh_known_hosts: str = ""
    http_username: str = ""
    http_password: str = ""
    bearer_token: str = ""
    remote_ssh_user: str = "gerrit"
    remote_ssh_port: int = 29418

    # Gerrit image / plugins
    gerrit_version: str = "3.13.1-ubuntu24"
    plugin_version: str = "stable-3.13"
    skip_plugin_install: bool = False
    additional_plugins: str = ""
    gerrit_init_args: str = ""

    # Ports
    base_http_port: int = 18080
    base_ssh_port: int = 29418

    # Replication
    sync_on_startup: bool = True
    sync_refs: str = "+refs/heads/*:refs/heads/*,+refs/tags/*:refs/tags/*"
    replication_threads: int = 4
    replication_timeout: int = 120
    fetch_every: str = "60s"
    require_replication_success: bool = False
    replication_wait_timeout: int = 180

    # Behaviour
    check_service: bool = True
    exit: bool = False
    enable_cache: bool = False
    cache_key_suffix: str = ""
    debug: bool = False
    use_api_path: bool = False
    max_projects: int = 500

    # Tunnelling
    tunnel_host: str = ""
    tunnel_ports_json: str = ""

    # SSH auth keys (for user account setup)
    ssh_auth_keys: str = ""
    ssh_auth_username: str = ""

    # Working directory
    work_dir: str = DEFAULT_WORK_DIR

    # Instances
    instances: list[InstanceConfig] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def work_path(self) -> Path:
        """Return the working directory as a :class:`Path`."""
        return Path(self.work_dir)

    @property
    def instances_json_path(self) -> Path:
        """Path to the ``instances.json`` file created by ``start-instances``."""
        return self.work_path / "instances.json"

    @property
    def api_paths_json_path(self) -> Path:
        """Path to the ``api_paths.json`` file created by ``detect-api-paths``."""
        return self.work_path / "api_paths.json"

    @property
    def custom_image(self) -> str:
        """Docker image tag for the extended Gerrit image."""
        return f"gerrit-extended:{self.gerrit_version}"

    @property
    def fetch_every_enabled(self) -> bool:
        """Whether ``fetchEvery`` polling is enabled (not zero)."""
        return not _is_zero_interval(self.fetch_every)

    @property
    def fetch_interval_seconds(self) -> int:
        """Parse :attr:`fetch_every` to an integer number of seconds."""
        return parse_interval_to_seconds(self.fetch_every)

    @property
    def tunnel_ports(self) -> dict[str, TunnelConfig]:
        """Parse :attr:`tunnel_ports_json` into a slug → TunnelConfig mapping."""
        if not self.tunnel_ports_json:
            return {}
        try:
            raw = json.loads(self.tunnel_ports_json)
        except json.JSONDecodeError:
            logger.warning("TUNNEL_PORTS is not valid JSON, ignoring")
            return {}

        result: dict[str, TunnelConfig] = {}
        for slug, ports in raw.items():
            http_port = ports.get("http")
            ssh_port = ports.get("ssh")
            if http_port and ssh_port:
                try:
                    tc = TunnelConfig(
                        http_port=int(http_port),
                        ssh_port=int(ssh_port),
                    )
                    if 1 <= tc.http_port <= 65535 and 1 <= tc.ssh_port <= 65535:
                        result[slug] = tc
                    else:
                        logger.warning(
                            "Tunnel ports out of range for %s, ignoring", slug
                        )
                except (ValueError, TypeError):
                    logger.warning("Invalid tunnel port values for %s, ignoring", slug)
        return result

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_environment(cls) -> ActionConfig:
        """Parse configuration from environment variables.

        This is the canonical way to create an :class:`ActionConfig` in a
        GitHub Actions context, where all inputs are exposed as
        environment variables.
        """
        env = os.environ.get

        # Parse the gerrit_setup JSON array
        setup_raw = env("GERRIT_SETUP", "[]")
        try:
            setup_json: list[dict[str, Any]] = json.loads(setup_raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"GERRIT_SETUP is not valid JSON: {exc}") from exc

        if not isinstance(setup_json, list):
            raise ConfigError("GERRIT_SETUP must be a JSON array")

        default_ssh_user = env("REMOTE_SSH_USER", "gerrit")
        default_ssh_port = int(env("REMOTE_SSH_PORT", "29418"))
        default_max_projects = int(env("MAX_PROJECTS", "500"))

        instances = [
            InstanceConfig.from_dict(
                inst,
                default_ssh_user=default_ssh_user,
                default_ssh_port=default_ssh_port,
                default_max_projects=default_max_projects,
            )
            for inst in setup_json
        ]

        work_dir = env("WORK_DIR", DEFAULT_WORK_DIR)

        return cls(
            auth_type=env("AUTH_TYPE", "ssh"),
            ssh_private_key=env("SSH_PRIVATE_KEY", ""),
            ssh_known_hosts=env("SSH_KNOWN_HOSTS", ""),
            http_username=env("HTTP_USERNAME", ""),
            http_password=env("HTTP_PASSWORD", ""),
            bearer_token=env("BEARER_TOKEN", ""),
            remote_ssh_user=default_ssh_user,
            remote_ssh_port=default_ssh_port,
            gerrit_version=env("GERRIT_VERSION", "3.13.1-ubuntu24"),
            plugin_version=env("PLUGIN_VERSION", "stable-3.13"),
            skip_plugin_install=_str_to_bool(env("SKIP_PLUGIN_INSTALL", "false")),
            additional_plugins=env("ADDITIONAL_PLUGINS", ""),
            gerrit_init_args=env("GERRIT_INIT_ARGS", ""),
            base_http_port=int(env("BASE_HTTP_PORT", "18080")),
            base_ssh_port=int(env("BASE_SSH_PORT", "29418")),
            sync_on_startup=_str_to_bool(env("SYNC_ON_STARTUP", "true")),
            sync_refs=env(
                "SYNC_REFS",
                "+refs/heads/*:refs/heads/*,+refs/tags/*:refs/tags/*",
            ),
            replication_threads=int(env("REPLICATION_THREADS", "4")),
            replication_timeout=int(env("REPLICATION_TIMEOUT", "120")),
            fetch_every=env("FETCH_EVERY", "60s"),
            require_replication_success=_str_to_bool(
                env("REQUIRE_REPLICATION_SUCCESS", "false")
            ),
            replication_wait_timeout=int(env("REPLICATION_WAIT_TIMEOUT", "180")),
            check_service=_str_to_bool(env("CHECK_SERVICE", "true")),
            exit=_str_to_bool(env("EXIT", "false")),
            enable_cache=_str_to_bool(env("ENABLE_CACHE", "false")),
            cache_key_suffix=env("CACHE_KEY_SUFFIX", ""),
            debug=_str_to_bool(env("DEBUG", "false")),
            use_api_path=_str_to_bool(env("USE_API_PATH", "false")),
            max_projects=default_max_projects,
            tunnel_host=env("TUNNEL_HOST", ""),
            tunnel_ports_json=env("TUNNEL_PORTS", ""),
            ssh_auth_keys=env("SSH_AUTH_KEYS", ""),
            ssh_auth_username=env("SSH_AUTH_USERNAME", ""),
            work_dir=work_dir,
            instances=instances,
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> list[str]:
        """Return a list of validation error messages (empty if valid).

        This performs the same checks that the ``action.yaml`` setup step
        does in Bash, so that Python entry points can report problems
        before starting Docker containers.
        """
        errors: list[str] = []

        if not self.instances:
            errors.append("gerrit_setup is empty – at least one instance is required")

        # Auth validation
        auth = self.auth_type.lower()
        if auth == "ssh" and not self.ssh_private_key:
            errors.append("ssh_private_key required when auth_type=ssh")
        elif auth == "http_basic":
            if not self.http_username or not self.http_password:
                errors.append(
                    "http_username and http_password required when auth_type=http_basic"
                )
        elif auth == "bearer_token":
            if not self.bearer_token:
                errors.append("bearer_token required when auth_type=bearer_token")
        elif auth not in ("ssh", "http_basic", "bearer_token"):
            errors.append(f"Invalid auth_type: {auth}")

        # Port validation
        if not (1 <= self.base_http_port <= 65535):
            errors.append(f"base_http_port out of range: {self.base_http_port}")
        if not (1 <= self.base_ssh_port <= 65535):
            errors.append(f"base_ssh_port out of range: {self.base_ssh_port}")

        # fetch_every format
        if not _INTERVAL_RE.match(self.fetch_every):
            errors.append(
                f"fetch_every must be a valid interval "
                f"(e.g. '60s', '5m', '1h', or '0' to disable): "
                f"got '{self.fetch_every}'"
            )

        # ssh_auth_username validation
        if self.ssh_auth_username:
            if not re.match(r"^[A-Za-z0-9._-]+$", self.ssh_auth_username):
                errors.append(
                    f"Invalid ssh_auth_username: '{self.ssh_auth_username}' – "
                    "must contain only letters, numbers, dots, underscores, hyphens"
                )
            if len(self.ssh_auth_username) > 64:
                errors.append("ssh_auth_username too long (max 64 characters)")

        return errors


# ---------------------------------------------------------------------------
# Instance store — reading / writing instances.json
# ---------------------------------------------------------------------------


class InstanceStore:
    """Read and write the ``instances.json`` metadata file.

    This replaces the ``jq`` iteration boilerplate duplicated in 6+
    shell scripts.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def load(self) -> dict[str, dict[str, Any]]:
        """Load instances from disk.

        Raises :class:`ConfigError` if the file does not exist.
        """
        if not self.path.exists():
            raise ConfigError(f"Instances file not found: {self.path}")
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON in {self.path}: {exc}") from exc
        return self._data

    def save(self) -> None:
        """Persist the current data back to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2) + "\n",
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def data(self) -> dict[str, dict[str, Any]]:
        """Return the raw instance data dict."""
        return self._data

    def slugs(self) -> list[str]:
        """Return sorted list of instance slugs."""
        return sorted(self._data.keys())

    def get(self, slug: str) -> dict[str, Any]:
        """Return metadata for *slug*, raising :class:`ConfigError` if missing."""
        if slug not in self._data:
            raise ConfigError(f"Instance '{slug}' not found in {self.path}")
        return self._data[slug]

    def __iter__(self) -> Iterator[tuple[str, dict[str, Any]]]:
        """Iterate over ``(slug, metadata)`` pairs, sorted by slug."""
        for slug in self.slugs():
            yield slug, self._data[slug]

    def __len__(self) -> int:
        return len(self._data)

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def set_instance(self, slug: str, metadata: dict[str, Any]) -> None:
        """Add or update the metadata for *slug*."""
        self._data[slug] = metadata

    def update_field(self, slug: str, key: str, value: Any) -> None:
        """Update a single field for *slug*."""
        if slug not in self._data:
            self._data[slug] = {}
        self._data[slug][key] = value


# ---------------------------------------------------------------------------
# API paths store
# ---------------------------------------------------------------------------


class ApiPathStore:
    """Read and write the ``api_paths.json`` file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, dict[str, str]] = {}

    def load(self) -> dict[str, dict[str, str]]:
        """Load API paths from disk; returns empty dict if file missing."""
        if not self.path.exists():
            self._data = {}
            return self._data
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("Invalid JSON in %s: %s", self.path, exc)
            self._data = {}
        return self._data

    def save(self) -> None:
        """Persist the current data back to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2) + "\n",
            encoding="utf-8",
        )

    @property
    def data(self) -> dict[str, dict[str, str]]:
        return self._data

    def set_path(
        self,
        slug: str,
        *,
        gerrit_host: str,
        api_path: str,
        api_url: str,
    ) -> None:
        """Record the detected API path for *slug*."""
        self._data[slug] = {
            "gerrit_host": gerrit_host,
            "api_path": api_path,
            "api_url": api_url,
        }

    def get_api_path(self, slug: str) -> str:
        """Return the API path for *slug*, defaulting to ``""``."""
        entry = self._data.get(slug, {})
        return entry.get("api_path", "")

    def get_api_url(self, slug: str) -> str:
        """Return the full API URL for *slug*, defaulting to ``""``."""
        entry = self._data.get(slug, {})
        return entry.get("api_url", "")


# ---------------------------------------------------------------------------
# Interval parsing
# ---------------------------------------------------------------------------

_INTERVAL_RE = re.compile(r"^(\d+)([smhSMH]?)$")


def parse_interval_to_seconds(interval: str) -> int:
    """Parse a time interval string (e.g. ``"60s"``, ``"5m"``, ``"1h"``) to seconds.

    Plain integers (e.g. ``"60"``) are treated as seconds.

    Raises :class:`ConfigError` for invalid formats.
    """
    m = _INTERVAL_RE.match(interval.strip())
    if not m:
        raise ConfigError(
            f"Invalid interval '{interval}'. "
            "Expected format: <integer>[s|m|h], e.g. 60s, 5m, 1h"
        )
    value = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "m":
        return value * 60
    if unit == "h":
        return value * 3600
    return value  # seconds (or no unit)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _str_to_bool(value: str) -> bool:
    """Convert a string to bool (``"true"`` → True, anything else → False)."""
    return value.strip().lower() == "true"


def _is_zero_interval(interval: str) -> bool:
    """Return True if *interval* represents zero (``"0"``, ``"0s"``, etc.)."""
    m = _INTERVAL_RE.match(interval.strip())
    if not m:
        return False
    return int(m.group(1)) == 0


def _normalise_path(path: str) -> str:
    """Normalise an API path prefix.

    * Ensures a leading ``/``.
    * Strips a trailing ``/``.
    * Collapses bare ``"/"`` to ``""``.
    * Returns ``""`` for empty input.
    """
    path = path.strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/")
    if path == "/":
        return ""
    return path
