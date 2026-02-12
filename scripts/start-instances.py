#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Start Gerrit instances based on JSON configuration.

This script is the main orchestrator for provisioning one or more local
Gerrit containers.  It handles:

- Docker image management (check/build custom image)
- SSH authentication setup (private key, known_hosts, ssh_config)
- Remote project list fetching (REST API with auth)
- Replication configuration generation (replication.config, secure.config)
- Plugin download (pull-replication, additional plugins)
- Gerrit site initialisation (``gerrit init`` via Docker)
- Gerrit configuration (``gerrit.config`` via ``git config``)
- Project pre-creation (bare git repos for fetchEvery mode)
- Container startup (``docker run`` with volumes, ports, env)
- SSH host key capture from running containers
- Instance metadata persistence (``instances.json``)

Replaces ``start-instances.sh`` (~1,100 lines).

Usage::

    # From action.yaml (via the venv created in the Dockerfile)
    python3 scripts/start-instances.py

    # Locally with environment variables
    WORK_DIR=/tmp/gerrit-action GERRIT_SETUP='[...]' \\
        python3 scripts/start-instances.py
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

# ---------------------------------------------------------------------------
# Path setup – ensure ``scripts/lib`` is importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from config import (  # noqa: E402
    ActionConfig,
    ApiPathStore,
    InstanceConfig,
    InstanceStore,
)
from docker_manager import DockerManager  # noqa: E402
from errors import DockerError, GerritActionError  # noqa: E402
from logging_utils import log_group, setup_logging  # noqa: E402
from outputs import write_summary  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Gerrit container runs as UID:GID 1000:1000
_GERRIT_UID = 1000
_GERRIT_GID = 1000

# Sub-directories mounted into the container under /var/gerrit/
_GERRIT_SUBDIRS = (
    "git",
    "cache",
    "index",
    "data",
    "etc",
    "logs",
    "plugins",
    "tmp",
)

# Plugin download URLs (primary and fallback)
_PLUGIN_URL_TEMPLATE = (
    "https://gerrit-ci.gerritforge.com/job/"
    "plugin-pull-replication-gh-bazel-{version}/"
    "lastSuccessfulBuild/artifact/"
    "bazel-bin/plugins/pull-replication/pull-replication.jar"
)
_PLUGIN_ALT_URL_TEMPLATE = (
    "https://github.com/GerritForge/pull-replication/releases/"
    "download/{version}/pull-replication.jar"
)

# Plugin cache directory
_PLUGIN_CACHE_DIR = Path("/tmp/gerrit-plugins")

# Gerrit API responses carry this XSSI-protection prefix
_XSSI_PREFIX = ")]}'\n"


# =====================================================================
# Docker image management
# =====================================================================


def ensure_custom_image(
    docker: DockerManager,
    config: ActionConfig,
) -> str:
    """Ensure the custom Gerrit image is available and return its tag.

    If the image already exists (e.g. built by a prior Docker layer
    cache step), it is reused.  Otherwise it is built from the
    Dockerfile alongside this script.  If the Dockerfile is missing the
    official ``gerritcodereview/gerrit`` image is used as a fallback.
    """
    image: str = config.custom_image

    if docker.image_exists(image):
        logger.info("Custom image %s already exists ✅", image)
        return image

    dockerfile_dir = str(SCRIPT_DIR.parent)
    dockerfile_path = Path(dockerfile_dir) / "Dockerfile"

    if not dockerfile_path.exists():
        logger.warning(
            "Custom image not found and Dockerfile not available at %s",
            dockerfile_path,
        )
        fallback = f"gerritcodereview/gerrit:{config.gerrit_version}"
        logger.warning("Falling back to official image: %s", fallback)
        return fallback

    logger.info("Building custom Gerrit image with uv and gerrit_to_platform…")
    logger.info("  Base image: gerritcodereview/gerrit:%s", config.gerrit_version)
    logger.info("  Custom image: %s", image)

    try:
        docker.build_image(
            tag=image,
            dockerfile_dir=dockerfile_dir,
            build_args={"GERRIT_VERSION": config.gerrit_version},
            timeout=600,
        )
        logger.info("Custom image built successfully ✅")
    except DockerError as exc:
        logger.warning("Failed to build custom image: %s", exc)
        fallback = f"gerritcodereview/gerrit:{config.gerrit_version}"
        logger.warning("Falling back to official image: %s", fallback)
        return fallback

    # Verify components are present in the image
    _verify_custom_image(docker, image)

    return image


def _verify_custom_image(docker: DockerManager, image: str) -> None:
    """Log verification of uv and gerrit-to-platform inside the image."""
    logger.info("Verifying custom image components…")
    try:
        out = docker.run_ephemeral(
            image, entrypoint="", command=["uv", "--version"], timeout=30
        )
        logger.info("  uv: %s ✅", out.strip())
    except DockerError:
        logger.warning("  uv not found in custom image")

    try:
        out = docker.run_ephemeral(
            image, entrypoint="", command=["which", "change-merged"], timeout=30
        )
        logger.info("  gerrit-to-platform: %s ✅", out.strip())
    except DockerError:
        logger.warning("  gerrit-to-platform not found in custom image")


# =====================================================================
# SSH authentication setup
# =====================================================================


def setup_ssh_auth(
    instance_dir: Path,
    gerrit_host: str,
    ssh_user: str,
    ssh_port: int,
    ssh_private_key: str,
    ssh_known_hosts: str,
) -> None:
    """Create the SSH directory structure for replication auth.

    Writes the private key, known_hosts (or fetches via ssh-keyscan),
    and an SSH config file into ``<instance_dir>/ssh/``.
    """
    ssh_dir = instance_dir / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)

    # Private key
    id_rsa = ssh_dir / "id_rsa"
    id_rsa.write_text(ssh_private_key, encoding="utf-8")
    id_rsa.chmod(0o600)

    # Known hosts
    known_hosts = ssh_dir / "known_hosts"
    if ssh_known_hosts:
        known_hosts.write_text(ssh_known_hosts, encoding="utf-8")
    else:
        logger.info("Auto-fetching SSH host key for %s:%d…", gerrit_host, ssh_port)
        try:
            result = subprocess.run(
                ["ssh-keyscan", "-H", "-p", str(ssh_port), gerrit_host],
                capture_output=True,
                text=True,
                timeout=30,
            )
            known_hosts.write_text(result.stdout, encoding="utf-8")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning(
                "Could not fetch SSH host key for %s:%d: %s",
                gerrit_host,
                ssh_port,
                exc,
            )
            known_hosts.touch()
    known_hosts.chmod(0o644)

    # SSH config
    ssh_config = ssh_dir / "config"
    ssh_config.write_text(
        f"Host {gerrit_host}\n"
        f"  HostName {gerrit_host}\n"
        f"  User {ssh_user}\n"
        f"  Port {ssh_port}\n"
        f"  IdentityFile /var/gerrit/ssh/id_rsa\n"
        f"  StrictHostKeyChecking yes\n"
        f"  UserKnownHostsFile /var/gerrit/ssh/known_hosts\n",
        encoding="utf-8",
    )
    ssh_config.chmod(0o600)


# =====================================================================
# Remote project list fetching
# =====================================================================


def fetch_remote_projects(
    gerrit_host: str,
    api_path: str,
    project_filter: str,
    max_projects: int,
    config: ActionConfig,
) -> list[str]:
    """Fetch the project list from a remote Gerrit server's REST API.

    Parameters
    ----------
    gerrit_host:
        Hostname of the remote Gerrit server.
    api_path:
        Detected API path prefix (e.g. ``"/r"``).
    project_filter:
        Regex or empty string to filter projects.
    max_projects:
        Maximum number of projects to return.
    config:
        Action config (for auth credentials).

    Returns
    -------
    list[str]
        Project names (keys from the Gerrit ``/projects/`` endpoint).
    """
    logger.info("Fetching project list from %s…", gerrit_host)

    # Build URL
    path = api_path.strip("/")
    if path:
        base_url = f"https://{gerrit_host}/{path}/projects/"
    else:
        base_url = f"https://{gerrit_host}/projects/"

    params: dict[str, str] = {"n": str(max_projects)}
    if project_filter and project_filter != ".*":
        params["r"] = project_filter

    query = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    full_url = f"{base_url}?{query}"
    logger.info("  API URL: %s", full_url)

    # Build request kwargs
    kwargs: dict[str, Any] = {"timeout": (30, 60)}
    auth_type = config.auth_type.lower()

    if auth_type == "http_basic" and config.http_username and config.http_password:
        kwargs["auth"] = (config.http_username, config.http_password)
        logger.info("  Using HTTP basic authentication")
    elif auth_type == "bearer_token" and config.bearer_token:
        kwargs["headers"] = {"Authorization": f"Bearer {config.bearer_token}"}
        logger.info("  Using bearer token authentication")
    else:
        logger.info("  Using anonymous access for REST API")

    try:
        resp = requests.get(full_url, **kwargs)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("Failed to fetch project list from %s: %s", gerrit_host, exc)
        return []

    # Strip XSSI prefix and parse JSON
    body = resp.text
    if body.startswith(_XSSI_PREFIX):
        body = body[len(_XSSI_PREFIX) :]
    elif body.startswith(")]}'"):
        # Variant without trailing newline
        body = body.split("\n", 1)[-1]

    try:
        data = json.loads(body)
        projects = list(data.keys())
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.warning("Failed to parse project list response: %s", exc)
        return []

    logger.info("  Found %d projects on remote server", len(projects))
    return projects


# =====================================================================
# Replication configuration
# =====================================================================


def generate_replication_config(
    config_file: Path,
    slug: str,
    gerrit_host: str,
    project: str,
    remote_ssh_user: str,
    remote_ssh_port: int,
    api_path: str,
    config: ActionConfig,
) -> None:
    """Generate ``replication.config`` for the pull-replication plugin.

    The generated config uses ``fetchEvery`` for polling-based
    replication rather than ``apiUrl`` (the two are mutually exclusive).
    """
    auth_type = config.auth_type.lower()

    # Build the git URL
    if auth_type == "ssh":
        git_url = (
            f"ssh://{remote_ssh_user}@{gerrit_host}:{remote_ssh_port}/${{name}}.git"
        )
    else:
        # HTTP-based auth uses /a/ prefix for authenticated access
        path = api_path.strip("/")
        if path:
            git_url = f"https://{gerrit_host}/{path}/a/${{name}}.git"
        else:
            git_url = f"https://{gerrit_host}/a/${{name}}.git"

    # Parse sync refs
    sync_refs = [r.strip() for r in config.sync_refs.split(",") if r.strip()]

    fetch_every_enabled = config.fetch_every_enabled
    fetch_interval = config.fetch_every

    # Calculate connection timeout (at least 2 minutes, in milliseconds)
    timeout_ms = config.replication_timeout * 1000
    connection_timeout_ms = max(timeout_ms, 120_000)

    # Build the config file content
    lines = [
        "# Pull-replication configuration",
        "# Auto-generated by gerrit-server-action",
        "#",
        "# This configuration uses fetchEvery for polling-based replication.",
        "# The plugin will poll the source Gerrit at the configured interval",
        "# to fetch any new or changed refs.",
        "",
        "[gerrit]",
        f"  replicateOnStartup = {str(config.sync_on_startup).lower()}",
        "  autoReload = true",
        "",
        "[replication]",
        "  lockErrorMaxRetries = 5",
        "  maxRetries = 5",
        "  useCGitClient = false",
        "  refsBatchSize = 50",
        "",
        f'[remote "{slug}"]',
        f"  url = {git_url}",
    ]

    if fetch_every_enabled:
        lines.append(f"  fetchEvery = {fetch_interval}")
        logger.info("  Fetch interval (polling): %s", fetch_interval)
    else:
        logger.info("  Automatic polling disabled (interval=%s)", fetch_interval)

    lines.extend(
        [
            f"  timeout = {config.replication_timeout}",
            f"  connectionTimeout = {connection_timeout_ms}",
            "  replicationDelay = 0",
            "  replicationRetry = 60",
            f"  threads = {config.replication_threads}",
            "  createMissingRepositories = true",
            "  replicateHiddenProjects = false",
        ]
    )

    logger.info("  Git URL for replication: %s", git_url)

    # Fetch refspecs
    for ref in sync_refs:
        lines.append(f"  fetch = {ref}")

    # Project filter
    if project:
        lines.append(f"  projects = {project}")

    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_secure_config(
    config_file: Path,
    slug: str,
    config: ActionConfig,
) -> None:
    """Generate ``secure.config`` with authentication credentials."""
    auth_type = config.auth_type.lower()

    if auth_type == "http_basic":
        content = (
            f'[remote "{slug}"]\n'
            f"  username = {config.http_username}\n"
            f"  password = {config.http_password}\n"
        )
    elif auth_type == "bearer_token":
        content = f"[auth]\n  bearerToken = {config.bearer_token}\n"
    else:
        # SSH auth — no secure.config needed
        content = ""

    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(content, encoding="utf-8")
    config_file.chmod(0o600)


# =====================================================================
# Plugin download
# =====================================================================


def download_plugin(
    plugin_dir: Path,
    plugin_version: str,
    skip_plugin_install: bool,
) -> bool:
    """Download the pull-replication plugin JAR.

    Uses a local cache at ``/tmp/gerrit-plugins`` and tries a fallback
    URL if the primary CI build is unavailable.

    Returns *True* on success, *False* on failure.
    """
    if skip_plugin_install:
        logger.info("Skipping plugin download (skip_plugin_install=true)")
        return True

    _PLUGIN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cached_jar = _PLUGIN_CACHE_DIR / f"pull-replication-{plugin_version}.jar"
    target_jar = plugin_dir / "pull-replication.jar"
    plugin_dir.mkdir(parents=True, exist_ok=True)

    if cached_jar.exists():
        logger.info("Using cached plugin: %s", cached_jar)
        shutil.copy2(cached_jar, target_jar)
        return True

    logger.info("Downloading pull-replication plugin…")

    # Primary URL
    primary_url = _PLUGIN_URL_TEMPLATE.format(version=plugin_version)
    if _download_file(primary_url, cached_jar):
        logger.info("Plugin downloaded ✅")
        shutil.copy2(cached_jar, target_jar)
        return True

    # Fallback URL
    logger.warning("Primary download failed, attempting alternate source…")
    alt_url = _PLUGIN_ALT_URL_TEMPLATE.format(version=plugin_version)
    if _download_file(alt_url, cached_jar):
        logger.info("Plugin downloaded from alternate source ✅")
        shutil.copy2(cached_jar, target_jar)
        return True

    logger.error("Failed to download pull-replication plugin ❌")
    return False


def download_additional_plugins(
    plugin_dir: Path,
    additional_plugins: str,
) -> None:
    """Download additional plugins from comma-separated URLs."""
    if not additional_plugins:
        return

    logger.info("Downloading additional plugins…")
    plugin_dir.mkdir(parents=True, exist_ok=True)

    for url in additional_plugins.split(","):
        url = url.strip()
        if not url:
            continue
        name = url.rsplit("/", 1)[-1]
        dest = plugin_dir / name
        logger.info("Downloading: %s", name)
        if _download_file(url, dest):
            logger.info("  ✅ %s", name)
        else:
            logger.warning("  Failed to download %s", name)


def _download_file(url: str, dest: Path) -> bool:
    """Download *url* to *dest*.  Returns *True* on success."""
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                fh.write(chunk)
        return True
    except requests.RequestException as exc:
        logger.debug("Download failed for %s: %s", url, exc)
        # Clean up partial download
        if dest.exists():
            dest.unlink(missing_ok=True)
        return False


# =====================================================================
# Gerrit site initialisation
# =====================================================================


def init_gerrit_site(
    docker: DockerManager,
    instance_dir: Path,
    slug: str,
    canonical_url: str,
    image: str,
) -> None:
    """Initialise a Gerrit site directory using ``gerrit init``.

    Runs the Gerrit image with ``init`` as the command, mounting only
    the individual sub-directories (not the whole ``/var/gerrit``
    directory) so that ``/var/gerrit/bin`` from the image is preserved.
    """
    logger.info("Initializing Gerrit site for %s…", slug)

    # Create sub-directories with Gerrit-compatible ownership
    for subdir in _GERRIT_SUBDIRS:
        d = instance_dir / subdir
        d.mkdir(parents=True, exist_ok=True)

    _chown_tree(instance_dir)

    # Build volumes: mount each sub-directory individually
    volumes = {str(instance_dir / sub): f"/var/gerrit/{sub}" for sub in _GERRIT_SUBDIRS}

    try:
        docker.run_ephemeral(
            image,
            volumes=volumes,
            env={"CANONICAL_WEB_URL": canonical_url},
            command=["init"],
            timeout=180,
        )
    except DockerError as exc:
        raise GerritActionError(
            f"Failed to initialize Gerrit site for {slug}: {exc}"
        ) from exc

    logger.info("Gerrit site initialized ✅")


# =====================================================================
# Gerrit configuration
# =====================================================================


def configure_gerrit(
    instance_dir: Path,
    slug: str,
    canonical_url: str,
    listen_url: str,
    api_path: str,
    advertised_ssh_addr: str,
    use_tunnel: bool,
) -> None:
    """Write ``gerrit.config`` settings via ``git config``.

    This mirrors the ``configure_gerrit()`` function from the shell
    script, setting auth to DEVELOPMENT_BECOME_ANY_ACCOUNT mode and
    configuring pull-replication.
    """
    logger.info("Configuring Gerrit for %s…", slug)

    config_file = str(instance_dir / "etc" / "gerrit.config")

    def _gc(*args: str) -> None:
        """Run ``git config -f <config_file> <args…>``."""
        subprocess.run(
            ["git", "config", "-f", config_file, *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

    if api_path:
        logger.info("  URL prefix: %s (mirroring production server)", api_path)
    else:
        logger.info("  URL prefix: (none)")

    # Core settings
    _gc("gerrit.instanceId", slug)
    _gc("gerrit.canonicalWebUrl", canonical_url)
    _gc("httpd.listenUrl", listen_url)
    _gc("sshd.listenAddress", "*:29418")
    _gc("sshd.advertisedAddress", advertised_ssh_addr)

    # Download schemes
    _gc("download.scheme", "ssh")
    _gc("--add", "download.scheme", "http")
    _gc("download.command", "checkout")
    _gc("--add", "download.command", "cherry_pick")
    _gc("--add", "download.command", "pull")

    # Auth — development mode for testing
    _gc("auth.type", "DEVELOPMENT_BECOME_ANY_ACCOUNT")

    # OOTB filter for automatic account creation
    _gc(
        "httpd.filterClass",
        "com.googlesource.gerrit.plugins.ootb.FirstTimeRedirect",
    )
    ootb_redirect_url = f"{api_path}/login/%23%2F?account_id=1000000"
    _gc("httpd.firstTimeRedirectUrl", ootb_redirect_url)

    # Remote plugin admin
    if use_tunnel:
        _gc("plugins.allowRemoteAdmin", "false")
        logger.warning(
            "⚠️  Tunnel mode active with DEVELOPMENT_BECOME_ANY_ACCOUNT auth."
        )
        logger.warning("   Anyone with network access can authenticate as any user.")
        logger.warning("   Remote plugin admin has been disabled to limit exposure.")
    else:
        _gc("plugins.allowRemoteAdmin", "true")

    _gc("container.user", "gerrit")
    _gc("plugin.pull-replication.enabled", "true")

    logger.info("Gerrit configured ✅")
    logger.info("  Mode: non-replica (web UI enabled)")
    logger.info("  Replication: fetchEvery polling")


# =====================================================================
# Project pre-creation
# =====================================================================


def _resolve_project_list(
    instance: InstanceConfig,
    api_path: str,
    config: ActionConfig,
) -> list[str]:
    """Resolve the list of projects to pre-create.

    Handles three cases:
    1. No project filter — fetch all from remote.
    2. ``regex:`` prefix — fetch matching from remote.
    3. Literal name(s) — comma-separated list.
    """
    project = instance.project
    gerrit_host = instance.gerrit_host
    max_projects = instance.max_projects or config.max_projects

    if not project:
        # No filter — fetch everything
        logger.info("  No project filter, fetching full project list…")
        logger.info(
            "  (Max projects: %d — set MAX_PROJECTS env to override)",
            max_projects,
        )
        return fetch_remote_projects(gerrit_host, api_path, "", max_projects, config)

    if project.startswith("regex:"):
        regex_pattern = project[len("regex:") :]
        logger.info("  Project filter explicitly marked as regex: %s", regex_pattern)
        logger.info("  Fetching matching projects from remote…")
        return fetch_remote_projects(
            gerrit_host, api_path, regex_pattern, max_projects, config
        )

    # Literal project name(s) — comma-separated
    return [p.strip() for p in project.split(",") if p.strip()]


def fetch_and_precreate_projects(
    instance_dir: Path,
    instance: InstanceConfig,
    api_path: str,
    config: ActionConfig,
) -> int:
    """Fetch expected projects and pre-create bare git repos.

    Pre-creation is **required** because the ``fetchEvery`` mode only
    polls repositories that already exist in Gerrit's ``projectCache``.
    Without pre-creating the directories the plugin will not know about
    them and will not fetch.

    Returns the expected project count (excluding system repos).
    """
    logger.info("Fetching expected project count from remote…")

    raw_projects = _resolve_project_list(instance, api_path, config)

    # Filter out Gerrit internal/system projects
    filtered = [p for p in raw_projects if p not in ("All-Projects", "All-Users")]

    expected_count = len(filtered)
    logger.info(
        "  Found %d projects on remote server (excluding All-Projects/All-Users)",
        expected_count,
    )

    # Store for later verification by check-services / verify-replication
    count_file = instance_dir / "expected_project_count"
    count_file.write_text(str(expected_count), encoding="utf-8")

    # Pre-create bare repositories
    logger.info("  Pre-creating project directories for replication…")
    created = 0
    git_dir = instance_dir / "git"
    for proj in filtered:
        project_dir = git_dir / f"{proj}.git"
        if not project_dir.exists():
            project_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "init", "--bare", str(project_dir)],
                capture_output=True,
                timeout=30,
                check=False,
            )
            _chown_tree(project_dir)
            created += 1

    logger.info("  Created %d project directories", created)
    return expected_count


# =====================================================================
# SSH host key capture
# =====================================================================


def capture_ssh_host_keys(
    docker: DockerManager,
    cid: str,
    work_dir: Path,
    slug: str,
) -> dict[str, str]:
    """Capture SSH host *public* keys from a running Gerrit container.

    Returns a mapping of key-file-name (without ``.pub``) to key
    content, e.g.::

        {"ssh_host_ed25519_key": "ssh-ed25519 AAAAC3…"}
    """
    logger.info("Capturing SSH host public keys…")

    keys_dir = work_dir / "ssh_host_keys" / slug
    keys_dir.mkdir(parents=True, exist_ok=True)

    # List public key files inside the container
    try:
        pub_files_raw = docker.exec_cmd(
            cid,
            "ls /var/gerrit/etc/ssh_host_*_key.pub 2>/dev/null",
            timeout=15,
            check=False,
        )
    except DockerError:
        pub_files_raw = ""

    result: dict[str, str] = {}
    for pub_key_path in pub_files_raw.strip().split():
        if not pub_key_path:
            continue
        filename = pub_key_path.rsplit("/", 1)[-1]
        try:
            docker.cp(
                f"{cid}:/var/gerrit/etc/{filename}",
                str(keys_dir / filename),
            )
        except DockerError:
            logger.debug("Could not copy %s from container", filename)
            continue

        local_file = keys_dir / filename
        if local_file.exists():
            key_name = filename.replace(".pub", "")
            content = local_file.read_text(encoding="utf-8").strip()
            result[key_name] = content

    logger.info("  SSH host keys captured ✅")
    return result


# =====================================================================
# Instance startup orchestrator
# =====================================================================


def _resolve_tunnel(
    slug: str,
    config: ActionConfig,
) -> tuple[bool, str, int, int]:
    """Determine tunnel configuration for an instance.

    Returns ``(use_tunnel, url_host, url_http_port, url_ssh_port)``.
    The ports returned are the *external* ports to advertise (either
    tunnel ports or the local mapped ports — the caller decides local
    ports separately).
    """
    tunnel_ports = config.tunnel_ports
    tunnel_host = config.tunnel_host

    if tunnel_host and slug in tunnel_ports:
        tc = tunnel_ports[slug]
        logger.info("  External tunnel configured: %s", tunnel_host)
        logger.info("    HTTP port: %d", tc.http_port)
        logger.info("    SSH port: %d", tc.ssh_port)
        return True, tunnel_host, tc.http_port, tc.ssh_port

    if tunnel_host:
        logger.info("  TUNNEL_HOST set but no ports found for slug '%s'", slug)
        logger.info("  Falling back to localhost URLs")

    return False, "localhost", 0, 0  # 0 → caller fills in local ports


def start_instance(
    docker: DockerManager,
    instance: InstanceConfig,
    index: int,
    config: ActionConfig,
    api_path_store: ApiPathStore,
    instance_store: InstanceStore,
    image: str,
) -> bool:
    """Provision and start a single Gerrit container.

    Returns *True* on success, *False* on failure.
    """
    slug = instance.slug
    gerrit_host = instance.gerrit_host
    project = instance.project

    # Per-instance SSH settings
    remote_ssh_user = instance.ssh_user or config.remote_ssh_user
    remote_ssh_port = instance.ssh_port or config.remote_ssh_port

    # Local ports
    http_port = config.base_http_port + index
    ssh_port = config.base_ssh_port + index

    # API path from detection phase
    api_path = api_path_store.get_api_path(slug)
    api_url = api_path_store.get_api_url(slug)

    # Effective API path (only used when USE_API_PATH=true)
    effective_api_path = instance.effective_api_path

    # Tunnel configuration
    use_tunnel, url_host, tunnel_http, tunnel_ssh = _resolve_tunnel(slug, config)
    if use_tunnel:
        url_http_port = tunnel_http
        url_ssh_port = tunnel_ssh
    else:
        url_host = "localhost"
        url_http_port = http_port
        url_ssh_port = ssh_port

    advertised_ssh_addr = f"{url_host}:{url_ssh_port}"

    # Build URLs
    if effective_api_path:
        canonical_url = f"http://{url_host}:{url_http_port}{effective_api_path}/"
        listen_url = f"http://*:8080{effective_api_path}/"
        logger.info("  Using API path: %s (USE_API_PATH=true)", effective_api_path)
    else:
        canonical_url = f"http://{url_host}:{url_http_port}/"
        listen_url = "http://*:8080/"
        if api_path:
            logger.info("  API path detected (%s) but USE_API_PATH is false", api_path)
            logger.info("  Serving at root instead")

    # Write env.sh for downstream steps
    _write_env_sh(
        config.work_path, canonical_url, listen_url, advertised_ssh_addr, use_tunnel
    )

    # Banner
    logger.info("")
    logger.info("========================================")
    logger.info("Instance %d: %s", index + 1, slug)
    logger.info("  Project: %s", project or "(all)")
    logger.info("  Source: %s", gerrit_host)
    logger.info("  Local HTTP Port: %d", http_port)
    logger.info("  Local SSH Port: %d", ssh_port)
    if use_tunnel:
        logger.info("  Tunnel Mode: ENABLED")
        logger.info("  Public URL: %s", canonical_url)
        logger.info("  Public SSH: %s", advertised_ssh_addr)
    else:
        logger.info("  Tunnel Mode: disabled (localhost)")
    logger.info("========================================")

    instance_dir = config.work_path / "instances" / slug

    # Step 1: Init site
    init_gerrit_site(docker, instance_dir, slug, canonical_url, image)

    # Step 2: Configure
    configure_gerrit(
        instance_dir,
        slug,
        canonical_url,
        listen_url,
        api_path,
        advertised_ssh_addr,
        use_tunnel,
    )

    # Step 3: Plugins
    if not download_plugin(
        instance_dir / "plugins", config.plugin_version, config.skip_plugin_install
    ):
        return False
    download_additional_plugins(instance_dir / "plugins", config.additional_plugins)

    # Step 4: SSH auth
    if config.auth_type.lower() == "ssh":
        setup_ssh_auth(
            instance_dir,
            gerrit_host,
            remote_ssh_user,
            remote_ssh_port,
            config.ssh_private_key,
            config.ssh_known_hosts,
        )

    # Step 5: Replication config
    generate_replication_config(
        instance_dir / "etc" / "replication.config",
        slug,
        gerrit_host,
        project,
        remote_ssh_user,
        remote_ssh_port,
        api_path,
        config,
    )
    generate_secure_config(
        instance_dir / "etc" / "secure.config",
        slug,
        config,
    )

    # Step 6: Pre-create projects
    expected_count = fetch_and_precreate_projects(
        instance_dir, instance, api_path, config
    )

    # Step 7: Remove bundled replication plugin (conflicts with pull-replication)
    bundled = instance_dir / "plugins" / "replication.jar"
    if bundled.exists():
        bundled.unlink()

    # Step 8: Start container
    logger.info("Starting Gerrit container…")

    container_name = f"gerrit-{slug}"
    cidfile = str(config.work_path / f"{container_name}.cid")

    # Volume mounts
    volumes: dict[str, str] = {
        str(instance_dir / sub): f"/var/gerrit/{sub}" for sub in _GERRIT_SUBDIRS
    }

    # Add SSH volume (read-only) when using SSH auth
    if config.auth_type.lower() == "ssh":
        volumes[f"{instance_dir / 'ssh'}:ro"] = "/var/gerrit/ssh"

    # Environment variables
    env: dict[str, str] = {
        "CANONICAL_WEB_URL": canonical_url,
        "HTTPD_LISTEN_URL": listen_url,
    }
    if config.debug:
        env["DEBUG"] = "1"

    try:
        cid = docker.run_container(
            image=image,
            name=container_name,
            ports={http_port: 8080, ssh_port: 29418},
            volumes=volumes,
            env=env,
            cidfile=cidfile,
            detach=True,
            timeout=60,
        )
    except DockerError as exc:
        logger.error("Failed to start Gerrit container for %s: %s ❌", slug, exc)
        return False

    # Wait for container process to settle
    time.sleep(2)

    # Get container IP
    try:
        container_ip = docker.container_ip(cid)
    except DockerError:
        container_ip = ""

    # Record container ID
    cid_file = config.work_path / "container_ids.txt"
    with open(cid_file, "a", encoding="utf-8") as fh:
        fh.write(f"{cid}\n")

    # Step 9: Capture SSH host keys
    ssh_host_keys = capture_ssh_host_keys(docker, cid, config.work_path, slug)

    # Step 10: Store instance metadata
    metadata: dict[str, Any] = {
        "cid": cid,
        "ip": container_ip,
        "http_port": http_port,
        "ssh_port": ssh_port,
        "url": f"http://{container_ip}:8080" if container_ip else "",
        "gerrit_host": gerrit_host,
        "project": project,
        "api_path": api_path,
        "api_url": api_url,
        "expected_project_count": expected_count,
        "ssh_host_keys": ssh_host_keys,
    }
    instance_store.set_instance(slug, metadata)
    instance_store.save()

    logger.info("✅ Gerrit instance started")
    logger.info("   Container ID: %s", cid[:12] if cid else "(unknown)")
    logger.info("   IP Address: %s", container_ip or "(unknown)")
    if container_ip:
        logger.info("   HTTP URL: http://%s:8080", container_ip)
    logger.info("   SSH URL: ssh://localhost:%d", ssh_port)
    logger.info("   Source API URL: %s", api_url)
    logger.info("")

    if config.debug:
        try:
            ps_output = docker.ps(filter_name=container_name)
            logger.debug("Container status:\n%s", ps_output)
        except DockerError:
            pass

    return True


# =====================================================================
# Helpers
# =====================================================================


def _chown_tree(path: Path) -> None:
    """Recursively ``chown`` *path* to the Gerrit UID:GID.

    Silently ignores errors (e.g. when running as a non-root user on
    GitHub Actions runners — the Docker entrypoint will handle
    ownership).
    """
    try:
        subprocess.run(
            ["chown", "-R", f"{_GERRIT_UID}:{_GERRIT_GID}", str(path)],
            capture_output=True,
            timeout=30,
            check=False,
        )
        subprocess.run(
            ["chmod", "-R", "755", str(path)],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, OSError):
        pass


def _write_env_sh(
    work_dir: Path,
    canonical_url: str,
    listen_url: str,
    ssh_addr: str,
    use_tunnel: bool,
) -> None:
    """Append environment variables to ``env.sh`` for downstream steps."""
    env_file = work_dir / "env.sh"
    lines = [
        f"GERRIT_CANONICAL_URL={canonical_url}",
        f"GERRIT_LISTEN_URL={listen_url}",
        f"GERRIT_SSH_ADDR={ssh_addr}",
    ]
    if use_tunnel:
        lines.append("GERRIT_TUNNEL_MODE=true")
    with open(env_file, "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(f"{line}\n")


def _write_startup_summary(instance_store: InstanceStore) -> None:
    """Write the step summary table for started instances."""
    lines = [
        "**Instances Started** 🚀",
        "",
        "| Slug | HTTP Port | SSH Port | Status |",
        "|------|-----------|----------|--------|",
    ]
    for slug, meta in instance_store:
        http_port = meta.get("http_port", "?")
        ssh_port = meta.get("ssh_port", "?")
        lines.append(f"| {slug} | {http_port} | {ssh_port} | ✅ Running |")
    lines.append("")
    write_summary("\n".join(lines))


# =====================================================================
# Main orchestrator
# =====================================================================


def run() -> int:
    """Start all Gerrit instances defined in ``$GERRIT_SETUP``.

    Reads configuration from environment variables, validates it,
    provisions each instance (init, config, plugins, replication,
    container start), and writes metadata to ``instances.json``.

    Returns
    -------
    int
        Exit code: 0 on success, 1 if any instance failed, 2 on
        unexpected errors.
    """
    config = ActionConfig.from_environment()
    setup_logging(debug=config.debug)

    logger.info("Starting Gerrit instances…")

    # Validate configuration
    errors = config.validate()
    if errors:
        for err in errors:
            logger.error("Configuration error: %s", err)
        return 1

    work_dir = config.work_path
    work_dir.mkdir(parents=True, exist_ok=True)

    # Initialise tracking files
    cid_file = work_dir / "container_ids.txt"
    cid_file.write_text("", encoding="utf-8")

    instance_store = InstanceStore(config.instances_json_path)
    # Start with empty data (don't try to load — file may not exist yet)
    instance_store._data = {}
    instance_store.save()

    # Load API paths from detection phase
    api_path_store = ApiPathStore(config.api_paths_json_path)
    api_path_store.load()

    # Ensure custom Docker image
    docker = DockerManager()

    with log_group("Docker image"):
        image = ensure_custom_image(docker, config)

    # Start each instance
    failed = 0
    for index, inst in enumerate(config.instances):
        with log_group(f"Instance {index + 1}: {inst.slug}"):
            ok = start_instance(
                docker,
                inst,
                index,
                config,
                api_path_store,
                instance_store,
                image,
            )
            if not ok:
                logger.error("Failed to start instance %d ❌", index)
                failed += 1

    # Summary
    total = len(config.instances)
    logger.info("========================================")
    if failed == 0:
        logger.info("All instances started! ✅")
    else:
        logger.error("%d of %d instances failed to start ❌", failed, total)
    logger.info("Total instances: %d", total)
    logger.info("========================================")
    logger.info("")

    _write_startup_summary(instance_store)

    return 1 if failed > 0 else 0


def main() -> int:
    """Entry point with structured error handling."""
    try:
        return run()
    except GerritActionError as exc:
        logger.error(str(exc))
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
