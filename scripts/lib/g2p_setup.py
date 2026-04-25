# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""G2P setup: generate config files and configure containers.

This module provides functions that translate a :class:`G2PConfig` into
the files and symlinks required inside a running Gerrit container for
``gerrit_to_platform`` to operate:

- ``gerrit_to_platform.ini`` — app config with token and mappings
- ``replication.config`` symlink — platform detection data
- Gerrit hook symlinks — connect events to g2p console scripts
- SSH configuration — keypair and ``known_hosts`` for github.com

Usage::

    from g2p_config import G2PConfig
    from g2p_setup import setup_g2p

    config = G2PConfig.from_environment()
    result = setup_g2p(config, docker, container_id)
"""

from __future__ import annotations

import configparser
import logging
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from docker_manager import DockerManager
from errors import G2PSetupError
from g2p_config import G2PConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Container paths
# ---------------------------------------------------------------------------

GERRIT_HOME = "/var/gerrit"
"""Gerrit base directory inside the container."""

GERRIT_USER_HOME = "/var/gerrit"
"""Home directory of the ``gerrit`` user inside the container."""

GERRIT_HOOKS_DIR = f"{GERRIT_HOME}/hooks"
"""Directory where Gerrit looks for hook scripts."""

GERRIT_PLUGINS_DIR = f"{GERRIT_HOME}/plugins"
"""Directory where Gerrit loads plugin JARs from at startup."""

GERRIT_ETC_DIR = f"{GERRIT_HOME}/etc"
"""Gerrit configuration directory."""

GERRIT_REPLICATION_CONFIG = f"{GERRIT_ETC_DIR}/replication.config"
"""Path to the Gerrit replication config inside the container."""

G2P_CONFIG_DIR = f"{GERRIT_USER_HOME}/.config/gerrit_to_platform"
"""XDG-style config directory for gerrit_to_platform."""

G2P_INI_PATH = f"{G2P_CONFIG_DIR}/gerrit_to_platform.ini"
"""Path to the g2p INI config inside the container."""

G2P_REPLICATION_SYMLINK = f"{G2P_CONFIG_DIR}/replication.config"
"""Symlink inside the g2p config dir pointing to the Gerrit repl config."""

GERRIT_TOOLS_VENV_BIN = "/opt/gerrit-tools/bin"
"""Path to the g2p console-script binaries inside the container."""

SSH_DIR = f"{GERRIT_USER_HOME}/.ssh"
"""SSH directory inside the container."""

# Well-known GitHub Ed25519 host key (fallback).
GITHUB_HOST_KEY_ED25519 = (
    "github.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class G2PSetupResult:
    """Captures the outcome of a G2P setup run for a single container.

    Attributes:
        config_path: Path to the generated INI inside the container.
        hooks_enabled: Hook names that received symlinks.
        ssh_public_key: Public key (for downstream deploy-key setup).
        ssh_private_key: SSH private key (for org-level secret provisioning).
        replication_remote_configured: Whether the g2p detection
            remote is present in ``replication.config`` (either
            already existing or newly appended).
    """

    config_path: str = ""
    hooks_enabled: list[str] = field(default_factory=list)
    ssh_public_key: str = ""
    ssh_private_key: str = ""
    replication_remote_configured: bool = False


# ---------------------------------------------------------------------------
# INI generation
# ---------------------------------------------------------------------------


def generate_g2p_ini(config: G2PConfig) -> str:
    """Produce the ``gerrit_to_platform.ini`` file content.

    Parameters
    ----------
    config:
        A validated :class:`G2PConfig` instance.

    Returns
    -------
    str
        INI-formatted string ready to write to disk.
    """
    cp = configparser.ConfigParser()
    # Preserve key case (comment keywords are case-sensitive).
    cp.optionxform = str  # type: ignore[assignment]

    # -- comment-added keyword mappings ----------------------------------
    section = 'mapping "comment-added"'
    cp.add_section(section)
    for keyword, workflow_filter in config.comment_mappings.items():
        cp.set(section, keyword, workflow_filter)

    # -- GitHub token ----------------------------------------------------
    if config.github_token:
        cp.add_section("github.com")
        cp.set("github.com", "token", config.github_token)

    buf = StringIO()
    cp.write(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Replication remote section for g2p platform detection
# ---------------------------------------------------------------------------


def generate_g2p_replication_section(config: G2PConfig) -> str:
    """Generate the replication config section for g2p platform detection.

    This section does **not** replicate data.  It exists solely so that
    ``gerrit_to_platform`` can detect the GitHub platform, owner, and
    repository naming convention by reading the replication config.

    Parameters
    ----------
    config:
        A validated :class:`G2PConfig` instance.

    Returns
    -------
    str
        INI-style config lines to append to ``replication.config``.
    """
    url = config.effective_remote_url
    if not url:
        return ""

    lines = [
        "",
        "# G2P platform detection remote (not for replication)",
        "# Auto-generated by gerrit-action",
        '[remote "github-g2p"]',
        f"  url = {url}",
        f"  authGroup = {config.remote_auth_group}",
        f"  remoteNameStyle = {config.remote_name_style}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SSH key generation
# ---------------------------------------------------------------------------


def generate_ssh_keypair() -> tuple[str, str]:
    """Generate an Ed25519 SSH keypair for g2p.

    The keypair is created in a temporary directory and both files are
    read into memory before the directory is cleaned up.

    Returns
    -------
    tuple[str, str]
        ``(private_key, public_key)`` as strings.

    Raises
    ------
    G2PSetupError
        If ``ssh-keygen`` fails.
    """
    with tempfile.TemporaryDirectory(prefix="g2p_ssh_") as tmpdir:
        key_path = os.path.join(tmpdir, "g2p_key")
        try:
            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "ed25519",
                    "-f",
                    key_path,
                    "-N",
                    "",
                    "-C",
                    "gerrit-action-g2p",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            raise G2PSetupError(f"ssh-keygen failed: {exc.stderr.strip()}") from exc
        except subprocess.TimeoutExpired as exc:
            raise G2PSetupError("ssh-keygen timed out after 30 seconds") from exc
        except FileNotFoundError as exc:
            raise G2PSetupError("ssh-keygen not found on PATH") from exc

        private_key = Path(key_path).read_text(encoding="utf-8")
        public_key = Path(f"{key_path}.pub").read_text(encoding="utf-8")

    return private_key.strip(), public_key.strip()


def fetch_github_host_keys() -> str:
    """Fetch GitHub SSH host keys via ``ssh-keyscan``.

    Falls back to the well-known Ed25519 key if the scan fails.

    Returns
    -------
    str
        One or more ``known_hosts``-formatted lines.
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-t", "ed25519,rsa", "github.com"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    logger.warning("ssh-keyscan failed; using well-known GitHub Ed25519 host key")
    return GITHUB_HOST_KEY_ED25519


# ---------------------------------------------------------------------------
# Container configuration helpers
# ---------------------------------------------------------------------------


def _write_file_in_container(
    docker: DockerManager,
    cid: str,
    path: str,
    content: str,
    *,
    mode: str = "0600",
    owner: str = "gerrit:gerrit",
) -> None:
    """Write a file inside a running container.

    Uses ``docker cp`` with a local temp file followed by
    ``docker exec chown/chmod`` to set ownership and permissions.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    path:
        Absolute path inside the container.
    content:
        File content to write.
    mode:
        Octal permission string (e.g. ``"0600"``).
    owner:
        ``user:group`` string for ``chown``.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Ensure parent directory exists (as root — gerrit user may
        # lack permission to create arbitrary parent directories).
        parent = str(Path(path).parent)
        docker.exec_cmd(
            cid,
            f"mkdir -p {parent}",
            check=True,
            user="0",
        )

        # docker cp creates files owned by root regardless of the
        # container's USER directive, so chmod/chown must also run
        # as root to modify the newly copied file.
        docker.cp(tmp_path, f"{cid}:{path}")
        docker.exec_cmd(cid, f"chmod {mode} {path}", user="0")
        docker.exec_cmd(cid, f"chown {owner} {path}", user="0")
    finally:
        os.unlink(tmp_path)


def _append_file_in_container(
    docker: DockerManager,
    cid: str,
    path: str,
    content: str,
) -> None:
    """Append content to an existing file inside a container.

    Creates a local temporary file, copies it into the container with
    ``docker cp``, then appends it to *path* using
    ``cat >> … && rm -f`` inside the container.  The temporary files
    (local and in-container) are removed after the operation.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    path:
        Absolute path to the file inside the container.
    content:
        Content to append.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Copy to a temp location in the container, then append.
        # docker cp creates the temp file owned by root (0600), so
        # the cat/rm must run as root to read and clean it up.
        container_tmp = f"/tmp/g2p_append_{uuid.uuid4().hex}.tmp"
        docker.cp(tmp_path, f"{cid}:{container_tmp}")
        docker.exec_cmd(
            cid,
            f"cat {container_tmp} >> {path} && rm -f {container_tmp}",
            user="0",
        )
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Setup steps
# ---------------------------------------------------------------------------


def setup_g2p_config_dir(
    docker: DockerManager,
    cid: str,
) -> None:
    """Create the g2p config directory inside the container.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    """
    docker.exec_cmd(cid, f"mkdir -p {G2P_CONFIG_DIR}", user="0")
    docker.exec_cmd(cid, f"chown -R gerrit:gerrit {G2P_CONFIG_DIR}", user="0")
    logger.debug("Created g2p config directory: %s", G2P_CONFIG_DIR)


def setup_g2p_ini(
    docker: DockerManager,
    cid: str,
    config: G2PConfig,
) -> str:
    """Generate and deploy ``gerrit_to_platform.ini`` inside a container.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    config:
        Validated :class:`G2PConfig`.

    Returns
    -------
    str
        The container path where the INI was written.
    """
    ini_content = generate_g2p_ini(config)

    _write_file_in_container(
        docker,
        cid,
        G2P_INI_PATH,
        ini_content,
        mode="0600",
        owner="gerrit:gerrit",
    )

    logger.info("Wrote g2p config: %s", G2P_INI_PATH)
    return G2P_INI_PATH


def setup_g2p_replication_symlink(
    docker: DockerManager,
    cid: str,
) -> None:
    """Create the replication.config symlink in the g2p config dir.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    """
    docker.exec_cmd(
        cid,
        f"ln -sf {GERRIT_REPLICATION_CONFIG} {G2P_REPLICATION_SYMLINK}",
        user="0",
    )
    docker.exec_cmd(
        cid,
        f"chown -h gerrit:gerrit {G2P_REPLICATION_SYMLINK}",
        user="0",
    )
    logger.info(
        "Symlinked %s -> %s",
        G2P_REPLICATION_SYMLINK,
        GERRIT_REPLICATION_CONFIG,
    )


def setup_g2p_replication_remote(
    docker: DockerManager,
    cid: str,
    config: G2PConfig,
) -> bool:
    """Ensure the g2p platform detection remote is in replication.config.

    Appends the section when absent; leaves it untouched when already
    present.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    config:
        Validated :class:`G2PConfig`.

    Returns
    -------
    bool
        *True* if the remote is configured (already present or newly
        appended), *False* if skipped (e.g. no effective URL).
    """
    section = generate_g2p_replication_section(config)
    if not section:
        logger.warning("No g2p replication section generated (no effective remote URL)")
        return False

    # Check the section doesn't already exist
    existing = docker.exec_cmd(
        cid,
        f"grep -q '^\\[remote \"github-g2p\"\\]' {GERRIT_REPLICATION_CONFIG} 2>/dev/null && echo found || echo missing",
        check=False,
    )
    if existing.strip() == "found":
        logger.info(
            "G2P detection remote already present in %s",
            GERRIT_REPLICATION_CONFIG,
        )
        return True

    _append_file_in_container(docker, cid, GERRIT_REPLICATION_CONFIG, section)
    logger.info(
        "Appended g2p platform detection remote to %s",
        GERRIT_REPLICATION_CONFIG,
    )
    return True


def setup_g2p_hooks(
    docker: DockerManager,
    cid: str,
    config: G2PConfig,
) -> list[str]:
    """Create Gerrit hook symlinks for each enabled g2p hook.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    config:
        Validated :class:`G2PConfig`.

    Returns
    -------
    list[str]
        Hook names that were successfully symlinked.
    """
    enabled: list[str] = []

    # Ensure the hooks directory exists
    docker.exec_cmd(cid, f"mkdir -p {GERRIT_HOOKS_DIR}", user="0")

    # Verify the Gerrit ``hooks`` plugin is installed.  Without it
    # Gerrit never invokes the scripts in /var/gerrit/hooks/, which
    # would silently break G2P.  ``gerrit init --install-all-plugins``
    # is responsible for placing hooks.jar; if it is missing here,
    # the hook symlinks we create below will be inert.
    if not docker.exec_test(cid, f"-f {GERRIT_PLUGINS_DIR}/hooks.jar"):
        logger.warning(
            "Gerrit 'hooks' plugin (hooks.jar) is missing from %s — "
            "G2P hook scripts will not run.  Ensure the site is "
            "initialised with 'gerrit init --install-all-plugins'.",
            GERRIT_PLUGINS_DIR,
        )

    for hook_name in config.hooks:
        target_bin = f"{GERRIT_TOOLS_VENV_BIN}/{hook_name}"
        hook_path = f"{GERRIT_HOOKS_DIR}/{hook_name}"

        # Verify the target binary exists
        if not docker.exec_test(cid, f"-f {target_bin}"):
            logger.warning(
                "G2P console script not found: %s — skipping hook %s",
                target_bin,
                hook_name,
            )
            continue

        docker.exec_cmd(
            cid,
            f"ln -sf {target_bin} {hook_path}",
            user="0",
        )
        docker.exec_cmd(
            cid,
            f"chown -h gerrit:gerrit {hook_path}",
            user="0",
        )
        enabled.append(hook_name)
        logger.info("Hook symlink: %s -> %s", hook_path, target_bin)

    return enabled


def setup_g2p_ssh(
    docker: DockerManager,
    cid: str,
    config: G2PConfig,
) -> tuple[str, str]:
    """Configure SSH for github.com inside the container.

    Handles:

    1. SSH private key — uses provided key or generates a new Ed25519
       keypair.
    2. ``known_hosts`` — appends github.com host keys (provided or
       scanned).
    3. SSH client config — adds a ``Host github.com`` block with
       ``User git``.

    Parameters
    ----------
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.
    config:
        Validated :class:`G2PConfig`.

    Returns
    -------
    tuple[str, str]
        ``(public_key, private_key)`` — the SSH public key (for
        deploy-key setup) and private key (for org-level secret
        provisioning).  Either may be an empty string if no key
        was configured.
    """
    public_key = ""
    private_key = ""
    key_deployed = False

    # Ensure .ssh directory exists with correct permissions
    docker.exec_cmd(cid, f"mkdir -p {SSH_DIR}", user="0")
    docker.exec_cmd(cid, f"chmod 700 {SSH_DIR}", user="0")
    docker.exec_cmd(cid, f"chown gerrit:gerrit {SSH_DIR}", user="0")

    # -- Private key -----------------------------------------------------
    key_path = f"{SSH_DIR}/g2p_github_key"
    if config.ssh_private_key:
        private_key = config.ssh_private_key
        _write_file_in_container(
            docker,
            cid,
            key_path,
            private_key + "\n",
            mode="0600",
            owner="gerrit:gerrit",
        )
        key_deployed = True
        logger.info("Deployed provided SSH private key to %s", key_path)

        # Try to derive public key from the private key
        try:
            result = subprocess.run(
                ["ssh-keygen", "-y", "-f", "/dev/stdin"],
                input=private_key,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                public_key = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.debug("Could not derive public key from private key")
    else:
        # Generate a new keypair
        logger.info("No SSH key provided; generating Ed25519 keypair")
        try:
            private_key, public_key = generate_ssh_keypair()
            _write_file_in_container(
                docker,
                cid,
                key_path,
                private_key + "\n",
                mode="0600",
                owner="gerrit:gerrit",
            )
            key_deployed = True
            logger.info("Generated and deployed SSH keypair to %s", key_path)
        except G2PSetupError as exc:
            logger.warning("SSH keypair generation failed: %s", exc)

    # -- Known hosts -----------------------------------------------------
    known_hosts_path = f"{SSH_DIR}/known_hosts"

    # Check if github.com is already in known_hosts
    existing = docker.exec_cmd(
        cid,
        f"grep -q 'github.com' {known_hosts_path} 2>/dev/null && echo found || echo missing",
        check=False,
    )
    if existing.strip() != "found":
        host_keys = config.github_known_hosts or fetch_github_host_keys()
        _append_file_in_container(
            docker,
            cid,
            known_hosts_path,
            host_keys + "\n",
        )
        docker.exec_cmd(cid, f"chmod 644 {known_hosts_path}", user="0")
        docker.exec_cmd(cid, f"chown gerrit:gerrit {known_hosts_path}", user="0")
        logger.info("Added github.com to %s", known_hosts_path)
    else:
        logger.info("github.com already in %s", known_hosts_path)

    # -- SSH client config -----------------------------------------------
    if key_deployed:
        ssh_config_path = f"{SSH_DIR}/config"
        ssh_config_block = (
            "\n"
            "# G2P: GitHub SSH configuration\n"
            "Host github.com\n"
            "  User git\n"
            f"  IdentityFile {key_path}\n"
            "  IdentitiesOnly yes\n"
            "  StrictHostKeyChecking yes\n"
        )

        # Check if there's already a github.com Host block
        existing_config = docker.exec_cmd(
            cid,
            f"grep -q 'Host github.com' {ssh_config_path} 2>/dev/null && echo found || echo missing",
            check=False,
        )
        if existing_config.strip() != "found":
            _append_file_in_container(
                docker,
                cid,
                ssh_config_path,
                ssh_config_block,
            )
            docker.exec_cmd(cid, f"chmod 644 {ssh_config_path}", user="0")
            docker.exec_cmd(cid, f"chown gerrit:gerrit {ssh_config_path}", user="0")
            logger.info("Added github.com SSH config to %s", ssh_config_path)
        else:
            logger.info("github.com SSH config already present in %s", ssh_config_path)
    else:
        logger.info("No SSH key deployed; skipping SSH client config")

    return public_key, private_key


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def setup_g2p(
    config: G2PConfig,
    docker: DockerManager,
    cid: str,
) -> G2PSetupResult:
    """Run the full G2P setup sequence for a single container.

    This is the main entry point called by the ``configure-g2p.py``
    script for each running Gerrit instance.

    Steps:

    1. Create the g2p config directory
    2. Generate and deploy ``gerrit_to_platform.ini``
    3. Append the g2p detection remote to ``replication.config``
    4. Symlink ``replication.config`` into the g2p config dir
    5. Create Gerrit hook symlinks
    6. Configure SSH for github.com

    Parameters
    ----------
    config:
        Validated :class:`G2PConfig`.
    docker:
        :class:`DockerManager` instance.
    cid:
        Container ID or name.

    Returns
    -------
    G2PSetupResult
        Summary of the setup operations performed.

    Raises
    ------
    G2PSetupError
        If a critical setup step fails.
    """
    result = G2PSetupResult()

    try:
        # Step 1: Config directory
        setup_g2p_config_dir(docker, cid)

        # Step 2: INI config
        result.config_path = setup_g2p_ini(docker, cid, config)

        # Step 3: Replication remote
        result.replication_remote_configured = setup_g2p_replication_remote(
            docker,
            cid,
            config,
        )

        # Step 4: Replication config symlink
        setup_g2p_replication_symlink(docker, cid)

        # Step 5: Hook symlinks
        result.hooks_enabled = setup_g2p_hooks(docker, cid, config)

        # Step 6: SSH
        result.ssh_public_key, result.ssh_private_key = setup_g2p_ssh(
            docker,
            cid,
            config,
        )

    except G2PSetupError:
        raise
    except Exception as exc:
        raise G2PSetupError(f"G2P setup failed for container {cid}: {exc}") from exc

    logger.info(
        "G2P setup complete for container %s: config=%s, hooks=%s, ssh_key=%s",
        cid,
        result.config_path,
        result.hooks_enabled,
        "provided" if result.ssh_public_key else "none",
    )
    return result
