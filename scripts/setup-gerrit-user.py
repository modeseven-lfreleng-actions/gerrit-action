#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
CLI script for setting up Gerrit users with SSH keys.

This script provides a command-line interface for setting up Gerrit users
in DEVELOPMENT_BECOME_ANY_ACCOUNT mode. It supports:

- Creating user accounts
- Adding SSH keys from files or strings
- Adding users to the Administrators group
- Running against local or containerized Gerrit instances
- Looping over all instances from an instances.json file (replaces
  add-ssh-auth-keys.sh)

Usage:
    # Setup user with SSH key from file
    ./setup-gerrit-user.py --url http://localhost:8080 \\
        --username testuser \\
        --ssh-key-file ~/.ssh/id_ed25519.pub

    # Setup user with SSH key from environment variable
    SSH_AUTH_KEYS="ssh-ed25519 AAAA... user@host" \\
    ./setup-gerrit-user.py --url http://localhost:8080 --username testuser

    # Run inside a container
    ./setup-gerrit-user.py --container gerrit-local-test \\
        --username testuser --ssh-key "ssh-ed25519 AAAA..."

    # Loop over all instances from instances.json (replaces add-ssh-auth-keys.sh)
    SSH_AUTH_KEYS="ssh-ed25519 AAAA... user@host" \\
    ./setup-gerrit-user.py --instances-file /tmp/gerrit-action/instances.json \\
        --loop-instances --username testuser

Environment Variables:
    SSH_AUTH_KEYS       - SSH public keys (newline-separated)
    SSH_AUTH_USERNAME   - Username to create (alternative to --username)
    GERRIT_URL          - Gerrit base URL (alternative to --url)
    WORK_DIR            - Working directory containing instances.json
    USE_API_PATH        - Whether to use API path prefix (optional)
    DEBUG               - Enable debug logging if "true"
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

# Add lib directory to path for local imports
SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

try:
    from gerrit_api import (
        GerritAPIError,
        GerritDevClient,
        parse_ssh_keys,
    )
except ImportError as e:
    print(f"Error: Failed to import gerrit_api module: {e}", file=sys.stderr)
    print("Make sure 'requests' is installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# Configure logging
logger = logging.getLogger(__name__)

# Username validation: only safe characters to prevent command injection
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_USERNAME_MAX_LEN = 64


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging based on verbosity settings."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def read_ssh_keys(
    key_string: str | None = None,
    key_file: str | None = None,
    env_var: str = "SSH_AUTH_KEYS",
) -> list[str]:
    """
    Read SSH keys from various sources.

    Args:
        key_string: SSH key(s) as a string
        key_file: Path to file containing SSH key(s)
        env_var: Environment variable name containing SSH keys

    Returns:
        List of SSH public key strings
    """
    keys = []

    # Read from file
    if key_file:
        try:
            with open(key_file) as f:
                content = f.read()
                keys.extend(parse_ssh_keys(content))
                logger.debug(f"Read {len(keys)} keys from {key_file}")
        except OSError as e:
            logger.warning(f"Failed to read key file {key_file}: {e}")

    # Read from string
    if key_string:
        keys.extend(parse_ssh_keys(key_string))

    # Read from environment
    env_keys = os.environ.get(env_var, "")
    if env_keys:
        keys.extend(parse_ssh_keys(env_keys))
        logger.debug(f"Read keys from ${env_var}")

    return keys


def get_container_gerrit_url(_container: str, port: int = 8080) -> str:
    """
    Get the Gerrit URL for a container.

    For containers, we use localhost with the mapped port.
    The container name is accepted for API consistency but not used
    since we connect via localhost with mapped ports.
    """
    return f"http://localhost:{port}"


def run_in_container(
    container: str,
    url: str,
    username: str,
    ssh_keys: list[str],
    name: str | None = None,
    email: str | None = None,
    add_to_admins: bool = True,
) -> dict[str, Any]:
    """
    Run the user setup directly (container is accessible via localhost).

    Args:
        container: Container name (for logging)
        url: Gerrit URL
        username: Username to create
        ssh_keys: List of SSH public keys
        name: Full name for the account
        email: Email address for the account
        add_to_admins: Whether to add to Administrators group

    Returns:
        Account info dict
    """
    logger.info(f"Setting up user in container: {container}")
    logger.info(f"Gerrit URL: {url}")

    client = GerritDevClient(url)
    admin_id = client.become_admin()
    logger.info(f"Authenticated as admin account {admin_id}")

    result: dict[str, Any] = client.setup_user_with_ssh_keys(
        username=username,
        ssh_keys=ssh_keys,
        name=name,
        email=email,
        add_to_admins=add_to_admins,
    )
    return result


def run_local(
    url: str,
    username: str,
    ssh_keys: list[str],
    name: str | None = None,
    email: str | None = None,
    add_to_admins: bool = True,
) -> dict[str, Any]:
    """
    Run the user setup against a local Gerrit instance.

    Args:
        url: Gerrit URL
        username: Username to create
        ssh_keys: List of SSH public keys
        name: Full name for the account
        email: Email address for the account
        add_to_admins: Whether to add to Administrators group

    Returns:
        Account info dict
    """
    logger.info(f"Setting up user on: {url}")

    client = GerritDevClient(url)
    admin_id = client.become_admin()
    logger.info(f"Authenticated as admin account {admin_id}")

    result: dict[str, Any] = client.setup_user_with_ssh_keys(
        username=username,
        ssh_keys=ssh_keys,
        name=name,
        email=email,
        add_to_admins=add_to_admins,
    )
    return result


def validate_username(username: str) -> str | None:
    """Validate a username, returning an error message or None if valid."""
    if not _USERNAME_RE.match(username):
        return (
            f"Invalid username: '{username}' – "
            "must contain only letters, numbers, dots, underscores, and hyphens"
        )
    if len(username) > _USERNAME_MAX_LEN:
        return f"Username too long (max {_USERNAME_MAX_LEN} characters)"
    return None


def output_github_summary(account: dict, username: str) -> None:
    """Write summary to GitHub Actions step summary if available."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    try:
        with open(summary_file, "a") as f:
            f.write("### Gerrit User Setup ✅\n\n")
            f.write(f"**Username:** `{username}`\n")
            f.write(f"**Account ID:** `{account.get('_account_id', 'unknown')}`\n")
            if account.get("email"):
                f.write(f"**Email:** `{account['email']}`\n")
            f.write("\n**Permissions:** Administrator (full create/merge access)\n")
    except OSError as e:
        logger.warning(f"Failed to write GitHub summary: {e}")


def output_multi_instance_summary(
    username: str,
    rows: list[tuple[str, str]],
    failure_count: int,
) -> None:
    """Write a multi-instance summary to GitHub Actions step summary."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    try:
        with open(summary_file, "a") as f:
            if failure_count == 0:
                f.write("### SSH Access Configured 🔑\n")
            else:
                f.write("### SSH Access Configuration ⚠️\n")
            f.write("\n")
            f.write(
                "SSH public keys have been processed for the Gerrit container(s).\n"
            )
            f.write("\n")
            f.write("| Instance | Status |\n")
            f.write("|----------|--------|\n")
            for slug, status in rows:
                f.write(f"| {slug} | {status} |\n")
            f.write("\n")
            f.write(f"**Username:** `{username}`\n")
            if username != "admin":
                f.write("\n")
                f.write("**Permissions:** Administrator (full create/merge access)\n")
            f.write("\n")
            f.write("**SSH Command:**\n")
            f.write("```bash\n")
            f.write(f"ssh -p 29418 {username}@<gerrit-host>\n")
            f.write("```\n")
    except OSError as e:
        logger.warning(f"Failed to write GitHub summary: {e}")


def load_instances_file(path: str) -> dict[str, Any]:
    """Load instances metadata from a JSON file.

    Returns:
        Dictionary mapping slug to instance metadata.

    Raises:
        SystemExit: If the file does not exist or contains invalid JSON.
    """
    instances_path = Path(path)
    if not instances_path.exists():
        logger.error(f"Instances file not found: {path}")
        sys.exit(1)

    try:
        data = json.loads(instances_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            logger.error(f"Instances file must contain a JSON object: {path}")
            sys.exit(1)
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in instances file {path}: {e}")
        sys.exit(1)


def run_loop_instances(
    instances: dict[str, Any],
    username: str,
    ssh_keys: list[str],
    *,
    name: str | None = None,
    email: str | None = None,
    add_to_admins: bool = True,
    use_api_path: bool = False,
    output_json: bool = False,
) -> int:
    """Run user setup across all instances from instances.json.

    This replaces the main loop from add-ssh-auth-keys.sh.

    Args:
        instances: Mapping of slug to instance metadata dict.
        username: Username to create/update.
        ssh_keys: List of SSH public key strings.
        name: Full name for the account.
        email: Email address for the account.
        add_to_admins: Whether to add to Administrators group.
        use_api_path: Whether to use API path prefix.
        output_json: Whether to output account info as JSON.

    Returns:
        Exit code: 0 if all instances succeeded, 1 if any failed.
    """
    if not ssh_keys:
        logger.info("No SSH auth keys provided, skipping...")
        return 0

    logger.info("Adding SSH authentication keys to Gerrit container(s)...")
    logger.info(f"Will create/update Gerrit user: {username}")

    success_count = 0
    failure_count = 0
    summary_rows: list[tuple[str, str]] = []

    for slug in sorted(instances.keys()):
        instance = instances[slug]
        logger.info("")
        logger.info(f"Processing instance: {slug}")
        logger.info("========================================")

        # Get container ID
        cid = instance.get("cid")
        if not cid or cid == "null":
            logger.warning(f"No container ID found for {slug}, skipping...")
            summary_rows.append((slug, "⚠️ Skipped (no container)"))
            continue

        logger.info(f"  Container ID: {cid[:12]}")

        # Get HTTP port
        http_port = instance.get("http_port", 8080)
        logger.info(f"  HTTP Port: {http_port}")

        # Compute effective API path (must match logic in other scripts)
        api_path = instance.get("api_path", "")
        effective_api_path = ""
        if use_api_path and api_path:
            effective_api_path = api_path

        # Build Gerrit URL
        gerrit_url = f"http://localhost:{http_port}{effective_api_path}"
        logger.info(f"  Gerrit URL: {gerrit_url}")

        # Run the setup
        try:
            account = run_local(
                url=gerrit_url,
                username=username,
                ssh_keys=ssh_keys,
                name=name,
                email=email,
                add_to_admins=add_to_admins,
            )

            if output_json:
                print(json.dumps(account, indent=2))
            else:
                logger.info(f"  SSH keys configured for {username} ✅")

            success_count += 1
            summary_rows.append((slug, "✅ Configured"))

        except GerritAPIError as e:
            logger.warning(
                f"Failed to configure SSH keys for {username} on {slug}: {e}"
            )
            failure_count += 1
            summary_rows.append((slug, "❌ Failed"))

        except Exception as e:
            logger.warning(
                f"Unexpected error configuring SSH keys for {username} on {slug}: {e}"
            )
            failure_count += 1
            summary_rows.append((slug, "❌ Failed"))

    # Final summary
    logger.info("")
    logger.info("========================================")
    if failure_count == 0:
        logger.info("SSH authentication keys configured ✅")
    else:
        logger.info(f"SSH authentication completed with {failure_count} failure(s)")
    logger.info("========================================")
    logger.info("")
    logger.info(f"Configured {success_count} instance(s) successfully")
    logger.info(f"You can now SSH to the Gerrit container(s) as '{username}'")
    logger.info(f"Example: ssh -p 29418 {username}@<host>")

    if username != "admin":
        logger.info("")
        logger.info(f"User '{username}' has been added to the Administrators group.")
        logger.info("This grants full permissions to create and merge changes.")

    # Write multi-instance GitHub summary
    output_multi_instance_summary(username, summary_rows, failure_count)

    return 1 if failure_count > 0 else 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Set up Gerrit users with SSH keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Connection options
    conn_group = parser.add_argument_group("Connection")
    conn_group.add_argument(
        "--url",
        default=os.environ.get("GERRIT_URL", "http://localhost:8080"),
        help="Gerrit base URL (default: $GERRIT_URL or http://localhost:8080)",
    )
    conn_group.add_argument(
        "--container",
        help="Docker container name (uses container's mapped port)",
    )
    conn_group.add_argument(
        "--port",
        type=int,
        default=8080,
        help="HTTP port for container (default: 8080)",
    )

    # Multi-instance mode (replaces add-ssh-auth-keys.sh)
    multi_group = parser.add_argument_group("Multi-instance mode")
    multi_group.add_argument(
        "--instances-file",
        help=(
            "Path to instances.json file. When combined with "
            "--loop-instances, iterates over all instances and "
            "configures SSH keys for each one."
        ),
    )
    multi_group.add_argument(
        "--loop-instances",
        action="store_true",
        help=(
            "Loop over all instances in the instances file "
            "(requires --instances-file). Replaces add-ssh-auth-keys.sh."
        ),
    )
    multi_group.add_argument(
        "--use-api-path",
        action="store_true",
        default=os.environ.get("USE_API_PATH", "false").lower() == "true",
        help=(
            "Use the api_path from instance metadata when building "
            "Gerrit URLs (default: $USE_API_PATH or false)"
        ),
    )

    # User options
    user_group = parser.add_argument_group("User")
    user_group.add_argument(
        "--username",
        "-u",
        default=os.environ.get("SSH_AUTH_USERNAME", "admin"),
        help="Username to create/update (default: $SSH_AUTH_USERNAME or 'admin')",
    )
    user_group.add_argument(
        "--name",
        "-n",
        help="Full name for the account (default: same as username)",
    )
    user_group.add_argument(
        "--email",
        "-e",
        help="Email address (default: username@example.com)",
    )
    user_group.add_argument(
        "--no-admin",
        action="store_true",
        help="Don't add user to Administrators group",
    )

    # SSH key options
    ssh_group = parser.add_argument_group("SSH Keys")
    ssh_group.add_argument(
        "--ssh-key",
        "-k",
        action="append",
        dest="ssh_keys",
        help="SSH public key (can be specified multiple times)",
    )
    ssh_group.add_argument(
        "--ssh-key-file",
        "-f",
        action="append",
        dest="ssh_key_files",
        help="File containing SSH public key(s) (can be specified multiple times)",
    )

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output account info as JSON",
    )

    args = parser.parse_args()

    # Check for DEBUG environment variable
    if os.environ.get("DEBUG", "").lower() == "true":
        args.debug = True

    setup_logging(verbose=args.verbose, debug=args.debug)

    # Validate username
    username_error = validate_username(args.username)
    if username_error:
        logger.error(username_error)
        print(f"::error::{username_error}", file=sys.stderr)
        return 1

    # Collect SSH keys
    ssh_keys = []
    for key in args.ssh_keys or []:
        ssh_keys.extend(parse_ssh_keys(key))
    for key_file in args.ssh_key_files or []:
        ssh_keys.extend(read_ssh_keys(key_file=key_file))
    # Also check environment
    ssh_keys.extend(read_ssh_keys())

    # -------------------------------------------------------------------
    # Multi-instance mode (replaces add-ssh-auth-keys.sh)
    # -------------------------------------------------------------------
    if args.loop_instances:
        # Determine the instances file path
        instances_file = args.instances_file
        if not instances_file:
            # Fall back to $WORK_DIR/instances.json
            work_dir = os.environ.get("WORK_DIR", "/tmp")
            instances_file = os.path.join(work_dir, "instances.json")

        if not ssh_keys:
            logger.info("No SSH auth keys provided, skipping...")
            return 0

        instances = load_instances_file(instances_file)
        return run_loop_instances(
            instances,
            args.username,
            ssh_keys,
            name=args.name,
            email=args.email,
            add_to_admins=not args.no_admin,
            use_api_path=args.use_api_path,
            output_json=args.json,
        )

    # -------------------------------------------------------------------
    # Single-instance mode (original behaviour)
    # -------------------------------------------------------------------
    if not ssh_keys:
        logger.warning("No SSH keys provided")

    logger.info(f"Setting up user: {args.username}")
    logger.info(f"SSH keys to add: {len(ssh_keys)}")

    try:
        if args.container:
            url = get_container_gerrit_url(args.container, args.port)
            account = run_in_container(
                container=args.container,
                url=url,
                username=args.username,
                ssh_keys=ssh_keys,
                name=args.name,
                email=args.email,
                add_to_admins=not args.no_admin,
            )
        else:
            account = run_local(
                url=args.url,
                username=args.username,
                ssh_keys=ssh_keys,
                name=args.name,
                email=args.email,
                add_to_admins=not args.no_admin,
            )

        # Output result
        if args.json:
            print(json.dumps(account, indent=2))
        else:
            print(f"✅ User '{args.username}' configured successfully")
            print(f"   Account ID: {account.get('_account_id', 'unknown')}")
            if account.get("email"):
                print(f"   Email: {account['email']}")
            if ssh_keys:
                print(f"   SSH keys: {len(ssh_keys)} added")

        # Write GitHub summary
        output_github_summary(account, args.username)

        return 0

    except GerritAPIError as e:
        logger.error(f"Gerrit API error: {e}")
        if e.response_text:
            logger.debug(f"Response: {e.response_text}")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
