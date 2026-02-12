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

Environment Variables:
    SSH_AUTH_KEYS       - SSH public keys (newline-separated)
    SSH_AUTH_USERNAME   - Username to create (alternative to --username)
    GERRIT_URL          - Gerrit base URL (alternative to --url)
    DEBUG               - Enable debug logging if "true"
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

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
) -> dict:
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

    return client.setup_user_with_ssh_keys(
        username=username,
        ssh_keys=ssh_keys,
        name=name,
        email=email,
        add_to_admins=add_to_admins,
    )


def run_local(
    url: str,
    username: str,
    ssh_keys: list[str],
    name: str | None = None,
    email: str | None = None,
    add_to_admins: bool = True,
) -> dict:
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

    return client.setup_user_with_ssh_keys(
        username=username,
        ssh_keys=ssh_keys,
        name=name,
        email=email,
        add_to_admins=add_to_admins,
    )


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

    # Collect SSH keys
    ssh_keys = []
    for key in args.ssh_keys or []:
        ssh_keys.extend(parse_ssh_keys(key))
    for key_file in args.ssh_key_files or []:
        ssh_keys.extend(read_ssh_keys(key_file=key_file))
    # Also check environment
    ssh_keys.extend(read_ssh_keys())

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
