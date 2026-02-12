#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Add SSH authentication keys to Gerrit container
#
# This script adds SSH public keys to a Gerrit user account using the Python
# Gerrit API client. It leverages the gerrit_api.py library for robust,
# testable user management.
#
# In DEVELOPMENT_BECOME_ANY_ACCOUNT mode, we can "become" any account via HTTP
# and use the REST API to manage accounts, SSH keys, and group memberships.
#
# When SSH_AUTH_USERNAME is provided, a new user account is created.
# Otherwise, keys are added to the default admin account.
#
# Environment variables:
#   SSH_AUTH_KEYS      - SSH public keys (newline-separated, required)
#   SSH_AUTH_USERNAME  - Username to create (optional, defaults to 'admin')
#   WORK_DIR           - Working directory containing instances.json
#   USE_API_PATH       - Whether to use API path prefix (optional)
#   DEBUG              - Enable debug output if "true" (optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if SSH_AUTH_KEYS is provided
if [ -z "${SSH_AUTH_KEYS:-}" ]; then
  echo "No SSH auth keys provided, skipping..."
  exit 0
fi

# Validate SSH_AUTH_USERNAME if provided
# Only allow safe characters to prevent command injection
if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
  if ! [[ "$SSH_AUTH_USERNAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid SSH_AUTH_USERNAME: '$SSH_AUTH_USERNAME'"
    echo "::error::Username must contain only letters, numbers, dots, underscores, and hyphens"
    exit 1
  fi
  if [ ${#SSH_AUTH_USERNAME} -gt 64 ]; then
    echo "::error::SSH_AUTH_USERNAME too long (max 64 characters)"
    exit 1
  fi
fi

echo "Adding SSH authentication keys to Gerrit container(s)..."

# Determine account configuration
USERNAME="${SSH_AUTH_USERNAME:-admin}"
echo "Will create/update Gerrit user: $USERNAME"

# Read instances from the tracking file
INSTANCES_JSON_FILE="${WORK_DIR:-/tmp}/instances.json"

if [ ! -f "$INSTANCES_JSON_FILE" ]; then
  echo "::error::Instances file not found: $INSTANCES_JSON_FILE"
  exit 1
fi

# Check for Python and the gerrit_api module
PYTHON_SCRIPT="$SCRIPT_DIR/setup-gerrit-user.py"
if [ ! -f "$PYTHON_SCRIPT" ]; then
  echo "::error::Python setup script not found: $PYTHON_SCRIPT"
  exit 1
fi

# Determine Python command - prefer python3
if command -v python3 &>/dev/null; then
  PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
  PYTHON_CMD="python"
else
  echo "::error::Python not found. Please install Python 3."
  exit 1
fi

# Check if requests module is available, if not try to use uv
if ! $PYTHON_CMD -c "import requests" 2>/dev/null; then
  if command -v uv &>/dev/null; then
    echo "Using uv to run Python script with requests..."
    PYTHON_CMD="uv run --with requests python3"
  else
    echo "::error::Python 'requests' module not found and 'uv' not available."
    echo "::error::Install requests: pip install requests"
    exit 1
  fi
fi

# Export SSH keys for the Python script
export SSH_AUTH_KEYS
export SSH_AUTH_USERNAME="$USERNAME"

# Build Python script arguments
PYTHON_ARGS=()
if [ "${DEBUG:-false}" = "true" ]; then
  PYTHON_ARGS+=("--debug")
else
  PYTHON_ARGS+=("-v")
fi

# Track success/failure
SUCCESS_COUNT=0
FAILURE_COUNT=0

# Process each Gerrit instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  echo ""
  echo "Processing instance: $slug"
  echo "========================================"

  # Get container ID
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
  if [ -z "$cid" ] || [ "$cid" = "null" ]; then
    echo "::warning::No container ID found for $slug, skipping..."
    continue
  fi

  echo "  Container ID: ${cid:0:12}"

  # Get HTTP port for this instance (from port mapping)
  http_port=$(jq -r ".\"$slug\".http_port // \"8080\"" "$INSTANCES_JSON_FILE")
  echo "  HTTP Port: $http_port"

  # Build root URL (without API path) - login is always at root in
  # DEVELOPMENT_BECOME_ANY_ACCOUNT mode
  ROOT_URL="http://localhost:${http_port}"
  echo "  Root URL: $ROOT_URL"

  # Run the Python setup script
  # The script reads SSH_AUTH_KEYS from environment
  # Note: We pass the root URL (without API path) because the login endpoint
  # in DEVELOPMENT_BECOME_ANY_ACCOUNT mode is always at the root, not under
  # any API path prefix like /r or /gerrit
  if $PYTHON_CMD "$PYTHON_SCRIPT" \
    "${PYTHON_ARGS[@]}" \
    --url "$ROOT_URL" \
    --username "$USERNAME"; then
    echo "  SSH keys configured for $USERNAME ✅"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    echo "::warning::Failed to configure SSH keys for $USERNAME on $slug"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
  fi

done

echo ""
echo "========================================"
if [ $FAILURE_COUNT -eq 0 ]; then
  echo "SSH authentication keys configured ✅"
else
  echo "SSH authentication completed with $FAILURE_COUNT failure(s)"
fi
echo "========================================"
echo ""
echo "Configured $SUCCESS_COUNT instance(s) successfully"
echo "You can now SSH to the Gerrit container(s) as '$USERNAME'"
echo "Example: ssh -p 29418 $USERNAME@<host>"

if [ "$USERNAME" != "admin" ]; then
  echo ""
  echo "User '$USERNAME' has been added to the Administrators group."
  echo "This grants full permissions to create and merge changes."
fi

# Add to step summary if available
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### SSH Access Configured 🔑"
    echo ""
    echo "SSH public keys have been added to the Gerrit container(s)."
    echo ""
    echo "| Instance | Status |"
    echo "|----------|--------|"
    for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
      echo "| $slug | ✅ Configured |"
    done
    echo ""
    echo "**Username:** \`$USERNAME\`"
    if [ "$USERNAME" != "admin" ]; then
      echo ""
      echo "**Permissions:** Administrator (full create/merge access)"
    fi
    echo ""
    echo "**SSH Command:**"
    echo "\`\`\`bash"
    echo "ssh -p 29418 $USERNAME@<gerrit-host>"
    echo "\`\`\`"
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Exit with error if any failures occurred
if [ $FAILURE_COUNT -gt 0 ]; then
  exit 1
fi
