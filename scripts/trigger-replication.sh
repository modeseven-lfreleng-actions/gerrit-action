#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Trigger Gerrit replication
# This script initiates pull-replication for all configured instances

set -euo pipefail

echo "Triggering initial replication..."
echo ""

# Function to check plugin status via container logs
check_plugin_in_logs() {
  local cid="$1"
  local plugin_name="$2"

  if docker logs "$cid" 2>&1 | grep -q "Loaded plugin $plugin_name"; then
    return 0
  fi
  return 1
}

# Read instances metadata
if [ ! -f "$WORK_DIR/instances.json" ]; then
  echo "::error::No instances metadata found ❌"
  exit 1
fi

INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
REPLICATION_FAILED=0

# Trigger replication for each instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  echo "========================================"
  echo "Triggering replication: $slug"
  echo "========================================"

  # Get instance details
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
  gerrit_host=$(jq -r ".\"$slug\".gerrit_host" "$INSTANCES_JSON_FILE")
  project=$(jq -r ".\"$slug\".project // \"\"" "$INSTANCES_JSON_FILE")

  echo "Container ID: $cid"
  echo "Source: $gerrit_host"
  if [ -n "$project" ]; then
    echo "Project filter: $project"
  fi
  echo ""

  # Check if replication.config exists
  if ! docker exec "$cid" test -f /var/gerrit/etc/replication.config; then
    echo "::warning::replication.config not found"
    echo "::warning::skipping replication trigger"
    REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
    continue
  fi

  # Check if pull-replication plugin is loaded via container logs
  if [ "$SKIP_PLUGIN_INSTALL" != "true" ]; then
    echo "Verifying pull-replication plugin is loaded..."

    if check_plugin_in_logs "$cid" "pull-replication"; then
      echo "Pull-replication plugin is active ✅"

      # Show the plugin version from logs
      PLUGIN_VERSION_LOG=$(docker logs "$cid" 2>&1 | \
        grep "Loaded plugin pull-replication" | tail -1 || echo "")
      if [ -n "$PLUGIN_VERSION_LOG" ]; then
        echo "  $PLUGIN_VERSION_LOG"
      fi
    else
      echo "::warning::Pull-replication plugin not detected in logs"

      # Fallback: check if plugin file exists
      if docker exec "$cid" test -f \
        /var/gerrit/plugins/pull-replication.jar; then
        echo "  Plugin file exists, may still be loading..."
      else
        echo "::warning::Plugin file not found in container"
        REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
      fi
    fi
    echo ""
  fi

  # Show replication configuration for debugging
  echo "Replication configuration:"
  if docker exec "$cid" test -f /var/gerrit/etc/replication.config; then
    echo "--- replication.config ---"
    docker exec "$cid" cat /var/gerrit/etc/replication.config 2>/dev/null | \
      grep -v "^#" | grep -v "^$" || true
    echo "---"
  else
    echo "::warning::replication.config not found"
  fi
  echo ""

  # Trigger replication via SSH (if available)
  if [ "$AUTH_TYPE" = "ssh" ]; then
    echo "Attempting to trigger replication via SSH..."

    # Try SSH-based replication trigger
    SSH_RESULT=$(docker exec "$cid" sh -c \
      "ssh -p 29418 -o StrictHostKeyChecking=no admin@localhost \
       gerrit pull-replication start --wait --all 2>&1" \
       || echo "ssh_failed")

    if echo "$SSH_RESULT" | \
      grep -q "ssh_failed\|Connection refused\|Permission denied"; then
      echo "::warning::SSH trigger not available"
      echo "::warning::(expected for new installations)"
      echo "Replication will occur based on configured schedule"
    else
      echo "SSH trigger response:"
      echo "$SSH_RESULT"
      echo "✅ Replication triggered via SSH"
    fi
  fi

  # Alternative: Check replication via filesystem/logs
  echo ""
  echo "Monitoring replication activity..."

  # Give replication a moment to start
  sleep 5

  # Check replication logs
  REPL_LOGS=$(docker logs "$cid" 2>&1 | \
    grep -i "pull-replication\|replication" | tail -20 || echo "")

  if [ -n "$REPL_LOGS" ]; then
    echo "Recent replication activity:"
    echo "$REPL_LOGS"
    echo ""
  else
    echo "No replication activity detected yet"
    echo "This is normal if replicateOnStartup is false"
    echo "or if no projects match"
    echo ""
  fi

  # Check if any repositories were created
  REPO_COUNT=$(docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | wc -l" \
    || echo "0")

  echo "Repositories in git directory: $REPO_COUNT"

  if [ "$REPO_COUNT" -gt 2 ]; then
    # More than All-Projects and All-Users
    echo "✅ Replication appears to be working (repositories detected)"

    # List some repositories
    echo ""
    echo "Sample repositories:"
    docker exec "$cid" sh -c \
      "find /var/gerrit/git -maxdepth 2 -name '*.git' -type d \
      2>/dev/null | head -5" || true
  elif [ "$SYNC_ON_STARTUP" = "true" ]; then
    echo "::warning::No replicated repositories detected yet"
    echo "Replication may still be in progress or"
    echo "configured projects may not exist on source"
    REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
  fi

  echo ""
  echo "Replication trigger completed for $slug"
  echo ""
done

# Summary
echo "========================================"
if [ $REPLICATION_FAILED -eq 0 ]; then
  echo "Replication triggered for all instances ✅"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Replication Status** 🔄"
    echo ""
    echo "Replication has been triggered for all instances."
    echo ""
    echo "_Note: Initial replication may take several minutes"
    echo "depending on repository sizes._"
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
else
  echo "Some replication triggers failed ⚠️"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Replication Trigger Status** ⚠️"
    echo ""
    echo "Some replication triggers encountered issues."
    echo "Check logs for details."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Always add monitoring instructions to step summary
{
  echo "To monitor ongoing replication, check container logs:"
  echo '```bash'
} >> "$GITHUB_STEP_SUMMARY"

for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
  echo "docker logs -f $cid | grep replication" >> "$GITHUB_STEP_SUMMARY"
done

{
  echo '```'
  echo ""
} >> "$GITHUB_STEP_SUMMARY"

# Note: Actual failure decision is delegated to verify-replication.sh
# which runs after this script when require_replication_success is true.
# This script only triggers replication; verification is separate.
