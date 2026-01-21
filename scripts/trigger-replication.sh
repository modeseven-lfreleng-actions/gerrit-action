#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Trigger Gerrit replication
# This script initiates pull-replication for all configured instances

set -euo pipefail

echo "Triggering initial replication..."
echo ""

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

  # Check if pull-replication plugin is loaded
  if [ "$SKIP_PLUGIN_INSTALL" != "true" ]; then
    echo "Verifying pull-replication plugin is loaded..."

    PLUGIN_STATUS=$(docker exec "$cid" sh -c \
      "gerrit plugin ls 2>/dev/null || echo 'command_not_found'" \
      || echo "error")

    if echo "$PLUGIN_STATUS" | grep -q "pull-replication"; then
      echo "Pull-replication plugin is active ✅"
    elif echo "$PLUGIN_STATUS" | grep -q "command_not_found"; then
      echo "::warning::Cannot verify plugin status"
      echo "::warning::(gerrit command not available)"
    else
      echo "::warning::Pull-replication plugin not detected"
      echo "Plugin status output:"
      echo "$PLUGIN_STATUS"
      REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
    fi
    echo ""
  fi

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
    echo "**Replication Status** ⚠️"
    echo ""
    echo "Some replication triggers encountered issues."
    echo "Check logs for details."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
fi

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
