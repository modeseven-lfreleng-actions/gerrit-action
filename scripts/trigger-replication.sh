#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Trigger Gerrit replication
# This script initiates pull-replication for all configured instances
#
# Key insight: The pull-replication plugin's replicateOnStartup feature
# schedules a FetchAll 30 seconds after the plugin loads (see OnStartStop.java).
# This script waits for that scheduled task to complete.

set -euo pipefail

echo "Triggering initial replication..."
echo ""

# Function to check plugin status via container logs
# Uses --tail to limit output and avoid pipe buffer issues with large logs
check_plugin_in_logs() {
  local cid="$1"
  local plugin_name="$2"

  # Check recent logs first (most reliable)
  # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
  if docker logs --tail 1000 "$cid" 2>&1 | grep "Loaded plugin $plugin_name" >/dev/null 2>&1; then
    return 0
  fi

  # Fallback: check full logs with head to limit output
  if docker logs "$cid" 2>&1 | head -n 5000 | grep "Loaded plugin $plugin_name" >/dev/null 2>&1; then
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

  # Wait for replicateOnStartup FetchAll to complete
  # The pull-replication plugin schedules FetchAll 30 seconds after startup
  # (see OnStartStop.java: fetchAll.schedule(30, TimeUnit.SECONDS))
  echo ""
  echo "Waiting for replicateOnStartup FetchAll to complete..."
  echo "(FetchAll is scheduled 30 seconds after plugin load)"

  # Wait up to 60 seconds for replication to start and complete
  MAX_WAIT=60
  WAITED=0
  REPLICATION_STARTED=false

  while [ $WAITED -lt $MAX_WAIT ]; do
    # Check pull_replication_log for activity
    if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
      REPL_LOG_CONTENT=$(docker exec "$cid" cat /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "")
      if [ -n "$REPL_LOG_CONTENT" ]; then
        REPLICATION_STARTED=true
        # Check if replication completed
        # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
        # The -q flag causes grep to exit immediately on match, which sends SIGPIPE to printf
        if printf '%s\n' "$REPL_LOG_CONTENT" 2>/dev/null | grep "completed" >/dev/null 2>&1; then
          echo "✅ Replication activity detected and completed"
          break
        fi
      fi
    fi

    sleep 5
    WAITED=$((WAITED + 5))
    if [ $((WAITED % 15)) -eq 0 ]; then
      echo "  Still waiting... ${WAITED}s elapsed"
    fi
  done

  if [ "$REPLICATION_STARTED" = "false" ] && [ $WAITED -ge $MAX_WAIT ]; then
    echo "::warning::No replication activity detected after ${MAX_WAIT}s"
  fi

  # Show pull_replication_log content
  echo ""
  echo "Pull replication log:"
  docker exec "$cid" cat /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "(empty)"
  echo ""

  # Check container logs for any replication-related messages
  echo "Container log replication activity:"
  docker logs "$cid" 2>&1 | \
    grep -iE "pull-replication|fetch|FetchAll" | tail -10 || echo "(none)"
  echo ""

  # Check if any repositories were created/populated
  REPO_COUNT=$(docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | wc -l" \
    || echo "0")

  echo "Repositories in git directory: $REPO_COUNT"

  # List repositories
  echo ""
  echo "Repositories:"
  docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null" || true
  echo ""

  # Check if repos have actual content (packed-refs indicates successful fetch)
  if [ -n "$project" ]; then
    echo "Checking replicated content for project: $project"
    PROJECT_GIT="/var/gerrit/git/${project}.git"

    if docker exec "$cid" test -d "$PROJECT_GIT" 2>/dev/null; then
      # Check for packed-refs (indicates successful fetch)
      if docker exec "$cid" test -f "$PROJECT_GIT/packed-refs" 2>/dev/null; then
        REFS_COUNT=$(docker exec "$cid" wc -l < "$PROJECT_GIT/packed-refs" 2>/dev/null || echo "0")
        echo "  ✅ packed-refs found: $REFS_COUNT lines (replication successful)"

        # Show branches
        BRANCHES=$(docker exec "$cid" bash -c "cd $PROJECT_GIT && git branch 2>/dev/null" || echo "")
        if [ -n "$BRANCHES" ]; then
          echo "  Branches:"
          printf '%s\n' "$BRANCHES" | while IFS= read -r branch; do
            echo "    $branch"
          done
        fi
      else
        echo "  ⚠️ No packed-refs found (replication may not have completed)"
        REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
      fi
    else
      echo "  ⚠️ Project directory not found: $PROJECT_GIT"
      REPLICATION_FAILED=$((REPLICATION_FAILED + 1))
    fi
  elif [ "$REPO_COUNT" -gt 2 ]; then
    # More than All-Projects and All-Users
    echo "✅ Replication appears to be working (repositories detected)"
  elif [ "$SYNC_ON_STARTUP" = "true" ]; then
    echo "::warning::No replicated repositories detected"
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
