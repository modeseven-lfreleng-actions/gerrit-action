#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Trigger Gerrit replication
# This script monitors pull-replication for all configured instances
#
# Replication approach: fetchEvery polling
# The pull-replication plugin is configured with fetchEvery which polls the
# source Gerrit at regular intervals (default: 60s) to fetch new/changed refs.
#
# This approach:
# - Enables full web UI access (non-replica mode)
# - Provides automatic, self-healing replication
# - First sync occurs within the configured poll interval
#
# This script:
# 1. Verifies the pull-replication plugin is loaded
# 2. Shows current replication configuration
# 3. Optionally attempts SSH trigger for faster initial sync
# 4. Waits for first poll cycle to show activity

set -euo pipefail

echo "Triggering initial replication..."
echo ""

# Get fetch interval (default 60s)
FETCH_EVERY="${FETCH_EVERY:-60s}"

# Function to parse time interval to seconds
# Supports: 60s, 5m, 1h, or plain seconds (e.g., 60)
parse_interval_to_seconds() {
  local interval="$1"
  local value
  local unit

  # Validate format: integer with optional s/m/h suffix
  if [[ "$interval" =~ ^([0-9]+)([smhSMH]?)$ ]]; then
    value="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
  else
    echo "Invalid FETCH_EVERY value: '$interval'. Expected format: <integer>[s|m|h], e.g. 60s, 5m, 1h." >&2
    return 1
  fi

  case "$unit" in
    ""|s|S) echo "$value" ;;
    m|M)    echo $((value * 60)) ;;
    h|H)    echo $((value * 3600)) ;;
  esac
}

# Calculate wait timeout based on fetch interval
FETCH_INTERVAL_SECONDS=$(parse_interval_to_seconds "$FETCH_EVERY")
# Wait for 1.5x the fetch interval to allow for first poll cycle
MAX_WAIT=$((FETCH_INTERVAL_SECONDS * 3 / 2))
# Minimum wait of 60 seconds
if [ "$MAX_WAIT" -lt 60 ]; then
  MAX_WAIT=60
fi

echo "Fetch interval: $FETCH_EVERY ($FETCH_INTERVAL_SECONDS seconds)"
echo "Wait timeout: ${MAX_WAIT}s (1.5x fetch interval)"
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

  # Fallback: check a larger window of recent logs without using head to avoid SIGPIPE with pipefail
  if docker logs --tail 5000 "$cid" 2>&1 | grep "Loaded plugin $plugin_name" >/dev/null 2>&1; then
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
  expected_count=$(jq -r ".\"$slug\".expected_project_count // 0" "$INSTANCES_JSON_FILE")

  echo "Container ID: $cid"
  echo "Source: $gerrit_host"
  if [ -n "$project" ]; then
    echo "Project filter: $project"
  fi
  if [ "$expected_count" -gt 0 ]; then
    echo "Expected repositories: $expected_count"
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
      PLUGIN_VERSION_LOG=$(docker logs --tail 200 "$cid" 2>&1 | \
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

  # Wait for fetchEvery polling to trigger replication
  # With fetchEvery configured, the plugin polls the source Gerrit at regular
  # intervals (default: 60s) to fetch new/changed refs. The first poll occurs
  # after the configured interval from when the plugin loads.
  echo ""
  echo "Waiting for fetchEvery polling to trigger replication..."
  echo "(First poll occurs within the configured fetch interval: $FETCH_EVERY)"

  # MAX_WAIT is calculated above based on FETCH_EVERY
  WAITED=0
  REPLICATION_STARTED=false

  while [ $WAITED -lt $MAX_WAIT ]; do
    # Check pull_replication_log for activity
    # Use tail -n 50 instead of cat to avoid reading the entire log file each iteration
    # This is more efficient for large replications where the log can grow quickly
    if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
      REPL_LOG_CONTENT=$(docker exec "$cid" tail -n 50 /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "")
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
    echo "This may be normal if the fetch interval is longer than ${MAX_WAIT}s"
    echo "Replication will continue in the background via fetchEvery polling"
  fi

  # Show pull_replication_log content (last 20 lines to avoid flooding CI logs)
  echo ""
  echo "Pull replication log (last 20 lines):"
  docker exec "$cid" tail -20 /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "(empty)"
  echo ""

  # Check container logs for any replication-related messages
  echo "Container log replication activity:"
  docker logs --tail 5000 "$cid" 2>&1 | \
    grep -iE "pull-replication|fetch|FetchAll" | tail -10 || echo "(none)"
  echo ""

  # Check if any repositories were created/populated (excludes All-Projects and All-Users)
  # Note: expected_count from remote API also excludes system repos, so counts are aligned
  REPO_COUNT=$(docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | grep -v -E 'All-Projects|All-Users' | wc -l" \
    || echo "0")

  echo "Replicated repositories: $REPO_COUNT"

  # List repositories (limit output to avoid flooding CI logs)
  echo ""
  echo "Repositories:"
  if [ "${DEBUG:-false}" = "true" ]; then
    echo "  (DEBUG=true: showing full repository list)"
    docker exec "$cid" sh -c \
      "find /var/gerrit/git -name '*.git' -type d 2>/dev/null" || true
  else
    echo "  (showing first 50 repositories; set DEBUG=true for full list)"
    docker exec "$cid" sh -c \
      "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | head -50" || true
  fi
  echo ""

  # Check repository count against expected
  if [ "$expected_count" -gt 0 ]; then
    echo "Expected repositories: $expected_count"
    if [ "$REPO_COUNT" -ge "$expected_count" ]; then
      echo "✅ Replication complete: $REPO_COUNT/$expected_count repositories"
    elif [ "$REPO_COUNT" -gt 2 ]; then
      echo "⏳ Replication in progress: $REPO_COUNT/$expected_count repositories"
    else
      echo "::warning::Replication may still be starting"
    fi
  elif [ "$REPO_COUNT" -gt 0 ]; then
    echo "✅ Replication appears to be working ($REPO_COUNT repositories detected)"
  elif [ "$SYNC_ON_STARTUP" = "true" ]; then
    echo "::warning::No replicated repositories detected"
    echo "Replication may still be in progress"
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
