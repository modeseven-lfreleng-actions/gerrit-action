#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Verify Gerrit replication success
# This script waits for and validates that replication has completed
# successfully for all configured instances
#
# Replication approach: fetchEvery polling
# The pull-replication plugin is configured with fetchEvery which polls the
# source Gerrit at regular intervals (default: 60s) to fetch new/changed refs.
# This script waits for at least one poll cycle to complete and verifies
# that repositories have been populated with content.
#
# Key insight: The pull-replication plugin logs activity to:
#   /var/gerrit/logs/pull_replication_log
# This is the primary source for verifying replication success.

set -euo pipefail

echo "Verifying replication success..."
echo ""

# Default timeout if not set
# With fetchEvery polling, we need to wait at least one poll interval (default 60s)
# plus time for the actual fetch operation. 180s provides ~3x the default interval.
REPLICATION_WAIT_TIMEOUT="${REPLICATION_WAIT_TIMEOUT:-180}"

# Read instances metadata
if [ ! -f "$WORK_DIR/instances.json" ]; then
  echo "::error::No instances metadata found ❌"
  exit 1
fi

INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
VERIFICATION_FAILED=0
TOTAL_INSTANCES=0

# Function to check if pull-replication plugin is loaded
# Uses multiple methods to ensure reliable detection:
# 1. Check recent logs (last 1000 lines) for plugin load message
# 2. Check full logs with timeout protection
# 3. Fallback: check if plugin jar file exists in container
check_plugin_loaded() {
  local cid="$1"

  # Method 1: Check recent logs (most reliable, avoids buffer issues)
  # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
  if docker logs --tail 1000 "$cid" 2>&1 | grep "Loaded plugin pull-replication" >/dev/null 2>&1; then
    return 0
  fi

  # Method 2: Check logs with timeout to avoid hanging on large log output
  # Use docker logs --tail to limit output and avoid SIGPIPE/pipefail issues from head
  if timeout 10 docker logs --tail 5000 "$cid" 2>&1 | grep "Loaded plugin pull-replication" >/dev/null 2>&1; then
    return 0
  fi

  # Method 3: Fallback - check if plugin file exists AND check pull_replication_log exists
  # If the log file exists, the plugin must have been loaded
  if docker exec "$cid" test -f /var/gerrit/plugins/pull-replication.jar 2>/dev/null; then
    if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

# Function to check for replication errors in pull_replication_log
# This is the PRIMARY source for replication errors
check_replication_errors() {
  local cid="$1"

  # First check pull_replication_log - this is the definitive source
  # Use tail and grep inside the container to avoid reading entire log into memory
  # This function is called frequently in wait_for_replication, so efficiency matters
  if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
    # Run tail and grep inside the container to check for error patterns
    # Using tail -n 500 to scan recent log entries without loading the entire file
    if docker exec "$cid" sh -c "tail -n 500 /var/gerrit/logs/pull_replication_log 2>/dev/null | grep -iE 'Cannot replicate|TransportException|git-upload-pack not permitted|Authentication.*failed|Permission denied|Connection refused|error|failed|Exception'" >/dev/null 2>&1; then
      return 0  # Found errors
    fi
  fi

  # Also check container logs for additional error patterns
  # Use --tail to limit output and avoid pipe buffer issues with large logs
  local error_patterns=(
    "Cannot replicate"
    "TransportException"
    "git-upload-pack not permitted"
    "Authentication.*failed"
    "Permission denied"
    "Connection refused"
    "replication.*error"
    "replication.*failed"
  )

  # Get recent logs once to avoid multiple docker logs calls
  local recent_logs
  recent_logs=$(docker logs --tail 2000 "$cid" 2>&1 || echo "")

  for pattern in "${error_patterns[@]}"; do
    # Use grep without -q and redirect output to avoid broken pipe errors
    if printf '%s\n' "$recent_logs" 2>/dev/null | grep -i "$pattern" >/dev/null 2>&1; then
      return 0  # Found errors
    fi
  done

  return 1  # No errors found
}

# Function to check pull_replication_log for successful replication
# Returns 0 ONLY if replication completed WITHOUT errors
check_pull_replication_log() {
  local cid="$1"

  # Check if the log file exists and has content
  # Use tail -n 100 instead of cat to avoid reading the entire log file each iteration
  # This function is called in a tight polling loop, so efficiency matters as the log grows
  if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
    local log_content
    log_content=$(docker exec "$cid" tail -n 100 /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "")

    if [ -n "$log_content" ]; then
      # FIRST check for errors - these take priority
      # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
      # The -q flag causes grep to exit immediately on match, which sends SIGPIPE to printf
      if printf '%s\n' "$log_content" 2>/dev/null | grep -iE "Cannot replicate|TransportException|git-upload-pack not permitted|failed|error|Exception" >/dev/null 2>&1; then
        return 1  # Found errors, replication failed
      fi

      # Check for successful completion only if no errors
      if printf '%s\n' "$log_content" 2>/dev/null | grep "completed" >/dev/null 2>&1; then
        return 0  # Replication completed successfully
      fi
    fi
  fi
  return 1  # No successful replication found
}

# Function to show pull_replication_log content
show_pull_replication_log() {
  local cid="$1"

  echo "  Pull replication log:"
  if docker exec "$cid" test -f /var/gerrit/logs/pull_replication_log 2>/dev/null; then
    local content
    content=$(docker exec "$cid" cat /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "")
    if [ -n "$content" ]; then
      printf '%s\n' "$content" | tail -50 | sed 's/^/    /'
    else
      echo "    (empty)"
    fi
  else
    echo "    (file not found)"
  fi
}

# Function to get the expected project count from instances metadata
get_expected_project_count() {
  local slug="$1"

  if [ -f "$WORK_DIR/instances.json" ]; then
    local count
    count=$(jq -r ".\"$slug\".expected_project_count // 0" "$WORK_DIR/instances.json" 2>/dev/null || echo "0")
    echo "$count"
  else
    echo "0"
  fi
}

# Function to validate project count against expected
validate_project_count() {
  local cid="$1"
  local slug="$2"
  local expected_count="$3"

  # count_repositories already excludes All-Projects and All-Users
  local actual_count
  actual_count=$(count_repositories "$cid")

  echo "  Expected projects from remote: $expected_count"
  echo "  Local repository count (excluding system repos): $actual_count"

  if [ "$expected_count" -eq 0 ]; then
    echo "  ⚠️ No expected count available, skipping count validation"
    return 0
  fi

  # Allow 5% tolerance for project count mismatch
  local min_required=$((expected_count * 95 / 100))

  if [ "$actual_count" -ge "$min_required" ]; then
    echo "  ✅ Project count matches expected (within 5% tolerance)"
    return 0
  else
    local percentage=$((actual_count * 100 / expected_count))
    echo "  ⚠️ Project count mismatch: got $percentage% of expected projects"
    return 1
  fi
}

# Function to count replicated repositories (excludes All-Projects and All-Users)
count_repositories() {
  local cid="$1"

  docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | grep -v -E 'All-Projects|All-Users' | wc -l" \
    || echo "0"
}

# Function to list all repositories in git directory
list_repositories() {
  local cid="$1"
  local max_items="${2:-20}"

  echo "  Repository listing (max $max_items):"
  docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | head -$max_items" | \
    sed 's/^/    /' || echo "    (none found)"
}

# Function to show disk usage of git directory
show_git_disk_usage() {
  local cid="$1"

  echo "  Git directory disk usage:"
  docker exec "$cid" sh -c \
    "du -sh /var/gerrit/git 2>/dev/null" | \
    sed 's/^/    /' || echo "    (unable to determine)"
}

# Function to check for fetch/HTTP activity in logs
# Uses --tail to limit output and avoid pipe buffer issues with large logs
check_fetch_activity() {
  local cid="$1"

  local fetch_logs
  fetch_logs=$(docker logs --tail 3000 "$cid" 2>&1 | \
    grep -iE "fetch|http|GET|POST|clone|pull" | \
    grep -v "healthcheck" | \
    tail -20 || echo "")

  if [ -n "$fetch_logs" ]; then
    echo "  Recent fetch/HTTP activity:"
    printf '%s\n' "$fetch_logs" | sed 's/^/    /'
    return 0
  fi
  return 1
}

# Function to show secure.config status (without exposing credentials)
check_secure_config() {
  local cid="$1"

  if docker exec "$cid" test -f /var/gerrit/etc/secure.config; then
    echo "  secure.config exists ✅"
    # Show structure without values
    echo "  secure.config sections:"
    docker exec "$cid" sh -c \
      "grep '^\[' /var/gerrit/etc/secure.config 2>/dev/null" | \
      sed 's/^/    /' || echo "    (no sections found)"
    return 0
  else
    echo "  ::warning::secure.config not found"
    return 1
  fi
}

# Function to wait for replication to complete
# Success criteria: repository count matches expected count from remote Gerrit
# (Some repos may be empty on the source, so we don't require 100% content)
wait_for_replication() {
  local cid="$1"
  local timeout="$2"
  local slug="$3"
  local project="$4"

  local elapsed=0
  local interval=5

  # Get expected project count - this is our completion target
  local expected_count
  expected_count=$(get_expected_project_count "$slug")

  local initial_count
  initial_count=$(count_repositories "$cid")

  echo "  Initial repository count: $initial_count"
  if [ "$expected_count" -gt 0 ]; then
    echo "  Expected from remote: $expected_count"
    echo "  Waiting up to ${timeout}s for all repositories..."
  else
    echo "  No expected count available, waiting for replication activity..."
  fi
  echo ""

  while [ "$elapsed" -lt "$timeout" ]; do
    sleep "$interval"
    elapsed=$((elapsed + interval))

    # Check for replication errors - fail fast
    if check_replication_errors "$cid"; then
      echo ""
      echo "  ❌ Replication errors detected!"
      show_pull_replication_log "$cid"
      return 1
    fi

    # Count current repositories (excluding All-Projects/All-Users)
    local current_count
    current_count=$(count_repositories "$cid")

    # Complete when repo count matches expected
    if [ "$expected_count" -gt 0 ] && [ "$current_count" -ge "$expected_count" ]; then
      echo ""
      echo "  ✅ Replication complete: $current_count/$expected_count repositories"
      show_git_disk_usage "$cid"
      return 0
    fi

    # Show progress every 15 seconds
    if [ $((elapsed % 15)) -eq 0 ]; then
      local disk_human
      disk_human=$(docker exec "$cid" sh -c "du -sh /var/gerrit/git 2>/dev/null | cut -f1" || echo "?")
      if [ "$expected_count" -gt 0 ]; then
        local pct=$((current_count * 100 / expected_count))
        echo "  [${elapsed}s/${timeout}s] $current_count/$expected_count repos ($pct%) disk=$disk_human"
      else
        echo "  [${elapsed}s/${timeout}s] $current_count repos disk=$disk_human"
      fi
    fi
  done

  # Timeout - show final state
  local final_count
  final_count=$(count_repositories "$cid")
  echo ""
  echo "  ❌ Timeout after ${timeout}s"
  echo "  Final: $final_count repositories"
  if [ "$expected_count" -gt 0 ]; then
    echo "  Expected: $expected_count"
  fi
  show_git_disk_usage "$cid"
  echo ""
  show_pull_replication_log "$cid"

  return 1
}

# Verify each instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  TOTAL_INSTANCES=$((TOTAL_INSTANCES + 1))

  echo "========================================"
  echo "Verifying replication: $slug"
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

  # Verify container is still running
  if ! docker inspect "$cid" >/dev/null 2>&1; then
    echo "::error::Container $cid not found ❌"
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  CONTAINER_STATE=$(docker inspect -f '{{.State.Status}}' "$cid")
  if [ "$CONTAINER_STATE" != "running" ]; then
    echo "::error::Container $cid is not running (state: $CONTAINER_STATE) ❌"
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  echo "Container state: $CONTAINER_STATE ✅"

  # Step 1: Verify pull-replication plugin is loaded
  echo ""
  echo "Step 1: Verifying pull-replication plugin..."

  if check_plugin_loaded "$cid"; then
    # Try to get the plugin version from logs, using tail to limit output
    PLUGIN_VERSION_LOG=$(docker logs --tail 2000 "$cid" 2>&1 | \
      grep "Loaded plugin pull-replication" | tail -1 || echo "")
    echo "  $PLUGIN_VERSION_LOG"
    echo "  Pull-replication plugin loaded ✅"
  else
    echo "::error::Pull-replication plugin not loaded ❌"
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  # Step 2: Verify replication configuration exists
  echo ""
  echo "Step 2: Verifying replication configuration..."

  if docker exec "$cid" test -f /var/gerrit/etc/replication.config; then
    echo "  replication.config found ✅"

    # Always show configuration for debugging replication issues
    echo "  Configuration content:"
    docker exec "$cid" cat /var/gerrit/etc/replication.config 2>/dev/null | \
      grep -v "^#" | grep -v "^$" | sed 's/^/    /' || true
  else
    echo "::error::replication.config not found ❌"
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  # Check secure.config for credentials
  echo ""
  echo "Step 2b: Verifying authentication configuration..."
  check_secure_config "$cid"

  # Step 3: Check for replication errors - THIS IS CRITICAL
  echo ""
  echo "Step 3: Checking for replication errors..."

  if check_replication_errors "$cid"; then
    echo "::error::Replication errors detected! ❌"
    echo ""
    echo "  Pull replication log errors:"
    show_pull_replication_log "$cid"
    echo ""
    echo "  Container log errors:"
    docker logs --tail 3000 "$cid" 2>&1 | \
      grep -iE "Cannot replicate|TransportException|git-upload-pack|error|exception|failed|denied" | \
      tail -20 | sed 's/^/    /' || true
    echo ""

    # This is a HARD FAILURE - replication errors mean we can't continue
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  else
    echo "  No replication errors detected ✅"
  fi

  # Step 4: Wait for and verify replicated repositories
  echo ""
  echo "Step 4: Waiting for replicated repositories..."

  if wait_for_replication "$cid" "$REPLICATION_WAIT_TIMEOUT" "$slug" "$project"; then
    echo "  Replication verified ✅"

    # List some repositories
    echo ""
    echo "  Sample replicated repositories:"
    docker exec "$cid" sh -c \
      "find /var/gerrit/git -maxdepth 3 -name '*.git' -type d 2>/dev/null | \
       grep -v 'All-Projects\|All-Users' | head -5" | \
      sed 's/^/    /' || true
  else
    echo "::error::No replicated repositories found after waiting ❌"

    # Show recent replication-related logs for debugging
    echo ""
    echo "  Recent replication logs:"
    docker logs --tail 3000 "$cid" 2>&1 | \
      grep -i "replication\|pull-replication\|fetch\|remote" | \
      tail -20 | sed 's/^/    /' || true

    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  # Step 5: Final disk usage and project count report
  echo ""
  echo "Step 5: Final replication statistics..."

  final_count=$(count_repositories "$cid")
  expected_count=$(get_expected_project_count "$slug")

  echo "  Replicated repositories: $final_count"
  if [ "$expected_count" -gt 0 ]; then
    echo "  Expected from remote: $expected_count"
  fi

  # Show final disk usage
  show_git_disk_usage "$cid"

  # Store stats for summary (format: slug|count|expected|disk)
  disk_usage=$(docker exec "$cid" sh -c "du -sh /var/gerrit/git 2>/dev/null | cut -f1" || echo "?")
  echo "$slug|$final_count|$expected_count|$disk_usage" >> "$WORK_DIR/replication_stats.txt"

  echo ""
  echo "✅ Instance $slug verification passed"
  echo ""
done

# Summary
echo "========================================"
echo "Verification Summary"
echo "========================================"
echo "Total instances: $TOTAL_INSTANCES"
echo "Failed: $VERIFICATION_FAILED"
echo ""

if [ $VERIFICATION_FAILED -eq 0 ]; then
  echo "All replication verifications passed! ✅"
  echo ""

  # Show final disk usage summary
  echo "========================================"
  echo "Disk Usage Summary"
  echo "========================================"
  for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
    cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
    echo ""
    echo "Instance: $slug"
    docker exec "$cid" sh -c "du -sh /var/gerrit/git 2>/dev/null" | sed 's/^/  /' || echo "  (unable to determine)"
  done
  echo ""

  # Add to step summary
  {
    echo "## Replication Verification ✅"
    echo ""
    echo "All instances successfully replicated from source Gerrit servers."
    echo ""
    echo "### Instance Details"
    echo ""
    echo "| Instance | Repos | Expected | Disk Usage |"
    echo "|----------|-------|----------|------------|"
  } >> "$GITHUB_STEP_SUMMARY"

  # Read stats from temp file if available
  if [ -f "$WORK_DIR/replication_stats.txt" ]; then
    while IFS='|' read -r slug final_count expected_count disk_usage; do
      expected_display="$expected_count"
      if [ "$expected_count" -eq 0 ]; then
        expected_display="N/A"
      fi
      echo "| $slug | $final_count | $expected_display | $disk_usage |" >> "$GITHUB_STEP_SUMMARY"
    done < "$WORK_DIR/replication_stats.txt"
  else
    for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
      echo "| $slug | ✅ | - | - | - |" >> "$GITHUB_STEP_SUMMARY"
    done
  fi

  echo "" >> "$GITHUB_STEP_SUMMARY"
else
  echo "Some verifications failed ❌"
  echo ""

  # Add to step summary
  {
    echo "**Replication Verification** ❌"
    echo ""
    echo "$VERIFICATION_FAILED of $TOTAL_INSTANCES instances failed verification."
    echo ""
    echo "Check the workflow logs for detailed error information."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"

  # Exit with failure
  exit 1
fi
