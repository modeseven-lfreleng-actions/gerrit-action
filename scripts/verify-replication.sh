#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Verify Gerrit replication success
# This script waits for and validates that replication has completed
# successfully for all configured instances

set -euo pipefail

echo "Verifying replication success..."
echo ""

# Default timeout if not set
REPLICATION_WAIT_TIMEOUT="${REPLICATION_WAIT_TIMEOUT:-120}"

# Read instances metadata
if [ ! -f "$WORK_DIR/instances.json" ]; then
  echo "::error::No instances metadata found ❌"
  exit 1
fi

INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
VERIFICATION_FAILED=0
TOTAL_INSTANCES=0

# Function to check if pull-replication plugin is loaded
check_plugin_loaded() {
  local cid="$1"

  if docker logs "$cid" 2>&1 | grep -q "Loaded plugin pull-replication"; then
    return 0
  fi
  return 1
}

# Function to check for replication errors in logs
check_replication_errors() {
  local cid="$1"

  # Look for common replication error patterns
  local error_patterns=(
    "pull-replication.*error"
    "pull-replication.*failed"
    "replication.*Exception"
    "Cannot replicate"
    "Replication.*failed"
    "Authentication.*failed"
    "Permission denied"
    "Connection refused"
  )

  for pattern in "${error_patterns[@]}"; do
    if docker logs "$cid" 2>&1 | grep -qi "$pattern"; then
      return 0  # Found errors
    fi
  done

  return 1  # No errors found
}

# Function to count replicated repositories
count_repositories() {
  local cid="$1"

  docker exec "$cid" sh -c \
    "find /var/gerrit/git -name '*.git' -type d 2>/dev/null | wc -l" \
    || echo "0"
}

# Function to wait for replication activity
wait_for_replication() {
  local cid="$1"
  local timeout="$2"
  local slug="$3"

  local elapsed=0
  local interval=10
  local initial_count
  local current_count
  local last_count

  initial_count=$(count_repositories "$cid")
  last_count=$initial_count

  echo "  Initial repository count: $initial_count"
  echo "  Waiting up to ${timeout}s for replication..."

  while [ "$elapsed" -lt "$timeout" ]; do
    sleep "$interval"
    elapsed=$((elapsed + interval))

    current_count=$(count_repositories "$cid")

    # Check if we have more than just All-Projects and All-Users
    if [ "$current_count" -gt 2 ]; then
      echo "  ✅ Repositories detected after ${elapsed}s: $current_count"
      return 0
    fi

    # Check if count is increasing (replication in progress)
    if [ "$current_count" -gt "$last_count" ]; then
      echo "  Progress: $current_count repositories (${elapsed}s elapsed)"
      last_count=$current_count
    fi

    # Check for errors
    if check_replication_errors "$cid"; then
      echo "  ::warning::Replication errors detected in logs"
    fi

    # Print status every 30 seconds
    if [ $((elapsed % 30)) -eq 0 ]; then
      echo "  Still waiting... ${elapsed}s/${timeout}s"
    fi
  done

  # Timeout reached
  echo "  ⚠️ Timeout after ${timeout}s, current count: $current_count"
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
    PLUGIN_VERSION_LOG=$(docker logs "$cid" 2>&1 | \
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

    if [ "${DEBUG:-false}" = "true" ]; then
      echo "  Configuration content:"
      docker exec "$cid" cat /var/gerrit/etc/replication.config 2>/dev/null | \
        sed 's/^/    /' || true
    fi
  else
    echo "::error::replication.config not found ❌"
    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

  # Step 3: Check for replication errors
  echo ""
  echo "Step 3: Checking for replication errors..."

  if check_replication_errors "$cid"; then
    echo "::warning::Replication errors detected in container logs"
    echo "  Recent error-related logs:"
    docker logs "$cid" 2>&1 | \
      grep -iE "error|exception|failed|denied" | \
      grep -i "replication\|pull-replication" | \
      tail -10 | sed 's/^/    /' || true
    echo ""
  else
    echo "  No replication errors detected ✅"
  fi

  # Step 4: Wait for and verify replicated repositories
  echo ""
  echo "Step 4: Waiting for replicated repositories..."

  if wait_for_replication "$cid" "$REPLICATION_WAIT_TIMEOUT" "$slug"; then
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
    docker logs "$cid" 2>&1 | \
      grep -i "replication\|pull-replication\|fetch\|remote" | \
      tail -20 | sed 's/^/    /' || true

    VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
    continue
  fi

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

  # Add to step summary
  {
    echo "**Replication Verification** ✅"
    echo ""
    echo "All instances successfully replicated from source Gerrit servers."
    echo ""
    echo "| Instance | Status |"
    echo "|----------|--------|"
  } >> "$GITHUB_STEP_SUMMARY"

  for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
    echo "| $slug | ✅ Verified |" >> "$GITHUB_STEP_SUMMARY"
  done

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
