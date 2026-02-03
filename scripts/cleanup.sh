#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Cleanup Gerrit containers
# This script gracefully terminates all Gerrit instances started by the
# action

set -euo pipefail

echo "Cleaning up Gerrit containers..."
echo ""

# Read instances metadata
if [ ! -f "$WORK_DIR/instances.json" ]; then
  echo "::warning::No instances metadata found, nothing to cleanup"
  exit 0
fi

INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
CLEANUP_FAILED=0

# Cleanup each instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  echo "========================================"
  echo "Cleaning up instance: $slug"
  echo "========================================"

  # Get instance details
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")

  echo "Container ID: $cid"

  # Check if container exists
  if ! docker inspect "$cid" >/dev/null 2>&1; then
    echo "Container $cid does not exist (already removed)"
    continue
  fi

  # Get container state
  CONTAINER_STATE=$(docker inspect -f '{{.State.Status}}' "$cid" \
    2>/dev/null || echo "unknown")
  echo "Container state: $CONTAINER_STATE"

  if [ "$CONTAINER_STATE" = "running" ]; then
    # Graceful shutdown attempt
    echo "Attempting graceful shutdown..."

    # Try to stop Gerrit gracefully first
    docker exec "$cid" sh -c "gerrit stop" 2>/dev/null || {
      echo "Graceful stop command not available"
      echo "proceeding with container kill"
    }

    # Wait a moment for graceful shutdown
    sleep 3

    # Check if still running
    CONTAINER_STATE=$(docker inspect -f '{{.State.Status}}' "$cid" \
      2>/dev/null || echo "stopped")

    if [ "$CONTAINER_STATE" = "running" ]; then
      echo "Killing container..."
      if timeout 30 docker kill "$cid" 2>/dev/null; then
        echo "Container killed ✅"
      else
        echo "::warning::Failed to kill container $cid"
        CLEANUP_FAILED=1
      fi
    else
      echo "Container stopped gracefully ✅"
    fi

    # Remove the container (no longer using --rm flag)
    echo "Removing container..."
    if docker rm "$cid" 2>/dev/null; then
      echo "Container removed ✅"
    else
      echo "::warning::Failed to remove container $cid (may already be removed)"
    fi
  else
    echo "Container not running, removing..."
    docker rm -f "$cid" 2>/dev/null || {
      echo "::warning::Failed to remove container $cid"
      CLEANUP_FAILED=1
    }
  fi

  # Clean up instance directory
  instance_dir="$WORK_DIR/instances/$slug"
  if [ -d "$instance_dir" ]; then
    echo "Cleaning up instance directory..."
    rm -rf "$instance_dir" 2>/dev/null || {
      echo "::warning::Failed to remove instance directory"
    }
  fi

  # Clean up CID file
  cidfile="$WORK_DIR/gerrit-$slug.cid"
  if [ -f "$cidfile" ]; then
    rm -f "$cidfile" 2>/dev/null || true
  fi

  echo "✅ Cleanup completed for $slug"
  echo ""
done

# Clean up working directory
if [ -d "$WORK_DIR" ]; then
  echo "Cleaning up working directory: $WORK_DIR"
  rm -rf "$WORK_DIR" 2>/dev/null || {
    echo "::warning::Failed to remove working directory"
  }
fi

# Preserve Docker cache if enabled
if [ "$ENABLE_CACHE" = "true" ]; then
  echo "Preserving Docker layers in cache..."
  docker system prune -f --filter "until=24h" \
    --filter "label!=keep-cache" 2>/dev/null || {
    echo "::warning::Docker cleanup skipped"
  }
fi

# Summary
echo "========================================"
if [ $CLEANUP_FAILED -eq 0 ]; then
  echo "All containers cleaned up! ✅"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Cleanup Complete** 🧹"
    echo ""
    echo "All Gerrit containers have been stopped and cleaned up."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
else
  echo "Some cleanup operations failed ⚠️"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Cleanup Status** ⚠️"
    echo ""
    echo "Some cleanup operations encountered issues."
    echo "Manual cleanup may be required."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Show remaining containers (if any)
REMAINING=$(docker ps -q -f "name=gerrit-" 2>/dev/null || echo "")
if [ -n "$REMAINING" ]; then
  echo "::warning::Some Gerrit containers are still running:"
  docker ps -f "name=gerrit-"
else
  echo "No Gerrit containers remaining ✅"
fi
echo ""
