#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Check Gerrit service availability
# This script verifies that all Gerrit instances are responding to HTTP
# requests

set -euo pipefail

echo "Checking Gerrit service availability..."
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
CHECK_FAILED=0

# Check each instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  echo "========================================"
  echo "Checking instance: $slug"
  echo "========================================"

  # Get instance details
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
  container_ip=$(jq -r ".\"$slug\".ip" "$INSTANCES_JSON_FILE")
  http_port=$(jq -r ".\"$slug\".http_port" "$INSTANCES_JSON_FILE")

  echo "Container ID: $cid"
  echo "IP Address: $container_ip"
  echo "HTTP Port: $http_port (container port 8080)"
  echo ""

  # Verify container is running
  if ! docker inspect "$cid" >/dev/null 2>&1; then
    echo "::error::Container $cid does not exist ❌"
    CHECK_FAILED=1
    continue
  fi

  CONTAINER_STATE=$(docker inspect -f '{{.State.Status}}' "$cid")
  if [ "$CONTAINER_STATE" != "running" ]; then
    echo "::error::Container $cid is not running ❌"
    echo "::error::(state: $CONTAINER_STATE)"
    CHECK_FAILED=1

    # Show logs for debugging
    echo "Container logs (last 20 lines):"
    docker logs "$cid" --tail 20 2>&1 || true
    continue
  fi

  echo "Container state: $CONTAINER_STATE ✅"
  echo ""

  # Wait for Gerrit to be ready
  echo "Waiting for Gerrit to initialize..."

  # Check if Gerrit is ready by looking at logs
  MAX_WAIT=180  # 3 minutes
  ELAPSED=0
  READY=false

  while [ $ELAPSED -lt $MAX_WAIT ]; do
    if docker logs "$cid" 2>&1 | grep -q "Gerrit Code Review.*ready"; then
      READY=true
      break
    fi

    sleep 2
    ELAPSED=$((ELAPSED + 2))

    if [ $((ELAPSED % 10)) -eq 0 ]; then
      echo "  Waiting... ${ELAPSED}s elapsed"
    fi
  done

  if [ "$READY" = "false" ]; then
    echo "::warning::Gerrit did not show 'ready' message in logs"
    echo "::warning::after ${MAX_WAIT}s"
    echo "Proceeding with HTTP check anyway..."
  else
    echo "Gerrit ready message detected in logs ✅"
  fi

  echo ""
  echo "Performing HTTP health check..."

  # Test basic connectivity with version endpoint
  MAX_RETRIES=30
  RETRY_COUNT=0
  HTTP_SUCCESS=false

  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      --connect-timeout 5 \
      --max-time 10 \
      "http://$container_ip:8080/config/server/version" 2>/dev/null \
      || echo "000")

    if [ "$HTTP_CODE" = "200" ] || \
       [ "$HTTP_CODE" = "401" ] || \
       [ "$HTTP_CODE" = "403" ]; then
      HTTP_SUCCESS=true
      echo "HTTP check passed (code: $HTTP_CODE) ✅"
      break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      sleep 2
      if [ $((RETRY_COUNT % 5)) -eq 0 ]; then
        echo "  Retry $RETRY_COUNT/$MAX_RETRIES (HTTP code: $HTTP_CODE)"
      fi
    fi
  done

  if [ "$HTTP_SUCCESS" = "false" ]; then
    echo "::error::HTTP health check failed for $slug ❌"
    echo "::error::after $MAX_RETRIES retries"
    echo "Last HTTP code: $HTTP_CODE"
    CHECK_FAILED=1

    # Show container logs for debugging
    echo ""
    echo "Container logs (last 50 lines):"
    docker logs "$cid" --tail 50 2>&1 || true
    echo ""
    continue
  fi

  # Check for pull-replication plugin
  if [ "$SKIP_PLUGIN_INSTALL" != "true" ]; then
    echo ""
    echo "Verifying pull-replication plugin..."

    # Method 1: Check container logs for plugin loading message
    # This is the most reliable method as Gerrit logs plugin loading
    if check_plugin_in_logs "$cid" "pull-replication"; then
      echo "Pull-replication plugin loaded ✅ (verified via logs)"
    else
      # Method 2: Check via HTTP API (may not work for all auth configs)
      PLUGIN_CHECK=$(curl -s "http://$container_ip:8080/plugins/" \
        2>/dev/null || echo "")

      if echo "$PLUGIN_CHECK" | grep -q "pull-replication"; then
        echo "Pull-replication plugin detected ✅"
      else
        # Method 3: Check if plugin file exists in container
        if docker exec "$cid" test -f \
          /var/gerrit/plugins/pull-replication.jar; then
          echo "  Plugin file exists in container"
          # Give it a moment and check logs again
          sleep 3
          if check_plugin_in_logs "$cid" "pull-replication"; then
            echo "  Pull-replication plugin loaded ✅"
          else
            echo "::warning::Plugin file exists but not yet loaded"
            echo "  This may be normal during initial startup"
          fi
        else
          echo "::error::Plugin file not found in container"
          CHECK_FAILED=1
        fi
      fi
    fi

    # Also verify replication-api is loaded (dependency)
    if check_plugin_in_logs "$cid" "replication-api"; then
      echo "Replication-api plugin loaded ✅"
    fi
  fi

  echo ""
  echo "✅ Instance $slug is healthy and responding"
  echo ""
done

# Summary
echo "========================================"
if [ $CHECK_FAILED -eq 0 ]; then
  echo "All service checks passed! ✅"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Service Health Checks** 💚"
    echo ""
    echo "All Gerrit instances are healthy and responding!"
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"
else
  echo "Some service checks failed ❌"
  echo "========================================"
  echo ""

  # Add to step summary
  {
    echo "**Service Health Checks** ❌"
    echo ""
    echo "Some instances failed health checks."
    echo "See logs above for details."
    echo ""
  } >> "$GITHUB_STEP_SUMMARY"

  exit 1
fi

# Show container status
echo "Current container status:"
docker ps -f "name=gerrit-*"
echo ""
