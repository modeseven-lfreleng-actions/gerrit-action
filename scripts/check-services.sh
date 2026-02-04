#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Check Gerrit service availability
# This script verifies that all Gerrit instances are responding
#
# Note: In replica/headless mode, the REST API is disabled so we use
# TCP port checks instead of HTTP health checks.

set -euo pipefail

echo "Checking Gerrit service availability..."
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

# Function to check if Gerrit is running in replica/headless mode
# In this mode, the REST API is disabled and HTTP health checks will fail
is_replica_mode() {
  local cid="$1"

  # Check recent logs first (most reliable)
  # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
  if docker logs --tail 500 "$cid" 2>&1 | grep "\[replica\].*\[headless\]" >/dev/null 2>&1; then
    return 0
  fi

  # Fallback: check full logs with head to limit output
  if docker logs "$cid" 2>&1 | head -n 2000 | grep "\[replica\].*\[headless\]" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

# Function to perform TCP port check
# Returns 0 if port is listening, 1 otherwise
check_tcp_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-5}"

  # Use nc (netcat) for TCP check, or fall back to bash /dev/tcp
  if command -v nc >/dev/null 2>&1; then
    nc -z -w "$timeout" "$host" "$port" 2>/dev/null
  elif command -v timeout >/dev/null 2>&1; then
    timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
  else
    # Last resort: use bash directly
    (echo >/dev/tcp/"$host"/"$port") 2>/dev/null
  fi
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
  api_path=$(jq -r ".\"$slug\".api_path // \"\"" "$INSTANCES_JSON_FILE")

  # Compute effective_api_path based on USE_API_PATH flag
  # This must match the logic in start-instances.sh
  effective_api_path=""
  if [ "${USE_API_PATH:-false}" = "true" ] && [ -n "$api_path" ]; then
    effective_api_path="$api_path"
  fi

  echo "Container ID: $cid"
  echo "IP Address: $container_ip"
  echo "HTTP Port: $http_port (container port 8080)"
  if [ -n "$api_path" ]; then
    echo "API Path: $api_path (USE_API_PATH=${USE_API_PATH:-false})"
  fi
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
    # Use --tail to limit output and avoid pipe buffer issues with large logs
    # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
    if docker logs --tail 500 "$cid" 2>&1 | grep "Gerrit Code Review.*ready" >/dev/null 2>&1; then
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

  # Check if running in replica/headless mode
  # In this mode, the REST API is disabled so we use TCP port checks + SSH
  if is_replica_mode "$cid"; then
    echo ""
    echo "Gerrit is running in replica/headless mode"
    echo "Using TCP port checks (REST API is disabled in this mode)..."

    # Step 1: Check HTTP port is listening
    echo ""
    echo "Step 1: Checking HTTP port (8080)..."
    MAX_RETRIES=30
    RETRY_COUNT=0
    HTTP_PORT_SUCCESS=false

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
      if check_tcp_port "$container_ip" 8080 5; then
        HTTP_PORT_SUCCESS=true
        echo "  TCP port 8080 is listening ✅"
        break
      fi

      RETRY_COUNT=$((RETRY_COUNT + 1))
      if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        sleep 2
        if [ $((RETRY_COUNT % 5)) -eq 0 ]; then
          echo "  Retry $RETRY_COUNT/$MAX_RETRIES (waiting for HTTP port)"
        fi
      fi
    done

    if [ "$HTTP_PORT_SUCCESS" = "false" ]; then
      echo "::error::TCP port check failed for $slug ❌"
      echo "::error::HTTP port 8080 not listening after $MAX_RETRIES retries"
      CHECK_FAILED=1
      echo ""
      echo "Container logs (last 50 lines):"
      docker logs "$cid" --tail 50 2>&1 || true
      echo ""
      continue
    fi

    # Step 2: Check SSH port is listening
    echo ""
    echo "Step 2: Checking SSH port (29418)..."
    MAX_RETRIES=15
    RETRY_COUNT=0
    SSH_PORT_SUCCESS=false

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
      if check_tcp_port "$container_ip" 29418 5; then
        SSH_PORT_SUCCESS=true
        echo "  TCP port 29418 is listening ✅"
        break
      fi

      RETRY_COUNT=$((RETRY_COUNT + 1))
      if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        sleep 2
        if [ $((RETRY_COUNT % 5)) -eq 0 ]; then
          echo "  Retry $RETRY_COUNT/$MAX_RETRIES (waiting for SSH port)"
        fi
      fi
    done

    if [ "$SSH_PORT_SUCCESS" = "false" ]; then
      echo "::error::TCP port check failed for $slug ❌"
      echo "::error::SSH port 29418 not listening after $MAX_RETRIES retries"
      CHECK_FAILED=1
      echo ""
      echo "Container logs (last 50 lines):"
      docker logs "$cid" --tail 50 2>&1 || true
      echo ""
      continue
    fi

    # Step 3: Verify Gerrit SSH service responds
    # Use ssh-keyscan to verify the SSH service is responding with a valid host key
    echo ""
    echo "Step 3: Verifying Gerrit SSH service..."
    SSH_KEYSCAN_RESULT=$(ssh-keyscan -p 29418 -T 10 "$container_ip" 2>/dev/null || echo "")
    if [ -n "$SSH_KEYSCAN_RESULT" ]; then
      echo "  Gerrit SSH service is responding ✅"
      echo "  Host key received: $(echo "$SSH_KEYSCAN_RESULT" | head -1 | awk '{print $2, $3}' | cut -c1-40)..."
    else
      echo "::warning::Could not retrieve SSH host key from Gerrit"
      echo "  SSH port is open but service may not be fully ready"
      # Don't fail here - the port is listening which is the main check
    fi

    echo ""
    echo "Replica mode health checks passed ✅"
  else
    echo ""
    echo "Performing HTTP health check..."

      # Test basic connectivity with version endpoint
      MAX_RETRIES=30
      RETRY_COUNT=0
      HTTP_SUCCESS=false

      # Build health check URL
      #
      # IMPORTANT: URL PATH CONFIGURATION - KEEP IN SYNC!
      # ================================================
      # The following files must be updated together if changing URL path handling:
      #
      #   1. scripts/start-instances.sh
      #      - canonical_url and listen_url variables
      #      - CANONICAL_WEB_URL and HTTPD_LISTEN_URL env vars in docker run
      #
      #   2. scripts/check-services.sh (this file)
      #      - HEALTH_URL construction below (must match listen_url path)
      #      - Plugin check URL further below (must match listen_url path)
      #
      #   3. test-gerrit-servers/.github/workflows/ (tunnel workflow)
      #      - Tunnel inputs configure public URLs
      #
      # When USE_API_PATH is true, we use the api_path to match the production
      # server's URL structure. Otherwise, we use root (/).
      #
      if [ -n "$effective_api_path" ]; then
        HEALTH_URL="http://$container_ip:8080${effective_api_path}/config/server/version"
      else
        HEALTH_URL="http://$container_ip:8080/config/server/version"
      fi
      echo "Health check URL: $HEALTH_URL"

      while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          --connect-timeout 5 \
          --max-time 10 \
          "$HEALTH_URL" 2>/dev/null \
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
      # NOTE: URL path must match listen_url - see KEEP IN SYNC comment above
      if [ -n "$effective_api_path" ]; then
        PLUGIN_CHECK=$(curl -s "http://$container_ip:8080${effective_api_path}/plugins/" \
          2>/dev/null || echo "")
      else
        PLUGIN_CHECK=$(curl -s "http://$container_ip:8080/plugins/" \
          2>/dev/null || echo "")
      fi

      if echo "$PLUGIN_CHECK" | grep "pull-replication" >/dev/null 2>&1; then
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
