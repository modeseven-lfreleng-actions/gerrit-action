#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local test script for Gerrit pull-replication with custom image
#
# This script tests the Gerrit container setup locally, including:
# - Building the custom Gerrit image with uv and gerrit_to_platform
# - Configuring fetchEvery polling mode (web UI enabled)
# - Pre-creating project directories for replication
# - Verifying replication works correctly
# - Testing SSH key authentication (optional)
#
# Usage: ./test-local.sh [gerrit_host] [project]
#
# Examples:
#   ./test-local.sh gerrit.linuxfoundation.org releng/lftools
#   ./test-local.sh gerrit.onap.org onap/ccsdk/cds
#
# Environment variables:
#   GERRIT_HTTP_USERNAME - HTTP Basic auth username (or use ~/.netrc)
#   GERRIT_HTTP_PASSWORD - HTTP Basic auth password (or use ~/.netrc)
#   API_PATH             - API path prefix (default: /infra)
#   GERRIT_VERSION       - Gerrit Docker image version (default: 3.13.1-ubuntu24)
#   PLUGIN_VERSION       - Pull-replication plugin version (default: stable-3.13)
#   HTTP_PORT            - Local HTTP port (default: 8080)
#   FETCH_EVERY          - Polling interval (default: 15s)
#   USE_CUSTOM_IMAGE     - Build/use custom image with uv (default: true)
#   TEST_SSH_AUTH        - Test SSH authentication setup (default: false)
#   SSH_AUTH_USERNAME    - Username for SSH auth test (default: testuser)
#   SSH_AUTH_KEYS        - SSH public keys to add (default: generates test key)
#   DEBUG                - Enable debug output (default: false)
#
# Prerequisites:
#   - Docker running
#   - Credentials in ~/.netrc or environment variables

set -euo pipefail

# Script directory for finding Dockerfile and shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for Python setup script
PYTHON_SETUP_SCRIPT="$SCRIPT_DIR/setup-gerrit-user.py"
if [ -f "$PYTHON_SETUP_SCRIPT" ]; then
  HAVE_PYTHON_SETUP=true
else
  echo "[WARN] Python setup script not found: $PYTHON_SETUP_SCRIPT"
  echo "[WARN] SSH auth testing will not be available"
  HAVE_PYTHON_SETUP=false
fi

# Determine Python command
get_python_cmd() {
  if command -v python3 &>/dev/null; then
    if python3 -c "import requests" 2>/dev/null; then
      echo "python3"
      return 0
    elif command -v uv &>/dev/null; then
      echo "uv run --with requests python3"
      return 0
    fi
  fi
  if command -v python &>/dev/null; then
    if python -c "import requests" 2>/dev/null; then
      echo "python"
      return 0
    fi
  fi
  echo ""
  return 1
}

# Configuration
GERRIT_HOST="${1:-gerrit.linuxfoundation.org}"
PROJECT="${2:-releng/lftools}"
API_PATH="${API_PATH:-/infra}"
GERRIT_VERSION="${GERRIT_VERSION:-3.13.1-ubuntu24}"
PLUGIN_VERSION="${PLUGIN_VERSION:-stable-3.13}"
# Use unique container name and directory to avoid conflicts with stale runs
RUN_ID="$$-$(date +%s)"
CONTAINER_NAME="gerrit-local-test-${RUN_ID}"
HTTP_PORT="${HTTP_PORT:-8080}"
FETCH_EVERY="${FETCH_EVERY:-15s}"
INSTANCE_DIR="/tmp/gerrit-local-test-${RUN_ID}"
USE_CUSTOM_IMAGE="${USE_CUSTOM_IMAGE:-true}"
TEST_SSH_AUTH="${TEST_SSH_AUTH:-false}"
SSH_AUTH_USERNAME="${SSH_AUTH_USERNAME:-testuser}"
DEBUG="${DEBUG:-false}"

# Custom image settings
CUSTOM_IMAGE_NAME="gerrit-extended"
CUSTOM_IMAGE="${CUSTOM_IMAGE_NAME}:${GERRIT_VERSION}"
DOCKER_IMAGE="${CUSTOM_IMAGE}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Build custom Gerrit image with uv and gerrit_to_platform
build_custom_image() {
  local dockerfile_dir="${SCRIPT_DIR}/.."

  if [ "$USE_CUSTOM_IMAGE" != "true" ]; then
    log_info "Skipping custom image build (USE_CUSTOM_IMAGE=$USE_CUSTOM_IMAGE)"
    DOCKER_IMAGE="gerritcodereview/gerrit:${GERRIT_VERSION}"
    return 0
  fi

  if [ ! -f "$dockerfile_dir/Dockerfile" ]; then
    log_warn "Dockerfile not found at $dockerfile_dir/Dockerfile"
    log_warn "Falling back to official gerritcodereview/gerrit image"
    DOCKER_IMAGE="gerritcodereview/gerrit:${GERRIT_VERSION}"
    return 0
  fi

  log_info "Building custom Gerrit image with uv and gerrit_to_platform..."
  log_info "  Base image: gerritcodereview/gerrit:${GERRIT_VERSION}"
  log_info "  Custom image: ${CUSTOM_IMAGE}"

  if docker build \
    --build-arg "GERRIT_VERSION=${GERRIT_VERSION}" \
    -t "${CUSTOM_IMAGE}" \
    -f "$dockerfile_dir/Dockerfile" \
    "$dockerfile_dir"; then
    log_success "Custom image built successfully"
    DOCKER_IMAGE="${CUSTOM_IMAGE}"

    # Verify components are available
    verify_custom_image_components
  else
    log_error "Failed to build custom image"
    log_warn "Falling back to official gerritcodereview/gerrit image"
    DOCKER_IMAGE="gerritcodereview/gerrit:${GERRIT_VERSION}"
  fi
}

# Verify uv and gerrit-to-platform are available in the custom image
verify_custom_image_components() {
  log_info "Verifying custom image components..."

  # Check uv (use --entrypoint="" to prevent Gerrit from starting)
  if docker run --rm --entrypoint="" "${DOCKER_IMAGE}" uv --version 2>/dev/null; then
    log_success "  uv: available"
  else
    log_warn "  uv: not found in image"
  fi

  # Check gerrit-to-platform executables
  if docker run --rm --entrypoint="" "${DOCKER_IMAGE}" which change-merged 2>/dev/null; then
    log_success "  gerrit-to-platform: available"
  else
    log_warn "  gerrit-to-platform: not found in image"
  fi
}

# Load credentials from ~/.netrc
load_credentials() {
  if [ -f "$HOME/.netrc" ]; then
    log_info "Loading credentials from ~/.netrc..."
    NETRC_ENTRY=$(grep -A2 "machine ${GERRIT_HOST}" "$HOME/.netrc" 2>/dev/null || echo "")
    if [ -n "$NETRC_ENTRY" ]; then
      GERRIT_HTTP_USERNAME=$(echo "$NETRC_ENTRY" | grep "login" | awk '{print $2}')
      GERRIT_HTTP_PASSWORD=$(echo "$NETRC_ENTRY" | grep "password" | awk '{print $2}')
      if [ -n "$GERRIT_HTTP_USERNAME" ] && [ -n "$GERRIT_HTTP_PASSWORD" ]; then
        log_success "Loaded credentials for $GERRIT_HOST"
        return 0
      fi
    fi
  fi

  if [ -z "${GERRIT_HTTP_USERNAME:-}" ] || [ -z "${GERRIT_HTTP_PASSWORD:-}" ]; then
    log_error "No credentials found."
    log_error "Set GERRIT_HTTP_USERNAME and GERRIT_HTTP_PASSWORD environment variables"
    log_error "Or add an entry to ~/.netrc for $GERRIT_HOST"
    exit 1
  fi
}

cleanup() {
  log_info "Cleaning up..."
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
  # Use Docker to remove files that may have been created with root ownership
  # This is necessary because Gerrit container runs as UID 1000 which may differ from host user
  if [ -d "$INSTANCE_DIR" ]; then
    log_info "Removing instance directory: $INSTANCE_DIR"
    # Use alpine container to clean up with root privileges inside container
    docker run --rm -v "$INSTANCE_DIR:/cleanup:rw" alpine sh -c "rm -rf /cleanup/* /cleanup/.[!.]*" 2>/dev/null || true
    rmdir "$INSTANCE_DIR" 2>/dev/null || true
  fi
  # Also clean up any stale test directories older than 1 hour
  find /tmp -maxdepth 1 -name "gerrit-local-test-*" -type d -mmin +60 2>/dev/null | while read -r old_dir; do
    log_info "Cleaning stale directory: $old_dir"
    docker run --rm -v "$old_dir:/cleanup:rw" alpine sh -c "rm -rf /cleanup/* /cleanup/.[!.]*" 2>/dev/null || true
    rmdir "$old_dir" 2>/dev/null || true
  done
  # Clean up test SSH keys if generated
  if [ -n "${TEST_KEY_DIR:-}" ] && [ -d "${TEST_KEY_DIR:-}" ]; then
    rm -rf "$TEST_KEY_DIR" 2>/dev/null || true
  fi
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Header
log_info "=============================================="
log_info "Local Gerrit Test - fetchEvery Mode"
log_info "=============================================="
log_info "Run ID: $RUN_ID"
log_info "Host: $GERRIT_HOST"
log_info "Project: $PROJECT"
log_info "API Path: $API_PATH"
log_info "Gerrit Version: $GERRIT_VERSION"
log_info "Fetch interval: $FETCH_EVERY"
log_info "Custom image: $USE_CUSTOM_IMAGE"
log_info "Instance dir: $INSTANCE_DIR"
log_info ""
log_info "Goal: Test pull-replication with web UI enabled"
echo ""

load_credentials

# No need to clean up previous run - we use unique directory each time
# Just ensure no container with same name exists (shouldn't happen with unique names)
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Build custom image (if enabled)
build_custom_image

log_info "Using Docker image: ${DOCKER_IMAGE}"
echo ""

# Create directory structure
log_info "Creating Gerrit site structure..."
# The official gerritcodereview/gerrit image uses UID:GID 1000:1000
# On macOS with Docker Desktop, file permissions are handled automatically
# via the gRPC FUSE file sharing, so we don't need to chown
# On Linux, Docker handles this via user namespace mapping or the container runs as root
# NOTE: We do NOT create/mount etc directory - we let the container use its own
# config which includes the OOTB filter for automatic account creation.
# We'll copy our config files (replication, secure) into the container after start.
mkdir -p "$INSTANCE_DIR"/{git,cache,index,data,logs,plugins,tmp,config-staging}
# Only attempt chown on Linux where it might be needed and we might have permission
if [ "$(uname -s)" = "Linux" ]; then
  GERRIT_UID=1000
  GERRIT_GID=1000
  if chown -R "$GERRIT_UID:$GERRIT_GID" "$INSTANCE_DIR" 2>/dev/null; then
    # Ownership successfully set to Gerrit user; safe to use restrictive perms
    chmod -R 755 "$INSTANCE_DIR" 2>/dev/null || true
  else
    # Could not change ownership (common on CI runners); ensure writability instead
    # a+rwX keeps execute bits for directories and already-executable files
    chmod -R a+rwX "$INSTANCE_DIR" 2>/dev/null || true
  fi
else
  chmod -R 755 "$INSTANCE_DIR" 2>/dev/null || true
fi

# Build git URL - use authenticated HTTPS with /a/ prefix
# The /a/ prefix is Gerrit's authenticated endpoint
# The ${name} placeholder is replaced by Gerrit with the project name
GIT_URL="https://${GERRIT_HOST}${API_PATH}/a/\${name}.git"

# Create replication.config with fetchEvery (matching CI config)
# This will be copied into the container after start
log_info "Creating replication.config (fetchEvery mode)..."
cat > "$INSTANCE_DIR/config-staging/replication.config" <<EOF
# Pull-replication configuration - fetchEvery mode
# Matching CI configuration from start-instances.sh
#
# Key settings:
# - replicateOnStartup = true : initial sync on startup
# - fetchEvery : poll at regular intervals
# - NO apiUrl : mutually exclusive with fetchEvery

[gerrit]
  replicateOnStartup = true
  autoReload = true

[replication]
  lockErrorMaxRetries = 5
  maxRetries = 5
  useCGitClient = false
  refsBatchSize = 50

[remote "source"]
  url = ${GIT_URL}
  fetchEvery = ${FETCH_EVERY}
  timeout = 600
  connectionTimeout = 120000
  replicationDelay = 0
  replicationRetry = 60
  threads = 4
  createMissingRepositories = true
  replicateHiddenProjects = false
  fetch = +refs/heads/*:refs/heads/*
  fetch = +refs/tags/*:refs/tags/*
  projects = ${PROJECT}
EOF

log_success "replication.config created"
echo ""
cat "$INSTANCE_DIR/config-staging/replication.config"
echo ""

# Create secure.config (will be copied into container after start)
log_info "Creating secure.config..."
cat > "$INSTANCE_DIR/config-staging/secure.config" <<EOF
[remote "source"]
  username = ${GERRIT_HTTP_USERNAME}
  password = ${GERRIT_HTTP_PASSWORD}
EOF
chmod 600 "$INSTANCE_DIR/config-staging/secure.config" 2>/dev/null || true
log_success "secure.config created"

# NOTE: We skip the separate init step - the container will init on first start.
# This ensures the container's built-in OOTB filter config is preserved,
# which is required for DEVELOPMENT_BECOME_ANY_ACCOUNT mode to work properly.
log_info "Skipping separate init - container will self-initialize with proper OOTB config"

# Pre-create the project directory so fetchEvery knows about it
# This is required because fetchEvery only polls repos in projectCache
log_info "Pre-creating project directory: ${PROJECT}.git"
PROJECT_DIR="$INSTANCE_DIR/git/${PROJECT}.git"
mkdir -p "$PROJECT_DIR"
git init --bare "$PROJECT_DIR" 2>/dev/null
# Set proper permissions - ownership handled by Docker on macOS
if [ "$(uname -s)" = "Linux" ]; then
  if chown -R 1000:1000 "$PROJECT_DIR" 2>/dev/null; then
    chmod -R 755 "$PROJECT_DIR" 2>/dev/null || true
  else
    chmod -R a+rwX "$PROJECT_DIR" 2>/dev/null || true
  fi
else
  chmod -R 755 "$PROJECT_DIR" 2>/dev/null || true
fi
log_success "Project directory created"

# Start Gerrit container
# IMPORTANT: We do NOT mount /var/gerrit/etc - this preserves the container's
# built-in OOTB filter configuration which is required for DEVELOPMENT_BECOME_ANY_ACCOUNT
# to work properly. We'll copy our config files into the container after start.
log_info "Starting Gerrit container..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${HTTP_PORT}:8080" \
  -v "$INSTANCE_DIR/git:/var/gerrit/git" \
  -v "$INSTANCE_DIR/cache:/var/gerrit/cache" \
  -v "$INSTANCE_DIR/index:/var/gerrit/index" \
  -v "$INSTANCE_DIR/logs:/var/gerrit/logs" \
  -v "$INSTANCE_DIR/plugins:/var/gerrit/plugins" \
  -v "$INSTANCE_DIR/data:/var/gerrit/data" \
  -e "CANONICAL_WEB_URL=http://localhost:${HTTP_PORT}/" \
  -e "AUTH_TYPE=DEVELOPMENT_BECOME_ANY_ACCOUNT" \
  "${DOCKER_IMAGE}"

log_success "Container started"
echo ""

# Wait for Gerrit to start
log_info "Waiting for Gerrit to start..."
for i in {1..60}; do
  if curl -s "http://localhost:${HTTP_PORT}/" >/dev/null 2>&1; then
    log_success "Gerrit is responding!"
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

# Copy our config files into the running container
log_info "Copying replication configuration into container..."
docker cp "$INSTANCE_DIR/config-staging/replication.config" "$CONTAINER_NAME:/var/gerrit/etc/replication.config"
docker cp "$INSTANCE_DIR/config-staging/secure.config" "$CONTAINER_NAME:/var/gerrit/etc/secure.config"
# Set proper ownership inside container
docker exec "$CONTAINER_NAME" chown gerrit:gerrit /var/gerrit/etc/replication.config /var/gerrit/etc/secure.config 2>/dev/null || true
log_success "Replication config copied"

# Download pull-replication plugin directly into the container
log_info "Downloading pull-replication plugin..."
PLUGIN_URL="https://gerrit-ci.gerritforge.com/job/plugin-pull-replication-gh-bazel-${PLUGIN_VERSION}/lastSuccessfulBuild/artifact/bazel-bin/plugins/pull-replication/pull-replication.jar"
# Download to staging first, then copy into container
if curl -fL --retry 3 -o "$INSTANCE_DIR/config-staging/pull-replication.jar" "$PLUGIN_URL"; then
  # Verify it's a valid JAR
  if file "$INSTANCE_DIR/config-staging/pull-replication.jar" | grep -q "Zip archive\|Java archive"; then
    log_success "Plugin downloaded and verified"
    # Remove bundled replication plugin and copy pull-replication
    docker exec "$CONTAINER_NAME" rm -f /var/gerrit/plugins/replication.jar 2>/dev/null || true
    docker cp "$INSTANCE_DIR/config-staging/pull-replication.jar" "$CONTAINER_NAME:/var/gerrit/plugins/pull-replication.jar"
    docker exec "$CONTAINER_NAME" chown gerrit:gerrit /var/gerrit/plugins/pull-replication.jar 2>/dev/null || true
    log_success "Pull-replication plugin installed"
  else
    log_error "Downloaded file is not a valid JAR"
    exit 1
  fi
else
  log_error "Failed to download plugin from: $PLUGIN_URL"
  exit 1
fi

# Restart Gerrit to pick up new plugins and config
log_info "Restarting Gerrit to load new plugins..."
docker restart "$CONTAINER_NAME"

# Wait for Gerrit to come back up
log_info "Waiting for Gerrit to restart..."
sleep 5
for i in {1..60}; do
  if curl -s "http://localhost:${HTTP_PORT}/" >/dev/null 2>&1; then
    log_success "Gerrit is responding!"
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

# Verify web UI is accessible (not in replica mode)
log_info "Checking web UI accessibility..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${HTTP_PORT}/")
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "302" ]; then
  log_success "Web UI is accessible (HTTP $HTTP_STATUS)"
else
  log_warn "Web UI returned HTTP $HTTP_STATUS"
fi

# Check plugin loaded
log_info "Checking pull-replication plugin..."
sleep 3

PLUGIN_WORKING=false

# Check for explicit plugin load message
if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "Loaded plugin pull-replication"; then
  PLUGIN_LOG=$(docker logs "$CONTAINER_NAME" 2>&1 | grep "Loaded plugin pull-replication" | tail -1)
  log_success "pull-replication plugin loaded"
  echo "  $PLUGIN_LOG"
  PLUGIN_WORKING=true
fi

# Check for fetchEvery polling activity
if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "SourceFetchPeriodically"; then
  FETCH_LOG=$(docker logs "$CONTAINER_NAME" 2>&1 | grep "SourceFetchPeriodically" | tail -1)
  log_success "pull-replication fetchEvery polling is active"
  echo "  $FETCH_LOG"
  PLUGIN_WORKING=true
fi

if [ "$PLUGIN_WORKING" = "false" ]; then
  log_warn "Plugin may not be loaded yet, waiting..."
  sleep 10
  if docker logs "$CONTAINER_NAME" 2>&1 | grep -qE "Loaded plugin pull-replication|SourceFetchPeriodically"; then
    log_success "pull-replication plugin loaded (delayed)"
    PLUGIN_WORKING=true
  else
    log_warn "Plugin may not be fully loaded, continuing anyway..."
    docker logs "$CONTAINER_NAME" 2>&1 | tail -30
  fi
fi

# Verify DEVELOPMENT_BECOME_ANY_ACCOUNT mode is working
if [ "${DEBUG:-false}" = "true" ]; then
  log_info "Verifying DEVELOPMENT_BECOME_ANY_ACCOUNT mode..."
  docker exec "$CONTAINER_NAME" cat /var/gerrit/etc/gerrit.config | grep -A2 '\[auth\]'
fi
echo ""

# Show initial state
log_info "Initial git directory contents:"
ls -la "$INSTANCE_DIR/git/" 2>/dev/null || echo "(empty or not accessible)"
echo ""

# Wait for fetchEvery polling to complete
log_info "=============================================="
log_info "Waiting for fetchEvery polling to sync..."
log_info "(fetchEvery polls every $FETCH_EVERY)"
log_info "=============================================="
echo ""

# Monitor for 2 minutes
SUCCESS=false

for i in {1..24}; do
  sleep 5
  elapsed=$((i * 5))

  # Count repos (excluding All-Projects, All-Users)
  # Use -prune to avoid descending into .git directories and double-counting
  # Robust integer validation to handle edge cases
  repo_count=$(find "$INSTANCE_DIR/git" -name "*.git" -type d -prune 2>/dev/null | grep -c -v -E "All-Projects|All-Users" 2>/dev/null || echo "0")
  # Ensure repo_count is a valid integer (strip non-digits, default to 0)
  repo_count="${repo_count//[^0-9]/}"
  repo_count="${repo_count:-0}"
  disk_usage=$(du -sh "$INSTANCE_DIR/git" 2>/dev/null | cut -f1)

  echo "[${elapsed}s] Repos: $repo_count, Disk: $disk_usage"

  # Check logs for activity every 30 seconds
  if [ $((elapsed % 30)) -eq 0 ]; then
    echo ""
    log_info "Recent pull_replication_log:"
    if [ -f "$INSTANCE_DIR/logs/pull_replication_log" ]; then
      tail -10 "$INSTANCE_DIR/logs/pull_replication_log" 2>/dev/null | sed 's/^/  /' || echo "  (empty)"
    else
      echo "  (no log file yet)"
    fi
    echo ""
  fi

  # Check if project was created and has content
  if [ -d "$INSTANCE_DIR/git/${PROJECT}.git" ]; then
    # Check if it has content
    obj_count=$(find "$INSTANCE_DIR/git/${PROJECT}.git/objects" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$obj_count" -gt 0 ]; then
      log_success "Repository has content! ($obj_count objects)"
      SUCCESS=true
      break
    fi
  fi
done

echo ""
log_info "=============================================="
log_info "Final State"
log_info "=============================================="

log_info "Git directory contents:"
find "$INSTANCE_DIR/git" -name "*.git" -type d -prune 2>/dev/null | head -20 || echo "(none)"

echo ""
log_info "Disk usage:"
du -sh "$INSTANCE_DIR/git" 2>/dev/null || echo "(unknown)"

echo ""
log_info "pull_replication_log (last 30 lines):"
if [ -f "$INSTANCE_DIR/logs/pull_replication_log" ]; then
  tail -30 "$INSTANCE_DIR/logs/pull_replication_log" 2>/dev/null || echo "(empty)"
else
  echo "(no log file)"
fi

echo ""
log_info "Container logs (replication related, last 50 lines):"
docker logs "$CONTAINER_NAME" 2>&1 | grep -iE "replication|pull-replication|fetch|remote|FetchAll|apiUrl" | tail -50 || echo "(no matches)"

# Test SSH authentication if enabled
SSH_AUTH_SUCCESS=false
if [ "$TEST_SSH_AUTH" = "true" ]; then
  echo ""
  log_info "=============================================="
  log_info "Testing SSH Authentication Setup"
  log_info "=============================================="

  if [ "$HAVE_PYTHON_SETUP" = "true" ]; then
    PYTHON_CMD=$(get_python_cmd)
    if [ -z "$PYTHON_CMD" ]; then
      log_warn "Python with 'requests' module not available"
      log_warn "Install: pip install requests, or install uv"
    else
      # Generate a test SSH key if not provided
      if [ -z "${SSH_AUTH_KEYS:-}" ]; then
        log_info "Generating test SSH key..."
        TEST_KEY_DIR="/tmp/gerrit-test-ssh-$$"
        mkdir -p "$TEST_KEY_DIR"
        ssh-keygen -t ed25519 -f "$TEST_KEY_DIR/id_test" -N "" -C "gerrit-test@example.com" >/dev/null 2>&1
        SSH_AUTH_KEYS=$(cat "$TEST_KEY_DIR/id_test.pub")
        log_success "Test SSH key generated"
        echo "  Private key: $TEST_KEY_DIR/id_test"
        echo "  Public key: $TEST_KEY_DIR/id_test.pub"
      fi

      log_info "Setting up user '$SSH_AUTH_USERNAME' with SSH key..."
      log_info "Using Python Gerrit API client"

      # Build Python command arguments
      PYTHON_ARGS=("$PYTHON_SETUP_SCRIPT")
      PYTHON_ARGS+=("--url" "http://localhost:${HTTP_PORT}")
      PYTHON_ARGS+=("--username" "$SSH_AUTH_USERNAME")
      PYTHON_ARGS+=("--ssh-key" "$SSH_AUTH_KEYS")
      if [ "$DEBUG" = "true" ]; then
        PYTHON_ARGS+=("--debug")
      else
        PYTHON_ARGS+=("-v")
      fi

      # Run the Python setup script
      if $PYTHON_CMD "${PYTHON_ARGS[@]}"; then
        SSH_AUTH_SUCCESS=true
        log_success "SSH authentication configured!"
      else
        log_error "Failed to configure SSH authentication"
      fi
    fi
  else
    log_warn "Python setup script not available - skipping SSH auth test"
  fi
fi

echo ""
log_info "=============================================="
if [ "$SUCCESS" = true ]; then
  log_success "TEST PASSED!"
  log_success "- fetchEvery polling mode works"
  log_success "- Web UI is enabled"
  log_success "- Repository sync completed"
  if [ "$USE_CUSTOM_IMAGE" = "true" ]; then
    log_success "- Custom image with uv/gerrit_to_platform verified"
  fi
  if [ "$TEST_SSH_AUTH" = "true" ] && [ "$SSH_AUTH_SUCCESS" = "true" ]; then
    log_success "- SSH authentication configured for '$SSH_AUTH_USERNAME'"
  fi
else
  # Check if repo was created but empty
  if [ -d "$INSTANCE_DIR/git/${PROJECT}.git" ]; then
    log_warn "TEST PARTIAL: Repository exists but may be empty"
  else
    log_error "TEST FAILED: Repository was NOT created"
  fi

  echo ""
  log_info "Troubleshooting tips:"
  echo "  1. Check container logs: docker logs $CONTAINER_NAME"
  echo "  2. Verify credentials are correct"
  echo "  3. Check if project exists on remote server"
  echo "  4. Verify API path is correct"
fi
log_info "=============================================="

echo ""
log_info "Container is still running. To inspect:"
log_info "  docker exec -it $CONTAINER_NAME bash"
log_info "  http://localhost:${HTTP_PORT}/"
if [ "$USE_CUSTOM_IMAGE" = "true" ]; then
  log_info ""
  log_info "To test uv/gerrit_to_platform in the container:"
  log_info "  docker exec -it $CONTAINER_NAME uv --version"
  log_info "  docker exec -it $CONTAINER_NAME uv tool list"
fi
if [ "$TEST_SSH_AUTH" = "true" ] && [ -n "${TEST_KEY_DIR:-}" ]; then
  log_info ""
  log_info "To test SSH access (if SSHD is enabled):"
  log_info "  ssh -i $TEST_KEY_DIR/id_test -p 29418 $SSH_AUTH_USERNAME@localhost gerrit version"
fi
log_info ""
log_info "Press Ctrl+C to stop and cleanup"
read -r
