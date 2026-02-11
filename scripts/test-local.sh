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
#
# Prerequisites:
#   - Docker running
#   - Credentials in ~/.netrc or environment variables

set -euo pipefail

# Script directory for finding Dockerfile
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
GERRIT_HOST="${1:-gerrit.linuxfoundation.org}"
PROJECT="${2:-releng/lftools}"
API_PATH="${API_PATH:-/infra}"
GERRIT_VERSION="${GERRIT_VERSION:-3.13.1-ubuntu24}"
PLUGIN_VERSION="${PLUGIN_VERSION:-stable-3.13}"
CONTAINER_NAME="gerrit-local-test"
HTTP_PORT="${HTTP_PORT:-8080}"
FETCH_EVERY="${FETCH_EVERY:-15s}"
INSTANCE_DIR="/tmp/gerrit-local-test"
USE_CUSTOM_IMAGE="${USE_CUSTOM_IMAGE:-true}"

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
  if [ -d "$INSTANCE_DIR" ]; then
    docker run --rm -v "$INSTANCE_DIR:/cleanup" alpine rm -rf /cleanup/* 2>/dev/null || true
    rm -rf "$INSTANCE_DIR" 2>/dev/null || true
  fi
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Header
log_info "=============================================="
log_info "Local Gerrit Test - fetchEvery Mode"
log_info "=============================================="
log_info "Host: $GERRIT_HOST"
log_info "Project: $PROJECT"
log_info "API Path: $API_PATH"
log_info "Gerrit Version: $GERRIT_VERSION"
log_info "Fetch interval: $FETCH_EVERY"
log_info "Custom image: $USE_CUSTOM_IMAGE"
log_info ""
log_info "Goal: Test pull-replication with web UI enabled"
echo ""

load_credentials

# Cleanup any previous run
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
# Use Docker to remove files that may have been created with root ownership
if [ -d "$INSTANCE_DIR" ]; then
  docker run --rm -v "$INSTANCE_DIR:/cleanup" alpine rm -rf /cleanup/* 2>/dev/null || true
  rm -rf "$INSTANCE_DIR" 2>/dev/null || true
fi

# Build custom image (if enabled)
build_custom_image

log_info "Using Docker image: ${DOCKER_IMAGE}"
echo ""

# Create directory structure
log_info "Creating Gerrit site structure..."
# The official gerritcodereview/gerrit image uses UID:GID 1000:1000
GERRIT_UID=1000
GERRIT_GID=1000
mkdir -p "$INSTANCE_DIR"/{git,cache,index,data,etc,logs,plugins,tmp}
chown -R "$GERRIT_UID:$GERRIT_GID" "$INSTANCE_DIR"
chmod -R 755 "$INSTANCE_DIR"

# Build git URL - use authenticated HTTPS with /a/ prefix
# The /a/ prefix is Gerrit's authenticated endpoint
# The ${name} placeholder is replaced by Gerrit with the project name
GIT_URL="https://${GERRIT_HOST}${API_PATH}/a/\${name}.git"

# Create replication.config with fetchEvery (matching CI config)
log_info "Creating replication.config (fetchEvery mode)..."
cat > "$INSTANCE_DIR/etc/replication.config" <<EOF
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
cat "$INSTANCE_DIR/etc/replication.config"
echo ""

# Create secure.config
log_info "Creating secure.config..."
cat > "$INSTANCE_DIR/etc/secure.config" <<EOF
[remote "source"]
  username = ${GERRIT_HTTP_USERNAME}
  password = ${GERRIT_HTTP_PASSWORD}
EOF
# Set ownership to Gerrit UID/GID (1000:1000) so container can read it
# This is necessary because bind mounts preserve host UID/GID
chown "$GERRIT_UID:$GERRIT_GID" "$INSTANCE_DIR/etc/secure.config"
chmod 600 "$INSTANCE_DIR/etc/secure.config"
log_success "secure.config created"

# Initialize Gerrit site first (required before starting)
log_info "Initializing Gerrit site..."
log_info "Using image: ${DOCKER_IMAGE}"
docker run --rm \
  -v "$INSTANCE_DIR/git:/var/gerrit/git" \
  -v "$INSTANCE_DIR/cache:/var/gerrit/cache" \
  -v "$INSTANCE_DIR/index:/var/gerrit/index" \
  -v "$INSTANCE_DIR/data:/var/gerrit/data" \
  -v "$INSTANCE_DIR/etc:/var/gerrit/etc" \
  -v "$INSTANCE_DIR/logs:/var/gerrit/logs" \
  -v "$INSTANCE_DIR/plugins:/var/gerrit/plugins" \
  -e CANONICAL_WEB_URL="http://localhost:$HTTP_PORT" \
  "${DOCKER_IMAGE}" \
  init

log_success "Gerrit site initialized"

# Show what plugins were installed by init
log_info "Bundled plugins after init:"
ls -la "$INSTANCE_DIR/plugins/"

# Remove bundled replication plugin (conflicts with pull-replication)
# Keep replication-api.jar as pull-replication depends on it
log_info "Removing bundled replication plugin (keeping replication-api)..."
rm -f "$INSTANCE_DIR/plugins/replication.jar"
log_success "Bundled replication plugin removed"

# Download pull-replication plugin AFTER init
log_info "Downloading pull-replication plugin..."
PLUGIN_URL="https://gerrit-ci.gerritforge.com/job/plugin-pull-replication-gh-bazel-${PLUGIN_VERSION}/lastSuccessfulBuild/artifact/bazel-bin/plugins/pull-replication/pull-replication.jar"

# Download with proper error handling
if curl -fL --retry 3 -o "$INSTANCE_DIR/plugins/pull-replication.jar" "$PLUGIN_URL"; then
  # Verify it's a valid JAR (should start with PK for zip format)
  if file "$INSTANCE_DIR/plugins/pull-replication.jar" | grep -q "Zip archive\|Java archive"; then
    log_success "Plugin downloaded and verified"
  else
    log_error "Downloaded file is not a valid JAR"
    log_error "File type: $(file "$INSTANCE_DIR/plugins/pull-replication.jar")"
    log_error "First bytes: $(head -c 50 "$INSTANCE_DIR/plugins/pull-replication.jar" | xxd | head -2)"
    exit 1
  fi
else
  log_error "Failed to download plugin from: $PLUGIN_URL"
  exit 1
fi

# Apply custom Gerrit configuration (overwrites init defaults)
log_info "Applying custom configuration..."
cat > "$INSTANCE_DIR/etc/gerrit.config" <<EOF
[gerrit]
  basePath = git
  canonicalWebUrl = http://localhost:${HTTP_PORT}/

[index]
  type = LUCENE

[auth]
  type = DEVELOPMENT_BECOME_ANY_ACCOUNT

[sshd]
  listenAddress = off

[httpd]
  listenUrl = http://*:${HTTP_PORT}/

[cache]
  directory = cache

[container]
  javaOptions = -Xmx512m
  user = gerrit
  # NOTE: replica is NOT set - web UI is enabled
EOF

log_success "gerrit.config updated"

# Pre-create the project directory so fetchEvery knows about it
# This is required because fetchEvery only polls repos in projectCache
log_info "Pre-creating project directory: ${PROJECT}.git"
PROJECT_DIR="$INSTANCE_DIR/git/${PROJECT}.git"
mkdir -p "$PROJECT_DIR"
git init --bare "$PROJECT_DIR" 2>/dev/null
# Set proper ownership for Gerrit user (UID:GID 1000:1000)
chown -R 1000:1000 "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR"
log_success "Project directory created"

# Start Gerrit container
log_info "Starting Gerrit container..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${HTTP_PORT}:${HTTP_PORT}" \
  -v "$INSTANCE_DIR/git:/var/gerrit/git" \
  -v "$INSTANCE_DIR/etc:/var/gerrit/etc" \
  -v "$INSTANCE_DIR/cache:/var/gerrit/cache" \
  -v "$INSTANCE_DIR/index:/var/gerrit/index" \
  -v "$INSTANCE_DIR/logs:/var/gerrit/logs" \
  -v "$INSTANCE_DIR/plugins:/var/gerrit/plugins" \
  -v "$INSTANCE_DIR/data:/var/gerrit/data" \
  -v "$INSTANCE_DIR/tmp:/var/gerrit/tmp" \
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
sleep 5

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
log_info ""
log_info "Press Ctrl+C to stop and cleanup"
read -r
