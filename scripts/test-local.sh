#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Docker test script for debugging pull-replication
# Usage: ./test-local.sh [gerrit_host] [api_path] [project_filter]
#
# Example:
#   ./test-local.sh gerrit.linuxfoundation.org /infra releng/lftools
#   ./test-local.sh gerrit.linuxfoundation.org /infra "releng/lftools,releng/ciman"
#   ./test-local.sh gerrit.linuxfoundation.org /infra ""           # All projects
#   ./test-local.sh gerrit.linuxfoundation.org /infra "all"        # All projects
#   ./test-local.sh gerrit.linuxfoundation.org /infra "releng/.*"  # Regex pattern
#
# Prerequisites:
#   - Docker running
#   - HTTP credentials in environment or .env file:
#     export GERRIT_HTTP_USERNAME="your-username"
#     export GERRIT_HTTP_PASSWORD="your-password"
#
# Key insight: The pull-replication plugin's replicateOnStartup feature
# iterates over projectCache.all() - meaning projects must exist locally
# before they can be replicated. This script creates empty bare repos
# for each project before starting Gerrit.

set -euo pipefail

# Configuration
GERRIT_HOST="${1:-gerrit.linuxfoundation.org}"
API_PATH="${2:-/infra}"
PROJECT_FILTER="${3:-releng/lftools}"
MAX_PROJECTS="${MAX_PROJECTS:-100}"  # Limit for fetching all projects
GERRIT_VERSION="${GERRIT_VERSION:-3.13.1-ubuntu24}"
PLUGIN_VERSION="${PLUGIN_VERSION:-stable-3.13}"
CONTAINER_NAME="gerrit-local-test"
HTTP_PORT="${HTTP_PORT:-8080}"
SSH_PORT="${SSH_PORT:-29418}"
REPLICA_MODE="${REPLICA_MODE:-true}"

# Fetch project list from remote Gerrit server
fetch_remote_projects() {
  local gerrit_host="$1"
  local api_path="${2:-}"
  local project_filter="${3:-}"
  local max_projects="${4:-100}"

  log_info "Fetching project list from $gerrit_host..."

  # Build API URL
  local api_url
  if [ -n "$api_path" ]; then
    api_path="${api_path#/}"  # Remove leading slash
    api_url="https://${gerrit_host}/${api_path}/projects/"
  else
    api_url="https://${gerrit_host}/projects/"
  fi

  # Add query parameters
  local query_params="n=${max_projects}"
  if [ -n "$project_filter" ] && [ "$project_filter" != ".*" ] && [ "$project_filter" != "all" ]; then
    # Use regex filter if it looks like a pattern, otherwise prefix match
    if [[ "$project_filter" == *"*"* ]] || [[ "$project_filter" == *"."* ]]; then
      query_params="${query_params}&r=$(printf '%s' "$project_filter" | jq -sRr @uri)"
    else
      query_params="${query_params}&p=$(printf '%s' "$project_filter" | jq -sRr @uri)"
    fi
  fi

  local full_url="${api_url}?${query_params}"
  log_info "  API URL: $full_url"

  # Fetch projects (Gerrit API returns )]}' prefix for XSSI protection)
  local response
  response=$(curl -s --connect-timeout 30 --max-time 60 "$full_url" 2>/dev/null) || {
    log_error "Failed to fetch project list from $gerrit_host"
    return 1
  }

  # Remove XSSI protection prefix and parse JSON
  local projects
  projects=$(echo "$response" | tail -n +2 | jq -r 'keys[]' 2>/dev/null) || {
    log_error "Failed to parse project list response"
    return 1
  }

  local count
  count=$(echo "$projects" | grep -c . || echo "0")
  log_success "Found $count projects on remote server"

  # Return project list (one per line)
  echo "$projects"
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Load .env file if it exists
if [ -f ".env" ]; then
  log_info "Loading .env file..."
  # shellcheck disable=SC1091
  source .env
fi

# Try to load credentials from .netrc if not already set
if [ -z "${GERRIT_HTTP_USERNAME:-}" ] || [ -z "${GERRIT_HTTP_PASSWORD:-}" ]; then
  if [ -f "$HOME/.netrc" ]; then
    log_info "Checking ~/.netrc for credentials..."
    NETRC_ENTRY=$(grep -A2 "machine ${GERRIT_HOST}" "$HOME/.netrc" 2>/dev/null || echo "")
    if [ -n "$NETRC_ENTRY" ]; then
      GERRIT_HTTP_USERNAME=$(echo "$NETRC_ENTRY" | grep "login" | awk '{print $2}')
      GERRIT_HTTP_PASSWORD=$(echo "$NETRC_ENTRY" | grep "password" | awk '{print $2}')
      if [ -n "$GERRIT_HTTP_USERNAME" ] && [ -n "$GERRIT_HTTP_PASSWORD" ]; then
        log_success "Loaded credentials from ~/.netrc for $GERRIT_HOST"
      fi
    fi
  fi
fi

# Check for credentials
if [ -z "${GERRIT_HTTP_USERNAME:-}" ] || [ -z "${GERRIT_HTTP_PASSWORD:-}" ]; then
  log_error "Missing credentials!"
  echo ""
  echo "Please set environment variables:"
  echo "  export GERRIT_HTTP_USERNAME='your-username'"
  echo "  export GERRIT_HTTP_PASSWORD='your-password'"
  echo ""
  echo "Or create a .env file with these variables."
  echo "Or add an entry to ~/.netrc for $GERRIT_HOST"
  exit 1
fi

# Create working directory
WORK_DIR=$(mktemp -d)
INSTANCE_DIR="$WORK_DIR/gerrit"
log_info "Working directory: $WORK_DIR"

cleanup() {
  log_info "Cleaning up..."
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
  # Uncomment to auto-remove work dir:
  # rm -rf "$WORK_DIR"
  log_info "Work directory preserved at: $WORK_DIR"
}
trap cleanup EXIT

# Stop any existing container
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Create directory structure
log_info "Creating Gerrit site structure..."
mkdir -p "$INSTANCE_DIR"/{git,cache,index,data,etc,logs,plugins,tmp}
chmod -R 777 "$INSTANCE_DIR"

# Download pull-replication plugin
PLUGIN_CACHE="/tmp/gerrit-plugins"
PLUGIN_JAR="$PLUGIN_CACHE/pull-replication-${PLUGIN_VERSION}.jar"
mkdir -p "$PLUGIN_CACHE"

if [ -f "$PLUGIN_JAR" ]; then
  log_info "Using cached plugin: $PLUGIN_JAR"
else
  log_info "Downloading pull-replication plugin..."
  PLUGIN_URL="https://gerrit-ci.gerritforge.com/job/plugin-pull-replication-gh-bazel-${PLUGIN_VERSION}/lastSuccessfulBuild/artifact/bazel-bin/plugins/pull-replication/pull-replication.jar"
  curl -fL -o "$PLUGIN_JAR" "$PLUGIN_URL" || {
    log_error "Failed to download plugin"
    exit 1
  }
  log_success "Plugin downloaded"
fi

# Initialize Gerrit site
log_info "Initializing Gerrit site..."
docker run --rm \
  -v "$INSTANCE_DIR/git:/var/gerrit/git" \
  -v "$INSTANCE_DIR/cache:/var/gerrit/cache" \
  -v "$INSTANCE_DIR/index:/var/gerrit/index" \
  -v "$INSTANCE_DIR/data:/var/gerrit/data" \
  -v "$INSTANCE_DIR/etc:/var/gerrit/etc" \
  -v "$INSTANCE_DIR/logs:/var/gerrit/logs" \
  -v "$INSTANCE_DIR/plugins:/var/gerrit/plugins" \
  -e CANONICAL_WEB_URL="http://localhost:$HTTP_PORT" \
  "gerritcodereview/gerrit:${GERRIT_VERSION}" \
  init

log_success "Gerrit site initialized"

# Configure Gerrit
log_info "Configuring Gerrit..."
CONFIG_FILE="$INSTANCE_DIR/etc/gerrit.config"

git config -f "$CONFIG_FILE" gerrit.instanceId "local-test"
git config -f "$CONFIG_FILE" gerrit.canonicalWebUrl "http://localhost:$HTTP_PORT"
git config -f "$CONFIG_FILE" httpd.listenUrl "http://*:8080/"
git config -f "$CONFIG_FILE" sshd.listenAddress "*:29418"
git config -f "$CONFIG_FILE" auth.type "DEVELOPMENT_BECOME_ANY_ACCOUNT"
git config -f "$CONFIG_FILE" container.user "root"
git config -f "$CONFIG_FILE" plugin.pull-replication.enabled "true"

# Enable replica mode if requested
# Replica mode is REQUIRED for replicateOnStartup to work!
if [ "$REPLICA_MODE" = "true" ]; then
  log_info "Enabling replica mode (required for replicateOnStartup)..."
  git config -f "$CONFIG_FILE" container.replica "true"
fi

log_success "Gerrit configured"

# Install plugin
log_info "Installing pull-replication plugin..."
cp "$PLUGIN_JAR" "$INSTANCE_DIR/plugins/pull-replication.jar"

# Remove bundled replication plugin to avoid conflicts
rm -f "$INSTANCE_DIR/plugins/replication.jar" 2>/dev/null || true
log_success "Plugin installed"

# Build API URL
API_PATH_CLEAN="${API_PATH#/}"
if [ -n "$API_PATH_CLEAN" ]; then
  API_URL="https://${GERRIT_HOST}/${API_PATH_CLEAN}"
  GIT_URL="https://${GERRIT_HOST}/${API_PATH_CLEAN}/a/\${name}.git"
else
  API_URL="https://${GERRIT_HOST}"
  GIT_URL="https://${GERRIT_HOST}/a/\${name}.git"
fi

log_info "API URL: $API_URL"
log_info "Git URL template: $GIT_URL"

# Create replication.config
log_info "Creating replication.config..."

# Build projects configuration for replication.config
# Only add projects filter if a specific filter is provided
PROJECTS_CONFIG=""
if [ -n "$PROJECT_FILTER" ] && [ "$PROJECT_FILTER" != "all" ]; then
  # Split by comma for literal project names
  IFS=',' read -ra PROJECT_ARRAY <<< "$PROJECT_FILTER"
  for project in "${PROJECT_ARRAY[@]}"; do
    project=$(echo "$project" | xargs)  # trim whitespace
    if [ -n "$project" ]; then
      PROJECTS_CONFIG="${PROJECTS_CONFIG}  projects = ${project}\n"
    fi
  done
fi
# Note: If PROJECTS_CONFIG is empty, all projects will be replicated

cat > "$INSTANCE_DIR/etc/replication.config" <<EOF
# Pull-replication configuration for local testing
# Key: replicateOnStartup requires projects to exist in local projectCache
# The FetchAll iterates over projectCache.all() to find projects to replicate

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
  apiUrl = ${API_URL}
  timeout = 600
  connectionTimeout = 120000
  replicationDelay = 0
  replicationRetry = 60
  threads = 4
  createMissingRepositories = true
  replicateHiddenProjects = false
  fetch = +refs/heads/*:refs/heads/*
  fetch = +refs/tags/*:refs/tags/*
$(echo -e "$PROJECTS_CONFIG")
EOF

log_success "replication.config created"
echo ""
cat "$INSTANCE_DIR/etc/replication.config"
echo ""

# Create secure.config with credentials
log_info "Creating secure.config with credentials..."
cat > "$INSTANCE_DIR/etc/secure.config" <<EOF
[remote "source"]
  username = ${GERRIT_HTTP_USERNAME}
  password = ${GERRIT_HTTP_PASSWORD}
EOF
chmod 600 "$INSTANCE_DIR/etc/secure.config"
log_success "secure.config created"

# CRITICAL: Create empty bare repos for each project
# The pull-replication plugin's FetchAll iterates over projectCache.all()
# which only includes projects that exist locally. Without creating these
# repos first, replicateOnStartup will have nothing to replicate!
log_info "Creating empty bare repositories for projects to replicate..."
log_info "(Required: FetchAll iterates over projectCache.all())"
echo ""

# Determine projects to create
declare -a PROJECTS_TO_CREATE=()

if [ -z "$PROJECT_FILTER" ] || [ "$PROJECT_FILTER" = "all" ]; then
  # Fetch all projects from remote server
  log_info "No specific project filter - fetching all projects from remote..."
  if remote_projects=$(fetch_remote_projects "$GERRIT_HOST" "$API_PATH" "" "$MAX_PROJECTS"); then
    while IFS= read -r proj; do
      [ -n "$proj" ] && PROJECTS_TO_CREATE+=("$proj")
    done <<< "$remote_projects"
  else
    log_error "Could not fetch remote project list"
    exit 1
  fi
elif [[ "$PROJECT_FILTER" == *"*"* ]] || [[ "$PROJECT_FILTER" == *"["* ]] || \
     [[ "$PROJECT_FILTER" == "^"* ]] || [[ "$PROJECT_FILTER" == ".*" ]]; then
  # Regex pattern - fetch matching projects
  log_info "Project filter is a regex: $PROJECT_FILTER"
  if remote_projects=$(fetch_remote_projects "$GERRIT_HOST" "$API_PATH" "$PROJECT_FILTER" "$MAX_PROJECTS"); then
    while IFS= read -r proj; do
      [ -n "$proj" ] && PROJECTS_TO_CREATE+=("$proj")
    done <<< "$remote_projects"
  else
    log_error "Could not fetch filtered project list"
    exit 1
  fi
else
  # Literal project name(s) - use as-is
  IFS=',' read -ra LITERAL_PROJECTS <<< "$PROJECT_FILTER"
  for project in "${LITERAL_PROJECTS[@]}"; do
    project=$(echo "$project" | xargs)  # trim whitespace
    [ -n "$project" ] && PROJECTS_TO_CREATE+=("$project")
  done
fi

log_info "Will create ${#PROJECTS_TO_CREATE[@]} project repositories"

for project in "${PROJECTS_TO_CREATE[@]}"; do
  PROJECT_DIR="$INSTANCE_DIR/git/${project}.git"

  log_info "Creating: ${project}.git"
  mkdir -p "$PROJECT_DIR"
  git init --bare "$PROJECT_DIR" 2>/dev/null

  # Set proper permissions
  chmod -R 777 "$PROJECT_DIR"
done

log_success "Project repositories created: ${#PROJECTS_TO_CREATE[@]}"
echo ""

# Start container
log_info "Starting Gerrit container..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${HTTP_PORT}:8080" \
  -p "${SSH_PORT}:29418" \
  -v "$INSTANCE_DIR/git:/var/gerrit/git" \
  -v "$INSTANCE_DIR/cache:/var/gerrit/cache" \
  -v "$INSTANCE_DIR/index:/var/gerrit/index" \
  -v "$INSTANCE_DIR/data:/var/gerrit/data" \
  -v "$INSTANCE_DIR/etc:/var/gerrit/etc" \
  -v "$INSTANCE_DIR/logs:/var/gerrit/logs" \
  -v "$INSTANCE_DIR/plugins:/var/gerrit/plugins" \
  -v "$INSTANCE_DIR/tmp:/var/gerrit/tmp" \
  -e "CANONICAL_WEB_URL=http://localhost:$HTTP_PORT" \
  "gerritcodereview/gerrit:${GERRIT_VERSION}"

log_success "Container started: $CONTAINER_NAME"
echo ""

# Wait for Gerrit to be ready
log_info "Waiting for Gerrit to start..."
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  # Use grep without -q and redirect stdout to /dev/null to avoid broken pipe errors
  if docker logs "$CONTAINER_NAME" 2>&1 | grep "Gerrit Code Review.*ready" >/dev/null 2>&1; then
    log_success "Gerrit is ready!"
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  if [ $((ELAPSED % 10)) -eq 0 ]; then
    echo "  Waiting... ${ELAPSED}s"
  fi
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
  log_warn "Gerrit didn't show ready message, continuing anyway..."
fi

echo ""
log_info "=== Container Info ==="
echo "Container: $CONTAINER_NAME"
echo "HTTP: http://localhost:$HTTP_PORT"
echo "SSH: ssh://localhost:$SSH_PORT"
echo "Work Dir: $WORK_DIR"
echo "Replica Mode: $REPLICA_MODE"
echo ""

# Check plugin loading
log_info "=== Plugin Status ==="
docker logs "$CONTAINER_NAME" 2>&1 | grep -i "plugin" | tail -10
echo ""

# Wait for replicateOnStartup to trigger (scheduled 30 seconds after plugin start)
log_info "=== Waiting for replicateOnStartup (triggers 30s after plugin load) ==="
log_info "The FetchAll is scheduled with a 30-second delay..."
sleep 35

# Check for replication activity
log_info "=== Replication Logs ==="
docker logs "$CONTAINER_NAME" 2>&1 | grep -iE "replication|fetch|pull|remote" | tail -20
echo ""

# Check pull_replication_log specifically
log_info "=== Pull Replication Log ==="
docker exec "$CONTAINER_NAME" cat /var/gerrit/logs/pull_replication_log 2>/dev/null || echo "(empty)"
echo ""

# Show repository status
log_info "=== Repository Status ==="
echo "Repositories in git directory:"
docker exec "$CONTAINER_NAME" find /var/gerrit/git -name '*.git' -type d 2>/dev/null | head -20
echo ""
echo "Disk usage:"
docker exec "$CONTAINER_NAME" du -sh /var/gerrit/git
echo ""

# Check if repos have content
log_info "=== Checking replicated content ==="
for project in "${PROJECTS_TO_CREATE[@]}"; do
  PROJECT_GIT="/var/gerrit/git/${project}.git"
  echo "Project: $project"

  # Check for branches
  BRANCHES=$(docker exec "$CONTAINER_NAME" bash -c "cd $PROJECT_GIT && git branch 2>/dev/null | wc -l" || echo "0")
  echo "  Branches: $BRANCHES"

  # Check for packed-refs (indicates successful fetch)
  if docker exec "$CONTAINER_NAME" test -f "$PROJECT_GIT/packed-refs"; then
    REFS=$(docker exec "$CONTAINER_NAME" wc -l < "$PROJECT_GIT/packed-refs" || echo "0")
    echo "  Packed refs: $REFS lines"
  else
    echo "  Packed refs: none"
  fi
  echo ""
done

# Interactive commands
echo ""
log_info "=== Useful Commands ==="
echo ""
echo "# Follow all logs:"
echo "docker logs -f $CONTAINER_NAME"
echo ""
echo "# Follow replication logs:"
echo "docker logs -f $CONTAINER_NAME 2>&1 | grep -i replication"
echo ""
echo "# Watch pull_replication_log:"
echo "docker exec $CONTAINER_NAME tail -f /var/gerrit/logs/pull_replication_log"
echo ""
echo "# Check repositories:"
echo "docker exec $CONTAINER_NAME find /var/gerrit/git -name '*.git' -type d"
echo ""
echo "# Check disk usage:"
echo "docker exec $CONTAINER_NAME du -sh /var/gerrit/git"
echo ""
echo "# View replication config:"
echo "cat $INSTANCE_DIR/etc/replication.config"
echo ""
echo "# Edit replication config (changes auto-reload):"
echo "nano $INSTANCE_DIR/etc/replication.config"
echo ""
echo "# Shell into container:"
echo "docker exec -it $CONTAINER_NAME bash"
echo ""
echo "# Stop container:"
echo "docker rm -f $CONTAINER_NAME"
echo ""

log_info "Container is running. Use the commands above to debug."
log_info "Press Ctrl+C to stop and cleanup, or run: docker rm -f $CONTAINER_NAME"
echo ""

# Keep script running and show logs
log_info "Tailing container logs (Ctrl+C to exit)..."
echo ""
docker logs -f "$CONTAINER_NAME" 2>&1 | grep -iE "replication|fetch|pull|remote|error|exception" || true
