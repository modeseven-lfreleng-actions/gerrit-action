#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Start Gerrit instances script
# This script starts one or more Gerrit server containers based on JSON
# configuration

set -euo pipefail

echo "Starting Gerrit instances..."

# API paths file (populated by detect-api-paths.sh)
API_PATHS_FILE="$WORK_DIR/api_paths.json"

# Function to get API path for a slug
get_api_path() {
  local slug="$1"
  if [ -f "$API_PATHS_FILE" ]; then
    jq -r ".\"$slug\".api_path // \"\"" "$API_PATHS_FILE"
  else
    echo ""
  fi
}

# Function to get API URL for a slug
get_api_url() {
  local slug="$1"
  if [ -f "$API_PATHS_FILE" ]; then
    jq -r ".\"$slug\".api_url // \"\"" "$API_PATHS_FILE"
  else
    echo ""
  fi
}

# Parse configuration
INSTANCES=$(echo "$GERRIT_SETUP" | jq -c '.[]')
INSTANCE_INDEX=0

# Initialize tracking files
CONTAINER_IDS_FILE="$WORK_DIR/container_ids.txt"
INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
: > "$CONTAINER_IDS_FILE"
echo "{}" > "$INSTANCES_JSON_FILE"

# Setup authentication
setup_ssh_auth() {
  local instance_dir="$1"
  local gerrit_host="$2"

  # Create SSH directory
  mkdir -p "$instance_dir/ssh"
  chmod 700 "$instance_dir/ssh"

  # Write private key
  echo "$SSH_PRIVATE_KEY" > "$instance_dir/ssh/id_rsa"
  chmod 600 "$instance_dir/ssh/id_rsa"

  # Setup known_hosts
  if [ -n "${SSH_KNOWN_HOSTS:-}" ]; then
    echo "$SSH_KNOWN_HOSTS" > "$instance_dir/ssh/known_hosts"
  else
    # Auto-fetch host key
    echo "Auto-fetching SSH host key for $gerrit_host..."
    ssh-keyscan -H "$gerrit_host" 2>/dev/null \
      > "$instance_dir/ssh/known_hosts" || {
      echo "Warning: Could not fetch SSH host key for $gerrit_host"
      touch "$instance_dir/ssh/known_hosts"
    }
  fi
  chmod 644 "$instance_dir/ssh/known_hosts"

  # Create SSH config
  cat > "$instance_dir/ssh/config" <<EOF
Host $gerrit_host
  HostName $gerrit_host
  User git
  IdentityFile /var/gerrit/ssh/id_rsa
  StrictHostKeyChecking yes
  UserKnownHostsFile /var/gerrit/ssh/known_hosts
EOF
  chmod 600 "$instance_dir/ssh/config"
}

# Fetch project list from remote Gerrit server
# This is needed for replicateOnStartup because FetchAll iterates over
# projectCache.all() - projects must exist locally before they can be replicated
fetch_remote_projects() {
  local gerrit_host="$1"
  local api_path="${2:-}"
  local project_filter="${3:-}"
  local max_projects="${4:-100}"  # Limit for safety

  echo "Fetching project list from $gerrit_host..." >&2

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
  if [ -n "$project_filter" ] && [ "$project_filter" != ".*" ]; then
    # Use regex filter if it looks like a pattern, otherwise prefix match
    if [[ "$project_filter" == *"*"* ]] || [[ "$project_filter" == *"."* ]]; then
      query_params="${query_params}&r=$(printf '%s' "$project_filter" | jq -sRr @uri)"
    else
      query_params="${query_params}&p=$(printf '%s' "$project_filter" | jq -sRr @uri)"
    fi
  fi

  local full_url="${api_url}?${query_params}"
  echo "  API URL: $full_url" >&2

  # Fetch projects (Gerrit API returns )]}' prefix for XSSI protection)
  local response
  response=$(curl -s --connect-timeout 30 --max-time 60 "$full_url" 2>/dev/null) || {
    echo "  Warning: Failed to fetch project list from $gerrit_host" >&2
    return 1
  }

  # Remove XSSI protection prefix and parse JSON
  local projects
  projects=$(echo "$response" | tail -n +2 | jq -r 'keys[]' 2>/dev/null) || {
    echo "  Warning: Failed to parse project list response" >&2
    return 1
  }

  local count
  count=$(echo "$projects" | grep -c . || echo "0")
  echo "  Found $count projects on remote server" >&2

  # Return project list (one per line)
  echo "$projects"
}

# Generate replication.config (used by both replication and pull-replication plugins)
generate_replication_config() {
  local config_file="$1"
  local slug="$2"
  local gerrit_host="$3"
  local project="${4:-}"

  # Get API path for this instance (detected by detect-api-paths.sh)
  # Note: We no longer use apiUrl because it's mutually exclusive with fetchEvery
  local api_path
  api_path=$(get_api_path "$slug")

  # Build the authenticated git-over-https URL
  # For HTTP Basic auth, Gerrit uses /a/ prefix for authenticated access
  # URL format: https://<host>/<api_path>/a/${name}.git
  local git_url
  if [ -n "$api_path" ]; then
    # Remove leading slash from api_path if present for consistent URL building
    api_path="${api_path#/}"
    git_url="https://${gerrit_host}/${api_path}/a/\${name}.git"
  else
    git_url="https://${gerrit_host}/a/\${name}.git"
  fi

  # Parse sync_refs from environment
  IFS=',' read -ra REFS <<< "$SYNC_REFS"

  # Get fetch interval (default to 60s if not set)
  local fetch_interval="${FETCH_EVERY:-60s}"

  cat > "$config_file" <<EOF
# Pull-replication configuration
# Auto-generated by gerrit-server-action
#
# This configuration uses fetchEvery for polling-based replication.
# The plugin will poll the source Gerrit at the configured interval
# to fetch any new or changed refs. This approach:
# - Enables full web UI access (non-replica mode)
# - Provides automatic, self-healing replication
# - Does not require apiUrl (which is mutually exclusive with fetchEvery)

[gerrit]
  replicateOnStartup = $SYNC_ON_STARTUP
  autoReload = true

[replication]
  lockErrorMaxRetries = 5
  maxRetries = 5
  useCGitClient = false
  refsBatchSize = 50

[remote "$slug"]
  url = ${git_url}
  fetchEvery = ${fetch_interval}
  timeout = $REPLICATION_TIMEOUT
  connectionTimeout = 120000
  replicationDelay = 0
  replicationRetry = 60
  threads = $REPLICATION_THREADS
  createMissingRepositories = true
  replicateHiddenProjects = false
EOF

  echo "  Git URL for replication: $git_url" >&2
  echo "  Fetch interval (polling): $fetch_interval" >&2

  # Note: apiUrl is NOT used because it's mutually exclusive with fetchEvery
  # The fetchEvery setting enables polling-based replication which:
  # 1. Works without replica mode (web UI remains functional)
  # 2. Automatically polls for changes at the configured interval
  # 3. Is ideal for mirroring from production Gerrit servers

  # Add fetch refspecs
  for ref in "${REFS[@]}"; do
    echo "  fetch = $ref" >> "$config_file"
  done

  # Add project filter if specified
  if [ -n "$project" ]; then
    echo "  projects = $project" >> "$config_file"
  fi
}

# Generate secure.config for authentication
generate_secure_config() {
  local config_file="$1"
  local slug="$2"

  case "$AUTH_TYPE" in
    http_basic)
      cat > "$config_file" <<EOF
[remote "$slug"]
  username = $HTTP_USERNAME
  password = $HTTP_PASSWORD
EOF
      ;;
    bearer_token)
      cat > "$config_file" <<EOF
[auth]
  bearerToken = $BEARER_TOKEN
EOF
      ;;
    ssh)
      # No secure.config needed for SSH
      touch "$config_file"
      ;;
  esac

  chmod 600 "$config_file"
}

# Download pull-replication plugin
download_plugin() {
  local plugin_dir="$1"

  if [ "$SKIP_PLUGIN_INSTALL" = "true" ]; then
    echo "Skipping plugin download (skip_plugin_install=true)"
    return 0
  fi

  mkdir -p /tmp/gerrit-plugins
  local plugin_jar="/tmp/gerrit-plugins/pull-replication-${PLUGIN_VERSION}.jar"

  if [ -f "$plugin_jar" ]; then
    echo "Using cached plugin: $plugin_jar"
    cp "$plugin_jar" "$plugin_dir/pull-replication.jar"
    return 0
  fi

  echo "Downloading pull-replication plugin..."
  local plugin_url="https://gerrit-ci.gerritforge.com/job/plugin-pull-replication-gh-bazel-${PLUGIN_VERSION}/lastSuccessfulBuild/artifact/bazel-bin/plugins/pull-replication/pull-replication.jar"

  if curl -f -L -o "$plugin_jar" "$plugin_url" 2>/dev/null; then
    echo "Plugin downloaded ✅"
    cp "$plugin_jar" "$plugin_dir/pull-replication.jar"
  else
    echo "::warning::Failed to download plugin from CI"
    echo "::warning::attempting alternate source..."
    # Try alternate source (GitHub releases)
    local alt_url="https://github.com/GerritForge/pull-replication/releases/download/${PLUGIN_VERSION}/pull-replication.jar"
    if curl -f -L -o "$plugin_jar" "$alt_url" 2>/dev/null; then
      echo "Plugin downloaded from alternate source ✅"
      cp "$plugin_jar" "$plugin_dir/pull-replication.jar"
    else
      echo "::error::Failed to download pull-replication plugin ❌"
      return 1
    fi
  fi
}

# Download more plugins
download_additional_plugins() {
  local plugin_dir="$1"

  if [ -z "$ADDITIONAL_PLUGINS" ]; then
    return 0
  fi

  echo "Downloading additional plugins..."
  IFS=',' read -ra PLUGINS <<< "$ADDITIONAL_PLUGINS"

  for plugin_url in "${PLUGINS[@]}"; do
    plugin_name=$(basename "$plugin_url")
    echo "Downloading: $plugin_name"

    if curl -f -L -o "$plugin_dir/$plugin_name" "$plugin_url" 2>/dev/null; then
      echo "  ✅ $plugin_name"
    else
      echo "  ::warning::Failed to download $plugin_name"
    fi
  done
}

# Initialize Gerrit site
init_gerrit_site() {
  local instance_dir="$1"
  local slug="$2"
  local http_port="$3"
  local canonical_url="$4"

  echo "Initializing Gerrit site for $slug..."

  # Create directory structure
  mkdir -p "$instance_dir"/{git,cache,index,data,etc,logs,plugins,tmp}
  chmod -R 777 "$instance_dir"

  # Run Gerrit init using the container's entrypoint
  # Mount only specific subdirectories to avoid hiding /var/gerrit/bin
  docker run --rm \
    -v "$instance_dir/git:/var/gerrit/git" \
    -v "$instance_dir/cache:/var/gerrit/cache" \
    -v "$instance_dir/index:/var/gerrit/index" \
    -v "$instance_dir/data:/var/gerrit/data" \
    -v "$instance_dir/etc:/var/gerrit/etc" \
    -v "$instance_dir/logs:/var/gerrit/logs" \
    -v "$instance_dir/plugins:/var/gerrit/plugins" \
    -e CANONICAL_WEB_URL="$canonical_url" \
    "gerritcodereview/gerrit:${GERRIT_VERSION}" \
    init || {
    echo "::error::Failed to initialize Gerrit site for $slug ❌"
    return 1
  }

  echo "Gerrit site initialized ✅"
}

# Configure Gerrit
configure_gerrit() {
  local instance_dir="$1"
  local slug="$2"
  local http_port="$3"
  local canonical_url="$4"
  local listen_url="$5"
  local api_path="$6"
  local advertised_ssh_addr="$7"  # Format: host:port (e.g., localhost:29418 or tunnel:12345)

  echo "Configuring Gerrit for $slug..."

  local config_file="$instance_dir/etc/gerrit.config"

  if [ -n "$api_path" ]; then
    echo "  URL prefix: $api_path (mirroring production server)"
  else
    echo "  URL prefix: (none)"
  fi

  # Update gerrit.config
  git config -f "$config_file" gerrit.instanceId "$slug"
  git config -f "$config_file" gerrit.canonicalWebUrl "$canonical_url"
  git config -f "$config_file" httpd.listenUrl "$listen_url"
  git config -f "$config_file" sshd.listenAddress "*:29418"

  # Configure advertised SSH address so clone URLs show correctly
  # This tells clients what address/port to use for SSH clones
  # When using tunnels, this will be the tunnel host:port
  git config -f "$config_file" sshd.advertisedAddress "$advertised_ssh_addr"

  # Enable both HTTP and SSH download schemes in the web UI
  # By default Gerrit shows SSH, HTTP, and Anonymous HTTP
  git config -f "$config_file" download.scheme "ssh"
  git config -f "$config_file" --add download.scheme "http"

  # Configure download commands shown in the UI
  git config -f "$config_file" download.command "checkout"
  git config -f "$config_file" --add download.command "cherry_pick"
  git config -f "$config_file" --add download.command "pull"

  # Set auth to development mode for testing
  git config -f "$config_file" auth.type "DEVELOPMENT_BECOME_ANY_ACCOUNT"

  # Container user
  git config -f "$config_file" container.user "root"

  # Enable replication plugin
  git config -f "$config_file" plugin.pull-replication.enabled "true"

  # NOTE: We intentionally do NOT set container.replica=true
  #
  # While replica mode would enable automatic replicateOnStartup (FetchAll),
  # it also disables the web UI entirely (Gerrit becomes read-only).
  #
  # Instead, we use fetchEvery polling which provides:
  # - Automatic replication at configured intervals
  # - Full web UI access (non-replica mode)
  # - Self-healing sync (retries on next poll cycle)
  #
  # The tradeoff is that initial sync takes up to one poll interval,
  # but this is acceptable for CI/CD testing scenarios.
  #
  # Previous (disabled):
  # git config -f "$config_file" container.replica "true"

  echo "Gerrit configured ✅"
  echo "  Mode: non-replica (web UI enabled)"
  echo "  Replication: fetchEvery polling"
}

# Create empty project directories for replication
# CRITICAL: The pull-replication plugin's FetchAll iterates over projectCache.all()
# which only includes projects that exist locally. Without creating these repos
# first, replicateOnStartup will have nothing to replicate!
create_project_directories() {
  local instance_dir="$1"
  local project="$2"
  local gerrit_host="$3"
  local slug="$4"

  echo "Creating project directories for replication..."
  echo "(Required: FetchAll iterates over projectCache.all())"

  local projects_to_create=()

  if [ -z "$project" ]; then
    # No specific project filter - fetch ALL projects from remote server
    echo "No project filter specified, fetching project list from remote..."

    # Get API path for this instance
    local api_path
    api_path=$(get_api_path "$slug")

    # Fetch remote projects
    local remote_projects
    if remote_projects=$(fetch_remote_projects "$gerrit_host" "$api_path" "" 500); then
      # Convert newline-separated list to array
      while IFS= read -r proj; do
        [ -n "$proj" ] && projects_to_create+=("$proj")
      done <<< "$remote_projects"
    else
      echo "  Warning: Could not fetch remote project list"
      echo "  Replication will only work for manually created repos"
      return 0
    fi
  else
    # Handle comma-separated project list or single project/pattern
    # Check if it's a regex pattern (contains special chars)
    if [[ "$project" == *"*"* ]] || [[ "$project" == *"["* ]] || \
       [[ "$project" == "^"* ]] || [[ "$project" == ".*" ]]; then
      echo "  Project filter appears to be a regex: $project"
      echo "  Fetching matching projects from remote..."

      local api_path
      api_path=$(get_api_path "$slug")

      local remote_projects
      if remote_projects=$(fetch_remote_projects "$gerrit_host" "$api_path" "$project" 500); then
        while IFS= read -r proj; do
          [ -n "$proj" ] && projects_to_create+=("$proj")
        done <<< "$remote_projects"
      else
        echo "  Warning: Could not fetch filtered project list"
        return 0
      fi
    else
      # Literal project name(s) - could be comma-separated
      IFS=',' read -ra PROJECTS <<< "$project"
      for proj in "${PROJECTS[@]}"; do
        proj=$(echo "$proj" | xargs)  # trim whitespace
        [ -n "$proj" ] && projects_to_create+=("$proj")
      done
    fi
  fi

  # Create directories for all projects
  local created_count=0
  for proj in "${projects_to_create[@]}"; do
    local project_dir="$instance_dir/git/${proj}.git"
    echo "  Creating: ${proj}.git"
    mkdir -p "$project_dir"
    git init --bare "$project_dir" 2>/dev/null || true
    chmod -R 777 "$project_dir"
    ((created_count++))
  done

  echo "Project directories created: $created_count ✅"

  # Store expected project count for later verification
  # This file will be read when building instances.json
  echo "$created_count" > "$instance_dir/expected_project_count"
}

# Start single instance
start_instance() {
  local instance_json="$1"
  local index="$2"

  # Parse instance config
  local project
  project=$(echo "$instance_json" | jq -r '.project // ""')
  local slug
  slug=$(echo "$instance_json" | jq -r '.slug')
  local gerrit_host
  gerrit_host=$(echo "$instance_json" | jq -r '.gerrit')

  # Calculate ports
  local http_port=$((BASE_HTTP_PORT + index))
  local ssh_port=$((BASE_SSH_PORT + index))

  # Get API path to mirror production server's URL structure
  # Compute this early so we can use it for both config and Docker env vars
  local api_path
  api_path=$(get_api_path "$slug")

  # Check if USE_API_PATH is enabled (default: false)
  # When false, we ignore api_path for local URLs but still store it for reference
  local effective_api_path=""
  if [ "${USE_API_PATH:-false}" = "true" ] && [ -n "$api_path" ]; then
    effective_api_path="$api_path"
  fi

  # Check for external tunnel configuration
  # When TUNNEL_HOST and TUNNEL_PORTS are set, use external URLs
  local tunnel_http_port=""
  local tunnel_ssh_port=""
  local use_tunnel="false"

  if [ -n "${TUNNEL_HOST:-}" ] && [ -n "${TUNNEL_PORTS:-}" ]; then
    # Extract tunnel ports for this slug from JSON
    tunnel_http_port=$(echo "$TUNNEL_PORTS" | jq -r --arg s "$slug" '.[$s].http // empty')
    tunnel_ssh_port=$(echo "$TUNNEL_PORTS" | jq -r --arg s "$slug" '.[$s].ssh // empty')

    if [ -n "$tunnel_http_port" ] && [ -n "$tunnel_ssh_port" ]; then
      use_tunnel="true"
      echo "  External tunnel configured: ${TUNNEL_HOST}"
      echo "    HTTP port: $tunnel_http_port"
      echo "    SSH port: $tunnel_ssh_port"
    else
      echo "  Warning: TUNNEL_HOST set but no ports found for slug '$slug'"
      echo "  Falling back to localhost URLs"
    fi
  fi

  # Build URLs using effective_api_path (may be empty if USE_API_PATH is false)
  #
  # IMPORTANT: URL PATH CONFIGURATION - KEEP IN SYNC!
  # ================================================
  # The following files must be updated together if changing URL path handling:
  #
  #   1. scripts/start-instances.sh (this file)
  #      - canonical_url and listen_url variables below
  #      - CANONICAL_WEB_URL and HTTPD_LISTEN_URL env vars in docker run
  #
  #   2. scripts/check-services.sh
  #      - HEALTH_URL construction (must match listen_url path)
  #      - Plugin check URL (must match listen_url path)
  #
  #   3. test-gerrit-servers/.github/workflows/ (tunnel workflow)
  #      - Tunnel inputs configure public URLs
  #
  # When USE_API_PATH is true and api_path is detected, the local container
  # will use the same URL structure as the production server. This ensures:
  # - Clone URLs displayed in the web UI match the expected format
  # - Static content is served from the correct path prefix
  # - Health checks and API endpoints use consistent paths
  #
  # When USE_API_PATH is false (default), the container serves at root (/)
  # which avoids potential issues with static asset loading in PolyGerrit.
  #
  local canonical_url
  local listen_url
  local advertised_ssh_addr

  # Determine the host and ports for canonical URLs
  local url_host
  local url_http_port
  local url_ssh_port

  if [ "$use_tunnel" = "true" ]; then
    url_host="$TUNNEL_HOST"
    url_http_port="$tunnel_http_port"
    url_ssh_port="$tunnel_ssh_port"
  else
    url_host="localhost"
    url_http_port="$http_port"
    url_ssh_port="$ssh_port"
  fi

  # Build the advertised SSH address (used in clone URLs)
  advertised_ssh_addr="${url_host}:${url_ssh_port}"

  if [ -n "$effective_api_path" ]; then
    # Use api_path to match production server structure
    canonical_url="http://${url_host}:${url_http_port}${effective_api_path}/"
    listen_url="http://*:8080${effective_api_path}/"
    echo "  Using API path: $effective_api_path (USE_API_PATH=true)"
  else
    # No api_path - serve at root
    canonical_url="http://${url_host}:${url_http_port}/"
    listen_url="http://*:8080/"
    if [ -n "$api_path" ]; then
      echo "  API path detected ($api_path) but USE_API_PATH is false"
      echo "  Serving at root instead"
    fi
  fi

  # Export for use by other steps (e.g., tunnel config updates)
  {
    echo "GERRIT_CANONICAL_URL=$canonical_url"
    echo "GERRIT_LISTEN_URL=$listen_url"
    echo "GERRIT_SSH_ADDR=$advertised_ssh_addr"
    if [ "$use_tunnel" = "true" ]; then
      echo "GERRIT_TUNNEL_MODE=true"
    fi
  } >> "$WORK_DIR/env.sh"

  echo ""
  echo "========================================"
  echo "Instance $((index + 1)): $slug"
  echo "  Project: $project"
  echo "  Source: $gerrit_host"
  echo "  Local HTTP Port: $http_port"
  echo "  Local SSH Port: $ssh_port"
  if [ "$use_tunnel" = "true" ]; then
    echo "  Tunnel Mode: ENABLED"
    echo "  Public URL: $canonical_url"
    echo "  Public SSH: $advertised_ssh_addr"
  else
    echo "  Tunnel Mode: disabled (localhost)"
  fi
  echo "========================================"

  # Instance directory
  local instance_dir="$WORK_DIR/instances/$slug"

  # Initialize site (pass canonical_url for consistency)
  init_gerrit_site "$instance_dir" "$slug" "$http_port" "$canonical_url" || return 1

  # Configure Gerrit (pass pre-computed URLs and advertised SSH address)
  configure_gerrit "$instance_dir" "$slug" "$http_port" \
    "$canonical_url" "$listen_url" "$api_path" "$advertised_ssh_addr" || return 1

  # Download and install plugins
  download_plugin "$instance_dir/plugins" || return 1
  download_additional_plugins "$instance_dir/plugins" || return 1

  # Setup authentication
  if [ "$AUTH_TYPE" = "ssh" ]; then
    setup_ssh_auth "$instance_dir" "$gerrit_host" || return 1
  fi

  # Generate replication configuration
  # Note: pull-replication plugin uses replication.config (same as bundled plugin)
  # We remove the bundled replication.jar to avoid conflicts
  generate_replication_config "$instance_dir/etc/replication.config" \
    "$slug" "$gerrit_host" "$project"
  generate_secure_config "$instance_dir/etc/secure.config" "$slug"

  # Create project directories for replication
  # Pass gerrit_host and slug so we can fetch remote project list if needed
  create_project_directories "$instance_dir" "$project" "$gerrit_host" "$slug"

  # Remove the bundled replication plugin to avoid conflicts
  # The pull-replication plugin will be used instead
  rm -f "$instance_dir/plugins/replication.jar" 2>/dev/null || true

  # Start container
  echo "Starting Gerrit container..."

  local container_name="gerrit-$slug"
  local cidfile="$WORK_DIR/${container_name}.cid"

  local docker_args=(
    -d
    --name "$container_name"
    --cidfile "$cidfile"
    # NOTE: --rm removed so containers can be stopped/started without recreation
    # This allows config changes to persist across restarts
    -p "$http_port:8080"
    -p "$ssh_port:29418"
    -v "$instance_dir/git:/var/gerrit/git"
    -v "$instance_dir/cache:/var/gerrit/cache"
    -v "$instance_dir/index:/var/gerrit/index"
    -v "$instance_dir/data:/var/gerrit/data"
    -v "$instance_dir/etc:/var/gerrit/etc"
    -v "$instance_dir/logs:/var/gerrit/logs"
    -v "$instance_dir/plugins:/var/gerrit/plugins"
    -v "$instance_dir/tmp:/var/gerrit/tmp"
    # Pass CANONICAL_WEB_URL so the entrypoint sets it correctly
    # The Gerrit Docker entrypoint overwrites gerrit.config from this env var
    # on every container start. We must pass it to prevent the entrypoint from
    # defaulting to the container hostname.
    -e "CANONICAL_WEB_URL=$canonical_url"
    -e "HTTPD_LISTEN_URL=$listen_url"
  )

  # Add SSH volume if using SSH auth
  if [ "$AUTH_TYPE" = "ssh" ]; then
    docker_args+=(-v "$instance_dir/ssh:/var/gerrit/ssh:ro")
  fi

  # Add debug flag if enabled
  if [ "$DEBUG" = "true" ]; then
    docker_args+=(-e "DEBUG=1")
  fi

  docker run "${docker_args[@]}" \
    --pull=missing \
    "gerritcodereview/gerrit:${GERRIT_VERSION}" || {
    echo "::error::Failed to start Gerrit container for $slug ❌"
    return 1
  }

  # Wait for container to start
  sleep 2

  # Get container ID and IP
  local cid
  cid=$(cat "$cidfile")
  local container_ip
  container_ip=$(docker inspect -f \
    '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cid")

  echo "$cid" >> "$CONTAINER_IDS_FILE"

  # Get API path and URL for this instance
  local api_path
  local api_url
  api_path=$(get_api_path "$slug")
  api_url=$(get_api_url "$slug")

  # Capture SSH host keys from the container
  # These are auto-generated during Gerrit init
  local ssh_host_keys_dir="$WORK_DIR/ssh_host_keys/$slug"
  mkdir -p "$ssh_host_keys_dir"

  echo "Capturing SSH host keys..."
  # Copy all host key files from the container
  for key_type in rsa ed25519 ecdsa_256 ecdsa_384 ecdsa_521; do
    local key_file="ssh_host_${key_type}_key"
    if docker exec "$cid" test -f "/var/gerrit/etc/${key_file}"; then
      docker cp "$cid:/var/gerrit/etc/${key_file}" \
        "$ssh_host_keys_dir/${key_file}" 2>/dev/null || true
      docker cp "$cid:/var/gerrit/etc/${key_file}.pub" \
        "$ssh_host_keys_dir/${key_file}.pub" 2>/dev/null || true
    fi
  done

  # Build SSH host public keys JSON for this instance
  local ssh_host_pub_keys=""
  for pub_key_file in "$ssh_host_keys_dir"/*.pub; do
    if [ -f "$pub_key_file" ]; then
      local key_name
      key_name=$(basename "$pub_key_file" .pub)
      local key_content
      key_content=$(tr -d '\n' < "$pub_key_file")
      if [ -n "$ssh_host_pub_keys" ]; then
        ssh_host_pub_keys="${ssh_host_pub_keys},"
      fi
      ssh_host_pub_keys="${ssh_host_pub_keys}\"${key_name}\":\"${key_content}\""
    fi
  done
  ssh_host_pub_keys="{${ssh_host_pub_keys}}"
  echo "  SSH host keys captured ✅"

  # Read expected project count from earlier step
  local expected_project_count=0
  if [ -f "$instance_dir/expected_project_count" ]; then
    expected_project_count=$(cat "$instance_dir/expected_project_count" 2>/dev/null || echo "0")
  fi

  # Store instance metadata
  local temp_json
  temp_json=$(mktemp)
  jq --arg slug "$slug" \
     --arg cid "$cid" \
     --arg ip "$container_ip" \
     --argjson http_port "$http_port" \
     --argjson ssh_port "$ssh_port" \
     --arg url "http://$container_ip:8080" \
     --arg gerrit_host "$gerrit_host" \
     --arg project "$project" \
     --arg api_path "$api_path" \
     --arg api_url "$api_url" \
     --argjson expected_project_count "$expected_project_count" \
     --argjson ssh_host_keys "$ssh_host_pub_keys" \
     '.[$slug] = {
       cid: $cid,
       ip: $ip,
       http_port: $http_port,
       ssh_port: $ssh_port,
       url: $url,
       gerrit_host: $gerrit_host,
       project: $project,
       api_path: $api_path,
       api_url: $api_url,
       expected_project_count: $expected_project_count,
       ssh_host_keys: $ssh_host_keys
     }' \
     "$INSTANCES_JSON_FILE" > "$temp_json"
  mv "$temp_json" "$INSTANCES_JSON_FILE"

  echo "✅ Gerrit instance started"
  echo "   Container ID: $cid"
  echo "   IP Address: $container_ip"
  echo "   HTTP URL: http://$container_ip:8080"
  echo "   SSH URL: ssh://localhost:$ssh_port"
  echo "   Source API URL: $api_url"
  echo ""

  # Log container status
  if [ "$DEBUG" = "true" ]; then
    echo "Container status:"
    docker ps -f "id=$cid"
    echo ""
  fi
}

# Main loop - start all instances
while IFS= read -r instance; do
  start_instance "$instance" "$INSTANCE_INDEX" || {
    echo "::error::Failed to start instance $INSTANCE_INDEX ❌"
    exit 1
  }
  INSTANCE_INDEX=$((INSTANCE_INDEX + 1))
done <<< "$INSTANCES"

# Summary
echo "========================================"
echo "All instances started! ✅"
echo "Total instances: $INSTANCE_INDEX"
echo "========================================"
echo ""

# Add to step summary
{
  echo "**Instances Started** 🚀"
  echo ""
  echo "| Slug | HTTP Port | SSH Port | Status |"
  echo "|------|-----------|----------|--------|"
} >> "$GITHUB_STEP_SUMMARY"

for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  http_port=$(jq -r ".\"$slug\".http_port" "$INSTANCES_JSON_FILE")
  ssh_port=$(jq -r ".\"$slug\".ssh_port" "$INSTANCES_JSON_FILE")
  echo "| $slug | $http_port | $ssh_port | ✅ Running |" \
    >> "$GITHUB_STEP_SUMMARY"
done

echo "" >> "$GITHUB_STEP_SUMMARY"
