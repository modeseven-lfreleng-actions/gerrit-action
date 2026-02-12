#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Common Gerrit functions shared between CI and local testing scripts
#
# This library provides reusable functions for:
# - User/account management via REST API
# - SSH key management
# - Cache flushing
# - Session management in DEVELOPMENT_BECOME_ANY_ACCOUNT mode
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/gerrit-common.sh"
#
# Required variables (set before sourcing):
#   None required, but functions expect parameters
#
# Optional environment variables:
#   DEBUG - Set to "true" for verbose output

# Prevent multiple sourcing
if [ -n "${_GERRIT_COMMON_LOADED:-}" ]; then
  return 0
fi
_GERRIT_COMMON_LOADED=1

# Debug logging
_gerrit_debug() {
  if [ "${DEBUG:-false}" = "true" ]; then
    echo "[DEBUG] $*" >&2
  fi
}

# Error logging
_gerrit_error() {
  echo "::error::$*" >&2
}

# Warning logging
_gerrit_warn() {
  echo "::warning::$*" >&2
}

# Info logging
_gerrit_info() {
  echo "$*"
}

###############################################################################
# Session Management
###############################################################################

# Extract XSRF token from cookie file
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - cookie file path
#
# Returns:
#   XSRF token (echoed), empty if not found
gerrit_get_xsrf_token() {
  local target="$1"
  local cookie_file="$2"
  local token

  if [ "$target" = "local" ]; then
    token=$(grep "XSRF_TOKEN" "$cookie_file" 2>/dev/null | awk '{print $NF}')
  else
    token=$(docker exec "$target" sh -c "grep XSRF_TOKEN '$cookie_file' 2>/dev/null | awk '{print \$NF}'" 2>/dev/null || true)
  fi

  # Sanitize: remove whitespace
  token=$(echo "$token" | tr -d '[:space:]')
  echo "${token:-}"
}

# Get a session cookie by "becoming" the admin account
# Uses DEVELOPMENT_BECOME_ANY_ACCOUNT mode
#
# Arguments:
#   $1 - container ID or "local" for local testing
#   $2 - base URL (e.g., http://localhost:8080)
#   $3 - cookie file path
#
# Returns:
#   Account ID on success (echoed), empty string on failure
#   Exit code 0 on success, 1 on failure
gerrit_get_admin_session() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"

  _gerrit_debug "Getting admin session from $base_url"
  _gerrit_debug "Cookie file path: $cookie_file"

  # Try to become account 1000000 first (Gerrit 3.x default admin)
  # Fall back to account 1 if that fails
  for account_id in 1000000 1; do
    local response

    if [ "$target" = "local" ]; then
      # Local testing - direct curl
      # Use -L to follow redirects, -b to send cookies on redirect (for XSRF token)
      response=$(curl -s -L -c "$cookie_file" -b "$cookie_file" -w "%{http_code}" \
        -o /dev/null "${base_url}/login/?account_id=${account_id}" 2>/dev/null || echo "000")
    else
      # Container - use docker exec
      # Use -L to follow redirects, -b to send cookies on redirect (for XSRF token)
      response=$(docker exec "$target" curl -s -L -c "$cookie_file" -b "$cookie_file" -w "%{http_code}" \
        -o /dev/null "${base_url}/login/?account_id=${account_id}" 2>/dev/null || echo "000")
    fi

    _gerrit_debug "Login response for account $account_id: HTTP $response"

    if [ "$response" = "302" ] || [ "$response" = "200" ]; then
      # Check if we got a session cookie
      # The cookie file is always on the host for our use case
      local has_cookie
      if [ "$target" = "local" ]; then
        # Use grep -c but capture output; grep returns 1 if no match but still outputs 0
        has_cookie=$(grep -c "GerritAccount" "$cookie_file" 2>/dev/null)
        # If grep failed (file not found, etc.), default to 0
        has_cookie="${has_cookie:-0}"
      else
        # For container, check inside the container where curl wrote the cookie
        # Debug: show cookie file contents
        if [ "${DEBUG:-false}" = "true" ]; then
          _gerrit_debug "Cookie file check in container:"
          docker exec "$target" cat "$cookie_file" 2>&1 | while read -r line; do _gerrit_debug "  $line"; done
        fi
        # Run grep and capture just the count; don't use || echo which causes double output
        has_cookie=$(docker exec "$target" sh -c "grep -c GerritAccount '$cookie_file' 2>/dev/null" || true)
        # Default to 0 if empty
        has_cookie="${has_cookie:-0}"
      fi
      # Sanitize: remove whitespace and ensure it's a valid integer
      has_cookie=$(echo "$has_cookie" | tr -d '[:space:]')
      has_cookie="${has_cookie:-0}"

      _gerrit_debug "Cookie count for account $account_id: $has_cookie"

      if [ "$has_cookie" -gt 0 ] 2>/dev/null; then
        _gerrit_debug "Successfully authenticated as account $account_id"
        echo "$account_id"
        return 0
      fi
    fi
  done

  _gerrit_error "Failed to authenticate as admin"
  echo ""
  return 1
}

# Make authenticated API request
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - HTTP method (GET, POST, PUT, DELETE)
#   $3 - endpoint URL
#   $4 - cookie file path
#   $5 - request data (optional, for POST/PUT)
#   $6 - content type (optional, default: application/json)
#
# Returns:
#   Response body (echoed)
#
# Note: This function automatically extracts the XSRF token from the cookie file
#       and sends it as the X-Gerrit-Auth header, which is required for write operations.
gerrit_api_request() {
  local target="$1"
  local method="$2"
  local endpoint="$3"
  local cookie_file="$4"
  local data="${5:-}"
  local content_type="${6:-application/json}"

  # Get XSRF token for authentication
  local xsrf_token
  xsrf_token=$(gerrit_get_xsrf_token "$target" "$cookie_file")

  local curl_args=("-s" "-b" "$cookie_file" "-X" "$method")

  # Add X-Gerrit-Auth header if we have an XSRF token (required for write operations)
  if [ -n "$xsrf_token" ]; then
    curl_args+=("-H" "X-Gerrit-Auth: $xsrf_token")
  fi

  if [ -n "$data" ]; then
    curl_args+=("-H" "Content-Type: $content_type" "-d" "$data")
  fi

  _gerrit_debug "API request: $method $endpoint (XSRF: ${xsrf_token:+present}${xsrf_token:-missing})"

  if [ "$target" = "local" ]; then
    curl "${curl_args[@]}" "${endpoint}" 2>/dev/null
  else
    docker exec "$target" curl "${curl_args[@]}" "${endpoint}" 2>/dev/null
  fi
}

# Make authenticated API request and return HTTP status code
#
# Arguments:
#   Same as gerrit_api_request
#
# Returns:
#   Echoes: "BODY\nHTTP_CODE" (body on all lines except last, HTTP code on last line)
#
# Note: This function automatically extracts the XSRF token from the cookie file
#       and sends it as the X-Gerrit-Auth header, which is required for write operations.
gerrit_api_request_with_status() {
  local target="$1"
  local method="$2"
  local endpoint="$3"
  local cookie_file="$4"
  local data="${5:-}"
  local content_type="${6:-application/json}"

  # Get XSRF token for authentication
  local xsrf_token
  xsrf_token=$(gerrit_get_xsrf_token "$target" "$cookie_file")

  local curl_args=("-s" "-b" "$cookie_file" "-X" "$method" "-w" "\n%{http_code}")

  # Add X-Gerrit-Auth header if we have an XSRF token (required for write operations)
  if [ -n "$xsrf_token" ]; then
    curl_args+=("-H" "X-Gerrit-Auth: $xsrf_token")
  fi

  if [ -n "$data" ]; then
    curl_args+=("-H" "Content-Type: $content_type" "-d" "$data")
  fi

  _gerrit_debug "API request (with status): $method $endpoint (XSRF: ${xsrf_token:+present}${xsrf_token:-missing})"

  if [ "$target" = "local" ]; then
    curl "${curl_args[@]}" "${endpoint}" 2>/dev/null
  else
    docker exec "$target" curl "${curl_args[@]}" "${endpoint}" 2>/dev/null
  fi
}

###############################################################################
# Account Management
###############################################################################

# Check if an account exists by username
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - base URL
#   $3 - cookie file
#   $4 - username to check
#
# Returns:
#   Exit code 0 if exists, 1 if not
gerrit_account_exists() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local username="$4"

  local response
  response=$(gerrit_api_request "$target" "GET" "${base_url}/a/accounts/${username}" "$cookie_file")

  # Gerrit API returns JSON with )]}' prefix
  if echo "$response" | grep -q "_account_id"; then
    return 0
  fi
  return 1
}

# Get account ID by username
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - base URL
#   $3 - cookie file
#   $4 - username
#
# Returns:
#   Account ID (echoed), empty if not found
gerrit_get_account_id() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local username="$4"

  local response
  response=$(gerrit_api_request "$target" "GET" "${base_url}/a/accounts/${username}" "$cookie_file")

  # Extract account ID from response (format: )]}'<newline>{"_account_id":1000001,...})
  echo "$response" | grep -o '"_account_id":[0-9]*' | head -1 | cut -d: -f2
}

# Create a new account
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - base URL
#   $3 - cookie file
#   $4 - username
#   $5 - full name
#   $6 - email
#
# Returns:
#   Account ID on success (echoed), empty on failure
#   Exit code 0 on success, 1 on failure
gerrit_create_account() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local username="$4"
  local full_name="$5"
  local email="$6"

  _gerrit_info "  Creating account: $username..."

  # Create account using PUT /accounts/{username}
  # Include username in payload to ensure it's set properly
  local payload
  payload=$(jq -n \
    --arg username "$username" \
    --arg name "$full_name" \
    --arg email "$email" \
    '{username: $username, name: $name, email: $email}')

  local response
  response=$(gerrit_api_request_with_status "$target" "PUT" \
    "${base_url}/a/accounts/${username}" "$cookie_file" "$payload")

  local http_code
  http_code=$(echo "$response" | tail -1)
  local body
  body=$(echo "$response" | sed '$d')

  _gerrit_debug "Create account response: HTTP $http_code"
  _gerrit_debug "Response body: $body"

  if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
    _gerrit_info "  Account created successfully ✅"
    # Extract and return account ID
    echo "$body" | grep -o '"_account_id":[0-9]*' | head -1 | cut -d: -f2
    return 0
  elif [ "$http_code" = "409" ]; then
    _gerrit_info "  Account already exists"
    gerrit_get_account_id "$target" "$base_url" "$cookie_file" "$username"
    return 0
  else
    _gerrit_error "Failed to create account (HTTP $http_code)"
    _gerrit_debug "Response: $body"
    return 1
  fi
}

# Set username for an account
#
# Arguments:
#   $1 - target
#   $2 - base URL
#   $3 - cookie file
#   $4 - account ID
#   $5 - username
#
# Returns:
#   Exit code 0 on success
gerrit_set_username() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local account_id="$4"
  local username="$5"

  _gerrit_info "  Setting username: $username..."

  # Set username using PUT /accounts/{account-id}/username
  local response
  response=$(gerrit_api_request_with_status "$target" "PUT" \
    "${base_url}/a/accounts/${account_id}/username" "$cookie_file" \
    "{\"username\": \"$username\"}")

  local http_code
  http_code=$(echo "$response" | tail -1)

  if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
    _gerrit_info "  Username set ✅"
    return 0
  elif [ "$http_code" = "409" ]; then
    _gerrit_info "  Username already set"
    return 0
  else
    _gerrit_warn "Could not set username via API (HTTP $http_code) - may already be set"
    return 0
  fi
}

# Add account to Administrators group
#
# Arguments:
#   $1 - target
#   $2 - base URL
#   $3 - cookie file
#   $4 - account ID
#
# Returns:
#   Exit code 0 on success
gerrit_add_to_administrators() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local account_id="$4"

  _gerrit_info "  Adding account to Administrators group..."

  # Add member to Administrators group
  local response
  response=$(gerrit_api_request_with_status "$target" "PUT" \
    "${base_url}/a/groups/Administrators/members/${account_id}" "$cookie_file")

  local http_code
  http_code=$(echo "$response" | tail -1)

  if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
    _gerrit_info "  Added to Administrators group ✅"
    return 0
  elif [ "$http_code" = "409" ]; then
    _gerrit_info "  Already in Administrators group"
    return 0
  else
    _gerrit_warn "Failed to add to Administrators group (HTTP $http_code)"
    return 1
  fi
}

###############################################################################
# SSH Key Management
###############################################################################

# Add SSH key to account
#
# Arguments:
#   $1 - target
#   $2 - base URL
#   $3 - cookie file
#   $4 - account (account ID or "self")
#   $5 - SSH public key
#
# Returns:
#   Exit code 0 on success
gerrit_add_ssh_key() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local account="$4"
  local ssh_key="$5"

  local response
  response=$(gerrit_api_request_with_status "$target" "POST" \
    "${base_url}/a/accounts/${account}/sshkeys" "$cookie_file" \
    "$ssh_key" "text/plain")

  local http_code
  http_code=$(echo "$response" | tail -1)

  if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
    return 0
  elif [ "$http_code" = "409" ]; then
    # Key already exists
    return 0
  else
    _gerrit_debug "Failed to add SSH key (HTTP $http_code)"
    return 1
  fi
}

# Validate SSH key format
#
# Arguments:
#   $1 - SSH key string (may be multiple lines)
#
# Returns:
#   Exit code 0 if valid, 1 if invalid
gerrit_validate_ssh_keys() {
  local keys="$1"
  local valid_types="ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256"
  local line_num=0

  while IFS= read -r line || [ -n "$line" ]; do
    line_num=$((line_num + 1))
    # Skip empty lines and comments
    [ -z "$line" ] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue

    # Check if line starts with a valid SSH key type
    if ! echo "$line" | grep -qE "^($valid_types) "; then
      _gerrit_error "Invalid SSH key format on line $line_num"
      _gerrit_error "Expected format: <key-type> <base64-key> [comment]"
      _gerrit_error "Got: ${line:0:50}..."
      return 1
    fi
  done <<< "$keys"
  return 0
}

###############################################################################
# Cache Management
###############################################################################

# Flush Gerrit caches
#
# Arguments:
#   $1 - target
#   $2 - base URL
#   $3 - cookie file
#   $4 - cache name (optional, default: all caches)
#
# Returns:
#   Exit code 0 on success
gerrit_flush_cache() {
  local target="$1"
  local base_url="$2"
  local cookie_file="$3"
  local cache_name="${4:-}"

  if [ -n "$cache_name" ]; then
    _gerrit_info "  Flushing cache: $cache_name..."
    gerrit_api_request "$target" "POST" \
      "${base_url}/a/config/server/caches/${cache_name}/flush" "$cookie_file" >/dev/null
  else
    _gerrit_info "  Flushing all caches..."
    # Flush critical caches for account management
    for cache in accounts accounts_byemail accounts_byname groups groups_byuuid groups_members; do
      gerrit_api_request "$target" "POST" \
        "${base_url}/a/config/server/caches/${cache}/flush" "$cookie_file" >/dev/null 2>&1 || true
    done
  fi
  return 0
}

###############################################################################
# High-level Operations
###############################################################################

# Setup user account with SSH keys
# This is the main entry point for user management
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - base URL (e.g., http://localhost:8080)
#   $3 - username (or empty for admin)
#   $4 - SSH keys (newline-separated)
#   $5 - full name (optional, defaults to username)
#   $6 - email (optional, defaults to username@example.com)
#
# Returns:
#   Exit code 0 on success, 1 on failure
gerrit_setup_user_with_ssh_keys() {
  local target="$1"
  local base_url="$2"
  local username="${3:-admin}"
  local ssh_keys="$4"
  local full_name="${5:-$username}"
  local email="${6:-${username}@example.com}"

  _gerrit_info "Setting up user: $username"

  # Validate SSH keys
  if [ -n "$ssh_keys" ]; then
    if ! gerrit_validate_ssh_keys "$ssh_keys"; then
      _gerrit_error "SSH key validation failed"
      return 1
    fi
  fi

  # Create temporary cookie file path
  # IMPORTANT: Do NOT pre-create the file - curl needs to create it fresh
  # to properly write cookies. If the file exists but is empty, curl may
  # not write cookies correctly.
  local cookie_file="/tmp/gerrit_session_$$"
  # Remove any stale cookie file first
  if [ "$target" = "local" ]; then
    rm -f "$cookie_file" 2>/dev/null || true
  else
    docker exec "$target" rm -f "$cookie_file" 2>/dev/null || true
  fi

  # Get admin session
  _gerrit_info "  Authenticating as admin..."
  local admin_account
  admin_account=$(gerrit_get_admin_session "$target" "$base_url" "$cookie_file")

  if [ -z "$admin_account" ]; then
    _gerrit_error "Failed to authenticate as admin"
    return 1
  fi

  _gerrit_info "  Authenticated as account $admin_account ✅"

  # Determine target account
  local target_account
  local account_id

  if [ "$username" = "admin" ]; then
    # Use the admin account we're already authenticated as
    target_account="self"
    account_id="$admin_account"
    _gerrit_info "  Using current admin account"
  else
    # Check if account exists
    if gerrit_account_exists "$target" "$base_url" "$cookie_file" "$username"; then
      _gerrit_info "  Account $username already exists"
      account_id=$(gerrit_get_account_id "$target" "$base_url" "$cookie_file" "$username")
      target_account="$account_id"
    else
      # Create new account
      account_id=$(gerrit_create_account "$target" "$base_url" "$cookie_file" "$username" "$full_name" "$email")
      if [ -z "$account_id" ]; then
        _gerrit_error "Failed to create account $username"
        # Cleanup
        if [ "$target" = "local" ]; then
          rm -f "$cookie_file"
        else
          docker exec "$target" rm -f "$cookie_file" 2>/dev/null || true
        fi
        return 1
      fi
      target_account="$account_id"

      # Set username explicitly (may already be set from creation)
      gerrit_set_username "$target" "$base_url" "$cookie_file" "$account_id" "$username"

      # Add to Administrators group
      gerrit_add_to_administrators "$target" "$base_url" "$cookie_file" "$account_id"
    fi
  fi

  _gerrit_info "  Target account ID: $account_id"

  # Add SSH keys
  if [ -n "$ssh_keys" ]; then
    _gerrit_info "  Adding SSH keys..."
    local key_count=0
    local keys_added=0

    while IFS= read -r key || [ -n "$key" ]; do
      # Skip empty lines and comments
      [ -z "$key" ] && continue
      [[ "$key" =~ ^[[:space:]]*# ]] && continue
      [[ "$key" =~ ^[[:space:]]*$ ]] && continue

      key_count=$((key_count + 1))

      if gerrit_add_ssh_key "$target" "$base_url" "$cookie_file" "$target_account" "$key"; then
        keys_added=$((keys_added + 1))
        _gerrit_info "    Added key $key_count ✅"
      else
        _gerrit_warn "    Failed to add key $key_count"
      fi
    done <<< "$ssh_keys"

    _gerrit_info "  Added $keys_added/$key_count SSH keys"
  fi

  # Flush caches to ensure changes are visible
  _gerrit_info "  Flushing caches..."
  gerrit_flush_cache "$target" "$base_url" "$cookie_file"

  # Cleanup cookie file
  if [ "$target" = "local" ]; then
    rm -f "$cookie_file"
  else
    docker exec "$target" rm -f "$cookie_file" 2>/dev/null || true
  fi

  _gerrit_info "  User $username configured ✅"
  return 0
}

###############################################################################
# Replication Log Parsing
###############################################################################

# Count unique completed replications from log
# Excludes system repos (All-Projects, All-Users)
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - log file path (for local) or just uses default path (for container)
#
# Returns:
#   Count of unique completed replications (echoed)
gerrit_count_completed_replications() {
  local target="$1"
  local log_file="${2:-/var/gerrit/logs/pull_replication_log}"

  local count
  if [ "$target" = "local" ]; then
    count=$(grep 'Replication from .* completed' "$log_file" 2>/dev/null | \
      sed 's|.*Replication from .*/a/||; s|\.git completed.*||' | \
      grep -v -E '^All-Projects$|^All-Users$' | \
      sort -u | wc -l || echo "0")
  else
    count=$(docker exec "$target" sh -c "grep 'Replication from .* completed' '$log_file' 2>/dev/null | sed 's|.*Replication from .*/a/||; s|\\.git completed.*||' | grep -v -E '^All-Projects\$|^All-Users\$' | sort -u | wc -l" 2>/dev/null || echo "0")
  fi

  # Ensure count is a valid integer
  count="${count//[^0-9]/}"
  echo "${count:-0}"
}

# Count repositories in git directory
# Excludes system repos (All-Projects, All-Users)
#
# Arguments:
#   $1 - target ("local" or container ID)
#   $2 - git directory path
#
# Returns:
#   Count of repositories (echoed)
gerrit_count_repositories() {
  local target="$1"
  local git_dir="${2:-/var/gerrit/git}"

  local count
  if [ "$target" = "local" ]; then
    count=$(find "$git_dir" -name '*.git' -type d -prune 2>/dev/null | \
      while read -r dir; do
        if [ -f "$dir/HEAD" ]; then
          echo "$dir"
        fi
      done | grep -c -v -E 'All-Projects|All-Users' || echo "0")
  else
    count=$(docker exec "$target" sh -c \
      "find '$git_dir' -name '*.git' -type d -prune 2>/dev/null | while read -r dir; do
        if [ -f \"\$dir/HEAD\" ]; then
          echo \"\$dir\"
        fi
      done | grep -c -v -E 'All-Projects|All-Users'" 2>/dev/null || echo "0")
  fi

  # Ensure count is a valid integer
  count="${count//[^0-9]/}"
  echo "${count:-0}"
}
