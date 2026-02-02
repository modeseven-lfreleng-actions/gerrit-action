#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Detect Gerrit API paths via redirect detection
# This script queries each Gerrit server to determine its API path prefix
# (e.g., /r/, /infra/, /gerrit/) and stores results for use in replication config

set -euo pipefail

echo "Detecting Gerrit API paths..."
echo ""

# Output file for API paths
API_PATHS_FILE="$WORK_DIR/api_paths.json"
echo "{}" > "$API_PATHS_FILE"

# Function to detect API path for a single Gerrit host
# Debug messages go to stderr, only the result goes to stdout
detect_api_path() {
  local gerrit_host="$1"
  local slug="$2"
  local provided_api_path="${3:-}"

  echo "Detecting API path for: $gerrit_host" >&2

  # If api_path is provided in the config, use it directly
  if [ -n "$provided_api_path" ]; then
    echo "  Using provided api_path: $provided_api_path" >&2
    echo "$provided_api_path"
    return 0
  fi

  # Try to detect via redirect
  local base_url="https://${gerrit_host}"
  local redirect_url=""
  local api_path=""

  # Follow redirects and capture the final URL
  redirect_url=$(curl -sI -o /dev/null -w "%{url_effective}" \
    --connect-timeout 10 \
    --max-time 30 \
    -L "$base_url/" 2>/dev/null || echo "")

  if [ -n "$redirect_url" ] && [ "$redirect_url" != "$base_url/" ]; then
    # Extract path from the redirect URL
    # Remove the protocol and host, keep the path
    api_path=$(echo "$redirect_url" | sed -E 's|https?://[^/]+||' | sed 's|/$||')

    if [ -n "$api_path" ]; then
      echo "  Detected via redirect: $api_path" >&2
      echo "$api_path"
      return 0
    fi
  fi

  # Try common Gerrit paths if redirect didn't work
  local common_paths=("/r" "/gerrit" "/infra" "")

  for path in "${common_paths[@]}"; do
    local test_url="${base_url}${path}/config/server/version"
    local http_code=""

    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
      --connect-timeout 5 \
      --max-time 10 \
      "$test_url" 2>/dev/null || echo "000")

    if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
      echo "  Detected via probe: $path" >&2
      echo "$path"
      return 0
    fi
  done

  # Default to empty path if nothing worked
  echo "  Warning: Could not detect API path, using empty path" >&2
  echo ""
  return 0
}

# Function to validate API path by checking version endpoint
validate_api_path() {
  local gerrit_host="$1"
  local api_path="$2"

  local test_url="https://${gerrit_host}${api_path}/config/server/version"
  local http_code=""

  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    --max-time 10 \
    "$test_url" 2>/dev/null || echo "000")

  if [ "$http_code" = "200" ]; then
    return 0
  else
    return 1
  fi
}

# Function to get Gerrit version
get_gerrit_version() {
  local gerrit_host="$1"
  local api_path="$2"

  local version_url="https://${gerrit_host}${api_path}/config/server/version"
  local response=""

  response=$(curl -s \
    --connect-timeout 5 \
    --max-time 10 \
    "$version_url" 2>/dev/null || echo "")

  # Gerrit responses have )]}' prefix, strip it and quotes
  echo "$response" | sed "s/^)]}'$//" | tr -d '"\n' | sed "s/^)]}'//"
}

# Parse GERRIT_SETUP and detect API paths for each instance
INSTANCES=$(echo "$GERRIT_SETUP" | jq -c '.[]')

while IFS= read -r instance; do
  slug=$(echo "$instance" | jq -r '.slug')
  gerrit_host=$(echo "$instance" | jq -r '.gerrit')
  provided_api_path=$(echo "$instance" | jq -r '.api_path // empty')

  echo "========================================"
  echo "Instance: $slug ($gerrit_host)"
  echo "========================================"

  # Detect API path
  api_path=$(detect_api_path "$gerrit_host" "$slug" "$provided_api_path")

  # Validate the detected path
  if validate_api_path "$gerrit_host" "$api_path"; then
    echo "  Validation: ✅ API path confirmed"

    # Get Gerrit version for info
    version=$(get_gerrit_version "$gerrit_host" "$api_path")
    if [ -n "$version" ]; then
      echo "  Gerrit version: $version"
    fi
  else
    echo "  Validation: ⚠️  Could not validate API path"
  fi

  # Construct full API URL
  api_url="https://${gerrit_host}${api_path}"
  echo "  API URL: $api_url"

  # Store in JSON file
  temp_json=$(mktemp)
  jq --arg slug "$slug" \
     --arg api_path "$api_path" \
     --arg api_url "$api_url" \
     --arg gerrit_host "$gerrit_host" \
     '.[$slug] = {
       gerrit_host: $gerrit_host,
       api_path: $api_path,
       api_url: $api_url
     }' \
     "$API_PATHS_FILE" > "$temp_json"
  mv "$temp_json" "$API_PATHS_FILE"

  echo ""
done <<< "$INSTANCES"

# Summary
echo "========================================"
echo "API Path Detection Complete ✅"
echo "========================================"
echo ""
echo "Detected paths:"
jq -r 'to_entries[] | "  \(.key): \(.value.api_path) -> \(.value.api_url)"' \
  "$API_PATHS_FILE"
echo ""

# Add to step summary
{
  echo "**Gerrit API Paths** 🔗"
  echo ""
  echo "| Instance | API Path | API URL |"
  echo "|----------|----------|---------|"
} >> "$GITHUB_STEP_SUMMARY"

for slug in $(jq -r 'keys[]' "$API_PATHS_FILE"); do
  api_path=$(jq -r ".\"$slug\".api_path" "$API_PATHS_FILE")
  api_url=$(jq -r ".\"$slug\".api_url" "$API_PATHS_FILE")
  echo "| $slug | \`$api_path\` | $api_url |" >> "$GITHUB_STEP_SUMMARY"
done

echo "" >> "$GITHUB_STEP_SUMMARY"
