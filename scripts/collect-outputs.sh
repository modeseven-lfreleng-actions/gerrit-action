#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Collect outputs from Gerrit instances
# This script aggregates instance metadata and exports to GitHub outputs

set -euo pipefail

echo "Collecting outputs..."
echo ""

# Read instances metadata
if [ ! -f "$WORK_DIR/instances.json" ]; then
  echo "::error::No instances metadata found ❌"
  exit 1
fi

INSTANCES_JSON_FILE="$WORK_DIR/instances.json"
API_PATHS_FILE="$WORK_DIR/api_paths.json"

# Build container IDs array
CONTAINER_IDS_JSON="["
FIRST=true
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")

  if [ "$FIRST" = true ]; then
    CONTAINER_IDS_JSON+="\"$cid\""
    FIRST=false
  else
    CONTAINER_IDS_JSON+=",\"$cid\""
  fi
done
CONTAINER_IDS_JSON+="]"

# Build container IPs array
CONTAINER_IPS_JSON="["
FIRST=true
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  ip=$(jq -r ".\"$slug\".ip" "$INSTANCES_JSON_FILE")

  if [ "$FIRST" = true ]; then
    CONTAINER_IPS_JSON+="\"$ip\""
    FIRST=false
  else
    CONTAINER_IPS_JSON+=",\"$ip\""
  fi
done
CONTAINER_IPS_JSON+="]"

# Build Gerrit URLs list (comma-separated)
GERRIT_URLS=""
FIRST=true
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  url=$(jq -r ".\"$slug\".url" "$INSTANCES_JSON_FILE")

  if [ "$FIRST" = true ]; then
    GERRIT_URLS="$url"
    FIRST=false
  else
    GERRIT_URLS="$GERRIT_URLS,$url"
  fi
done

# Build API paths JSON (mapping slug to api_path and api_url)
if [ -f "$API_PATHS_FILE" ]; then
  API_PATHS_JSON=$(cat "$API_PATHS_FILE")
else
  # Build from instances.json if api_paths.json doesn't exist
  API_PATHS_JSON="{}"
  for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
    api_path=$(jq -r ".\"$slug\".api_path // \"\"" "$INSTANCES_JSON_FILE")
    api_url=$(jq -r ".\"$slug\".api_url // \"\"" "$INSTANCES_JSON_FILE")
    gerrit_host=$(jq -r ".\"$slug\".gerrit_host // \"\"" "$INSTANCES_JSON_FILE")

    temp_json=$(mktemp)
    echo "$API_PATHS_JSON" | jq \
      --arg slug "$slug" \
      --arg api_path "$api_path" \
      --arg api_url "$api_url" \
      --arg gerrit_host "$gerrit_host" \
      '.[$slug] = {
        gerrit_host: $gerrit_host,
        api_path: $api_path,
        api_url: $api_url
      }' > "$temp_json"
    API_PATHS_JSON=$(cat "$temp_json")
    rm -f "$temp_json"
  done
fi

# Build SSH host keys JSON (mapping slug to host public keys)
SSH_HOST_KEYS_JSON="{}"
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  ssh_keys=$(jq -c ".\"$slug\".ssh_host_keys // {}" "$INSTANCES_JSON_FILE")
  temp_json=$(mktemp)
  echo "$SSH_HOST_KEYS_JSON" | jq \
    --arg slug "$slug" \
    --argjson keys "$ssh_keys" \
    '.[$slug] = $keys' > "$temp_json"
  SSH_HOST_KEYS_JSON=$(cat "$temp_json")
  rm -f "$temp_json"
done

# Read full instances JSON
INSTANCES_JSON=$(cat "$INSTANCES_JSON_FILE")

# Export to GitHub outputs
{
  echo "container_ids=$CONTAINER_IDS_JSON"
  echo "container_ips=$CONTAINER_IPS_JSON"
  echo "gerrit_urls=$GERRIT_URLS"
  echo "instances<<EOF"
  echo "$INSTANCES_JSON"
  echo "EOF"
  echo "api_paths<<EOF"
  echo "$API_PATHS_JSON"
  echo "EOF"
  echo "ssh_host_keys<<EOF"
  echo "$SSH_HOST_KEYS_JSON"
  echo "EOF"
} >> "$GITHUB_OUTPUT"

# Display summary
echo "Outputs collected ✅"
echo ""
echo "Container IDs: $CONTAINER_IDS_JSON"
echo "Container IPs: $CONTAINER_IPS_JSON"
echo "Gerrit URLs: $GERRIT_URLS"
echo "API Paths: $API_PATHS_JSON"
echo "SSH Host Keys: $SSH_HOST_KEYS_JSON"
echo ""

# Add to step summary
{
  echo "**Outputs** 📤"
  echo ""
  echo '```json'
  echo "$INSTANCES_JSON" | jq '.'
  echo '```'
  echo ""
  echo "**API Paths** 🔗"
  echo ""
  echo '```json'
  echo "$API_PATHS_JSON" | jq '.'
  echo '```'
  echo ""
  echo "**SSH Host Keys** 🔑"
  echo ""
  echo '```json'
  echo "$SSH_HOST_KEYS_JSON" | jq '.'
  echo '```'
  echo ""
  echo "**Access URLs** 🔗"
  echo ""
} >> "$GITHUB_STEP_SUMMARY"

for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  http_port=$(jq -r ".\"$slug\".http_port" "$INSTANCES_JSON_FILE")
  ssh_port=$(jq -r ".\"$slug\".ssh_port" "$INSTANCES_JSON_FILE")
  api_url=$(jq -r ".\"$slug\".api_url // \"N/A\"" "$INSTANCES_JSON_FILE")

  {
    echo "- **$slug**"
    echo "  - HTTP: \`http://localhost:$http_port\`"
    echo "  - SSH: \`ssh://localhost:$ssh_port\`"
    echo "  - Source API: \`$api_url\`"
  } >> "$GITHUB_STEP_SUMMARY"
done

echo "" >> "$GITHUB_STEP_SUMMARY"
