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
} >> "$GITHUB_OUTPUT"

# Display summary
echo "Outputs collected ✅"
echo ""
echo "Container IDs: $CONTAINER_IDS_JSON"
echo "Container IPs: $CONTAINER_IPS_JSON"
echo "Gerrit URLs: $GERRIT_URLS"
echo ""

# Add to step summary
{
  echo "**Outputs** 📤"
  echo ""
  echo '```json'
  echo "$INSTANCES_JSON" | jq '.'
  echo '```'
  echo ""
  echo "**Access URLs** 🔗"
  echo ""
} >> "$GITHUB_STEP_SUMMARY"

for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  http_port=$(jq -r ".\"$slug\".http_port" "$INSTANCES_JSON_FILE")
  ssh_port=$(jq -r ".\"$slug\".ssh_port" "$INSTANCES_JSON_FILE")

  {
    echo "- **$slug**"
    echo "  - HTTP: \`http://localhost:$http_port\`"
    echo "  - SSH: \`ssh://localhost:$ssh_port\`"
  } >> "$GITHUB_STEP_SUMMARY"
done

echo "" >> "$GITHUB_STEP_SUMMARY"
