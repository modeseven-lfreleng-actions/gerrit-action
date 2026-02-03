#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Add SSH authentication keys to Gerrit container
# This script adds SSH public keys to a Gerrit admin account, allowing
# external SSH access to the Gerrit container for debugging or automation.

set -euo pipefail

# Check if SSH_AUTH_KEYS is provided
if [ -z "${SSH_AUTH_KEYS:-}" ]; then
  echo "No SSH auth keys provided, skipping..."
  exit 0
fi

echo "Adding SSH authentication keys to Gerrit container(s)..."

# Gerrit admin account ID (created automatically in DEVELOPMENT_BECOME_ANY_ACCOUNT mode)
ADMIN_ACCOUNT_ID="1000000"
ADMIN_USERNAME="admin"

# Read instances from the tracking file
INSTANCES_JSON_FILE="$WORK_DIR/instances.json"

if [ ! -f "$INSTANCES_JSON_FILE" ]; then
  echo "::error::Instances file not found: $INSTANCES_JSON_FILE"
  exit 1
fi

# Process each instance
for slug in $(jq -r 'keys[]' "$INSTANCES_JSON_FILE"); do
  echo "Processing instance: $slug"

  # Get container ID
  cid=$(jq -r ".\"$slug\".cid" "$INSTANCES_JSON_FILE")
  if [ -z "$cid" ] || [ "$cid" = "null" ]; then
    echo "::warning::No container ID found for $slug, skipping..."
    continue
  fi

  echo "  Container ID: $cid"

  # Create the admin account in All-Users repository
  # Gerrit stores accounts in refs/users/XX/ACCOUNTID where XX is the last 2 digits
  ACCOUNT_SHARD=$(printf "%02d" $((ADMIN_ACCOUNT_ID % 100)))
  ACCOUNT_REF="refs/users/${ACCOUNT_SHARD}/${ADMIN_ACCOUNT_ID}"

  echo "  Creating admin account at $ACCOUNT_REF..."

  # Create a temporary directory for git operations
  docker exec "$cid" mkdir -p /tmp/account-setup

  # Write the SSH keys to a temporary file on the host
  KEYS_TMPFILE=$(mktemp)
  echo "$SSH_AUTH_KEYS" > "$KEYS_TMPFILE"

  # Copy the keys file into the container
  docker cp "$KEYS_TMPFILE" "$cid:/tmp/authorized_keys_input"
  rm -f "$KEYS_TMPFILE"

  # Initialize a bare repo for the account ref
  docker exec "$cid" bash -c '
    cd /tmp/account-setup
    rm -rf account-repo
    git init account-repo
    cd account-repo

    # Configure git
    git config user.email "admin@example.com"
    git config user.name "Administrator"

    # Create account.config
    cat > account.config <<EOF
[account]
  fullName = Administrator
  preferredEmail = admin@example.com
  active = true
EOF

    # Copy the authorized_keys from the input file
    cp /tmp/authorized_keys_input authorized_keys

    # Add and commit
    git add account.config authorized_keys
    git commit -m "Create admin account with SSH keys"
  '

  # Push to All-Users repository
  # First, check if the ref already exists
  REF_EXISTS=$(docker exec "$cid" git -C /var/gerrit/git/All-Users.git \
    show-ref "$ACCOUNT_REF" 2>/dev/null || echo "")

  if [ -n "$REF_EXISTS" ]; then
    echo "  Account ref already exists, updating..."
    # Fetch the existing ref, update it, and push
    docker exec "$cid" bash -c '
      cd /tmp/account-setup/account-repo
      git fetch /var/gerrit/git/All-Users.git '"'$ACCOUNT_REF'"':existing
      git checkout existing

      # Update authorized_keys from the input file
      cp /tmp/authorized_keys_input authorized_keys

      git add authorized_keys
      git commit -m "Update SSH authorized keys" --allow-empty

      # Push back
      git push /var/gerrit/git/All-Users.git HEAD:'"'$ACCOUNT_REF'"'
    '
  else
    echo "  Creating new account ref..."
    docker exec "$cid" bash -c '
      cd /tmp/account-setup/account-repo
      git push /var/gerrit/git/All-Users.git HEAD:'"'$ACCOUNT_REF'"'
    '
  fi

  # Also need to add the account to the accounts ref (refs/meta/accounts)
  # This registers the account ID -> external ID mapping
  echo "  Registering account in accounts index..."

  # Create the external-ids script on the host and copy it to the container
  EXTID_SCRIPT=$(mktemp)
  cat > "$EXTID_SCRIPT" << 'EXTID_SCRIPT_EOF'
#!/bin/bash
set -e
cd /tmp/account-setup
rm -rf accounts-repo
git init accounts-repo
cd accounts-repo

git config user.email "admin@example.com"
git config user.name "Administrator"

# Try to fetch existing accounts ref
if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:external-ids 2>/dev/null; then
  git checkout external-ids
else
  # Create new external-ids tracking
  git checkout --orphan external-ids
  git rm -rf . 2>/dev/null || true
fi

# Create external ID file for username
# External ID format: username:admin -> account 1000000
EXTERNAL_ID_FILE="username:admin"
EXTERNAL_ID_HASH=$(echo -n "$EXTERNAL_ID_FILE" | sha1sum | cut -d' ' -f1)
EXTERNAL_ID_SHARD="${EXTERNAL_ID_HASH:0:2}"

mkdir -p "$EXTERNAL_ID_SHARD"
cat > "$EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH" <<EOF
[externalId "username:admin"]
  accountId = 1000000
EOF

git add .
git commit -m "Add admin external ID" --allow-empty

git push /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids 2>/dev/null || true
EXTID_SCRIPT_EOF

  docker cp "$EXTID_SCRIPT" "$cid:/tmp/register-external-ids.sh"
  rm -f "$EXTID_SCRIPT"
  docker exec "$cid" bash /tmp/register-external-ids.sh

  # Reload the account cache
  echo "  Reloading Gerrit caches..."

  # Try to flush caches via SSH (may not work if SSH isn't ready yet)
  docker exec "$cid" bash -c '
    # Wait a moment for Gerrit to be ready
    sleep 2

    # Try to flush caches using the Gerrit SSH interface locally
    # This requires the container internal SSH to be ready
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -p 29418 \
        -i /var/gerrit/.ssh/id_rsa \
        admin@localhost \
        gerrit flush-caches --cache accounts 2>/dev/null || true
  ' || true

  # Clean up
  docker exec "$cid" rm -rf /tmp/account-setup /tmp/authorized_keys_input

  echo "  SSH keys added for $slug ✅"

  # Display the keys that were added
  KEY_COUNT=$(echo "$SSH_AUTH_KEYS" | grep -c '^[a-z]' || echo "0")
  echo "  Added $KEY_COUNT SSH public key(s)"
done

echo ""
echo "SSH authentication keys configured ✅"
echo ""
echo "You can now SSH to the Gerrit container(s) as '$ADMIN_USERNAME'"
echo "Example: ssh -p <port> $ADMIN_USERNAME@<host>"

# Add to step summary
{
  echo "### SSH Access Configured 🔑"
  echo ""
  echo "SSH public keys have been added to the Gerrit container(s)."
  echo ""
  echo "**Username:** \`$ADMIN_USERNAME\`"
  echo ""
  echo "**Keys added:**"
  echo '```'
  echo "$SSH_AUTH_KEYS" | head -5
  if [ "$(echo "$SSH_AUTH_KEYS" | wc -l)" -gt 5 ]; then
    echo "... (and more)"
  fi
  echo '```'
  echo ""
} >> "$GITHUB_STEP_SUMMARY"
