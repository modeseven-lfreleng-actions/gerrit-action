#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Add SSH authentication keys to Gerrit container
# This script adds SSH public keys to a Gerrit user account, allowing
# external SSH access to the Gerrit container for debugging or automation.
#
# When SSH_AUTH_USERNAME is provided, a new user account is created.
# Otherwise, keys are added to the default admin account.

set -euo pipefail

# Check if SSH_AUTH_KEYS is provided
if [ -z "${SSH_AUTH_KEYS:-}" ]; then
  echo "No SSH auth keys provided, skipping..."
  exit 0
fi

# Validate SSH_AUTH_USERNAME if provided
# Only allow safe characters to prevent command injection
if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
  if ! [[ "$SSH_AUTH_USERNAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "::error::Invalid SSH_AUTH_USERNAME: '$SSH_AUTH_USERNAME'"
    echo "::error::Username must contain only letters, numbers, dots, underscores, and hyphens"
    exit 1
  fi
  if [ ${#SSH_AUTH_USERNAME} -gt 64 ]; then
    echo "::error::SSH_AUTH_USERNAME too long (max 64 characters)"
    exit 1
  fi
fi

# Validate SSH_AUTH_KEYS format
# Each line should start with a valid SSH key type
validate_ssh_keys() {
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
      echo "::error::Invalid SSH key format on line $line_num"
      echo "::error::Expected format: <key-type> <base64-key> [comment]"
      echo "::error::Got: ${line:0:50}..."
      return 1
    fi
  done <<< "$keys"
  return 0
}

if ! validate_ssh_keys "$SSH_AUTH_KEYS"; then
  echo "::error::SSH_AUTH_KEYS validation failed"
  exit 1
fi

echo "Adding SSH authentication keys to Gerrit container(s)..."

# Determine account configuration
# If SSH_AUTH_USERNAME is provided, create a new account with that username
# Otherwise, use the default admin account
if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
  # Custom username provided - create a new account
  # Use account ID 1000001+ for custom users (1000000 is reserved for admin)
  ACCOUNT_ID="1000001"
  USERNAME="$SSH_AUTH_USERNAME"
  FULL_NAME="$SSH_AUTH_USERNAME"
  EMAIL="${SSH_AUTH_USERNAME}@gerrit.local"
  echo "Creating custom Gerrit user: $USERNAME (account ID: $ACCOUNT_ID)"
else
  # Default admin account
  ACCOUNT_ID="1000000"
  USERNAME="admin"
  FULL_NAME="Administrator"
  EMAIL="admin@example.com"
  echo "Using default admin account (ID: $ACCOUNT_ID)"
fi

# Read instances from the tracking file
INSTANCES_JSON_FILE="$WORK_DIR/instances.json"

# Function to create the internal admin account (ID 1000000) with SSH keys
# This is needed for cache flushing operations
create_internal_admin() {
  local cid="$1"

  echo "  Creating internal admin account for cache operations..."

  # Check if SSH key exists in container (from auth_type=ssh)
  local ssh_key_path="/var/gerrit/ssh/id_rsa"
  if ! docker exec "$cid" test -f "$ssh_key_path" 2>/dev/null; then
    echo "  No SSH key found at $ssh_key_path, generating one..."
    docker exec "$cid" bash -c '
      mkdir -p /var/gerrit/ssh
      ssh-keygen -t ed25519 -f /var/gerrit/ssh/id_rsa -N "" -q
      chmod 600 /var/gerrit/ssh/id_rsa
      chmod 644 /var/gerrit/ssh/id_rsa.pub
    '
  fi

  # Get the public key
  local pub_key
  pub_key=$(docker exec "$cid" cat /var/gerrit/ssh/id_rsa.pub 2>/dev/null || echo "")
  if [ -z "$pub_key" ]; then
    echo "::warning::Could not get SSH public key for internal admin"
    return 1
  fi

  # Create admin account (ID 1000000) with SSH keys
  local admin_account_id="1000000"
  local admin_email="admin@example.com"
  local admin_fullname="Administrator"
  local account_shard="00"
  local account_ref="refs/users/${account_shard}/${admin_account_id}"

  docker exec "$cid" bash -c '
    cd /tmp
    rm -rf internal-admin-setup
    mkdir -p internal-admin-setup
    cd internal-admin-setup

    git init -q --initial-branch=main admin-repo
    cd admin-repo

    git config user.email "gerrit@localhost"
    git config user.name "Gerrit System"

    # Check if account ref exists
    if git fetch /var/gerrit/git/All-Users.git "'"$account_ref"'":existing 2>/dev/null; then
      git checkout existing
      # Update authorized_keys
      echo "'"$pub_key"'" > authorized_keys
      git add authorized_keys
      git commit -m "Update SSH keys for internal admin" --allow-empty
    else
      # Create new account
      cat > account.config <<EOF
[account]
  fullName = '"$admin_fullname"'
  preferredEmail = '"$admin_email"'
  active = true
EOF
      echo "'"$pub_key"'" > authorized_keys
      git add account.config authorized_keys
      git commit -m "Create internal admin account"
    fi

    git push /var/gerrit/git/All-Users.git HEAD:"'"$account_ref"'"
  ' 2>/dev/null || echo "  Note: Internal admin account may already exist"

  # Register external ID for admin username
  docker exec "$cid" bash -c '
    cd /tmp/internal-admin-setup
    rm -rf extid-repo
    git init -q --initial-branch=main extid-repo
    cd extid-repo

    git config user.email "gerrit@localhost"
    git config user.name "Gerrit System"

    # Fetch existing external-ids or create new
    if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:external-ids 2>/dev/null; then
      git checkout external-ids
    else
      git checkout --orphan external-ids
      git rm -rf . 2>/dev/null || true
    fi

    # Create external ID for username:admin
    EXTERNAL_ID_FILE="username:admin"
    EXTERNAL_ID_HASH=$(echo -n "$EXTERNAL_ID_FILE" | sha1sum | cut -d" " -f1)
    EXTERNAL_ID_SHARD="${EXTERNAL_ID_HASH:0:2}"

    mkdir -p "$EXTERNAL_ID_SHARD"
    cat > "$EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH" <<EOF
[externalId "username:admin"]
  accountId = 1000000
EOF

    git add .
    git commit -m "Add external ID for internal admin" --allow-empty
    git push /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids
  ' 2>/dev/null || echo "  Note: Admin external ID may already exist"

  # Add admin to Administrators group
  docker exec "$cid" bash -c '
    cd /tmp/internal-admin-setup
    rm -rf group-repo
    git init -q --initial-branch=main group-repo
    cd group-repo

    git config user.email "gerrit@localhost"
    git config user.name "Gerrit System"

    # Fetch group-names to find Administrators UUID
    if ! git fetch /var/gerrit/git/All-Users.git refs/meta/group-names:group-names 2>/dev/null; then
      echo "Could not fetch group-names"
      exit 0
    fi
    git checkout group-names

    # Find Administrators group UUID
    ADMIN_UUID=""
    for f in *; do
      if [ -f "$f" ] && grep -q "name = Administrators" "$f" 2>/dev/null; then
        ADMIN_UUID="$f"
        break
      fi
    done

    if [ -z "$ADMIN_UUID" ]; then
      echo "Could not find Administrators group"
      exit 0
    fi

    # Fetch and update group membership
    SHARD="${ADMIN_UUID:0:2}"
    GROUP_REF="refs/groups/$SHARD/$ADMIN_UUID"

    cd /tmp/internal-admin-setup
    rm -rf members-repo
    git init -q --initial-branch=main members-repo
    cd members-repo

    git config user.email "gerrit@localhost"
    git config user.name "Gerrit System"

    if git fetch /var/gerrit/git/All-Users.git "$GROUP_REF":group-ref 2>/dev/null; then
      git checkout group-ref
    else
      git checkout --orphan group-ref
      git rm -rf . 2>/dev/null || true
      cat > group.config <<EOF
[group]
  name = Administrators
  visibleToAll = false
EOF
      touch members
    fi

    # Add account ID 1000000 if not already present
    if ! grep -q "^1000000$" members 2>/dev/null; then
      echo "1000000" >> members
      sort -u members -o members
      git add .
      git commit -m "Add internal admin to Administrators" --allow-empty
      git push /var/gerrit/git/All-Users.git HEAD:"$GROUP_REF"
    fi
  ' 2>/dev/null || echo "  Note: Admin may already be in Administrators group"

  # Cleanup
  docker exec "$cid" rm -rf /tmp/internal-admin-setup 2>/dev/null || true

  echo "  Internal admin account configured ✅"
}

if [ ! -f "$INSTANCES_JSON_FILE" ]; then
  echo "::error::Instances file not found: $INSTANCES_JSON_FILE"
  exit 1
fi

# Function to create or update a Gerrit account with SSH keys
create_gerrit_account() {
  local cid="$1"
  local account_id="$2"
  local username="$3"
  local full_name="$4"
  local email="$5"

  # Calculate account ref shard (last 2 digits of account ID)
  local account_shard
  account_shard=$(printf "%02d" $((account_id % 100)))
  local account_ref="refs/users/${account_shard}/${account_id}"

  echo "  Creating/updating account at $account_ref..."

  # Create a temporary directory for git operations
  docker exec "$cid" mkdir -p /tmp/account-setup

  # Write the SSH keys to a temporary file on the host
  local keys_tmpfile
  keys_tmpfile=$(mktemp)
  echo "$SSH_AUTH_KEYS" > "$keys_tmpfile"

  # Copy the keys file into the container
  docker cp "$keys_tmpfile" "$cid:/tmp/authorized_keys_input"
  rm -f "$keys_tmpfile"

  # Check if the ref already exists
  local ref_exists
  ref_exists=$(docker exec "$cid" git -C /var/gerrit/git/All-Users.git \
    show-ref "$account_ref" 2>/dev/null || echo "")

  if [ -n "$ref_exists" ]; then
    echo "  Account ref already exists, updating SSH keys..."
    docker exec "$cid" bash -c '
      cd /tmp/account-setup
      rm -rf account-repo
      git init -q --initial-branch=main account-repo
      cd account-repo

      git config user.email "'"$email"'"
      git config user.name "'"$full_name"'"

      # Fetch existing account ref
      git fetch /var/gerrit/git/All-Users.git '"'$account_ref'"':existing
      git checkout existing

      # Update authorized_keys from the input file
      cp /tmp/authorized_keys_input authorized_keys

      git add authorized_keys
      git commit -m "Update SSH authorized keys for '"$username"'" --allow-empty

      # Push back
      git push /var/gerrit/git/All-Users.git HEAD:'"'$account_ref'"'
    '
  else
    echo "  Creating new account ref..."
    docker exec "$cid" bash -c '
      cd /tmp/account-setup
      rm -rf account-repo
      git init -q --initial-branch=main account-repo
      cd account-repo

      git config user.email "'"$email"'"
      git config user.name "'"$full_name"'"

      # Create account.config
      cat > account.config <<EOF
[account]
  fullName = '"$full_name"'
  preferredEmail = '"$email"'
  active = true
EOF

      # Copy the authorized_keys from the input file
      cp /tmp/authorized_keys_input authorized_keys

      # Add and commit
      git add account.config authorized_keys
      git commit -m "Create account '"$username"' with SSH keys"

      # Push to All-Users repository
      git push /var/gerrit/git/All-Users.git HEAD:'"'$account_ref'"'
    '
  fi
}

# Function to register external ID for a username
register_external_id() {
  local cid="$1"
  local account_id="$2"
  local username="$3"
  local full_name="$4"
  local email="$5"

  echo "  Registering external ID for username: $username..."

  # Create the external-ids script
  local extid_script
  extid_script=$(mktemp)
  cat > "$extid_script" << EXTID_SCRIPT_EOF
#!/bin/bash
set -e
cd /tmp/account-setup
rm -rf accounts-repo
git init -q --initial-branch=main accounts-repo
cd accounts-repo

git config user.email "$email"
git config user.name "$full_name"

# Try to fetch existing external-ids ref
if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:external-ids 2>/dev/null; then
  git checkout external-ids
else
  # Create new external-ids tracking
  git checkout --orphan external-ids
  git rm -rf . 2>/dev/null || true
fi

# Create external ID file for username
EXTERNAL_ID_FILE="username:$username"
EXTERNAL_ID_HASH=\$(echo -n "\$EXTERNAL_ID_FILE" | sha1sum | cut -d' ' -f1)
EXTERNAL_ID_SHARD="\${EXTERNAL_ID_HASH:0:2}"

mkdir -p "\$EXTERNAL_ID_SHARD"
cat > "\$EXTERNAL_ID_SHARD/\$EXTERNAL_ID_HASH" <<EOF
[externalId "username:$username"]
  accountId = $account_id
EOF

git add .
git commit -m "Add external ID for $username" --allow-empty

# Force push to handle potential conflicts with concurrent updates
if ! git push --force /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids; then
  echo "ERROR: Failed to push external ID for $username"
  exit 1
fi
echo "External ID registered successfully for $username"
EXTID_SCRIPT_EOF

  docker cp "$extid_script" "$cid:/tmp/register-external-ids.sh"
  rm -f "$extid_script"
  if ! docker exec "$cid" bash /tmp/register-external-ids.sh; then
    echo "::warning::Failed to register external ID for $username"
  fi
}

# Function to add user to Administrators group for full permissions
add_to_administrators_group() {
  local cid="$1"
  local account_id="$2"
  local username="$3"

  echo "  Adding user '$username' to Administrators group..."

  # Create the script to add user to Administrators group
  local admin_script
  admin_script=$(mktemp)
  cat > "$admin_script" << 'ADMIN_SCRIPT_EOF'
#!/bin/bash
set -e

ACCOUNT_ID="$1"
USERNAME="$2"

cd /tmp/account-setup
rm -rf admin-group-repo
git init -q --initial-branch=main admin-group-repo
cd admin-group-repo

git config user.email "gerrit@localhost"
git config user.name "Gerrit System"

# First, find the Administrators group UUID from group-names ref
if ! git fetch /var/gerrit/git/All-Users.git refs/meta/group-names:group-names 2>/dev/null; then
  echo "Warning: Could not fetch group-names ref"
  exit 0
fi

git checkout group-names

# Find the Administrators group file (it's named after the UUID)
ADMIN_UUID=""
for f in *; do
  if [ -f "$f" ] && grep -q "name = Administrators" "$f" 2>/dev/null; then
    ADMIN_UUID="$f"
    break
  fi
done

if [ -z "$ADMIN_UUID" ]; then
  echo "ERROR: Could not find Administrators group UUID"
  echo "Available group files:"
  ls -la
  exit 1
fi

echo "Found Administrators group UUID: $ADMIN_UUID"

# Now fetch the group ref and add the user
SHARD="${ADMIN_UUID:0:2}"
GROUP_REF="refs/groups/$SHARD/$ADMIN_UUID"

cd /tmp/account-setup
rm -rf group-members-repo
git init -q --initial-branch=main group-members-repo
cd group-members-repo

git config user.email "gerrit@localhost"
git config user.name "Gerrit System"

if git fetch /var/gerrit/git/All-Users.git "$GROUP_REF":group-ref 2>/dev/null; then
  git checkout group-ref
else
  # Group ref doesn't exist yet, create it
  git checkout --orphan group-ref
  git rm -rf . 2>/dev/null || true
  # Create group.config
  cat > group.config <<EOF
[group]
  name = Administrators
  visibleToAll = false
EOF
  touch members
fi

# Check if account is already a member
if grep -q "^${ACCOUNT_ID}$" members 2>/dev/null; then
  echo "Account $ACCOUNT_ID is already a member of Administrators"
  exit 0
fi

# Add the account ID to members file
echo "$ACCOUNT_ID" >> members

# Sort and deduplicate
sort -u members -o members

git add .
git commit -m "Add $USERNAME (account $ACCOUNT_ID) to Administrators group" --allow-empty

if ! git push /var/gerrit/git/All-Users.git HEAD:"$GROUP_REF"; then
  echo "ERROR: Failed to push group membership changes"
  exit 1
fi

echo "Successfully added $USERNAME to Administrators group"
ADMIN_SCRIPT_EOF

  docker cp "$admin_script" "$cid:/tmp/add-to-admin-group.sh"
  rm -f "$admin_script"
  if ! docker exec "$cid" bash /tmp/add-to-admin-group.sh "$account_id" "$username"; then
    echo "::warning::Failed to add user to Administrators group"
  fi
}

# Function to flush Gerrit caches
# Uses the internal admin account with SSH key at /var/gerrit/ssh/id_rsa
flush_caches() {
  local cid="$1"

  echo "  Reloading Gerrit caches..."

  # Try HTTP-based cache flush first (works with DEVELOPMENT_BECOME_ANY_ACCOUNT)
  # This is more reliable than SSH as it doesn't require internal admin account setup
  docker exec "$cid" bash -c '
    # Wait a moment for Gerrit to be ready
    sleep 2

    # Get a session by "becoming" account 1000000 (internal admin)
    # In DEVELOPMENT_BECOME_ANY_ACCOUNT mode, this gives us admin access
    SESSION_COOKIE=$(curl -s -c - "http://localhost:8080/login/?account_id=1000000" 2>/dev/null | grep GerritAccount | awk "{print \$7}")
    XSRF_TOKEN=$(curl -s -c - "http://localhost:8080/login/?account_id=1000000" 2>/dev/null | grep XSRF_TOKEN | awk "{print \$7}")

    if [ -n "$SESSION_COOKIE" ] && [ -n "$XSRF_TOKEN" ]; then
      echo "Using HTTP API to flush caches..."
      for cache in accounts external_ids groups groups_byuuid groups_members; do
        curl -s -X POST \
          -b "GerritAccount=$SESSION_COOKIE" \
          -H "X-Gerrit-Auth: $XSRF_TOKEN" \
          "http://localhost:8080/a/config/server/caches/$cache/flush" 2>/dev/null || true
      done
      echo "HTTP cache flush completed"
      exit 0
    fi

    # Fall back to SSH-based cache flush
    SSH_KEY="/var/gerrit/ssh/id_rsa"
    if [ ! -f "$SSH_KEY" ]; then
      SSH_KEY="/var/gerrit/.ssh/id_rsa"
    fi
    if [ ! -f "$SSH_KEY" ]; then
      echo "No SSH key found for cache flushing, skipping..."
      exit 0
    fi

    # Try to flush all caches at once (most efficient)
    if ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=5 \
           -p 29418 \
           -i "$SSH_KEY" \
           admin@localhost \
           gerrit flush-caches --all 2>/dev/null; then
      echo "All caches flushed successfully via SSH"
      exit 0
    fi

    # If --all failed, try individual caches
    for cache in accounts external_ids groups groups_byuuid groups_members; do
      ssh -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=5 \
          -p 29418 \
          -i "$SSH_KEY" \
          admin@localhost \
          gerrit flush-caches --cache "$cache" 2>/dev/null || true
    done
  ' || echo "  Note: Cache flush not available, changes may take effect on next Gerrit restart"
}

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

  # First, ensure internal admin account exists for cache operations
  create_internal_admin "$cid"

  # Create or update the user account
  create_gerrit_account "$cid" "$ACCOUNT_ID" "$USERNAME" "$FULL_NAME" "$EMAIL"

  # Register external ID
  register_external_id "$cid" "$ACCOUNT_ID" "$USERNAME" "$FULL_NAME" "$EMAIL"

  # Add user to Administrators group for full create/merge permissions
  add_to_administrators_group "$cid" "$ACCOUNT_ID" "$USERNAME"

  # Flush caches
  flush_caches "$cid"

  # Clean up
  docker exec "$cid" rm -rf /tmp/account-setup /tmp/authorized_keys_input 2>/dev/null || true

  echo "  SSH keys added ✅"

  # Display the keys that were added
  KEY_COUNT=$(echo "$SSH_AUTH_KEYS" | grep -c '^[a-z]' || echo "0")
  echo "  Added $KEY_COUNT SSH public key(s) for user '$USERNAME'"
  if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
    echo "  User added to Administrators group (create/merge permissions)"
  fi
done

echo ""
echo "SSH authentication keys configured ✅"
echo ""
echo "You can now SSH to the Gerrit container(s) as '$USERNAME'"
echo "Example: ssh -p <port> $USERNAME@<host>"
if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
  echo ""
  echo "User '$USERNAME' has been added to the Administrators group."
  echo "This grants full permissions to create and merge changes."
fi

# Add to step summary
{
  echo "### SSH Access Configured 🔑"
  echo ""
  echo "SSH public keys have been added to the Gerrit container(s)."
  echo ""
  echo "**Username:** \`$USERNAME\`"
  if [ -n "${SSH_AUTH_USERNAME:-}" ]; then
    echo ""
    echo "**Account:** Custom user account created (ID: $ACCOUNT_ID)"
    echo ""
    echo "**Group:** Added to Administrators (full create/merge permissions)"
  else
    echo ""
    echo "**Account:** Default admin account (ID: $ACCOUNT_ID)"
  fi
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
