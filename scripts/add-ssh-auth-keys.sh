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
  local ssh_key_path="/var/gerrit/ssh/id_ed25519"
  if ! docker exec "$cid" test -f "$ssh_key_path" 2>/dev/null; then
    echo "  No SSH key found at $ssh_key_path, generating one..."
    docker exec "$cid" bash -c '
      mkdir -p /var/gerrit/ssh
      ssh-keygen -t ed25519 -f /var/gerrit/ssh/id_ed25519 -N "" -q
      chmod 600 /var/gerrit/ssh/id_ed25519
      chmod 644 /var/gerrit/ssh/id_ed25519.pub
    '
  fi

  # Get the public key
  local pub_key
  pub_key=$(docker exec "$cid" cat /var/gerrit/ssh/id_ed25519.pub 2>/dev/null || echo "")
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
  # This links the username "admin" to account 1000000
  echo "  Registering external ID for admin username..."
  docker exec "$cid" bash -c '
    set -e
    cd /tmp/internal-admin-setup
    rm -rf extid-repo
    git init -q --initial-branch=main extid-repo
    cd extid-repo

    git config user.email "gerrit@localhost"
    git config user.name "Gerrit System"

    # Fetch existing external-ids or create new
    if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:external-ids 2>/dev/null; then
      git checkout external-ids
      echo "  Fetched existing external-ids ref"
    else
      git checkout --orphan external-ids
      git rm -rf . 2>/dev/null || true
      echo "  Created new external-ids ref"
    fi

    # Create external ID for username:admin
    # The filename is the SHA-1 hash of the external ID string
    EXTERNAL_ID_FILE="username:admin"
    EXTERNAL_ID_HASH=$(echo -n "$EXTERNAL_ID_FILE" | sha1sum | cut -d" " -f1)
    EXTERNAL_ID_SHARD="${EXTERNAL_ID_HASH:0:2}"

    echo "  External ID hash: $EXTERNAL_ID_HASH (shard: $EXTERNAL_ID_SHARD)"

    mkdir -p "$EXTERNAL_ID_SHARD"
    cat > "$EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH" <<EOF
[externalId "username:admin"]
  accountId = 1000000
EOF

    echo "  Created external ID file: $EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH"
    cat "$EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH"

    git add .
    git status
    git commit -m "Add external ID for internal admin" --allow-empty

    echo "  Pushing external-ids ref..."
    if git push /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids; then
      echo "  External ID for admin pushed successfully"
    else
      echo "  Push failed, trying force push..."
      git push --force /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids
    fi

    # Verify the external ID was written
    echo "  Verifying external ID in repository..."
    cd /tmp/internal-admin-setup
    rm -rf verify-extid
    git clone --bare /var/gerrit/git/All-Users.git verify-extid 2>/dev/null
    cd verify-extid
    git show refs/meta/external-ids:"$EXTERNAL_ID_SHARD/$EXTERNAL_ID_HASH" 2>/dev/null && echo "  Verified: admin external ID exists" || echo "  WARNING: admin external ID not found!"
  '
  local admin_extid_result=$?
  if [ $admin_extid_result -ne 0 ]; then
    echo "::warning::Failed to register external ID for admin"
  fi

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
  # This script carefully preserves existing external IDs while adding the new one
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

# Retry loop to handle concurrent updates
MAX_RETRIES=3
RETRY=0
while [ \$RETRY -lt \$MAX_RETRIES ]; do
  # Always fetch the latest external-ids ref
  rm -rf .git/refs/heads/* 2>/dev/null || true
  if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:external-ids 2>/dev/null; then
    git checkout -f external-ids
    git clean -fd
  else
    # Create new external-ids tracking if it doesn't exist
    git checkout --orphan external-ids
    git rm -rf . 2>/dev/null || true
  fi

  # Create external ID file for username
  EXTERNAL_ID_FILE="username:$username"
  EXTERNAL_ID_HASH=\$(echo -n "\$EXTERNAL_ID_FILE" | sha1sum | cut -d' ' -f1)
  EXTERNAL_ID_SHARD="\${EXTERNAL_ID_HASH:0:2}"

  mkdir -p "\$EXTERNAL_ID_SHARD"
  # External ID must include accountId to link username to account
  cat > "\$EXTERNAL_ID_SHARD/\$EXTERNAL_ID_HASH" <<EOF
[externalId "username:$username"]
  accountId = $account_id
EOF

  git add .
  git commit -m "Add external ID for $username" --allow-empty

  # Try to push (without force first to detect conflicts)
  if git push /var/gerrit/git/All-Users.git HEAD:refs/meta/external-ids 2>/dev/null; then
    echo "External ID registered successfully for $username"

    # Verify the external ID was written correctly
    cd /tmp/account-setup
    rm -rf verify-repo
    git init -q verify-repo
    cd verify-repo
    git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:verify 2>/dev/null
    git checkout verify
    if grep -r "username:$username" . >/dev/null 2>&1; then
      echo "  Verified: external ID for $username exists in NoteDb"
    else
      echo "  WARNING: external ID for $username not found after push!"
    fi
    exit 0
  fi

  # Push failed - likely a concurrent update, retry
  RETRY=\$((RETRY + 1))
  echo "  Push conflict, retrying (\$RETRY/\$MAX_RETRIES)..."
  sleep 1
done

echo "ERROR: Failed to push external ID for $username after \$MAX_RETRIES retries"
exit 1
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

# Function to reload Gerrit caches by clearing disk cache and restarting container
# Direct restart is the most reliable way to ensure Gerrit picks up NoteDb changes
# HTTP/SSH cache flush methods don't work during initial setup (chicken-and-egg problem)
flush_caches() {
  local cid="$1"
  local api_path="${2:-}"  # Optional API path (e.g., /r) for context-path deployments

  echo "  Reloading Gerrit caches..."

  # Clear ALL disk caches and indexes BEFORE restart to force Gerrit to rebuild from NoteDb
  # This is critical - if stale cache/index data exists, username lookups fail
  echo "  Clearing Gerrit disk cache and indexes..."
  docker exec "$cid" bash -c '
    echo "  Clearing H2 cache database files..."
    rm -rf /var/gerrit/cache/*.h2.db 2>/dev/null || true
    rm -rf /var/gerrit/cache/*.lock 2>/dev/null || true

    echo "  Clearing specific cache types..."
    rm -rf /var/gerrit/cache/accounts* 2>/dev/null || true
    rm -rf /var/gerrit/cache/external_ids* 2>/dev/null || true
    rm -rf /var/gerrit/cache/groups* 2>/dev/null || true
    rm -rf /var/gerrit/cache/ldap* 2>/dev/null || true
    rm -rf /var/gerrit/cache/sshkeys* 2>/dev/null || true
    rm -rf /var/gerrit/cache/web_sessions* 2>/dev/null || true

    echo "  Clearing account and external ID indexes..."
    rm -rf /var/gerrit/index/accounts_* 2>/dev/null || true
    rm -rf /var/gerrit/index/groups_* 2>/dev/null || true

    echo "  Verifying external IDs in NoteDb before restart..."
    cd /tmp && rm -rf verify-extids 2>/dev/null
    git clone --bare /var/gerrit/git/All-Users.git verify-extids 2>/dev/null || true
    if [ -d verify-extids ]; then
      cd verify-extids
      echo "  External IDs in refs/meta/external-ids:"
      git ls-tree refs/meta/external-ids 2>/dev/null | head -10 || echo "  (none found)"
      echo "  Looking for username external IDs..."
      git show refs/meta/external-ids 2>/dev/null | grep -r "externalId.*username" || echo "  (no username external IDs found in tree)"
      cd /tmp && rm -rf verify-extids
    fi

    echo "  Cache and index files cleared"
    echo "  Remaining cache files:"
    ls -la /var/gerrit/cache/ 2>/dev/null | head -10 || echo "  (cache directory empty)"
    echo "  Index directory:"
    ls -la /var/gerrit/index/ 2>/dev/null | head -10 || echo "  (index directory empty)"
  ' || echo "  Note: Some cache/index files may not exist yet"

  echo "  Restarting Gerrit container..."
  if docker restart "$cid" >/dev/null 2>&1; then
    echo "  Container restarted, waiting for Gerrit to be ready..."
    # Wait for Gerrit to be ready again using multiple detection methods
    local max_wait=180  # Increased timeout for large repos
    local waited=0
    local ready=0
    # Build health check URL with optional API path
    local health_url="http://localhost:8080${api_path}/config/server/version"

    while [ $waited -lt $max_wait ]; do
      # Method 1: HTTP health check (most reliable when working)
      local http_code
      http_code=$(docker exec "$cid" curl -s -o /dev/null -w "%{http_code}" "$health_url" 2>/dev/null || echo "000")
      if [ "$http_code" = "200" ]; then
        echo "  Gerrit is ready (HTTP check) ✅"
        ready=1
        break
      fi

      # Method 2: Check for "Gerrit Code Review" ready message in logs
      if docker logs --tail 100 "$cid" 2>&1 | grep -q "Gerrit Code Review .* ready"; then
        # Also verify the HTTP port is responding (even if not 200)
        if [ "$http_code" != "000" ]; then
          echo "  Gerrit is ready (log check + HTTP responding) ✅"
          ready=1
          break
        fi
      fi

      # Method 3: Check if SSH port is responding (Gerrit is mostly ready)
      if docker exec "$cid" bash -c "echo | nc -w1 localhost 29418" >/dev/null 2>&1; then
        # SSH is up, Gerrit is likely ready enough for our purposes
        if [ $waited -ge 30 ]; then
          echo "  Gerrit SSH port ready, proceeding ✅"
          ready=1
          break
        fi
      fi

      sleep 2
      waited=$((waited + 2))
      if [ $((waited % 10)) -eq 0 ]; then
        echo "    Waiting... ${waited}s (HTTP: $http_code)"
      fi
    done

    if [ $ready -eq 0 ]; then
      echo "::warning::Gerrit health check did not succeed within ${max_wait}s"
      echo "  Note: Gerrit may still be functional, continuing..."
    fi
  else
    echo "::warning::Failed to restart container"
    # Continue anyway - Gerrit might still work
  fi

  # Verify external ID is now visible via API after restart
  echo "  Verifying external ID is visible via API..."
  sleep 2  # Give Gerrit a moment to fully initialize
  local account_url="http://localhost:8080${api_path}/accounts/$USERNAME"
  # Get API response and count matches, with robust integer validation
  # The grep -c command may output non-integer values in edge cases
  local api_response
  api_response=$(docker exec "$cid" curl -s "$account_url" 2>/dev/null || echo "")
  local API_CHECK
  API_CHECK=$(printf '%s' "$api_response" | grep -c "_account_id" 2>/dev/null || echo "0")
  # Strip any non-digit characters and ensure we have a valid integer
  API_CHECK="${API_CHECK//[^0-9]/}"
  API_CHECK="${API_CHECK:-0}"
  if [ "$API_CHECK" -gt 0 ]; then
    echo "  External ID visible via API ✅"
  else
    # Check if it exists in NoteDb at least
    EXTID_EXISTS=$(docker exec "$cid" bash -c '
      cd /tmp
      rm -rf extid-check
      git init -q extid-check
      cd extid-check
      if git fetch /var/gerrit/git/All-Users.git refs/meta/external-ids:extids 2>/dev/null; then
        git checkout extids
        if grep -rq "username:'"$USERNAME"'" . 2>/dev/null; then
          echo "found"
        else
          echo "not_found"
        fi
      else
        echo "no_ref"
      fi
      cd /tmp && rm -rf extid-check
    ' 2>/dev/null || echo "error")

    if [ "$EXTID_EXISTS" = "found" ]; then
      echo "::warning::External ID exists in NoteDb but not visible via API"
      echo "::warning::SSH authentication may not work until Gerrit fully loads"
    elif [ "$EXTID_EXISTS" = "not_found" ]; then
      echo "::error::External ID for $USERNAME not found in NoteDb - registration failed"
    else
      echo "::warning::Could not verify external ID status"
    fi
  fi
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

  # Get API path for this instance (for context-path deployments like /r)
  api_path=$(jq -r ".\"$slug\".api_path // \"\"" "$INSTANCES_JSON_FILE")
  effective_api_path=""
  if [ "${USE_API_PATH:-false}" = "true" ] && [ -n "$api_path" ]; then
    effective_api_path="$api_path"
  fi

  # Flush caches
  flush_caches "$cid" "$effective_api_path"

  # Clean up
  docker exec "$cid" rm -rf /tmp/account-setup /tmp/authorized_keys_input 2>/dev/null || true

  echo "  SSH keys added ✅"

  # Display the keys that were added
  # Robustly count SSH keys with integer validation
  KEY_COUNT=$(echo "$SSH_AUTH_KEYS" | grep -c '^[a-z]' 2>/dev/null || echo "0")
  KEY_COUNT="${KEY_COUNT//[^0-9]/}"
  KEY_COUNT="${KEY_COUNT:-0}"
  echo "  Added $KEY_COUNT SSH public key(s) for user '$USERNAME'"
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
