<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# ⚙️ Gerrit Server Container

Starts and runs Gerrit Code Review server(s) in Docker containers with
automated pull-replication plugin configuration for mirroring production
Gerrit instances in CI/CD workflows.

## Features

- 🚀 **Multi-instance support** - Start multiple Gerrit servers from a
  single JSON configuration
- 🔄 **Automatic replication** - Built-in pull-replication plugin for
  syncing from production servers
- 🔐 **Flexible authentication** - Support for SSH keys, HTTP basic
  auth, and bearer tokens
- 🐳 **Docker layer caching** - Optimized performance with intelligent caching
- 💾 **Persistent containers** - Containers remain available throughout
  workflow duration
- 🧹 **Automatic cleanup** - Graceful shutdown and cleanup on workflow completion
- 🏥 **Health checking** - Automated service availability verification
- 📊 **Comprehensive outputs** - Full instance metadata and access URLs

## Quick Start

<!-- markdownlint-disable MD046 -->

```yaml
steps:
  - name: "Start Gerrit mirror"
    id: gerrit
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: |
        [{
          "project": "ONAP",
          "slug": "onap",
          "gerrit": "gerrit.onap.org"
        }]
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      sync_on_startup: true

  - name: "Use Gerrit instance"
    run: |
      echo "Gerrit URL: ${{ steps.gerrit.outputs.gerrit_urls }}"
      # Access Gerrit at http://localhost:8080
```

<!-- markdownlint-enable MD046 -->

## Use Cases

Use this action in CI/CD pipelines that need to:

- **Test against production data** - Mirror a production Gerrit server
  for integration testing
- **Develop offline** - Work with Gerrit repositories without
  affecting production
- **Verify changes** - Test plugin configurations, migrations, or upgrades
- **CI/CD automation** - Automate workflows that require Gerrit
  repository access
- **Multi-site testing** - Test against multiple Gerrit instances simultaneously

## Inputs

<!-- markdownlint-disable MD013 -->

### Required Inputs

<!-- markdownlint-disable MD013 -->

| Name         | Required | Default | Description                                                                              |
| ------------ | -------- | ------- | ---------------------------------------------------------------------------------------- |
| gerrit_setup | **True** |         | JSON array defining Gerrit instances                                                     |

<!-- markdownlint-enable MD013 -->

### Authentication Inputs (one method required)

<!-- markdownlint-disable MD013 -->

| Name              | Required | Default | Description                                                      |
| ----------------- | -------- | ------- | ---------------------------------------------------------------- |
| ssh_private_key   | False    |         | SSH private key for authentication (required if `auth_type=ssh`) |
| ssh_known_hosts   | False    | auto    | SSH known_hosts entries (auto-generated if not provided)         |
| ssh_auth_keys     | False    |         | SSH public keys to add for container access (one key per line)   |
| ssh_auth_username | False    |         | Gerrit username to create for SSH access (uses admin if omitted) |
| http_username     | False    |         | HTTP basic auth username (required if `auth_type=http_basic`)    |
| http_password     | False    |         | HTTP basic auth password (required if `auth_type=http_basic`)    |
| bearer_token      | False    |         | Bearer token (required if `auth_type=bearer_token`)              |

<!-- markdownlint-enable MD013 -->

### Gerrit Configuration

<!-- markdownlint-disable MD013 -->

| Name            | Required | Default           | Description                                                        |
| --------------- | -------- | ----------------- | ------------------------------------------------------------------ |
| gerrit_version  | False    | `3.13.1-ubuntu24` | Gerrit Docker image version tag                                    |
| plugin_version  | False    | `stable-3.13`     | Pull-replication plugin version/branch                             |
| base_http_port  | False    | `8080`            | Starting HTTP port (increments for multi-instance)                 |
| base_ssh_port   | False    | `29418`           | Starting SSH port (increments for multi-instance)                  |
| auth_type       | False    | `ssh`             | Authentication method: `ssh`, `http_basic`, or `bearer_token`      |
| remote_ssh_user | False    | `gerrit`          | SSH username for remote Gerrit servers (can override per-instance) |
| remote_ssh_port | False    | `29418`           | SSH port for remote Gerrit servers (can override per-instance)     |

<!-- markdownlint-enable MD013 -->

### Replication Settings

<!-- markdownlint-disable MD013 -->

| Name                        | Required | Default | Description                                                                       |
| --------------------------- | -------- | ------- | --------------------------------------------------------------------------------- |
| sync_on_startup             | False    | `true`  | Trigger replication after startup                                                 |
| fetch_every                 | False    | `60s`   | Interval for pull-replication polling (e.g., `60s`, `5m`, `0s` to disable)        |
| replication_timeout         | False    | `600`   | Timeout for initial replication sync (seconds)                                    |
| replication_wait_timeout    | False    | `600`   | Max time to wait for replication to match expected repo count (seconds)           |
| require_replication_success | False    | `true`  | Fail workflow if replication verification fails                                   |
| sync_refs                   | False    | (all)   | Comma-separated refs to sync (e.g., `+refs/heads/*:refs/heads/*`)                 |
| replication_threads         | False    | `4`     | Number of replication threads per instance                                        |
| max_projects                | False    | `800`   | Maximum projects to fetch when no filter specified (increase for large instances) |

<!-- markdownlint-enable MD013 -->

### Container Management

<!-- markdownlint-disable MD013 -->

| Name             | Required | Default | Description                                       |
| ---------------- | -------- | ------- | ------------------------------------------------- |
| exit             | False    | `true`  | Stop containers when job completes                |
| check_service    | False    | `true`  | Verify service availability after startup         |
| enable_cache     | False    | `true`  | Enable Docker layer and dependency caching        |
| cache_key_suffix | False    |         | Extra suffix for cache keys (for cache isolation) |

<!-- markdownlint-enable MD013 -->

### Advanced Options

<!-- markdownlint-disable MD013 -->

| Name                | Required | Default | Description                                                             |
| ------------------- | -------- | ------- | ----------------------------------------------------------------------- |
| debug               | False    | `false` | Enable debugging output                                                 |
| use_api_path        | False    | `false` | Use source server's URL path (e.g., `/r`, `/infra`) for local container |
| additional_plugins  | False    |         | Comma-separated list of extra plugin URLs to install                    |
| gerrit_init_args    | False    |         | Extra arguments for `gerrit.war init`                                   |
| skip_plugin_install | False    | `false` | Skip pull-replication plugin installation (testing)                     |

<!-- markdownlint-enable MD013 -->

### External Tunnel Configuration

These inputs configure Gerrit with public tunnel URLs for remote access.

<!-- markdownlint-disable MD013 -->

| Name         | Required | Default | Description                                                                                                        |
| ------------ | -------- | ------- | ------------------------------------------------------------------------------------------------------------------ |
| tunnel_host  | False    |         | External tunnel hostname (e.g., `bore.pub`, Tailscale IP). Used for `canonicalWebUrl` and `sshd.advertisedAddress` |
| tunnel_ports | False    |         | JSON mapping slugs to tunnel ports: `{"slug": {"http": 12345, "ssh": 54321}}`                                      |

<!-- markdownlint-enable MD013 -->

> **Note:** When using tunnels, start the tunnel *before* invoking this action.
> Some tunnel tools (like [bore](https://github.com/ekzhang/bore)) don't require
> the local port to be listening—they connect on-demand when traffic arrives.
> Other tunnels (like [Tailscale](https://tailscale.com)) provide a stable IP
> that can be used directly with the local ports.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name          | Description                                  | Example                                          |
| ------------- | -------------------------------------------- | ------------------------------------------------ |
| container_ids | JSON array of running container IDs          | `["abc123", "def456"]`                           |
| container_ips | JSON array of container IP addresses         | `["172.17.0.2", "172.17.0.3"]`                   |
| instances     | JSON object mapping slug to instance details | See [Instances Output](#instances-output)        |
| gerrit_urls   | Comma-separated list of Gerrit HTTP URLs     | `http://172.17.0.2:8080,http://172.17.0.3:8080`  |
| api_paths     | JSON object mapping slug to API path details | `{"onap": {"api_path": "/r", "api_url": "..."}}` |
| ssh_host_keys | JSON object mapping slug to SSH host keys    | `{"onap": {"ssh_host_ed25519_key": "..."}}`      |

<!-- markdownlint-enable MD013 -->

### Instances Output

```json
{
  "onap": {
    "cid": "abc123def456",
    "ip": "172.17.0.2",
    "http_port": 8080,
    "ssh_port": 29418,
    "url": "http://172.17.0.2:8080",
    "gerrit_host": "gerrit.onap.org",
    "project": "ONAP"
  }
}
```

## Configuration Format

The `gerrit_setup` input accepts a JSON array of instance configurations:

```json
[
  {
    "slug": "onap",
    "gerrit": "gerrit.onap.org",
    "project": "",
    "api_path": "/r"
  },
  {
    "slug": "opendaylight",
    "gerrit": "git.opendaylight.org",
    "project": "regex:releng/.*",
    "api_path": "/gerrit",
    "ssh_user": "replication-bot",
    "ssh_port": "29418"
  }
]
```

### Configuration Fields

- **`slug`** (required) - Unique identifier for this instance (used in
  container naming and credential lookup)
- **`gerrit`** (required) - Hostname of the source Gerrit server to
  replicate from
- **`project`** (optional) - Project filter for replication:
  - **Empty string** (`""`) or omitted: Replicate **all projects** from the server
  - **Literal name**: `"releng/lftools"` - single project
  - **Comma-separated**: `"releng/lftools,ci-management"` - multiple projects
  - **Regex pattern**: `"regex:releng/.*"` or `"regex:^infra/.*"` - pattern
    matching (must use `regex:` prefix to avoid misclassifying literal names
    containing special characters like `.` or `[`)
- **`api_path`** (optional) - API path prefix if Gerrit is not at the root
  (e.g., `/infra`, `/r`, `/gerrit`). Auto-detected if not provided.
- **`ssh_user`** (optional) - SSH username for the remote Gerrit server.
  Overrides global `remote_ssh_user`. This is the account on the remote
  server that has your `ssh_private_key`'s public key registered.
- **`ssh_port`** (optional) - SSH port for the remote Gerrit server.
  Overrides global `remote_ssh_port`. Typically `29418` for Gerrit.

### Project Filter Behavior

When the `project` field is empty or omitted, the action will:

1. Query the remote Gerrit server's `/projects/` API endpoint
2. Fetch the list of all available projects
3. Pre-create empty bare repositories for each project locally
4. Configure pull-replication to sync all projects on startup

This enables full server mirroring without needing to specify individual
project names.

## Usage Examples

### Example 1: Single Instance with SSH

```yaml
steps:
  - name: "Start Gerrit mirror"
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: |
        [{
          "project": "ONAP",
          "slug": "onap",
          "gerrit": "gerrit.onap.org"
        }]
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      sync_on_startup: true
```

### Example 2: Multi-Instance Setup

```yaml
steps:
  - name: "Start multiple Gerrit mirrors"
    id: gerrit
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      base_http_port: 9000
      base_ssh_port: 30000

  - name: "Access instances"
    run: |
      echo "All URLs: ${{ steps.gerrit.outputs.gerrit_urls }}"
      echo "Instance data:"
      echo '${{ steps.gerrit.outputs.instances }}' | jq '.'
```

### Example 3: HTTP Basic Authentication

```yaml
steps:
  - name: "Start Gerrit with HTTP auth"
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      auth_type: http_basic
      http_username: ${{ vars.GERRIT_USERNAME }}
      http_password: ${{ secrets.GERRIT_PASSWORD }}
```

### Example 4: Persistent Container

```yaml
steps:
  - name: "Start Gerrit (persistent)"
    id: gerrit
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      exit: false  # Keep containers running

  - name: "Run tests"
    run: |
      # Gerrit is available at http://localhost:8080
      curl http://localhost:8080/config/server/version

  - name: "More work with Gerrit"
    run: |
      # Container is still available
      git clone http://localhost:8080/my-project

  - name: "Manual cleanup"
    if: always()
    run: |
      # Cleanup containers manually
      docker kill ${{ fromJson(steps.gerrit.outputs.container_ids)[0] }}
```

### Example 5: Custom Gerrit Version

```yaml
steps:
  - name: "Start specific Gerrit version"
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      gerrit_version: "3.9.4-ubuntu24"
      plugin_version: "stable-3.9"
```

### Example 6: Custom Replication Configuration

```yaml
steps:
  - name: "Selective replication"
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      sync_refs: "+refs/heads/*:refs/heads/*,+refs/tags/*:refs/tags/*"
      replication_threads: 8
      sync_on_startup: true
```

### Example 7: With Extra Plugins

```yaml
steps:
  - name: "Start Gerrit with extra plugins"
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: ${{ vars.GERRIT_SETUP }}
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      additional_plugins: |
        https://example.com/plugins/my-plugin.jar,
        https://example.com/plugins/another-plugin.jar
```

### Example 8: Public Access via External Tunnel (Bore)

This example shows how to expose Gerrit publicly using an external tunnel.
The example uses [bore](https://github.com/ekzhang/bore), but other tunnel
methods like [Tailscale](https://tailscale.com) can also be used.
Bore tunnels can be started before Gerrit since they connect on-demand.

<!-- markdownlint-disable MD013 -->

```yaml
steps:
  # Calculate the local ports that Gerrit will use
  - name: "Calculate local ports"
    id: ports
    run: |
      # These match gerrit-action defaults (BASE_PORT + index)
      echo "http_port=8080" >> "$GITHUB_OUTPUT"
      echo "ssh_port=29418" >> "$GITHUB_OUTPUT"

  # Install bore tunnel client
  - name: "Install bore"
    run: |
      BORE_VERSION="0.5.2"
      curl -sSL "https://github.com/ekzhang/bore/releases/download/v${BORE_VERSION}/bore-v${BORE_VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar xz
      sudo mv bore /usr/local/bin/

  # Start tunnels BEFORE Gerrit (bore connects on-demand)
  - name: "Start bore tunnels"
    id: tunnels
    env:
      LOCAL_HTTP: ${{ steps.ports.outputs.http_port }}
      LOCAL_SSH: ${{ steps.ports.outputs.ssh_port }}
      SERVER_SLUG: my-gerrit  # Must match slug in gerrit_setup
    run: |
      # Start tunnels - local ports don't need to be listening yet!
      bore local "$LOCAL_HTTP" --to bore.pub > bore-http.log 2>&1 &
      bore local "$LOCAL_SSH" --to bore.pub > bore-ssh.log 2>&1 &

      # Wait for tunnels to establish
      sleep 10

      # Extract assigned public ports from logs
      HTTP_PORT=$(grep -oP 'listening at bore\.pub:\K\d+' bore-http.log || true)
      SSH_PORT=$(grep -oP 'listening at bore\.pub:\K\d+' bore-ssh.log || true)

      # Validate extracted ports before using them
      if [ -z "$HTTP_PORT" ] || [ -z "$SSH_PORT" ] || \
         ! [[ "$HTTP_PORT" =~ ^[0-9]+$ ]] || ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to extract valid bore tunnel ports from logs." >&2
        echo "HTTP_PORT='$HTTP_PORT', SSH_PORT='$SSH_PORT'" >&2
        echo "Check bore-http.log and bore-ssh.log for connection issues." >&2
        exit 1
      fi

      # Build tunnel_ports JSON for gerrit-action
      TUNNEL_PORTS=$(jq -n \
        --arg slug "$SERVER_SLUG" \
        --argjson http "$HTTP_PORT" \
        --argjson ssh "$SSH_PORT" \
        '{($slug): {http: $http, ssh: $ssh}}')

      echo "tunnel_ports=$TUNNEL_PORTS" >> "$GITHUB_OUTPUT"
      echo "Tunnels ready: bore.pub:$HTTP_PORT (HTTP), bore.pub:$SSH_PORT (SSH)"

  # Start Gerrit with tunnel URLs configured from the start
  - name: "Start Gerrit mirror"
    id: gerrit
    uses: lfreleng-actions/gerrit-server-action@main
    with:
      gerrit_setup: |
        [{
          "project": "my-project",
          "slug": "my-gerrit",
          "gerrit": "gerrit.example.org"
        }]
      ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
      sync_on_startup: true
      # Pass tunnel configuration - Gerrit uses public URLs from the start
      tunnel_host: bore.pub
      tunnel_ports: ${{ steps.tunnels.outputs.tunnel_ports }}

  # Gerrit is now accessible at the public bore.pub URLs!
```

<!-- markdownlint-enable MD013 -->

> **Real-world example:** See the tunnel workflow in
> [`test-deploy-gerrit`](https://github.com/modeseven-lfreleng-actions/test-deploy-gerrit)
> for a complete working implementation with multiple tunnel options.

## Using Repository Variables

You can store the Gerrit setup configuration as a repository variable:

**Variable Name:** `GERRIT_SETUP`

**Variable Value:**

```json
[
  {
    "project": "ONAP",
    "slug": "onap",
    "gerrit": "gerrit.onap.org"
  },
  {
    "project": "OpenDaylight",
    "slug": "opendaylight",
    "gerrit": "git.opendaylight.org"
  }
]
```

**In Workflow:**

```yaml
- uses: lfreleng-actions/gerrit-server-action@main
  with:
    gerrit_setup: ${{ vars.GERRIT_SETUP }}
    ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
```

## Authentication Methods

### SSH Authentication (Recommended)

Generate an SSH key pair and add the public key to your Gerrit account:

```bash
ssh-keygen -t rsa -b 4096 -f gerrit_key -N ""
```

Add `gerrit_key.pub` to your Gerrit account's SSH keys, then add
the private key as a GitHub secret:

```yaml
with:
  auth_type: ssh
  ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}
```

### HTTP Basic Authentication

```yaml
with:
  auth_type: http_basic
  http_username: ${{ vars.GERRIT_USERNAME }}
  http_password: ${{ secrets.GERRIT_PASSWORD }}
```

### Bearer Token Authentication

```yaml
with:
  auth_type: bearer_token
  bearer_token: ${{ secrets.GERRIT_BEARER_TOKEN }}
```

## Performance & Caching

This action includes intelligent caching for optimal performance:

### Docker Layer Caching

- **Caches Gerrit container images** for faster follow-up runs
- **Pre-pulls images** to reduce startup time
- **Smart cache keys** based on OS, version, and optional suffix

### Plugin Download Caching

- **Caches downloaded plugins** to avoid repeated downloads
- **Shares cache** across workflows in the same repository

### Performance Benefits

- **First run**: Downloads and caches all necessary components
- **Follow-up runs**: **50-80% faster** startup using cached layers
- **Reduced bandwidth**: Fewer external downloads
- **Lower costs**: Reduced GitHub Actions minutes

### Disabling Cache

```yaml
with:
  enable_cache: false
```

### Cache Isolation

Use different cache keys for different purposes:

```yaml
with:
  cache_key_suffix: '-production'  # Separate cache for production tests
```

## Accessing Gerrit

Once started, Gerrit instances are accessible via:

### HTTP Access

```bash
# Using localhost (from host)
curl http://localhost:8080/config/server/version

# Using container IP (from other containers)
curl http://172.17.0.2:8080/config/server/version
```

### SSH Access

```bash
# Port is configurable (default: 29418)
ssh -p 29418 admin@localhost gerrit version
```

### Git Operations

```bash
# Clone a repository
git clone http://localhost:8080/my-project

# With authentication
git clone http://username:password@localhost:8080/my-project
```

## Monitoring Replication

Check replication status via container logs:

```yaml
- name: "Check replication"
  run: |
    docker logs ${{ fromJson(steps.gerrit.outputs.container_ids)[0] }} | grep replication
```

Check replicated repositories:

```yaml
- name: "List replicated repositories"
  run: |
    docker exec ${{ fromJson(steps.gerrit.outputs.container_ids)[0] }} \
      find /var/gerrit/git -name '*.git' -type d
```

## Troubleshooting

### Gerrit Won't Start

Check container logs:

```bash
docker logs <container_id>
```

Common issues:

- Port conflicts (change `base_http_port` or `base_ssh_port`)
- Invalid Gerrit version tag
- Insufficient memory

### Replication Not Working

1. **Check plugin installation:**

```bash
docker exec <container_id> ls -la /var/gerrit/plugins/
```

1. **Verify replication config:**

```bash
docker exec <container_id> cat /var/gerrit/etc/replication.config
```

1. **Check authentication:**
   - Verify SSH keys are valid
   - Ensure credentials have proper permissions
   - Check network connectivity to source Gerrit

2. **Check replication logs:**

```bash
docker logs -f <container_id> | grep -i replication
```

### Health Check Failures

Increase timeout if Gerrit takes longer to initialize:

```yaml
with:
  replication_timeout: 900  # 15 minutes
```

Or disable health checks for debugging:

```yaml
with:
  check_service: false
```

### Authentication Issues

Verify SSH key format:

```bash
ssh-keygen -l -f gerrit_key
```

Test SSH connection manually:

```bash
ssh -i gerrit_key -p 29418 git@gerrit.example.org
```

## Advanced Configuration

### Custom Gerrit Configuration

You can mount custom configuration by modifying the instance before
container start. This requires workflow customization beyond the
basic action usage.

### Database Configuration

By default, Gerrit uses H2 database. For production use, consider:

- Mounting external database configuration
- Using PostgreSQL or MySQL backends
- Persisting data volumes between runs

### Network Configuration

Containers use Docker's default bridge network. For custom networking:

- Use Docker compose for complex setups
- Configure custom networks in workflow
- Use service discovery for multi-container scenarios

## Security Considerations

1. **Secrets Management**: Always use GitHub Secrets for sensitive data
2. **SSH Keys**: Use dedicated keys with minimal permissions
3. **Network Isolation**: Consider using private runners for sensitive data
4. **Authentication**: Prefer SSH over HTTP basic auth
5. **Cleanup**: Ensure containers stop to avoid data leakage

## Limitations

- Max of 10 instances per workflow (port exhaustion)
- Replication time depends on repository size
- SSH authentication requires pre-configured keys on source server
- Container persistence limited to workflow duration
- H2 database by default (not suitable for heavy production use)

## Implementation Details

This action uses:

- Official Gerrit Docker image: `gerritcodereview/gerrit`
- Pull-replication plugin from GerritForge
- Docker BuildKit for layer caching
- Bash scripts for orchestration

## Contributing

See the main repository for contribution guidelines.

## License

Apache-2.0

## Support

For issues and questions, please use the GitHub issue tracker.
