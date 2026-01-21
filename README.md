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

| Name            | Required | Default | Description                                                      |
| --------------- | -------- | ------- | ---------------------------------------------------------------- |
| ssh_private_key | False    |         | SSH private key for authentication (required if `auth_type=ssh`) |
| ssh_known_hosts | False    | auto    | SSH known_hosts entries (auto-generated if not provided)         |
| http_username   | False    |         | HTTP basic auth username (required if `auth_type=http_basic`)    |
| http_password   | False    |         | HTTP basic auth password (required if `auth_type=http_basic`)    |
| bearer_token    | False    |         | Bearer token (required if `auth_type=bearer_token`)              |

<!-- markdownlint-enable MD013 -->

### Gerrit Configuration

<!-- markdownlint-disable MD013 -->

| Name           | Required | Default           | Description                                                   |
| -------------- | -------- | ----------------- | ------------------------------------------------------------- |
| gerrit_version | False    | `3.13.1-ubuntu24` | Gerrit Docker image version tag                               |
| plugin_version | False    | `stable-3.13`     | Pull-replication plugin version/branch                        |
| base_http_port | False    | `8080`            | Starting HTTP port (increments for multi-instance)            |
| base_ssh_port  | False    | `29418`           | Starting SSH port (increments for multi-instance)             |
| auth_type      | False    | `ssh`             | Authentication method: `ssh`, `http_basic`, or `bearer_token` |

<!-- markdownlint-enable MD013 -->

### Replication Settings

<!-- markdownlint-disable MD013 -->

| Name                | Required | Default | Description                                                       |
| ------------------- | -------- | ------- | ----------------------------------------------------------------- |
| sync_on_startup     | False    | `true`  | Trigger replication after startup                                 |
| replication_timeout | False    | `600`   | Timeout for initial replication sync (seconds)                    |
| sync_refs           | False    | (all)   | Comma-separated refs to sync (e.g., `+refs/heads/*:refs/heads/*`) |
| replication_threads | False    | `4`     | Number of replication threads per instance                        |

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

| Name                | Required | Default | Description                                          |
| ------------------- | -------- | ------- | ---------------------------------------------------- |
| debug               | False    | `false` | Enable debugging output                              |
| additional_plugins  | False    |         | Comma-separated list of extra plugin URLs to install |
| gerrit_init_args    | False    |         | Extra arguments for `gerrit.war init`                |
| skip_plugin_install | False    | `false` | Skip pull-replication plugin installation (testing)  |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name          | Description                                  | Example                                         |
| ------------- | -------------------------------------------- | ----------------------------------------------- |
| container_ids | JSON array of running container IDs          | `["abc123", "def456"]`                          |
| container_ips | JSON array of container IP addresses         | `["172.17.0.2", "172.17.0.3"]`                  |
| instances     | JSON object mapping slug to instance details | See [Instances Output](#instances-output)       |
| gerrit_urls   | Comma-separated list of Gerrit HTTP URLs     | `http://172.17.0.2:8080,http://172.17.0.3:8080` |

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

### Configuration Fields

- **`project`** (optional) - Project name/filter for replication
- **`slug`** (required) - Unique identifier for this instance (used in
  container naming)
- **`gerrit`** (required) - Hostname of the source Gerrit server to
  replicate from

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
