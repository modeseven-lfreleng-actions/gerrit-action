<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Gerrit Server Action - Quick Start Guide

## Prerequisites

1. **GitHub Secrets/Variables:**
   - Create a secret `GERRIT_SSH_KEY` with your SSH private key
   - Create a variable `GERRIT_SETUP` with your instance configuration (optional)

2. **SSH Key Setup:**

   ```bash
   # Generate SSH key
   ssh-keygen -t rsa -b 4096 -f gerrit_key -N ""

   # Add gerrit_key.pub to your Gerrit account
   # Add gerrit_key (private) to GitHub Secrets as GERRIT_SSH_KEY
   ```

## 5-Minute Setup

### Step 1: Create Workflow File

Create `.github/workflows/test-gerrit.yaml`:

```yaml
name: 'Test with Gerrit'

on:
  workflow_dispatch:

jobs:
  test:
    runs-on: 'ubuntu-latest'
    steps:
      - uses: actions/checkout@v4

      - name: 'Start Gerrit'
        id: gerrit
        uses: lfreleng-actions/gerrit-server-action@main
        with:
          gerrit_setup: |
            [{
              "slug": "my-gerrit",
              "gerrit": "gerrit.example.org"
            }]
          ssh_private_key: ${{ secrets.GERRIT_SSH_KEY }}

      - name: 'Use Gerrit'
        run: |
          curl http://localhost:8080/config/server/version
```

### Step 2: Add Secrets

1. Go to repository Settings → Secrets and variables → Actions
2. Add new secret:
   - Name: `GERRIT_SSH_KEY`
   - Value: (paste your private key)

### Step 3: Run

1. Go to Actions tab
2. Select "Test with Gerrit" workflow
3. Click "Run workflow"

## Common Tasks

### Access Gerrit Web UI

The Gerrit web UI is available at `http://localhost:8080` by default.

### Clone a Repository

```bash
git clone http://localhost:8080/project-name
```

### Check Replication Status

```bash
docker logs <container_id> | grep replication
```

Get container ID from outputs:

```yaml
run: echo "${{ steps.gerrit.outputs.container_ids }}"
```

### Run Multi-Instance Setup

```yaml
with:
  gerrit_setup: |
    [
      {"slug": "onap", "gerrit": "gerrit.onap.org"},
      {"slug": "opendaylight", "gerrit": "git.opendaylight.org"}
    ]
  base_http_port: 9000  # ONAP on 9000, OpenDaylight on 9001
```

### Keep Container Running

```yaml
with:
  exit: false  # Don't stop after action completes
```

Clean up manually:

```yaml
- name: 'Cleanup'
  if: always()
  run: docker kill ${{ fromJson(steps.gerrit.outputs.container_ids)[0] }}
```

### Disable Caching (for testing)

```yaml
with:
  enable_cache: false
```

### Debug Mode

```yaml
with:
  debug: true
```

## Troubleshooting

### Container won't start

Check port availability:

```yaml
with:
  base_http_port: 9000  # Try different port
```

### Replication not working

1. Verify SSH key is correct
2. Check source Gerrit is accessible
3. Look at container logs:

   ```bash
   docker logs <container_id> --tail 100
   ```

### Health check timeout

Increase timeout:

```yaml
with:
  replication_timeout: 900  # 15 minutes
```

Or disable checks:

```yaml
with:
  check_service: false
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [examples/](examples/) for more workflow examples
- Review the [CHANGELOG.md](CHANGELOG.md) for updates

## Support

For issues and questions:

- GitHub Issues: [Report an issue](https://github.com/lfreleng-actions/gerrit-server-action/issues)
- Documentation: [Full README](README.md)
