<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Changelog

This file documents all notable changes to the gerrit-server-action.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial implementation of Gerrit Server Action
- Multi-instance support for running multi-Gerrit servers
- Automatic pull-replication plugin installation and configuration
- Support for SSH, HTTP basic auth, and bearer token authentication
- Docker layer caching for improved performance
- Comprehensive health checking using container logs and HTTP endpoints
- Automatic replication triggering on startup
- Persistent container mode for workflows requiring long-running Gerrit instances
- Graceful container cleanup with replication queue draining
- Full JSON-based configuration via `gerrit_setup` input
- Comprehensive outputs including container IDs, IPs, and instance metadata
- Debug mode for troubleshooting
- Cache key suffix for cache isolation across different workflow contexts
- Support for extra plugins installation
- Custom Gerrit initialization arguments
- Configurable port ranges for HTTP and SSH
- Selective ref synchronization
- Thread pool configuration for replication

### Documentation

- Comprehensive README with usage examples
- Workflow examples in `examples/` directory
- Detailed input and output documentation
- Authentication method guides
- Troubleshooting section
- Performance and caching documentation

### Testing

- Basic functionality tests
- Multi-instance tests
- Persistent container tests
- Input validation tests
- Cache disabled tests
- Test summary generation

## [0.1.0] - 2025-01-20

### Released

- Initial release

[Unreleased]: https://github.com/lfreleng-actions/gerrit-server-action/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lfreleng-actions/gerrit-server-action/releases/tag/v0.1.0
