# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Extended Gerrit image with uv and gerrit-to-platform
#
# This Dockerfile extends the official Gerrit image to include:
# - uv/uvx: Fast Python package installer and runner
# - gerrit-to-platform: Tool for Gerrit to GitHub/GitLab synchronization
#
# Build:
#   docker build --build-arg GERRIT_VERSION=3.13.1-ubuntu24 -t gerrit-extended .
#
# The following plugins are already bundled in the official Gerrit image:
# - commit-message-length-validator
# - delete-project
# - download-commands
# - hooks
# - replication (removed at runtime, replaced with pull-replication)
# - reviewnotes
# - replication-api
# - avatars-gravatar
# - codemirror-editor
# - gitiles
# - plugin-manager
# - singleusergroup
# - uploadvalidator
# - webhooks

ARG GERRIT_VERSION=3.13.1-ubuntu24
ARG UV_VERSION=0.10.2
FROM gerritcodereview/gerrit:${GERRIT_VERSION}

LABEL org.opencontainers.image.title="Gerrit Extended"
LABEL org.opencontainers.image.description="Gerrit Code Review with uv and gerrit-to-platform"
LABEL org.opencontainers.image.source="https://github.com/lfreleng-actions/gerrit-action"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install dependencies as root
USER root

# Install Python and required packages
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Install uv system-wide with version pinning for reproducibility
# Note: UV_INSTALL_DIR specifies where uv and uvx binaries are placed directly
# Using versioned installer URL for security (avoid unverified latest script)
ARG UV_VERSION
RUN set -eux; \
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" -o /tmp/uv-install.sh; \
    env UV_INSTALL_DIR=/usr/local/bin sh /tmp/uv-install.sh; \
    rm /tmp/uv-install.sh; \
    uv --version
ENV PATH="/usr/local/bin:${PATH}"

# Create a shared tools directory accessible by all users
ENV UV_TOOL_DIR=/opt/uv-tools
ENV UV_TOOL_BIN_DIR=/opt/uv-tools/bin
RUN mkdir -p /opt/uv-tools/bin && chmod 755 /opt/uv-tools

# Install gerrit-to-platform using uv tool
# This installs executables: change-merged, comment-added, patchset-created
RUN /usr/local/bin/uv tool install gerrit-to-platform

# Make tool binaries accessible system-wide
RUN ln -sf /opt/uv-tools/bin/change-merged /usr/local/bin/change-merged && \
    ln -sf /opt/uv-tools/bin/comment-added /usr/local/bin/comment-added && \
    ln -sf /opt/uv-tools/bin/patchset-created /usr/local/bin/patchset-created

# Verify installations work as root
RUN set -eux; \
    echo "=== Verifying as root ===" && \
    uv --version && \
    uvx --version && \
    uv tool list && \
    change-merged --help | head -5 || echo "Note: change-merged requires args" && \
    echo "=== Root verification complete ==="

# Switch back to gerrit user for normal operation
USER gerrit

# Set PATH to include uv tools for gerrit user
ENV PATH="/opt/uv-tools/bin:/usr/local/bin:${PATH}"

# Verify tools are accessible as gerrit user
RUN set -eux; \
    echo "=== Verifying as gerrit user ===" && \
    uv --version && \
    which change-merged && \
    echo "=== Gerrit user verification complete ==="

# The entrypoint and command are inherited from the base image
# No need to override them
