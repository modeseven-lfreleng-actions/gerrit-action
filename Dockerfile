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

# --- uv: direct binary install with SHA-256 integrity verification ----------
# Version and checksum are kept in sync by the pre-commit hook
# scripts/check-uv-checksum.sh (which also runs in CI).
#
# To update manually:
#   1. Set UV_VERSION to the desired release tag
#   2. Fetch the checksum:
#        curl -sSfL https://github.com/astral-sh/uv/releases/download/<VERSION>/uv-x86_64-unknown-linux-gnu.tar.gz.sha256
#   3. Paste the hex digest into UV_CHECKSUM below
#
# renovate: datasource=github-releases depName=astral-sh/uv
ARG UV_VERSION=0.10.4
ARG UV_CHECKSUM=6b52a47358deea1c5e173278bf46b2b489747a59ae31f2a4362ed5c6c1c269f7

RUN set -eux; \
    UV_TARBALL="uv-x86_64-unknown-linux-gnu.tar.gz"; \
    curl -LsSf \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${UV_TARBALL}" \
      -o "/tmp/${UV_TARBALL}"; \
    echo "${UV_CHECKSUM}  /tmp/${UV_TARBALL}" | sha256sum -c -; \
    tar -xzf "/tmp/${UV_TARBALL}" -C /usr/local/bin --strip-components=1; \
    rm "/tmp/${UV_TARBALL}"; \
    uv --version
ENV PATH="/usr/local/bin:${PATH}"

# Create a shared tools directory accessible by all users
ENV UV_TOOL_DIR=/opt/uv-tools
ENV UV_TOOL_BIN_DIR=/opt/uv-tools/bin
RUN mkdir -p /opt/uv-tools/bin && chmod 755 /opt/uv-tools

# --- gerrit-to-platform: version-pinned install from requirements file -------
# The pinned version (with hash) lives in docker/requirements.txt and is
# kept up-to-date automatically by Dependabot (pip ecosystem, directory: /docker).
COPY docker/requirements.txt /tmp/docker-requirements.txt

RUN set -eux; \
    G2P_VERSION=$(grep -oP 'gerrit-to-platform==\K[0-9][0-9.]*' /tmp/docker-requirements.txt); \
    /usr/local/bin/uv tool install "gerrit-to-platform==${G2P_VERSION}"; \
    rm /tmp/docker-requirements.txt

# Create a Python virtual environment for the Gerrit API scripts
# and install required dependencies
ENV GERRIT_SCRIPTS_VENV=/opt/gerrit-scripts
RUN python3 -m venv $GERRIT_SCRIPTS_VENV && \
    $GERRIT_SCRIPTS_VENV/bin/pip install --no-cache-dir requests

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
    $GERRIT_SCRIPTS_VENV/bin/python -c "import requests; print('requests:', requests.__version__)" && \
    echo "=== Root verification complete ==="

# Switch back to gerrit user for normal operation
USER gerrit

# Set PATH to include uv tools and scripts venv for gerrit user
ENV PATH="/opt/gerrit-scripts/bin:/opt/uv-tools/bin:/usr/local/bin:${PATH}"

# Verify tools are accessible as gerrit user
RUN set -eux; \
    echo "=== Verifying as gerrit user ===" && \
    uv --version && \
    which change-merged && \
    echo "=== Gerrit user verification complete ==="

# The entrypoint and command are inherited from the base image
# No need to override them
