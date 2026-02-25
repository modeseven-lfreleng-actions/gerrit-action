#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
#
# Pre-commit hook: validate (and optionally update) the uv binary checksum
# stored in the Dockerfile.
#
# Behaviour
# ---------
#   1. Parses UV_VERSION and UV_CHECKSUM ARGs from the Dockerfile.
#   2. Fetches the published SHA-256 digest for that version from the
#      astral-sh/uv GitHub release assets.
#   3. If the stored checksum does not match the published one, the
#      Dockerfile is patched in-place and the hook exits non-zero so that
#      pre-commit can show the autofix diff.
#   4. On a subsequent run (after `git add`) the checksums will match and
#      the hook passes.
#
# Flags
# -----
#   --check-latest   After validating the current version, also query the
#                    GitHub API for the newest release and print an advisory
#                    if an upgrade is available.  (Never modifies files.)
#
#   --update-latest  Like --check-latest, but also updates UV_VERSION and
#                    UV_CHECKSUM in the Dockerfile to the latest release.
#                    Exits non-zero when a change is made (autofix pattern).
#
# Environment
# -----------
#   DOCKERFILE       Path to the Dockerfile (default: auto-detected relative
#                    to the repository root).
#   GITHUB_TOKEN     Optional; used for GitHub API requests to avoid
#                    anonymous rate-limits.
#
# Exit codes
# ----------
#   0  Everything is valid and up-to-date.
#   1  The Dockerfile was modified (autofix) — re-stage and retry.
#   2  A hard error occurred (network failure, missing file, …).

set -euo pipefail

# ── Colour helpers (disabled when stdout is not a terminal) ──────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

info()  { printf "${CYAN}ℹ${RESET}  %s\n" "$*"; }
ok()    { printf "${GREEN}✔${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET}  %s\n" "$*" >&2; }
err()   { printf "${RED}✖${RESET}  %s\n" "$*" >&2; }

# ── Locate the Dockerfile ───────────────────────────────────────────────
find_dockerfile() {
    if [[ -n "${DOCKERFILE:-}" ]]; then
        echo "$DOCKERFILE"
        return
    fi
    # Walk upward from CWD to find the repo root (contains .git/)
    local dir="$PWD"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/Dockerfile" ]]; then
            echo "$dir/Dockerfile"
            return
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}

# ── Parse an ARG from the Dockerfile ────────────────────────────────────
# Usage: parse_arg <DOCKERFILE> <ARG_NAME>
#   Matches lines like:  ARG UV_VERSION=0.10.2
parse_arg() {
    local file="$1" name="$2"
    # Use grep + sed to be POSIX-ish (no perl dependency)
    grep -E "^ARG ${name}=" "$file" \
        | head -1 \
        | sed -E "s/^ARG ${name}=//"
}

# ── Build curl auth arguments ───────────────────────────────────────────
# Populates the global _CURL_AUTH array.  Using an array avoids
# word-splitting pitfalls with ${VAR:+...} inline expansions.
_CURL_AUTH=()
_build_curl_auth() {
    _CURL_AUTH=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        _CURL_AUTH+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi
}

# ── Fetch the published checksum for a given uv release ─────────────────
# The astral-sh/uv releases publish per-target .sha256 sidecar files.
fetch_published_checksum() {
    local version="$1"
    local target="uv-x86_64-unknown-linux-gnu.tar.gz"
    local url="https://github.com/astral-sh/uv/releases/download/${version}/${target}.sha256"

    _build_curl_auth

    local curl_stderr body
    curl_stderr="$(mktemp)"
    if ! body="$(curl -fsSL --retry 2 --retry-delay 3 \
        "${_CURL_AUTH[@]}" \
        "$url" 2>"$curl_stderr")"; then
        err "Failed to fetch checksum from: ${url}"
        if [[ -s "$curl_stderr" ]]; then
            err "curl: $(cat "$curl_stderr")"
        fi
        err "Ensure UV_VERSION=${version} refers to an existing release."
        rm -f "$curl_stderr"
        return 2
    fi
    rm -f "$curl_stderr"

    # The .sha256 file format is:  <hex-digest>  <filename>
    echo "$body" | awk '{print $1}'
}

# ── Query the latest uv release version ─────────────────────────────────
fetch_latest_version() {
    local api_url="https://api.github.com/repos/astral-sh/uv/releases/latest"

    _build_curl_auth

    local curl_stderr body
    curl_stderr="$(mktemp)"
    if ! body="$(curl -fsSL --retry 2 --retry-delay 3 \
        "${_CURL_AUTH[@]}" \
        -H "Accept: application/vnd.github+json" \
        "$api_url" 2>"$curl_stderr")"; then
        err "Failed to query GitHub API for latest uv release."
        if [[ -s "$curl_stderr" ]]; then
            err "curl: $(cat "$curl_stderr")"
        fi
        rm -f "$curl_stderr"
        return 2
    fi
    rm -f "$curl_stderr"

    # Parse "tag_name" without requiring jq (which may not be installed)
    # Use sed instead of grep -P for macOS/BSD compatibility
    echo "$body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# ── Patch an ARG value in the Dockerfile in-place ───────────────────────
# Usage: patch_arg <DOCKERFILE> <ARG_NAME> <NEW_VALUE>
patch_arg() {
    local file="$1" name="$2" value="$3"
    # macOS & GNU sed compatible in-place edit
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "s|^ARG ${name}=.*|ARG ${name}=${value}|" "$file"
    else
        sed -i '' "s|^ARG ${name}=.*|ARG ${name}=${value}|" "$file"
    fi
}

# ── Validate a SHA-256 hex string ───────────────────────────────────────
is_valid_sha256() {
    local digest="$1"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]]
}

# ── Validate a version string ──────────────────────────────────────────
is_valid_version() {
    local version="$1"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([a-zA-Z0-9.+-]*)?$ ]]
}

# ── Main ────────────────────────────────────────────────────────────────
main() {
    local check_latest=false
    local update_latest=false

    for arg in "$@"; do
        case "$arg" in
            --check-latest)   check_latest=true ;;
            --update-latest)  update_latest=true; check_latest=true ;;
            --help|-h)
                cat <<'USAGE'
Usage: check-uv-checksum.sh [OPTIONS]

Validate the uv binary checksum stored in the Dockerfile.

Options:
  --check-latest    Also check whether a newer uv release exists
  --update-latest   Fetch the latest release and update the Dockerfile
  -h, --help        Show this help message

Environment:
  DOCKERFILE        Path to the Dockerfile (auto-detected by default)
  GITHUB_TOKEN      Optional GitHub token (avoids rate-limits)
USAGE
                exit 0
                ;;
            *)
                err "Unknown argument: ${arg}"
                exit 2
                ;;
        esac
    done

    # --- Locate Dockerfile ---
    local dockerfile
    if ! dockerfile="$(find_dockerfile)"; then
        err "Could not locate Dockerfile. Set the DOCKERFILE env var."
        exit 2
    fi
    info "Dockerfile: ${dockerfile}"

    # --- Parse current values ---
    local current_version current_checksum
    current_version="$(parse_arg "$dockerfile" UV_VERSION)"
    current_checksum="$(parse_arg "$dockerfile" UV_CHECKSUM)"

    if [[ -z "$current_version" ]]; then
        err "Could not parse ARG UV_VERSION from ${dockerfile}"
        exit 2
    fi
    if [[ -z "$current_checksum" ]]; then
        err "Could not parse ARG UV_CHECKSUM from ${dockerfile}"
        exit 2
    fi

    info "Current UV_VERSION  = ${current_version}"
    info "Current UV_CHECKSUM = ${current_checksum}"

    # --- Basic format validation ---
    if ! is_valid_version "$current_version"; then
        err "UV_VERSION '${current_version}' does not look like a valid version."
        exit 2
    fi
    if ! is_valid_sha256 "$current_checksum"; then
        warn "UV_CHECKSUM '${current_checksum}' is not a valid SHA-256 hex digest."
        warn "Will attempt to fetch the correct checksum."
    fi

    # --- Fetch published checksum for the current version ---
    info "Fetching published checksum for uv ${current_version}…"
    local published_checksum
    if ! published_checksum="$(fetch_published_checksum "$current_version")"; then
        exit 2
    fi

    if ! is_valid_sha256 "$published_checksum"; then
        err "Fetched checksum is not a valid SHA-256 digest: '${published_checksum}'"
        exit 2
    fi

    info "Published checksum  = ${published_checksum}"

    # --- Compare ---
    local modified=false

    if [[ "$current_checksum" != "$published_checksum" ]]; then
        warn "Checksum mismatch for UV_VERSION=${current_version}!"
        warn "  Dockerfile:  ${current_checksum}"
        warn "  Published:   ${published_checksum}"
        info "Updating UV_CHECKSUM in ${dockerfile}…"
        patch_arg "$dockerfile" "UV_CHECKSUM" "$published_checksum"
        modified=true
        ok "UV_CHECKSUM updated to ${published_checksum}"
    else
        ok "UV_CHECKSUM is correct for UV_VERSION=${current_version}"
    fi

    # --- Optionally check / update to latest release ---
    if [[ "$check_latest" == true ]]; then
        info "Checking for latest uv release…"
        local latest_version
        if ! latest_version="$(fetch_latest_version)"; then
            warn "Could not determine the latest uv release (network issue?)."
            # Non-fatal: we already validated the current version above.
        elif [[ -z "$latest_version" ]]; then
            warn "GitHub API returned an empty tag_name (rate-limited?)."
        elif [[ "$latest_version" == "$current_version" ]]; then
            ok "uv ${current_version} is already the latest release."
        else
            warn "A newer uv release is available: ${latest_version} (current: ${current_version})"

            if [[ "$update_latest" == true ]]; then
                info "Fetching checksum for uv ${latest_version}…"
                local latest_checksum
                if ! latest_checksum="$(fetch_published_checksum "$latest_version")"; then
                    err "Could not fetch checksum for ${latest_version}; aborting update."
                    exit 2
                fi
                if ! is_valid_sha256 "$latest_checksum"; then
                    err "Fetched checksum for ${latest_version} is invalid: '${latest_checksum}'"
                    exit 2
                fi

                info "Updating UV_VERSION  → ${latest_version}"
                info "Updating UV_CHECKSUM → ${latest_checksum}"
                patch_arg "$dockerfile" "UV_VERSION" "$latest_version"
                patch_arg "$dockerfile" "UV_CHECKSUM" "$latest_checksum"
                modified=true
                ok "Dockerfile updated to uv ${latest_version}"
            else
                info "Run with --update-latest to apply the upgrade."
            fi
        fi
    fi

    # --- Exit code ---
    if [[ "$modified" == true ]]; then
        warn "Dockerfile was modified. Please stage the changes and retry."
        exit 1
    fi

    ok "All checks passed."
    exit 0
}

main "$@"
