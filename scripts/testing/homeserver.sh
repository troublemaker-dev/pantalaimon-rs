#!/usr/bin/env bash
# homeserver.sh — Lifecycle manager for a local Matrix homeserver (continuwuity)
# used by pantalaimon-rs's real key-exchange integration tests
# (crates/pantalaimon/tests/key_exchange_test.rs).
#
# Ported from ../relay/scripts/seed-homeserver.sh's container-provisioning
# logic, generalized and made non-interactive so it's safe to call from
# automation as well as by hand.
#
# Prerequisites: a container runtime (Apple `container`, Docker, or Podman),
# curl, jq.
#
# Usage:
#   ./scripts/testing/homeserver.sh up             # start (or reuse) the homeserver
#   ./scripts/testing/homeserver.sh down [--wipe]  # stop it; --wipe also deletes data
#   ./scripts/testing/homeserver.sh status          # check whether it's reachable
#
# Override runtime detection with:  CONTAINER_RUNTIME=podman ./scripts/testing/homeserver.sh up

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

CONTAINER_NAME="pantalaimon-test-homeserver"
VOLUME_NAME="pantalaimon-test-homeserver-data"
IMAGE="ghcr.io/continuwuity/continuwuity:latest"
SERVER_NAME="pantalaimon-test.local"
PORT=8008
SERVER_URL="http://localhost:${PORT}"
REGISTRATION_TOKEN="pantalaimon-test-token"
SEED_USER="harness-seed"
SEED_PASSWORD="harness-seed-password"

# =============================================================================
# Runtime detection (same precedence as relay/scripts/seed-homeserver.sh)
# =============================================================================

detect_runtime() {
    if [[ -n "${CONTAINER_RUNTIME:-}" ]]; then
        RUNTIME="$CONTAINER_RUNTIME"
    elif command -v container &> /dev/null; then
        RUNTIME="container"
    elif command -v docker &>/dev/null; then
        RUNTIME="docker"
    elif command -v podman &>/dev/null; then
        RUNTIME="podman"
    else
        echo "Error: No container runtime found. Install Docker, Podman, or Apple's container CLI." >&2
        exit 1
    fi
}

# Apple's `container` CLI needs its background VM service running before any
# other subcommand will work (`container list` fails with an XPC connection
# error otherwise). Best-effort: harmless to call if it's already running.
ensure_system_started() {
    if [[ "$RUNTIME" == "container" ]]; then
        container system start >/dev/null 2>&1 || true
    fi
}

# =============================================================================
# Helpers
# =============================================================================

log() { echo "  $*"; }

container_exists() {
    "$RUNTIME" inspect "$CONTAINER_NAME" &>/dev/null
}

container_running() {
    local state
    # Docker/Podman report a plain string at .State.Status; Apple's `container`
    # reports an object at .status with a nested .state string instead.
    state=$("$RUNTIME" inspect "$CONTAINER_NAME" 2>/dev/null | jq -r '.[0].State.Status // .[0].status.state? // .[0].status // empty' 2>/dev/null || true)
    [[ "$state" == "running" ]]
}

wait_for_server() {
    local max_attempts=30
    local attempt=0
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/_matrix/client/versions" 2>/dev/null | grep -q "200"; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    echo "Error: Homeserver did not become available within ${max_attempts} seconds." >&2
    exit 1
}

# Scrape the one-time bootstrap registration token continuwuity prints to its
# own logs on first startup with an empty account table. Only the very first
# account ever created on a fresh volume needs this; every account after that
# can use the static REGISTRATION_TOKEN configured via env var.
get_bootstrap_token() {
    local max_attempts=10
    local attempt=0
    while [[ $attempt -lt $max_attempts ]]; do
        local token
        token=$("$RUNTIME" logs "$CONTAINER_NAME" 2>&1 \
            | sed 's/\x1b\[[0-9;]*m//g' \
            | grep -o 'registration token [^ ]*' \
            | head -1 \
            | awk '{print $NF}')
        if [[ -n "$token" ]]; then
            echo "$token"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    echo ""
    return 1
}

# Two-step m.login.registration_token registration flow. Returns 0 and prints
# nothing on success; returns 1 if the token was rejected (session couldn't
# even be created) vs. exits 0 quietly if the account already exists
# (M_USER_IN_USE), since that's the expected steady state on repeat `up` runs.
register_user() {
    local username="$1"
    local password="$2"
    local reg_token="$3"

    local init_response
    init_response=$(curl -s -X POST "${SERVER_URL}/_matrix/client/v3/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${username}\", \"password\": \"${password}\", \"inhibit_login\": true}")

    local session
    session=$(echo "$init_response" | jq -r '.session // empty')
    if [[ -z "$session" ]]; then
        return 1
    fi

    local response
    response=$(curl -s -X POST "${SERVER_URL}/_matrix/client/v3/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"${username}\",
            \"password\": \"${password}\",
            \"auth\": {
                \"type\": \"m.login.registration_token\",
                \"token\": \"${reg_token}\",
                \"session\": \"${session}\"
            },
            \"inhibit_login\": true
        }")

    # inhibit_login:true means a successful registration returns user_id
    # (and device_id: null), not an access_token.
    if echo "$response" | jq -e '.user_id' &>/dev/null; then
        return 0
    fi

    local errcode
    errcode=$(echo "$response" | jq -r '.errcode // empty')
    if [[ "$errcode" == "M_USER_IN_USE" ]]; then
        return 0
    fi

    echo "Error: registration failed for '${username}': ${response}" >&2
    return 1
}

# Guarantee the static REGISTRATION_TOKEN is valid by ensuring at least one
# account exists. Tries the static token first (the steady-state case on a
# reused volume); only falls back to scraping the bootstrap token from
# container logs if that fails (a genuinely fresh volume).
ensure_seed_user() {
    if register_user "$SEED_USER" "$SEED_PASSWORD" "$REGISTRATION_TOKEN"; then
        return 0
    fi

    log "Static registration token not yet valid — looking for continuwuity's bootstrap token..."
    local bootstrap
    bootstrap=$(get_bootstrap_token) || {
        echo "Error: could not find a bootstrap registration token in container logs." >&2
        exit 1
    }

    if ! register_user "$SEED_USER" "$SEED_PASSWORD" "$bootstrap"; then
        echo "Error: seed registration failed even with the bootstrap token." >&2
        exit 1
    fi
}

# =============================================================================
# Subcommands
# =============================================================================

cmd_up() {
    detect_runtime
    ensure_system_started

    "$RUNTIME" volume create "$VOLUME_NAME" &>/dev/null || true

    if container_exists; then
        if container_running; then
            log "Homeserver container already running."
        else
            log "Starting existing homeserver container..."
            "$RUNTIME" start "$CONTAINER_NAME" >/dev/null
        fi
    else
        log "Creating homeserver container ($RUNTIME, image $IMAGE)..."
        "$RUNTIME" run -d \
            --name "$CONTAINER_NAME" \
            -p "${PORT}:${PORT}" \
            -v "${VOLUME_NAME}:/var/lib/continuwuity" \
            -e CONTINUWUITY_SERVER_NAME="$SERVER_NAME" \
            -e CONTINUWUITY_DATABASE_PATH=/var/lib/continuwuity \
            -e CONTINUWUITY_ADDRESS=0.0.0.0 \
            -e CONTINUWUITY_PORT="$PORT" \
            -e CONTINUWUITY_ALLOW_REGISTRATION=true \
            -e CONTINUWUITY_ALLOW_GUEST_REGISTRATION=false \
            -e CONTINUWUITY_REGISTRATION_TOKEN="$REGISTRATION_TOKEN" \
            -e CONTINUWUITY_NEW_USER_DISPLAYNAME_SUFFIX= \
            -e CONTINUWUITY_LOG=warn \
            "$IMAGE" >/dev/null
    fi

    log "Waiting for homeserver to become reachable at ${SERVER_URL}..."
    wait_for_server

    ensure_seed_user

    echo ""
    echo "  Homeserver is up: ${SERVER_URL}"
    echo "  Registration token for tests: ${REGISTRATION_TOKEN}"
    echo ""
    echo "  Run the real key-exchange tests with:"
    echo "    cargo test --test key_exchange_test -- --ignored --nocapture"
    echo ""
    echo "  Tear down with: ./scripts/testing/homeserver.sh down [--wipe]"
}

cmd_down() {
    detect_runtime
    local wipe=false
    if [[ "${1:-}" == "--wipe" ]]; then
        wipe=true
    fi

    if container_exists; then
        log "Stopping homeserver container..."
        "$RUNTIME" stop "$CONTAINER_NAME" &>/dev/null || true
        "$RUNTIME" rm -f "$CONTAINER_NAME" &>/dev/null || true
    else
        log "No homeserver container to stop."
    fi

    if [[ "$wipe" == true ]]; then
        log "Removing homeserver data volume..."
        "$RUNTIME" volume rm "$VOLUME_NAME" &>/dev/null || true
    fi
}

cmd_status() {
    detect_runtime
    if container_exists && container_running; then
        echo "  Container: running ($RUNTIME)"
    elif container_exists; then
        echo "  Container: stopped ($RUNTIME)"
    else
        echo "  Container: not created ($RUNTIME)"
    fi

    if curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/_matrix/client/versions" 2>/dev/null | grep -q "200"; then
        echo "  Reachable: yes (${SERVER_URL})"
    else
        echo "  Reachable: no (${SERVER_URL})"
    fi
}

# =============================================================================
# Entry point
# =============================================================================

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down "${2:-}" ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {up|down [--wipe]|status}" >&2
        exit 1
        ;;
esac
