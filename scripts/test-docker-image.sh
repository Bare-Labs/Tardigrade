#!/usr/bin/env bash
# Smoke-test the local Dockerfile build: image build, non-root runtime user,
# health endpoint, PID file, reload, and graceful stop over Docker's normal
# SIGTERM path. Proves actual container behavior, not just Dockerfile syntax.
#
# Usage: ./scripts/test-docker-image.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="tardigrade-smoke-test:local"
CONTAINER_NAME="tardigrade-smoke-test"
TMPDIR="$(mktemp -d)"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rmi "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "skipping Docker smoke test outside Linux" >&2
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "skipping Docker smoke test because docker is unavailable" >&2
    exit 0
fi

retry() {
    local attempts="$1"
    shift
    local delay=2
    local n=1
    while ! "$@"; do
        if (( n >= attempts )); then
            return 1
        fi
        sleep "$delay"
        delay=$((delay * 2))
        n=$((n + 1))
    done
}

# ── Validate compose.yaml, if compose is available ───────────────────────────
if docker compose version >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && docker compose -f compose.yaml config --quiet)
    echo "compose.yaml: valid"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
docker build -t "$IMAGE_TAG" "$REPO_ROOT"

# ── Runtime image must not contain Zig/compiler build tooling ───────────────
if docker run --rm --entrypoint sh "$IMAGE_TAG" -c 'command -v zig' >/dev/null 2>&1; then
    echo "FAIL: runtime image contains a zig binary; build tooling leaked into final stage" >&2
    exit 1
fi

# ── Non-root runtime UID ─────────────────────────────────────────────────────
RUNTIME_UID="$(docker run --rm --entrypoint id "$IMAGE_TAG" -u)"
if [[ "$RUNTIME_UID" == "0" ]]; then
    echo "FAIL: container runs as root (uid 0)" >&2
    exit 1
fi
echo "runtime uid: $RUNTIME_UID (non-root)"

# ── tardi version ────────────────────────────────────────────────────────────
docker run --rm "$IMAGE_TAG" version

# ── Start with a minimal valid config, matching the shared starter config ──
docker run -d --name "$CONTAINER_NAME" \
    -p 18069:8069 \
    -v "${REPO_ROOT}/packaging/tardigrade.conf:/etc/tardigrade/tardigrade.conf:ro" \
    --tmpfs /run/tardigrade:uid=999,gid=999,mode=0750 \
    -e TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid \
    "$IMAGE_TAG" >/dev/null

# ── Wait for /health (Host header must match the starter config's server_name) ──
health_check() {
    curl -fsS -H "Host: localhost" http://127.0.0.1:18069/health >/dev/null
}
if ! retry 10 health_check; then
    echo "FAIL: /health never became reachable" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
echo "/health: OK"

# ── PID file exists in the container ─────────────────────────────────────────
docker exec "$CONTAINER_NAME" test -f /run/tardigrade/tardigrade.pid
echo "pid file: present"

# ── tardi check against the running container's config ──────────────────────
docker exec "$CONTAINER_NAME" tardi check /etc/tardigrade/tardigrade.conf

# ── Reload and assert the same process stays alive ───────────────────────────
docker exec "$CONTAINER_NAME" tardi reload --pid-file /run/tardigrade/tardigrade.pid
sleep 1
if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" != "true" ]]; then
    echo "FAIL: container is not running after reload" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
if ! health_check; then
    echo "FAIL: /health unreachable after reload" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
echo "reload: service remained alive"

# ── Graceful stop over Docker's normal SIGTERM path (tardi is PID 1) ────────
docker stop --time 35 "$CONTAINER_NAME" >/dev/null
EXIT_CODE="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER_NAME")"
if [[ "$EXIT_CODE" != "0" ]]; then
    echo "FAIL: container did not exit cleanly after SIGTERM (exit code $EXIT_CODE)" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
if ! docker logs "$CONTAINER_NAME" 2>&1 | grep -q "Graceful shutdown complete"; then
    echo "FAIL: no graceful-shutdown-complete log line found" >&2
    docker logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
echo "stop: graceful exit (code 0)"

printf 'docker image smoke test passed\n'
