#!/usr/bin/env bash
# Smoke-test the local Dockerfile build: image build, non-root runtime user,
# health endpoint, PID file, reload, and graceful stop over Docker's normal
# SIGTERM path. Proves actual container behavior, not just Dockerfile syntax.
#
# Usage: ./scripts/test-docker-image.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="tardigrade-smoke-test:local"
BUILD_IMAGE_TAG="tardigrade-smoke-test-build:local"
CONTAINER_NAME="tardigrade-smoke-test"
TMPDIR="$(mktemp -d)"

PIDCHECK_CONTAINER_NAME="${CONTAINER_NAME}-pidcheck"
AUDIT_CONTAINER_NAME="${CONTAINER_NAME}-audit"

cleanup() {
    docker rm -f "$CONTAINER_NAME" "$PIDCHECK_CONTAINER_NAME" "$AUDIT_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rmi "$IMAGE_TAG" "$BUILD_IMAGE_TAG" >/dev/null 2>&1 || true
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
docker build --target build -t "$BUILD_IMAGE_TAG" "$REPO_ROOT"

# ── Neither stage explicitly installs an OpenSSL/libcrypto package ─────────
# The binary linkage audit below proves the shipped artifact doesn't *link*
# OpenSSL, but that alone would not catch a Dockerfile regression that
# re-installs libssl-dev/libssl3 without anything ending up linked against
# them (#650's close rule requires catching Docker re-installing OpenSSL, not
# just re-linking it).
#
# A raw dpkg presence check is not the right test here: on this base image,
# ca-certificates has a genuine transitive `Depends: openssl` (which in turn
# depends on libssl3) for its own certificate-bundle tooling, so libssl3 is
# unavoidably present regardless of anything Tardigrade does -- that is
# exactly the "ordinary OS/package substrate" the issue says must not be
# confused with a foreign product implementation. `apt-mark showmanual`
# distinguishes packages the Dockerfile explicitly named on an `apt-get
# install` line from ones pulled in only as someone else's dependency, so it
# catches a real Dockerfile regression without false-failing on
# ca-certificates' own dependency chain.
FORBIDDEN_PACKAGES_PATTERN='^(libssl-dev|libssl3|libssl1\.1|openssl)$'
if docker run --rm --entrypoint sh "$BUILD_IMAGE_TAG" -c "apt-mark showmanual | grep -qE '$FORBIDDEN_PACKAGES_PATTERN'"; then
    echo "FAIL: build stage explicitly installs an OpenSSL package; Tardigrade's native build needs no OpenSSL headers" >&2
    exit 1
fi
echo "build stage: no OpenSSL package explicitly installed"

if docker run --rm --entrypoint sh "$IMAGE_TAG" -c "apt-mark showmanual | grep -qE '$FORBIDDEN_PACKAGES_PATTERN'"; then
    echo "FAIL: runtime image explicitly installs an OpenSSL package; Tardigrade's native binary needs no OpenSSL runtime library" >&2
    exit 1
fi
echo "runtime stage: no OpenSSL package explicitly installed"

# ── Audit the exact runtime binary for native-only linkage/identity ─────────
# Composition must never be inferred from Dockerfile text alone: extract the
# precise binary copied into the runtime stage and run the same linkage/
# self-report audit the release pipeline runs, proving it links no
# OpenSSL/libcrypto (or other foreign TLS/crypto/QUIC/H3) library and
# self-reports the native production identity.
docker create --name "$AUDIT_CONTAINER_NAME" "$IMAGE_TAG" >/dev/null
docker cp "${AUDIT_CONTAINER_NAME}:/usr/local/bin/tardi" "$TMPDIR/tardi"
docker rm -f "$AUDIT_CONTAINER_NAME" >/dev/null 2>&1
chmod +x "$TMPDIR/tardi"
"${REPO_ROOT}/scripts/audit-release-binary.sh" \
    --binary "$TMPDIR/tardi" \
    --profile general \
    --output "$TMPDIR/dependency-inventory.json"
echo "docker runtime binary: native-only linkage audit passed"

# ── Runtime image must not contain Zig/compiler build tooling ───────────────
if docker run --rm --entrypoint sh "$IMAGE_TAG" -c 'command -v zig' >/dev/null 2>&1; then
    echo "FAIL: runtime image contains a zig binary; build tooling leaked into final stage" >&2
    exit 1
fi

# ── Runtime UID/GID match the fixed identity pinned in the Dockerfile ───────
# compose.yaml's tmpfs mount and the pidcheck regression below both hard-code
# this value; assert it exactly rather than just "non-root" so a Dockerfile
# change that drifts the UID/GID fails here instead of silently breaking
# tmpfs ownership downstream.
EXPECTED_UID_GID="10001:10001"
RUNTIME_UID_GID="$(docker run --rm --entrypoint id "$IMAGE_TAG" -u):$(docker run --rm --entrypoint id "$IMAGE_TAG" -g)"
if [[ "$RUNTIME_UID_GID" != "$EXPECTED_UID_GID" ]]; then
    echo "FAIL: runtime uid:gid is '$RUNTIME_UID_GID', expected '$EXPECTED_UID_GID'" >&2
    exit 1
fi
echo "runtime uid:gid: $RUNTIME_UID_GID (fixed, non-root)"

# ── tardi version ────────────────────────────────────────────────────────────
docker run --rm "$IMAGE_TAG" version

# ── Start with a minimal valid config, matching the shared starter config ──
docker run -d --name "$CONTAINER_NAME" \
    -p 18069:8069 \
    -v "${REPO_ROOT}/packaging/tardigrade.conf:/etc/tardigrade/tardigrade.conf:ro" \
    --tmpfs /run/tardigrade:uid=10001,gid=10001,mode=0750 \
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

# ── Regression: a conflicting env-file PID path must not win ────────────────
# The systemd unit's ExecStart forces TARDIGRADE_PID_FILE at exec time
# because EnvironmentFile= values otherwise override unit-level Environment=
# and desync ExecReload/ExecStop from where the process actually writes its
# PID (see packaging/systemd/tardigrade.service). Reproduce that same
# EnvironmentFile-then-ExecStart shape here: inject a conflicting
# TARDIGRADE_PID_FILE via `-e` (standing in for EnvironmentFile=), then use
# `env` in the container command (standing in for ExecStart) to force the
# deterministic path, exactly like the unit does.
docker run -d --name "$PIDCHECK_CONTAINER_NAME" \
    -v "${REPO_ROOT}/packaging/tardigrade.conf:/etc/tardigrade/tardigrade.conf:ro" \
    --tmpfs /run/tardigrade:uid=10001,gid=10001,mode=0750 \
    -e TARDIGRADE_PID_FILE=/tmp/conflicting.pid \
    --entrypoint /usr/bin/env \
    "$IMAGE_TAG" \
    TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid \
    /usr/local/bin/tardi run -c /etc/tardigrade/tardigrade.conf >/dev/null

sleep 1
if [[ "$(docker inspect -f '{{.State.Running}}' "$PIDCHECK_CONTAINER_NAME")" != "true" ]]; then
    echo "FAIL: conflicting-env-file regression container did not start" >&2
    docker logs "$PIDCHECK_CONTAINER_NAME" >&2 || true
    exit 1
fi
docker exec "$PIDCHECK_CONTAINER_NAME" test -f /run/tardigrade/tardigrade.pid
if docker exec "$PIDCHECK_CONTAINER_NAME" test -e /tmp/conflicting.pid; then
    echo "FAIL: process wrote the conflicting env-file PID path instead of the forced one" >&2
    exit 1
fi
docker rm -f "$PIDCHECK_CONTAINER_NAME" >/dev/null 2>&1
echo "conflicting-env regression: deterministic PID path won"

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
