#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BINARY="${REPO_ROOT}/zig-out/bin/tardi"
VERSION="0.0.0-smoke"
OUTPUT_DIR="${TMPDIR}/dist"
DEB_TEST_IMAGE="${DEB_TEST_IMAGE:-ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90}"

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

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "skipping DEB smoke test outside Linux" >&2
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "skipping DEB smoke test because docker is unavailable" >&2
    exit 0
fi

"${REPO_ROOT}/packaging/deb/build.sh" \
    --version "$VERSION" \
    --arch amd64 \
    --binary "$BINARY" \
    --output "$OUTPUT_DIR"

DEB_PATH="${OUTPUT_DIR}/tardigrade_${VERSION}_amd64.deb"
test -f "$DEB_PATH"

# ── Regression: the standalone builder must not accept a caller-asserted
# OpenSSL backend as a valid production mode (#650) ─────────────────────────
if "${REPO_ROOT}/packaging/deb/build.sh" \
    --version "$VERSION" \
    --arch amd64 \
    --binary "$BINARY" \
    --tls-backend openssl-adapter \
    --output "${OUTPUT_DIR}/rejected" 2>/dev/null; then
    echo "FAIL: deb builder accepted --tls-backend openssl-adapter" >&2
    exit 1
fi
echo "deb builder: --tls-backend openssl-adapter correctly rejected"

# ── Regression: cross-architecture packaging via --audit-inventory (#650) ───
# The audit-inventory path is what preserves cross-architecture packaging
# without a caller-asserted backend flag; exercise it here (a non-executable
# copy of the host binary stands in for a foreign-architecture artifact)
# rather than leaving it validated only by hand.
NONEXEC_BINARY="${TMPDIR}/tardi-nonexec"
cp "$BINARY" "$NONEXEC_BINARY"
chmod -x "$NONEXEC_BINARY"
INVENTORY_PATH="${TMPDIR}/audit-inventory.json"
"${REPO_ROOT}/scripts/audit-release-binary.sh" \
    --binary "$BINARY" \
    --profile general \
    --output "$INVENTORY_PATH"
"${REPO_ROOT}/packaging/deb/build.sh" \
    --version "$VERSION" \
    --arch amd64 \
    --binary "$NONEXEC_BINARY" \
    --audit-inventory "$INVENTORY_PATH" \
    --output "${OUTPUT_DIR}/cross-arch"
test -f "${OUTPUT_DIR}/cross-arch/tardigrade_${VERSION}_amd64.deb"
echo "deb builder: --audit-inventory cross-architecture path succeeded"

# A mismatched inventory (not generated for this exact binary) must be rejected.
OTHER_INVENTORY="${TMPDIR}/audit-inventory-mismatched.json"
jq '.binary_sha256 = "0000000000000000000000000000000000000000000000000000000000000"' \
    "$INVENTORY_PATH" > "$OTHER_INVENTORY"
if "${REPO_ROOT}/packaging/deb/build.sh" \
    --version "$VERSION" \
    --arch amd64 \
    --binary "$NONEXEC_BINARY" \
    --audit-inventory "$OTHER_INVENTORY" \
    --output "${OUTPUT_DIR}/rejected-mismatch" 2>/dev/null; then
    echo "FAIL: deb builder accepted an --audit-inventory with a mismatched SHA-256" >&2
    exit 1
fi
echo "deb builder: mismatched --audit-inventory correctly rejected"

# ── Regression: package metadata must declare no OpenSSL runtime dependency ──
DEB_DEPENDS="$(dpkg-deb -f "$DEB_PATH" Depends 2>/dev/null || true)"
if printf '%s\n' "$DEB_DEPENDS" | grep -qiE 'libssl|libcrypto|openssl'; then
    echo "FAIL: native DEB unexpectedly declares an OpenSSL dependency: $DEB_DEPENDS" >&2
    exit 1
fi
echo "deb metadata: no OpenSSL dependency"

if ! retry 3 docker pull "$DEB_TEST_IMAGE"; then
    echo "CI infrastructure failure: unable to pull DEB smoke test image ($DEB_TEST_IMAGE)" >&2
    exit 75
fi

docker run --pull=never --rm \
    -v "${OUTPUT_DIR}:/artifacts:ro" \
    -v "${REPO_ROOT}/scripts/audit-release-binary.sh:/opt/audit-release-binary.sh:ro" \
    "$DEB_TEST_IMAGE" bash -euxc '
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get -o Acquire::Retries=3 update; then
        echo "CI infrastructure failure: apt index refresh failed in DEB smoke setup" >&2
        exit 75
    fi
    if ! apt-get -o Acquire::Retries=3 install -y ca-certificates curl binutils; then
        echo "CI infrastructure failure: apt dependency bootstrap failed in DEB smoke setup" >&2
        exit 75
    fi
    apt-get -o Acquire::Retries=3 install -y /artifacts/tardigrade_0.0.0-smoke_amd64.deb
    test -x /usr/bin/tardi
    /usr/bin/tardi version >/dev/null

    # Audit the exact binary actually installed by the package (#650) --
    # metadata/layout checks alone would not catch a package that installs
    # a binary linking OpenSSL, or one that mismatches its own reported
    # identity.
    bash /opt/audit-release-binary.sh \
        --binary /usr/bin/tardi \
        --profile general \
        --output /tmp/deb-inventory.json

    # A real request against the installed binary/config, not just `tardi
    # version` (#650): start it with the same starter config the package
    # ships, wait for a live response, then stop it.
    tardi run -c /etc/tardigrade/tardigrade.conf &
    tardi_pid=$!
    ready=false
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS -H "Host: localhost" http://127.0.0.1:8069/health >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 1
    done
    if [ "$ready" != true ]; then
        echo "FAIL: installed tardi never became ready to serve /health" >&2
        exit 1
    fi
    curl -fsS -H "Host: localhost" http://127.0.0.1:8069/health
    kill "$tardi_pid"
    wait "$tardi_pid" 2>/dev/null || true

    test -f /etc/tardigrade/tardigrade.conf
    test -f /etc/tardigrade/tardigrade.env
    test -f /lib/systemd/system/tardigrade.service
    test -f /etc/logrotate.d/tardigrade
    test -d /var/lib/tardigrade
    test -d /var/log/tardigrade
    grep -F "EnvironmentFile=-/etc/tardigrade/tardigrade.env" /lib/systemd/system/tardigrade.service
    grep -F "ExecStart=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi run -c /etc/tardigrade/tardigrade.conf" /lib/systemd/system/tardigrade.service
    grep -F "RuntimeDirectory=tardigrade" /lib/systemd/system/tardigrade.service
    grep -F "Environment=TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid" /lib/systemd/system/tardigrade.service
    grep -F "ExecStartPre=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi check /etc/tardigrade/tardigrade.conf" /lib/systemd/system/tardigrade.service
    grep -F "ExecReload=/usr/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid" /lib/systemd/system/tardigrade.service
    grep -F "ExecStop=/usr/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid" /lib/systemd/system/tardigrade.service
    grep -F "TimeoutStopSec=35s" /lib/systemd/system/tardigrade.service
    test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.env)" = "640 root tardigrade"
    test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.conf)" = "644 root root"
    test "$(stat -c "%a %U %G" /etc/logrotate.d/tardigrade)" = "644 root root"
    test "$(stat -c "%a %U %G" /var/lib/tardigrade)" = "755 tardigrade tardigrade"
    test "$(stat -c "%U %G" /var/log/tardigrade)" = "tardigrade tardigrade"
    grep -F "systemctl kill --kill-who=main --signal=USR1 tardigrade.service" /etc/logrotate.d/tardigrade
    apt-get remove -y tardigrade
    test ! -e /usr/bin/tardi
'

printf 'deb smoke test passed\n'
