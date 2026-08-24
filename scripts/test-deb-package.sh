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

docker run --pull=never --rm -v "${OUTPUT_DIR}:/artifacts:ro" "$DEB_TEST_IMAGE" bash -euxc '
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get -o Acquire::Retries=3 update; then
        echo "CI infrastructure failure: apt index refresh failed in DEB smoke setup" >&2
        exit 75
    fi
    if ! apt-get -o Acquire::Retries=3 install -y ca-certificates; then
        echo "CI infrastructure failure: apt dependency bootstrap failed in DEB smoke setup" >&2
        exit 75
    fi
    apt-get -o Acquire::Retries=3 install -y /artifacts/tardigrade_0.0.0-smoke_amd64.deb
    test -x /usr/bin/tardi
    /usr/bin/tardi version >/dev/null
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
