#!/usr/bin/env bash
# Smoke-test the RPM package.
#
# Builds the binary from source inside a Rocky Linux 9 container so it links
# against that platform's glibc (2.34), then builds the RPM and installs it.
# The host Zig install directory is mounted into the container.
#
# Usage: ./scripts/test-rpm-package.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
RPM_TEST_IMAGE="${RPM_TEST_IMAGE:-rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6}"

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
    echo "skipping RPM smoke test outside Linux" >&2
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "skipping RPM smoke test because docker is unavailable" >&2
    exit 0
fi

# Locate the Zig installation directory to mount into the container.
# Zig's binary is statically linked, but it still needs its adjacent lib dir.
ZIG_BIN="${ZIG_BIN:-$(command -v zig 2>/dev/null || true)}"
if [[ -z "$ZIG_BIN" ]]; then
    ZIG_BIN="$(find "${REPO_ROOT}/.zig" -maxdepth 4 -name zig -type f 2>/dev/null | head -1 || true)"
fi
if [[ -z "$ZIG_BIN" ]]; then
    echo "error: zig binary not found; set ZIG_BIN or run scripts/install-zig.sh first" >&2
    exit 1
fi

ZIG_BIN="$(readlink -f "$ZIG_BIN")"
ZIG_DIR="$(cd "$(dirname "$ZIG_BIN")" && pwd)"

if [[ ! -x "${ZIG_DIR}/zig" || ! -d "${ZIG_DIR}/lib" ]]; then
    echo "error: invalid Zig install directory: ${ZIG_DIR}" >&2
    exit 1
fi

OUTPUT_DIR="${TMPDIR}/dist"
mkdir -p "$OUTPUT_DIR"

if ! retry 3 docker pull "$RPM_TEST_IMAGE"; then
    echo "CI infrastructure failure: unable to pull RPM smoke test image ($RPM_TEST_IMAGE)" >&2
    exit 75
fi

docker run --pull=never --rm \
    --volume "${REPO_ROOT}:/repo:ro" \
    --volume "${OUTPUT_DIR}:/output" \
    --volume "${ZIG_DIR}:/opt/zig:ro" \
    "$RPM_TEST_IMAGE" bash -euxc '
        # Rocky minor repos can briefly offer a newer best candidate before all
        # matching dependency packages are mirrored. jq is required by
        # packaging/rpm/build.sh to validate the native-linkage audit result;
        # binutils (readelf) is required by scripts/audit-release-binary.sh.
        # curl is not listed here: the base image already ships curl-minimal,
        # which provides a fully working `curl` binary for the plain HTTP
        # request below, and the full curl package conflicts with it.
        if ! dnf --setopt=retries=3 --nobest install -y rpm-build systemd-rpm-macros jq binutils; then
            echo "CI infrastructure failure: dnf dependency bootstrap failed in RPM smoke setup" >&2
            exit 75
        fi

        export PATH="/opt/zig:${PATH}"

        # Build from source inside this container so the binary links against
        # Rocky Linux 9'"'"'s glibc (2.34) rather than the CI runner'"'"'s. Discard
        # any zig-out/.zig-cache copied in from the host/CI runner first: without
        # this, a build failure inside this container (wrong glibc, missing libs,
        # etc.) can go unnoticed because a stale host-built binary still satisfies
        # the path below, and the smoke test would package that binary instead of
        # actually proving the Rocky build works.
        cp -a /repo /tmp/tardigrade
        cd /tmp/tardigrade
        rm -rf zig-out .zig-cache

        # Before #649/#650, this needed an explicit glibc-version floor
        # (`-Dtarget=$arch-linux-gnu.2.34`): glibc 2.34 (Rocky/RHEL 9'"'"'s
        # version) merged libpthread into libc and re-versioned
        # pthread_create/pthread_join/etc. under a new GLIBC_2.34 symbol
        # version, and dynamically linking the OpenSSL adapter'"'"'s libssl.so
        # pulled in those reversioned symbols before Zig'"'"'s default
        # native-target glibc floor knew they existed, failing with
        # "undefined reference" even though the symbols were genuinely
        # present at runtime. Tardigrade'"'"'s native build links no OpenSSL (or
        # any other foreign library) at all, so that failure no longer
        # reproduces here -- confirmed by building this exact target with
        # the bare native target and no explicit floor -- and the floor is
        # not re-added.
        zig_arch="$(uname -m)"
        zig build -Doptimize=ReleaseFast
        test -x zig-out/bin/tardi

        /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch "$zig_arch" \
            --binary /tmp/tardigrade/zig-out/bin/tardi \
            --output /output

        rpm_path=$(find /output -name "tardigrade-*.rpm" | head -1)
        test -n "$rpm_path"
        test -f "$rpm_path"

        # Regression: the standalone builder must not accept a caller-asserted
        # OpenSSL backend as a valid production mode (#650).
        if /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch "$zig_arch" \
            --binary /tmp/tardigrade/zig-out/bin/tardi \
            --tls-backend openssl-adapter \
            --output /output/rejected 2>/dev/null; then
            echo "FAIL: rpm builder accepted --tls-backend openssl-adapter" >&2
            exit 1
        fi
        echo "rpm builder: --tls-backend openssl-adapter correctly rejected"

        # Regression: cross-architecture packaging via --audit-inventory (#650).
        # The audit-inventory path is what preserves cross-architecture
        # packaging without a caller-asserted backend flag; exercise it here
        # (a non-executable copy of the host binary stands in for a
        # foreign-architecture artifact) rather than leaving it validated only
        # by hand.
        cp /tmp/tardigrade/zig-out/bin/tardi /tmp/tardi-nonexec
        chmod -x /tmp/tardi-nonexec
        /repo/scripts/audit-release-binary.sh \
            --binary /tmp/tardigrade/zig-out/bin/tardi \
            --profile general \
            --output /tmp/audit-inventory.json
        /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch "$zig_arch" \
            --binary /tmp/tardi-nonexec \
            --audit-inventory /tmp/audit-inventory.json \
            --output /output/cross-arch
        test -n "$(find /output/cross-arch -name "tardigrade-*.rpm" -print -quit)"
        echo "rpm builder: --audit-inventory cross-architecture path succeeded"

        # A mismatched inventory (not generated for this exact binary) must be
        # rejected.
        jq ".binary_sha256 = \"0000000000000000000000000000000000000000000000000000000000000\"" \
            /tmp/audit-inventory.json > /tmp/audit-inventory-mismatched.json
        if /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch "$zig_arch" \
            --binary /tmp/tardi-nonexec \
            --audit-inventory /tmp/audit-inventory-mismatched.json \
            --output /output/rejected-mismatch 2>/dev/null; then
            echo "FAIL: rpm builder accepted an --audit-inventory with a mismatched SHA-256" >&2
            exit 1
        fi
        echo "rpm builder: mismatched --audit-inventory correctly rejected"

        # Regression: package metadata must declare no OpenSSL runtime dependency.
        rpm_requires="$(rpm -qp --requires "$rpm_path")"
        if printf "%s\n" "$rpm_requires" | grep -qiE "libssl|libcrypto|openssl"; then
            echo "FAIL: native RPM unexpectedly declares an OpenSSL dependency:" >&2
            printf "%s\n" "$rpm_requires" >&2
            exit 1
        fi
        echo "rpm metadata: no OpenSSL dependency"

        dnf --setopt=retries=3 install -y "$rpm_path"

        test -x /usr/bin/tardi
        /usr/bin/tardi version >/dev/null

        # Audit the exact binary actually installed by the package (#650) --
        # metadata/layout checks alone would not catch a package that installs
        # a binary linking OpenSSL, or one that mismatches its own reported
        # identity.
        /repo/scripts/audit-release-binary.sh \
            --binary /usr/bin/tardi \
            --profile general \
            --output /tmp/rpm-installed-inventory.json

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

        test -f /etc/tardigrade/tardigrade.env
        test -f /etc/tardigrade/tardigrade.conf
        test -f /usr/lib/systemd/system/tardigrade.service
        test -f /usr/share/licenses/tardigrade/LICENSE
        test -f /etc/logrotate.d/tardigrade
        test -d /var/log/tardigrade
        test -d /var/lib/tardigrade
        test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.env)" = "640 root tardigrade"
        test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.conf)" = "644 root root"
        test "$(stat -c "%a %U %G" /etc/logrotate.d/tardigrade)" = "644 root root"
        test "$(stat -c "%a %U %G" /var/lib/tardigrade)" = "755 tardigrade tardigrade"
        test "$(stat -c "%U %G" /var/log/tardigrade)" = "tardigrade tardigrade"
        grep -F "systemctl kill --kill-who=main --signal=USR1 tardigrade.service" /etc/logrotate.d/tardigrade
        grep -F "EnvironmentFile=-/etc/tardigrade/tardigrade.env" /usr/lib/systemd/system/tardigrade.service
        grep -F "ExecStart=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi run -c /etc/tardigrade/tardigrade.conf" /usr/lib/systemd/system/tardigrade.service
        grep -F "WorkingDirectory=/var/lib/tardigrade" /usr/lib/systemd/system/tardigrade.service
        grep -F "RuntimeDirectory=tardigrade" /usr/lib/systemd/system/tardigrade.service
        grep -F "Environment=TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid" /usr/lib/systemd/system/tardigrade.service
        grep -F "ExecStartPre=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi check /etc/tardigrade/tardigrade.conf" /usr/lib/systemd/system/tardigrade.service
        grep -F "ExecReload=/usr/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid" /usr/lib/systemd/system/tardigrade.service
        grep -F "ExecStop=/usr/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid" /usr/lib/systemd/system/tardigrade.service
        grep -F "TimeoutStopSec=35s" /usr/lib/systemd/system/tardigrade.service

        dnf remove -y tardigrade
        test ! -e /usr/bin/tardi
    '

printf 'rpm smoke test passed\n'
