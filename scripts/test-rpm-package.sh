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
        # matching dependency packages are mirrored. The smoke test only needs a
        # coherent distro-provided OpenSSL development stack.
        if ! dnf --setopt=retries=3 --nobest install -y rpm-build openssl-devel openssl-libs systemd-rpm-macros; then
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

        # glibc 2.34 (Rocky/RHEL 9'"'"'s version) merged libpthread into libc and
        # re-versioned pthread_create/pthread_join/etc. under a new GLIBC_2.34
        # symbol version. Zig'"'"'s default native-target glibc floor predates that,
        # so it doesn'"'"'t know those symbol versions exist and dynamic linking
        # against the real /usr/lib64/libssl.so fails with "undefined reference"
        # even though the symbols are genuinely present at runtime. Passing an
        # explicit glibc-version floor (not a ceiling -- linking is still against
        # the real system libc.so.6 dynamically) fixes it; bare "native"/"native-native-gnu"
        # does not, and was confirmed to reproduce the same failure.
        zig_arch="$(uname -m)"
        zig build -Doptimize=ReleaseFast -Dtarget="${zig_arch}-linux-gnu.2.34"
        test -x zig-out/bin/tardi

        /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch "$zig_arch" \
            --binary /tmp/tardigrade/zig-out/bin/tardi \
            --output /output

        rpm_path=$(find /output -name "tardigrade-*.rpm" | head -1)
        test -n "$rpm_path"
        test -f "$rpm_path"

        dnf --setopt=retries=3 install -y "$rpm_path"

        test -x /usr/bin/tardi
        /usr/bin/tardi version >/dev/null
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
