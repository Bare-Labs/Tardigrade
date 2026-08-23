#!/usr/bin/env bash
# Build an RPM package for Tardigrade.
#
# Usage:
#   ./packaging/rpm/build.sh [--version VERSION] [--arch ARCH] [--binary PATH] [--tls-backend BACKEND] [--output DIR]
#
# ARCH accepts Debian-style names (amd64, arm64) or RPM-style (x86_64, aarch64).
# --tls-backend accepts native or openssl-adapter. When omitted, it is inferred
# from an executable host-native binary's `tardi version` output.
# Prerequisites:
#   rpm-build (dnf install rpm-build / apt-get install rpm-build)
#   A pre-built tardi binary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""
ARCH=""
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
TLS_BACKEND=""
OUTPUT_DIR="${REPO_ROOT}/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)     VERSION="$2"; shift 2 ;;
        --arch)        ARCH="$2"; shift 2 ;;
        --binary)      BINARY="$2"; shift 2 ;;
        --tls-backend) TLS_BACKEND="$2"; shift 2 ;;
        --output)      OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//')
fi

# Map Debian-style arch names to RPM arch names
case "$ARCH" in
    amd64)  RPM_ARCH="x86_64" ;;
    arm64)  RPM_ARCH="aarch64" ;;
    "")     RPM_ARCH="$(uname -m)" ;;
    *)      RPM_ARCH="$ARCH" ;;
esac

if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found: $BINARY" >&2
    exit 1
fi

# Keep package metadata aligned with the exact artifact being packaged.
# Official releases pass --tls-backend native explicitly. Host-native local
# builds can auto-detect; cross-compiled binaries remain packageable by passing
# the backend explicitly rather than attempting to execute a foreign-arch file.
if [[ -z "$TLS_BACKEND" ]]; then
    if [[ ! -x "$BINARY" ]]; then
        echo "Binary is not executable on this host; pass --tls-backend native or --tls-backend openssl-adapter" >&2
        exit 1
    fi
    BINARY_VERSION_OUTPUT="$("$BINARY" version 2>/dev/null || true)"
    case "$BINARY_VERSION_OUTPUT" in
        *"tls-backend=native"*) TLS_BACKEND="native" ;;
        *"tls-backend=openssl-adapter"*) TLS_BACKEND="openssl-adapter" ;;
        *)
            echo "Unable to determine TLS backend from '$BINARY version'; pass --tls-backend explicitly" >&2
            exit 1
            ;;
    esac
fi

case "$TLS_BACKEND" in
    native) RPM_REQUIRES_OPENSSL=0 ;;
    openssl-adapter) RPM_REQUIRES_OPENSSL=1 ;;
    *)
        echo "Invalid --tls-backend '$TLS_BACKEND' (expected native or openssl-adapter)" >&2
        exit 1
        ;;
esac

echo "Building tardigrade-${VERSION}-1.${RPM_ARCH}.rpm ..."

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "${WORK_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BINARY"                                                  "${WORK_DIR}/SOURCES/tardi"
cp "${REPO_ROOT}/LICENSE"                                     "${WORK_DIR}/SOURCES/LICENSE"
cp "${REPO_ROOT}/packaging/systemd/tardigrade.service"        "${WORK_DIR}/SOURCES/tardigrade.service"
cp "${REPO_ROOT}/packaging/tardigrade.conf"                   "${WORK_DIR}/SOURCES/tardigrade.conf"
cp "${REPO_ROOT}/packaging/rpm/tardigrade.spec"               "${WORK_DIR}/SPECS/tardigrade.spec"

cat > "${WORK_DIR}/SOURCES/tardigrade.env" <<'ENVEOF'
# Tardigrade environment configuration
TARDIGRADE_LISTEN_PORT=8069
TARDIGRADE_LOG_LEVEL=info
TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true
# TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080
ENVEOF

# Same SIGUSR1-reopen logrotate policy as the DEB package (packaging/deb/build.sh).
cat > "${WORK_DIR}/SOURCES/tardigrade.logrotate" <<'LREOF'
/var/log/tardigrade/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl kill --kill-who=main --signal=USR1 tardigrade.service 2>/dev/null || true
    endscript
}
LREOF

rpmbuild --define "_topdir ${WORK_DIR}" \
         --define "version ${VERSION}" \
         --define "build_arch ${RPM_ARCH}" \
         --define "tardigrade_requires_openssl ${RPM_REQUIRES_OPENSSL}" \
         --define "_unitdir /usr/lib/systemd/system" \
         --target "${RPM_ARCH}-linux" \
         -bb "${WORK_DIR}/SPECS/tardigrade.spec"

mkdir -p "$OUTPUT_DIR"
find "${WORK_DIR}/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/" \;
echo "Built RPM(s) in: $OUTPUT_DIR"
