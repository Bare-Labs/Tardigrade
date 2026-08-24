#!/usr/bin/env bash
# Build an RPM package for Tardigrade.
#
# Usage:
#   ./packaging/rpm/build.sh [--version VERSION] [--arch ARCH] [--binary PATH] \
#       [--profile {general|appliance}] [--audit-inventory PATH] [--output DIR]
#
# ARCH accepts Debian-style names (amd64, arm64) or RPM-style (x86_64, aarch64).
#
# --profile is the TLS/crypto product policy the binary was built with:
# general or appliance (default: general, the general-purpose native profile
# this builder ships).
#
# --audit-inventory is a scripts/audit-release-binary.sh --output inventory
# JSON already generated for this exact BINARY (matched by SHA-256). Required
# when BINARY cannot execute on this host (cross-architecture packaging);
# ignored otherwise in favor of a fresh self-audit.
#
# Tardigrade ships exactly one production TLS/crypto implementation: the
# native path, with no OpenSSL/libcrypto (or other foreign TLS/crypto/QUIC/H3)
# linkage (#649). This builder proves that with scripts/audit-release-binary.sh
# rather than trusting a caller-supplied backend flag, and the resulting
# package declares no OpenSSL runtime dependency.
#
# Prerequisites:
#   rpm-build (dnf install rpm-build / apt-get install rpm-build)
#   jq
#   scripts/audit-release-binary.sh's own prerequisites (readelf/objdump on
#   Linux, otool on macOS)
#   A pre-built tardi binary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""
ARCH=""
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
PROFILE="general"
AUDIT_INVENTORY=""
OUTPUT_DIR="${REPO_ROOT}/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         VERSION="$2"; shift 2 ;;
        --arch)            ARCH="$2"; shift 2 ;;
        --binary)          BINARY="$2"; shift 2 ;;
        --profile)         PROFILE="$2"; shift 2 ;;
        --audit-inventory) AUDIT_INVENTORY="$2"; shift 2 ;;
        --output)          OUTPUT_DIR="$2"; shift 2 ;;
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

case "$PROFILE" in
    general | appliance) ;;
    *) echo "Invalid --profile '$PROFILE' (expected general or appliance)" >&2; exit 1 ;;
esac

# ── Prove the packaged artifact is the native production implementation ────
# The only supported production Tardigrade implementation is the native
# TLS/crypto path (#649). This must never be established by a caller-provided
# boolean/backend flag or inferred from the binary's filename -- always by
# running (or checking the result of) scripts/audit-release-binary.sh.
AUDIT_DIR=$(mktemp -d)
trap 'rm -rf "$AUDIT_DIR"' EXIT
AUDIT_JSON="${AUDIT_DIR}/audit.json"

if [[ -x "$BINARY" ]] && "$BINARY" version >/dev/null 2>&1; then
    "${REPO_ROOT}/scripts/audit-release-binary.sh" \
        --binary "$BINARY" \
        --profile "$PROFILE" \
        --output "$AUDIT_JSON"
elif [[ -n "$AUDIT_INVENTORY" ]]; then
    if [[ ! -f "$AUDIT_INVENTORY" ]]; then
        echo "Audit inventory not found: $AUDIT_INVENTORY" >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        binary_sha256="$(sha256sum "$BINARY" | awk '{print $1}')"
    else
        binary_sha256="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
    fi
    inventory_sha256="$(jq -r '.binary_sha256 // empty' "$AUDIT_INVENTORY")"
    if [[ -z "$inventory_sha256" || "$inventory_sha256" != "$binary_sha256" ]]; then
        echo "Audit inventory SHA-256 does not match --binary '$BINARY'; it was not generated for this exact artifact" >&2
        exit 1
    fi
    cp "$AUDIT_INVENTORY" "$AUDIT_JSON"
else
    echo "Binary is not executable on this host (cross-architecture packaging)." >&2
    echo "Pass --audit-inventory pointing to a scripts/audit-release-binary.sh --output" >&2
    echo "inventory JSON already generated for this exact binary (e.g. on the target" >&2
    echo "architecture, or under emulation)." >&2
    exit 1
fi

if [[ "$(jq -r '.status' "$AUDIT_JSON")" != "pass" ]] ||
   [[ "$(jq -r '.reported_backend' "$AUDIT_JSON")" != "native" ]] ||
   [[ "$(jq -r '.links_openssl' "$AUDIT_JSON")" != "false" ]] ||
   [[ "$(jq -r '.reported_profile' "$AUDIT_JSON")" != "$PROFILE" ]]; then
    echo "Audit does not prove a native, OpenSSL-free '$PROFILE' production artifact:" >&2
    jq -r '.violations[]? // empty' "$AUDIT_JSON" >&2 || true
    exit 1
fi

echo "Building tardigrade-${VERSION}-1.${RPM_ARCH}.rpm ..."

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR" "$AUDIT_DIR"' EXIT

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
         --define "_unitdir /usr/lib/systemd/system" \
         --target "${RPM_ARCH}-linux" \
         -bb "${WORK_DIR}/SPECS/tardigrade.spec"

mkdir -p "$OUTPUT_DIR"
find "${WORK_DIR}/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/" \;
echo "Built RPM(s) in: $OUTPUT_DIR"
