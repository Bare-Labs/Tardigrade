#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb package for Tardigrade.
#
# Usage:
#   ./packaging/deb/build.sh [--version VERSION] [--arch ARCH] [--binary PATH] \
#       [--profile {general|appliance}] [--audit-inventory PATH] [--output DIR]
#
# Options:
#   --version VERSION        Package version (default: inferred from `git describe`)
#   --arch ARCH              Target architecture: amd64 or arm64 (default: host arch)
#   --binary PATH            Path to pre-built tardi binary (default: zig-out/bin/tardi)
#   --profile PROFILE        TLS/crypto product policy the binary was built with:
#                             general or appliance (default: general, the
#                             general-purpose native profile this builder ships)
#   --audit-inventory PATH   A scripts/audit-release-binary.sh --output inventory
#                             JSON already generated for this exact BINARY (matched
#                             by SHA-256). Required when BINARY cannot execute on
#                             this host (cross-architecture packaging); ignored
#                             otherwise in favor of a fresh self-audit.
#   --output DIR             Output directory for .deb file (default: dist/)
#
# Tardigrade ships exactly one production TLS/crypto implementation: the
# native path, with no OpenSSL/libcrypto (or other foreign TLS/crypto/QUIC/H3)
# linkage (#649). This builder proves that with scripts/audit-release-binary.sh
# rather than trusting a caller-supplied backend flag, and the resulting
# package declares no OpenSSL runtime dependency.
#
# Prerequisites:
#   dpkg-deb (part of dpkg, available on Debian/Ubuntu)
#   jq
#   scripts/audit-release-binary.sh's own prerequisites (readelf/objdump on
#   Linux, otool on macOS)
#   A pre-built tardi binary for the target architecture

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

# Infer version from git if not specified
if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//')
fi

# Infer arch from host if not specified
if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

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

echo "Building tardigrade_${VERSION}_${ARCH}.deb ..."

# ── Package tree ─────────────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR" "$AUDIT_DIR"' EXIT

PKG_DIR="${WORK_DIR}/tardigrade_${VERSION}_${ARCH}"
BIN_DIR="${PKG_DIR}/usr/bin"
CONF_DIR="${PKG_DIR}/etc/tardigrade"
SYSTEMD_DIR="${PKG_DIR}/lib/systemd/system"
LOGROTATE_DIR="${PKG_DIR}/etc/logrotate.d"
STATE_DIR="${PKG_DIR}/var/lib/tardigrade"
LOG_DIR="${PKG_DIR}/var/log/tardigrade"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"

mkdir -p "$BIN_DIR" "$CONF_DIR" "$SYSTEMD_DIR" "$LOGROTATE_DIR" "$STATE_DIR" "$LOG_DIR" "$DEBIAN_DIR"

# Binary
install -m 0755 "$BINARY" "${BIN_DIR}/tardi"
ln -s tardi "${BIN_DIR}/tardigrade"

# Default config
cat > "${CONF_DIR}/tardigrade.env" <<'ENVEOF'
# Tardigrade environment configuration
# See https://github.com/Bare-Systems/Tardigrade for full reference.
TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf
TARDIGRADE_LISTEN_PORT=8069
TARDIGRADE_LOG_LEVEL=info
TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true
# TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080
# TARDIGRADE_TLS_CERT_PATH=/etc/tardigrade/tls/server.crt
# TARDIGRADE_TLS_KEY_PATH=/etc/tardigrade/tls/server.key
ENVEOF
chmod 0640 "${CONF_DIR}/tardigrade.env"

# Starter config
install -m 0644 "${REPO_ROOT}/packaging/tardigrade.conf" "${CONF_DIR}/tardigrade.conf"

# systemd unit
cp "${REPO_ROOT}/packaging/systemd/tardigrade.service" "${SYSTEMD_DIR}/tardigrade.service"

# logrotate config
cat > "${LOGROTATE_DIR}/tardigrade" <<'LREOF'
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
chmod 0644 "${LOGROTATE_DIR}/tardigrade"

# Preserve operator-edited config files across upgrades.
cat > "${DEBIAN_DIR}/conffiles" <<'CONFEOF'
/etc/tardigrade/tardigrade.conf
/etc/tardigrade/tardigrade.env
CONFEOF

# DEBIAN/control. The native package declares no OpenSSL/libssl/libcrypto
# runtime dependency for Tardigrade -- there is no other production backend.
cat > "${DEBIAN_DIR}/control" <<CONTROL
Package: tardigrade
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Bare Systems <security@baresystems.dev>
Installed-Size: $(du -sk "$BIN_DIR" | awk '{print $1}')
Section: net
Priority: optional
Homepage: https://github.com/Bare-Systems/Tardigrade
Description: Tardigrade edge gateway
 High-performance Zig edge gateway and HTTP server for TLS termination,
 reverse proxying, protocol bridging, and realtime event transport.
CONTROL

# DEBIAN/postinst
cat > "${DEBIAN_DIR}/postinst" <<'POSTINST'
#!/bin/sh
set -e
# Create tardigrade user if missing
if ! id -u tardigrade >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin tardigrade
fi
chown root:tardigrade /etc/tardigrade/tardigrade.env
install -d -o tardigrade -g tardigrade /var/lib/tardigrade /var/log/tardigrade
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
POSTINST
chmod 0755 "${DEBIAN_DIR}/postinst"

# DEBIAN/prerm
cat > "${DEBIAN_DIR}/prerm" <<'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop tardigrade.service 2>/dev/null || true
    systemctl disable tardigrade.service 2>/dev/null || true
fi
PRERM
chmod 0755 "${DEBIAN_DIR}/prerm"

# ── Build .deb ────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
DEB_PATH="${OUTPUT_DIR}/tardigrade_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_PATH"

echo "Built: $DEB_PATH"
