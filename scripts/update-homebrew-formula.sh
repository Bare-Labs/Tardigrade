#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG=""
VERSION=""
CHECKSUMS_PATH=""
CHECKSUMS_URL=""
DEFAULT_FORMULA_PATH="${REPO_ROOT}/packaging/homebrew/tardigrade.rb"
FORMULA_PATH="$DEFAULT_FORMULA_PATH"
FORMULA_EXPLICIT=false
TAP_DIR=""
REPO="Bare-Systems/Tardigrade"

usage() {
    cat <<'EOF'
Usage:
  update-homebrew-formula.sh --tag vX.Y.Z [--formula PATH] [--tap-dir DIR]
  update-homebrew-formula.sh --version VERSION --checksums PATH [--formula PATH]

Production updates must use --tag. That mode resolves one GitHub release,
downloads that release's tardigrade-checksums.txt, verifies every emitted
archive exists in the same release, and renders the formula from that single
source.

The --version/--checksums mode is only for local release-shaped smoke fixtures.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --checksums) CHECKSUMS_PATH="$2"; shift 2 ;;
        --checksums-url) CHECKSUMS_URL="$2"; shift 2 ;;
        --formula) FORMULA_PATH="$2"; FORMULA_EXPLICIT=true; shift 2 ;;
        --tap-dir) TAP_DIR="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -n "$TAG" ]; then
    if [ -n "$VERSION" ] || [ -n "$CHECKSUMS_PATH" ] || [ -n "$CHECKSUMS_URL" ]; then
        echo "--tag cannot be combined with --version, --checksums, or --checksums-url" >&2
        exit 2
    fi
    case "$TAG" in
        v*) VERSION="${TAG#v}" ;;
        *) echo "--tag must be a release tag like v1.2.3" >&2; exit 2 ;;
    esac
else
    if [ -z "$VERSION" ] || [ -z "$CHECKSUMS_PATH" ]; then
        echo "use --tag vX.Y.Z for production updates or --version VERSION --checksums PATH for local smoke fixtures" >&2
        exit 2
    fi
    if [ -n "$CHECKSUMS_URL" ]; then
        echo "--checksums-url is only supported through --tag-derived release metadata" >&2
        exit 2
    fi
    if [ -n "$TAP_DIR" ]; then
        echo "fixture mode cannot write to --tap-dir; use --tag for tap updates" >&2
        exit 2
    fi
    if [ "$FORMULA_EXPLICIT" != true ]; then
        echo "fixture mode requires an explicit non-canonical --formula output path" >&2
        exit 2
    fi
fi

canonical_path() {
    dir="$(cd "$(dirname "$1")" && pwd)"
    printf '%s/%s\n' "$dir" "$(basename "$1")"
}

if [ -z "$TAG" ] && [ "$(canonical_path "$FORMULA_PATH")" = "$(canonical_path "$DEFAULT_FORMULA_PATH")" ]; then
    echo "fixture mode cannot overwrite the canonical formula; use --tag for packaging/homebrew/tardigrade.rb" >&2
    exit 2
fi

tmpdir="$(mktemp -d)"
# shellcheck disable=SC2317,SC2329 # invoked by trap
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

manifest="$CHECKSUMS_PATH"
assets_path="$tmpdir/assets.txt"
if [ -n "$TAG" ]; then
    release_json="$tmpdir/release.json"
    gh release view "$TAG" --repo "$REPO" --json tagName,assets > "$release_json"
    jq -r '.assets[].name' "$release_json" | sort > "$assets_path"
    if ! grep -Fx 'tardigrade-checksums.txt' "$assets_path" >/dev/null; then
        echo "release $TAG does not contain tardigrade-checksums.txt" >&2
        exit 1
    fi
    manifest="$tmpdir/tardigrade-checksums.txt"
    gh release download "$TAG" --repo "$REPO" --pattern tardigrade-checksums.txt --dir "$tmpdir" --clobber
else
    if [ ! -f "$manifest" ]; then
        echo "checksum manifest not found: $manifest" >&2
        exit 2
    fi
    : > "$assets_path"
fi

checksum_for() {
    asset="$1"
    awk -v asset="$asset" '
        {
            path = $0
            sub(/^[[:xdigit:]]+[[:space:]]+\*?/, "", path)
            n = split(path, parts, "/")
            if (parts[n] == asset) {
                print $1
                found = 1
            }
        }
        END { if (!found) exit 1 }
    ' "$manifest"
}

validate_sha() {
    asset="$1"
    sha="$2"
    if ! printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "invalid sha256 for $asset: $sha" >&2
        exit 1
    fi
}

validate_release_asset() {
    asset="$1"
    if [ -n "$TAG" ] && ! grep -Fx "$asset" "$assets_path" >/dev/null; then
        echo "release $TAG does not contain formula asset $asset" >&2
        exit 1
    fi
}

validate_native_inventory() {
    asset="$1"
    if [ -z "$TAG" ]; then
        return
    fi

    archive_name="${asset%.tar.gz}"
    inventory_asset="dependency-inventory-${archive_name}.json"
    if ! grep -Fx "$inventory_asset" "$assets_path" >/dev/null; then
        echo "release $TAG does not contain native dependency inventory $inventory_asset" >&2
        exit 1
    fi

    gh release download "$TAG" --repo "$REPO" --pattern "$inventory_asset" --dir "$tmpdir" --clobber
    inventory_path="$tmpdir/$inventory_asset"
    if [ "$(jq -r '.profile' "$inventory_path")" != "general" ] ||
        [ "$(jq -r '.reported_profile' "$inventory_path")" != "general" ] ||
        [ "$(jq -r '.reported_backend' "$inventory_path")" != "native" ] ||
        [ "$(jq -r '.links_openssl' "$inventory_path")" != "false" ] ||
        [ "$(jq -r '.status' "$inventory_path")" != "pass" ]; then
        echo "release $TAG inventory $inventory_asset does not prove native, OpenSSL-free artifact status" >&2
        exit 1
    fi
}

sync_tap_formula() {
    formula="$1"
    tap_dir="$2"

    mkdir -p "$tap_dir/Formula"
    install -m 0644 "$formula" "$tap_dir/Formula/tardigrade.rb"
}

emit_branch() {
    arch_dsl="$1"
    asset="$2"
    sha="$3"

    cat <<EOF
    ${arch_dsl} do
      url "https://github.com/${REPO}/releases/download/v${VERSION}/${asset}"
      sha256 "${sha}"
    end
EOF
}

linux_arm_asset="tardigrade-linux-aarch64.tar.gz"
linux_intel_asset="tardigrade-linux-x86_64.tar.gz"
darwin_arm_asset="tardigrade-darwin-arm64.tar.gz"
darwin_intel_asset="tardigrade-darwin-x86_64.tar.gz"

linux_arm_sha="$(checksum_for "$linux_arm_asset" || true)"
linux_intel_sha="$(checksum_for "$linux_intel_asset" || true)"
darwin_arm_sha="$(checksum_for "$darwin_arm_asset" || true)"
darwin_intel_sha="$(checksum_for "$darwin_intel_asset" || true)"

if [ -z "$linux_arm_sha" ] && [ -z "$linux_intel_sha" ] && [ -z "$darwin_arm_sha" ] && [ -z "$darwin_intel_sha" ]; then
    echo "manifest contains no Homebrew-supported Tardigrade archives" >&2
    exit 1
fi

for pair in \
    "$linux_arm_asset:$linux_arm_sha" \
    "$linux_intel_asset:$linux_intel_sha" \
    "$darwin_arm_asset:$darwin_arm_sha" \
    "$darwin_intel_asset:$darwin_intel_sha"; do
    asset="${pair%%:*}"
    sha="${pair#*:}"
    if [ -n "$sha" ]; then
        validate_sha "$asset" "$sha"
        validate_release_asset "$asset"
        validate_native_inventory "$asset"
    fi
done

mkdir -p "$(dirname "$FORMULA_PATH")"
formula_tmp="$tmpdir/tardigrade.rb"

{
    cat <<EOF
# This formula is generated by scripts/update-homebrew-formula.sh.
# Canonical source: Bare-Systems/Tardigrade packaging/homebrew/tardigrade.rb

class Tardigrade < Formula
  desc "Small Zig edge server for static file serving, reverse proxying, and TLS termination"
  homepage "https://github.com/${REPO}"
  version "${VERSION}"
  license "Apache-2.0"

EOF

    if [ -z "$darwin_arm_sha" ] && [ -z "$darwin_intel_sha" ]; then
        printf '  depends_on :linux\n\n'
    fi

    if [ -n "$darwin_arm_sha" ] || [ -n "$darwin_intel_sha" ]; then
        printf '  on_macos do\n'
        [ -z "$darwin_arm_sha" ] || emit_branch "on_arm" "$darwin_arm_asset" "$darwin_arm_sha"
        [ -z "$darwin_intel_sha" ] || emit_branch "on_intel" "$darwin_intel_asset" "$darwin_intel_sha"
        printf '  end\n\n'
    fi

    if [ -n "$linux_arm_sha" ] || [ -n "$linux_intel_sha" ]; then
        printf '  on_linux do\n'
        [ -z "$linux_arm_sha" ] || emit_branch "on_arm" "$linux_arm_asset" "$linux_arm_sha"
        if [ -n "$linux_arm_sha" ] && [ -n "$linux_intel_sha" ]; then
            printf '\n'
        fi
        [ -z "$linux_intel_sha" ] || emit_branch "on_intel" "$linux_intel_asset" "$linux_intel_sha"
        printf '  end\n\n'
    fi

    cat <<'EOF'
  def install
    bin.install "tardi"
    bin.install_symlink "tardi" => "tardigrade"
  end

  test do
    output = shell_output("#{bin}/tardi version")
    assert_match version.to_s, output
    assert_match "tls-profile=general", output
    assert_match "tls-backend=native", output
    assert_equal (bin/"tardi").realpath, (bin/"tardigrade").realpath
  end
end
EOF
} > "$formula_tmp"

ruby -c "$formula_tmp" >/dev/null
install -m 0644 "$formula_tmp" "$FORMULA_PATH"

if [ -n "$TAP_DIR" ]; then
    sync_tap_formula "$formula_tmp" "$TAP_DIR"
fi

printf 'updated %s from %s\n' "$FORMULA_PATH" "$manifest"
if [ -n "$TAP_DIR" ]; then
    printf 'updated %s\n' "$TAP_DIR"
fi
