#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
TAP_NAME="bare-systems/tardigrade-smoke"
INSTALLED_FORMULA=false
TAP_CREATED=false

# shellcheck disable=SC2329 # invoked by trap
cleanup() {
    if [ "$INSTALLED_FORMULA" = true ]; then
        brew uninstall --formula "$TAP_NAME/tardigrade" >/dev/null 2>&1 || true
    fi
    if [ "$TAP_CREATED" = true ]; then
        brew untap "$TAP_NAME" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required for formula smoke testing" >&2
    exit 2
fi
if brew list --formula tardigrade >/dev/null 2>&1; then
    echo "refusing to run smoke while a Homebrew tardigrade formula is already installed" >&2
    exit 2
fi

host_platform() {
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64|Linux/amd64) printf 'linux-x86_64\n' ;;
        Linux/aarch64|Linux/arm64) printf 'linux-aarch64\n' ;;
        Darwin/x86_64|Darwin/amd64) printf 'darwin-x86_64\n' ;;
        Darwin/arm64|Darwin/aarch64) printf 'darwin-arm64\n' ;;
        *) echo "unsupported host platform for Homebrew formula smoke" >&2; exit 1 ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

binary="${REPO_ROOT}/zig-out/bin/tardi"
if [ ! -x "$binary" ]; then
    echo "build zig-out/bin/tardi before running this smoke" >&2
    exit 2
fi

platform="$(host_platform)"
version="0.0.0-homebrew-smoke"
release_dir="$TMPDIR/release"
mkdir -p "$release_dir"

"$REPO_ROOT/scripts/package-release-archive.sh" \
    --archive-name "tardigrade-$platform" \
    --binary "$binary" \
    --output-dir "$release_dir" >/dev/null

(
    cd "$release_dir"
    sha256_file "tardigrade-$platform.tar.gz" > tardigrade-checksums.txt
)

"$REPO_ROOT/scripts/update-homebrew-formula.sh" \
    --version "$version" \
    --checksums "$release_dir/tardigrade-checksums.txt" \
    --formula "$TMPDIR/tardigrade.rb" >/dev/null

release_url="file://${release_dir}/tardigrade-${platform}.tar.gz"
perl -0pi -e "s#https://github\\.com/Bare-Systems/Tardigrade/releases/download/v\\Q${version}\\E/tardigrade-\\Q${platform}\\E\\.tar\\.gz#${release_url}#g" \
    "$TMPDIR/tardigrade.rb"

if brew tap | grep -Fx "$TAP_NAME" >/dev/null; then
    echo "temporary tap already exists: $TAP_NAME" >&2
    exit 2
fi

tap_repo="$TMPDIR/homebrew-tardigrade-smoke"
mkdir -p "$tap_repo/Formula"
install -m 0644 "$TMPDIR/tardigrade.rb" "$tap_repo/Formula/tardigrade.rb"
(
    cd "$tap_repo"
    git init -q
    git add Formula/tardigrade.rb
    git -c user.name="Tardigrade Smoke" -c user.email="tardigrade-smoke@example.invalid" \
        commit -q -m "Add smoke formula"
)

HOMEBREW_NO_AUTO_UPDATE=1 brew tap "$TAP_NAME" "$tap_repo" >/dev/null
TAP_CREATED=true

HOMEBREW_NO_AUTO_UPDATE=1 brew install --formula "$TAP_NAME/tardigrade" --force --verbose
INSTALLED_FORMULA=true
HOMEBREW_NO_AUTO_UPDATE=1 brew test "$TAP_NAME/tardigrade" --verbose

installed="$(brew --prefix)/bin/tardi"
alias_path="$(brew --prefix)/bin/tardigrade"
test -x "$installed"
test -e "$alias_path"
"$installed" version >/dev/null

"$REPO_ROOT/scripts/audit-release-binary.sh" \
    --binary "$installed" \
    --profile native \
    --output "$TMPDIR/dependency-inventory.json"

mkdir -p "$TMPDIR/site"
printf '%s\n' '<h1>homebrew smoke</h1>' > "$TMPDIR/site/index.html"
cat > "$TMPDIR/tardigrade.conf" <<EOF
listen 18089;
server_name localhost;

location = /health {
    return 200 homebrew-smoke;
}
EOF

"$installed" check "$TMPDIR/tardigrade.conf" >/dev/null
"$installed" run -c "$TMPDIR/tardigrade.conf" >"$TMPDIR/server.log" 2>&1 &
pid="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://127.0.0.1:18089/health | grep -F "homebrew-smoke" >/dev/null; then
        kill "$pid"
        wait "$pid" 2>/dev/null || true
        printf 'Homebrew formula smoke passed\n'
        exit 0
    fi
    sleep 0.5
done

cat "$TMPDIR/server.log" >&2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
echo "Tardigrade did not serve the Homebrew smoke request" >&2
exit 1
