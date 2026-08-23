#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMULA_PATH="${REPO_ROOT}/packaging/homebrew/tardigrade.rb"
TAP_NAME="bare-systems/tardigrade-release-smoke"
TMPDIR="$(mktemp -d)"
INSTALLED_FORMULA=false
TAP_CREATED=false

usage() {
    cat <<'EOF'
Usage: test-homebrew-release-formula.sh [--formula PATH]

Installs the provided formula through Homebrew, runs brew test, and audits the
installed binary. Use this only after packaging/homebrew/tardigrade.rb has been
rendered from a real native release tag.
EOF
}

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

while [ "$#" -gt 0 ]; do
    case "$1" in
        --formula) FORMULA_PATH="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required for release formula smoke testing" >&2
    exit 2
fi
if brew list --formula tardigrade >/dev/null 2>&1; then
    echo "refusing to run smoke while a Homebrew tardigrade formula is already installed" >&2
    exit 2
fi
if [ ! -f "$FORMULA_PATH" ]; then
    echo "formula not found: $FORMULA_PATH" >&2
    exit 2
fi
if grep -F "No release-backed native Tardigrade Homebrew formula" "$FORMULA_PATH" >/dev/null; then
    echo "formula is still preparatory; render it from a native release before running this smoke" >&2
    exit 2
fi
if brew tap | grep -Fx "$TAP_NAME" >/dev/null; then
    echo "temporary tap already exists: $TAP_NAME" >&2
    exit 2
fi

tap_repo="$TMPDIR/homebrew-tardigrade-release-smoke"
mkdir -p "$tap_repo/Formula"
install -m 0644 "$FORMULA_PATH" "$tap_repo/Formula/tardigrade.rb"
(
    cd "$tap_repo"
    git init -q
    git add Formula/tardigrade.rb
    git -c user.name="Tardigrade Release Smoke" -c user.email="tardigrade-release-smoke@example.invalid" \
        commit -q -m "Add release formula"
)

HOMEBREW_NO_AUTO_UPDATE=1 brew tap "$TAP_NAME" "$tap_repo" >/dev/null
TAP_CREATED=true
HOMEBREW_NO_AUTO_UPDATE=1 brew install --formula "$TAP_NAME/tardigrade" --force --verbose
INSTALLED_FORMULA=true
HOMEBREW_NO_AUTO_UPDATE=1 brew test "$TAP_NAME/tardigrade" --verbose

installed="$(brew --prefix)/bin/tardi"
test -x "$installed"
"$installed" version
"$REPO_ROOT/scripts/audit-release-binary.sh" \
    --binary "$installed" \
    --profile native \
    --output "$TMPDIR/dependency-inventory.json"

printf 'Homebrew release formula smoke passed\n'
