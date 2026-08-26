#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAP_NAME="bare-systems/tap"
FORMULA_REF="$TAP_NAME/tardigrade"
INSTALL_MODE="qualified"
TMPDIR="$(mktemp -d)"
INSTALLED_FORMULA=false
TAPPED=false
TRUSTED_FORMULA=false
SERVER_PID=""

usage() {
    cat <<'EOF'
Usage: test-public-homebrew-tap.sh [--install-mode qualified|tap-short]

Installs Tardigrade from the public Bare-Systems/homebrew-tap path and smokes
only the installed Homebrew artifact from a temporary directory outside the
checkout. This is intended for post-release/manual/scheduled distribution
validation, not PR-time generated-formula validation.
EOF
}

# shellcheck disable=SC2317,SC2329 # invoked by trap
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill -INT "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    if [ "$INSTALLED_FORMULA" = true ]; then
        brew uninstall --formula tardigrade >/dev/null 2>&1 || true
    fi
    if [ "$TRUSTED_FORMULA" = true ]; then
        brew untrust --formula "$FORMULA_REF" >/dev/null 2>&1 || true
    fi
    if [ "$TAPPED" = true ]; then
        brew untap "$TAP_NAME" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

while [ "$#" -gt 0 ]; do
    case "$1" in
    --install-mode)
        INSTALL_MODE="$2"
        shift 2
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
done

case "$INSTALL_MODE" in
qualified | tap-short) ;;
*)
    echo "invalid install mode: $INSTALL_MODE (expected qualified or tap-short)" >&2
    usage >&2
    exit 2
    ;;
esac

if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required for public tap smoke testing" >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for public tap smoke testing" >&2
    exit 2
fi
if brew list --formula tardigrade >/dev/null 2>&1; then
    echo "refusing to run smoke while a Homebrew tardigrade formula is already installed" >&2
    exit 2
fi
if brew tap | grep -Fx "$TAP_NAME" >/dev/null; then
    echo "refusing to run smoke while public tap is already tapped: $TAP_NAME" >&2
    exit 2
fi

emit_evidence() {
    local installed="$1" alias_path="$2" version_output="$3" audit_output="$4"
    local tap_repo tap_commit formula_version install_ref

    tap_repo="$(brew --repo "$TAP_NAME")"
    tap_commit="$(git -C "$tap_repo" rev-parse HEAD)"
    formula_version="$(
        brew info --json=v2 "$FORMULA_REF" |
            ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("formulae").fetch(0).fetch("versions").fetch("stable")'
    )"
    if [ "$INSTALL_MODE" = qualified ]; then
        install_ref="$FORMULA_REF"
    else
        install_ref="tardigrade"
    fi

    printf 'Public Homebrew smoke evidence\n'
    printf 'install_mode=%s\n' "$INSTALL_MODE"
    printf 'install_ref=%s\n' "$install_ref"
    printf 'homebrew_version<<EOF\n%s\nEOF\n' "$(brew --version)"
    printf 'os_arch=%s %s\n' "$(uname -s)" "$(uname -m)"
    printf 'tap=%s\n' "$TAP_NAME"
    printf 'tap_commit=%s\n' "$tap_commit"
    printf 'formula_version=%s\n' "$formula_version"
    printf 'installed_binary=%s\n' "$installed"
    printf 'installed_alias=%s\n' "$alias_path"
    printf 'tardi_version<<EOF\n%s\nEOF\n' "$version_output"
    printf 'linkage_audit=%s\n' "$audit_output"
}

case "$INSTALL_MODE" in
qualified)
    HOMEBREW_NO_AUTO_UPDATE=1 brew install --formula "$FORMULA_REF" --verbose
    INSTALLED_FORMULA=true
    TAPPED=true
    ;;
tap-short)
    HOMEBREW_NO_AUTO_UPDATE=1 brew tap "$TAP_NAME" >/dev/null
    TAPPED=true
    HOMEBREW_NO_AUTO_UPDATE=1 brew trust --formula "$FORMULA_REF" >/dev/null
    TRUSTED_FORMULA=true
    HOMEBREW_NO_AUTO_UPDATE=1 brew install --formula tardigrade --verbose
    INSTALLED_FORMULA=true
    ;;
esac

brew test "$FORMULA_REF" --verbose

prefix="$(brew --prefix)"
installed="$(command -v tardi)"
alias_path="$(command -v tardigrade)"
case "$installed" in
"$prefix"/*) ;;
*)
    echo "tardi resolved outside Homebrew prefix: $installed (prefix: $prefix)" >&2
    exit 1
    ;;
esac
case "$alias_path" in
"$prefix"/*) ;;
*)
    echo "tardigrade alias resolved outside Homebrew prefix: $alias_path (prefix: $prefix)" >&2
    exit 1
    ;;
esac
test -x "$installed"
test -e "$alias_path"
ruby -e 'exit(File.realpath(ARGV.fetch(0)) == File.realpath(ARGV.fetch(1)) ? 0 : 1)' "$installed" "$alias_path" || {
    echo "tardigrade does not resolve to the installed tardi binary" >&2
    exit 1
}

version_output="$("$installed" version)"
printf '%s\n' "$version_output" | grep -F 'tls-profile=general' >/dev/null
printf '%s\n' "$version_output" | grep -F 'tls-backend=native' >/dev/null

"$REPO_ROOT/scripts/audit-release-binary.sh" \
    --binary "$installed" \
    --profile general \
    --output "$TMPDIR/dependency-inventory.json" >/dev/null
audit_status="$(
    ruby -rjson -e 'puts JSON.parse(File.read(ARGV.fetch(0))).fetch("status")' \
        "$TMPDIR/dependency-inventory.json"
)"
test "$audit_status" = pass

smoke_dir="$TMPDIR/public-tap-runtime"
mkdir -p "$smoke_dir/public"
printf '%s\n' '<h1>public-tap-smoke</h1>' > "$smoke_dir/public/index.html"

cd "$smoke_dir"
"$installed" init static > tardigrade.conf
"$installed" check tardigrade.conf
"$installed" run -c tardigrade.conf > server.log 2>&1 &
SERVER_PID="$!"

body=""
ready=false
for _ in $(seq 1 50); do
    if body="$(curl -fsS -H 'Host: localhost' http://127.0.0.1:8080/ 2>/dev/null)"; then
        ready=true
        break
    fi
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

if [ "$ready" != true ]; then
    cat server.log >&2
    echo "public Homebrew artifact did not become ready" >&2
    exit 1
fi

test "$body" = '<h1>public-tap-smoke</h1>'
test "$(curl -fsS -H 'Host: localhost' http://127.0.0.1:8080/health)" = ok
kill -INT "$SERVER_PID"
wait "$SERVER_PID"
SERVER_PID=""

emit_evidence "$installed" "$alias_path" "$version_output" "$audit_status"
printf 'Public Homebrew tap smoke passed\n'
