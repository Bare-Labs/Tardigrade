#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# shellcheck disable=SC2317,SC2329 # invoked by trap
cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

fakebin="$TMPDIR/bin"
mkdir -p "$fakebin"

cat > "$fakebin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$1" != "release" ]; then
    echo "unexpected gh command: $*" >&2
    exit 1
fi

case "$2" in
    view)
        cat <<'JSON'
{
  "tagName": "v9.9.9",
  "assets": [
    { "name": "tardigrade-checksums.txt" },
    { "name": "tardigrade-linux-x86_64.tar.gz" },
    { "name": "dependency-inventory-tardigrade-linux-x86_64.json" }
  ]
}
JSON
        ;;
    download)
        pattern=""
        dir=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --pattern) pattern="$2"; shift 2 ;;
                --dir) dir="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        mkdir -p "$dir"
        case "$pattern" in
            tardigrade-checksums.txt)
                printf '%s  %s\n' \
                    "1111111111111111111111111111111111111111111111111111111111111111" \
                    "tardigrade-linux-x86_64.tar.gz" > "$dir/tardigrade-checksums.txt"
                ;;
            dependency-inventory-tardigrade-linux-x86_64.json)
                cat > "$dir/dependency-inventory-tardigrade-linux-x86_64.json" <<'JSON'
{
  "profile": "native",
  "reported_profile": "native",
  "reported_backend": "native",
  "links_openssl": false,
  "status": "pass"
}
JSON
                ;;
            *)
                echo "unexpected gh release download pattern: $pattern" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "unexpected gh release subcommand: $2" >&2
        exit 1
        ;;
esac
EOF
chmod +x "$fakebin/gh"

tap="$TMPDIR/tap"
mkdir -p "$tap/Formula"
printf '%s\n' "tap-owned-readme" > "$tap/README.md"

PATH="$fakebin:$PATH" "$REPO_ROOT/scripts/update-homebrew-formula.sh" \
    --tag v9.9.9 \
    --repo Bare-Systems/Tardigrade \
    --formula "$TMPDIR/generated.rb" \
    --tap-dir "$tap" >/dev/null

test -f "$tap/Formula/tardigrade.rb"
grep -F 'version "9.9.9"' "$tap/Formula/tardigrade.rb" >/dev/null

if [ "$(cat "$tap/README.md")" != "tap-owned-readme" ]; then
    echo "--tap-dir rewrote tap-owned README.md" >&2
    exit 1
fi

printf 'Homebrew tap sync preserved tap-owned README.md\n'
