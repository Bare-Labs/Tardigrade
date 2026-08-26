#!/bin/bash
# Live black-box F-06 campaign for #673: auth enforcement + hostile HTTP/1.1
# framing against a real local `tardi` process fronting a disposable upstream.
#
# Builds (or reuses via TARDI_BIN) a tardi binary, starts the disposable
# upstream fixture and a synthetic auth-protected edge config, runs the raw
# byte-exact probe engine in tests/security/f06_live_campaign.py, captures
# evidence, and tears everything down.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

TARDI_PORT="${TARDI_PORT:-18089}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18189}"
VALID_TOKEN="f06-valid-token-9f3c2a9b7e"
JWT_SECRET="f06-jwt-secret-do-not-use-in-prod-4c1a"

evidence_dir="${F06_EVIDENCE_DIR:-$repo/.zig-cache/f06-campaign-673}"
mkdir -p "$evidence_dir"
metadata="$evidence_dir/metadata.txt"
evidence_json="$evidence_dir/results.json"
tardi_log="$evidence_dir/tardi.log"
upstream_log="$evidence_dir/upstream.log"

say() { printf '%s\n' "$*"; }

if command -v shasum >/dev/null 2>&1; then
  token_hash="$(printf '%s' "$VALID_TOKEN" | shasum -a 256 | awk '{print $1}')"
else
  token_hash="$(printf '%s' "$VALID_TOKEN" | sha256sum | awk '{print $1}')"
fi

if [ -n "${TARDI_BIN:-}" ]; then
  tardi_bin="$TARDI_BIN"
else
  say "==> building tardi (zig build)"
  zig build
  tardi_bin="$repo/zig-out/bin/tardi"
fi

if [ ! -x "$tardi_bin" ]; then
  say "tardi binary not found or not executable at $tardi_bin"
  exit 2
fi

{
  printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'repo=%s\n' "$repo"
  printf 'git_sha=%s\n' "$(git rev-parse HEAD)"
  printf 'git_branch=%s\n' "$(git rev-parse --abbrev-ref HEAD)"
  printf 'tardi_bin=%s\n' "$tardi_bin"
  printf 'tardi_port=%s\n' "$TARDI_PORT"
  printf 'upstream_port=%s\n' "$UPSTREAM_PORT"
  printf 'zig='
  zig version 2>&1 || true
  printf 'python3='
  python3 --version 2>&1 || true
  printf 'uname='
  uname -a
} >"$metadata"

say "metadata: $metadata"
cat "$metadata"

upstream_pid=""
tardi_pid=""

# shellcheck disable=SC2317,SC2329 # invoked by trap
cleanup() {
  if [ -n "$tardi_pid" ]; then
    kill "$tardi_pid" >/dev/null 2>&1 || :
    wait "$tardi_pid" 2>/dev/null || :
  fi
  if [ -n "$upstream_pid" ]; then
    kill "$upstream_pid" >/dev/null 2>&1 || :
    wait "$upstream_pid" 2>/dev/null || :
  fi
}
trap cleanup EXIT INT TERM

say ""
say "==> starting disposable upstream on 127.0.0.1:$UPSTREAM_PORT"
python3 "$repo/tests/security/fixtures/f06_upstream.py" --port "$UPSTREAM_PORT" >"$upstream_log" 2>&1 &
upstream_pid=$!

for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$UPSTREAM_PORT/hits" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

tardi_health() {
  curl -sf -H "Host: localhost" "http://127.0.0.1:$TARDI_PORT/health" >/dev/null 2>&1
}

say "==> starting tardi on 127.0.0.1:$TARDI_PORT with synthetic auth config"
TARDIGRADE_CONFIG_PATH="$repo/tests/security/fixtures/f06_tardigrade.conf" \
TARDIGRADE_LISTEN_PORT="$TARDI_PORT" \
TARDIGRADE_UPSTREAM_BASE_URL="http://127.0.0.1:$UPSTREAM_PORT" \
TARDIGRADE_AUTH_TOKEN_HASHES="$token_hash" \
TARDIGRADE_JWT_SECRET="$JWT_SECRET" \
TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY=true \
TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES=10.99.99.99 \
  "$tardi_bin" >"$tardi_log" 2>&1 &
tardi_pid=$!

for _ in $(seq 1 50); do
  if tardi_health; then
    break
  fi
  sleep 0.1
done

if ! tardi_health; then
  say "tardi did not become healthy; log follows:"
  cat "$tardi_log" || true
  exit 3
fi

say ""
say "==> running live F-06 probe engine"
set +e
python3 "$repo/tests/security/f06_live_campaign.py" \
  --tardi-port "$TARDI_PORT" \
  --upstream-port "$UPSTREAM_PORT" \
  --evidence-json "$evidence_json"
campaign_status=$?
set -e

say ""
say "evidence: $evidence_dir"
say "  metadata: $metadata"
say "  results:  $evidence_json"
say "  tardi log: $tardi_log"
say "  upstream log: $upstream_log"

exit "$campaign_status"
