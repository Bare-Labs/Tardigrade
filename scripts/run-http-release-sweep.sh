#!/bin/bash
# Repeatable HTTP/2 + HTTP/3 release-artifact sweep for #677.
#
# By default this targets the first `tardi` on PATH. Set TARDI_BIN to exercise
# an installed release candidate, Homebrew package, or a local ReleaseFast
# binary without silently substituting the source-tree debug executable.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

say() { printf '%s\n' "$*"; }

enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

run_step() {
  name="$1"
  shift
  say ""
  say "==> $name"
  "$@"
}

if [ -n "${TARDI_BIN:-}" ]; then
  tardi_bin="$TARDI_BIN"
else
  tardi_bin="$(command -v tardi || true)"
fi

if [ -z "$tardi_bin" ] || [ ! -x "$tardi_bin" ]; then
  say "TARDI_BIN must point to an executable tardi artifact, or tardi must be on PATH."
  exit 2
fi

if command -v realpath >/dev/null 2>&1; then
  tardi_bin="$(realpath "$tardi_bin")"
fi

evidence_dir="${HTTP_SWEEP_EVIDENCE_DIR:-$repo/.zig-cache/http-release-sweep-677}"
mkdir -p "$evidence_dir"
metadata="$evidence_dir/metadata.txt"

{
  printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'repo=%s\n' "$repo"
  printf 'git_sha=%s\n' "$(cd "$repo" && git rev-parse HEAD)"
  printf 'git_branch=%s\n' "$(cd "$repo" && git rev-parse --abbrev-ref HEAD)"
  printf 'tardi_bin=%s\n' "$tardi_bin"
  printf 'tardi_version='
  "$tardi_bin" version 2>&1 || true
  if command -v shasum >/dev/null 2>&1; then
    printf 'tardi_sha256='
    shasum -a 256 "$tardi_bin" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    printf 'tardi_sha256='
    sha256sum "$tardi_bin" | awk '{print $1}'
  else
    printf 'tardi_sha256=unavailable: no shasum or sha256sum\n'
  fi
  printf 'file='
  file "$tardi_bin" 2>&1 || true
  printf 'uname='
  uname -a
  printf 'zig='
  zig version 2>&1 || true
  printf 'curl='
  curl --version 2>&1 | head -n 1 || true
  printf 'nghttp='
  nghttp --version 2>&1 || true
  printf 'h2load='
  h2load --version 2>&1 || true
  printf 'openssl='
  openssl version 2>&1 || true
  printf 'gnutls-cli='
  gnutls-cli --version 2>&1 | head -n 1 || true
  if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ]; then
    printf 'ngtcp2_examples_dir=%s\n' "$NGTCP2_EXAMPLES_DIR"
    [ -x "$NGTCP2_EXAMPLES_DIR/gtlsclient" ] && "$NGTCP2_EXAMPLES_DIR/gtlsclient" --version 2>&1 | sed 's/^/gtlsclient=/' || true
    [ -x "$NGTCP2_EXAMPLES_DIR/gtlsserver" ] && "$NGTCP2_EXAMPLES_DIR/gtlsserver" --version 2>&1 | sed 's/^/gtlsserver=/' || true
  fi
  [ -n "${QUICHE_EXAMPLES_DIR:-}" ] && printf 'quiche_examples_dir=%s\n' "$QUICHE_EXAMPLES_DIR"
  [ -n "${AIOQUIC_PYTHON:-}" ] && printf 'aioquic_python=%s\n' "$AIOQUIC_PYTHON"
} >"$metadata"

say "metadata: $metadata"
cat "$metadata"

cd "$repo" || exit 1

run_step "format check" \
  zig fmt --check build.zig src/ tests/

run_step "HTTP/2 malformed/proxy/flow-control integration rows" \
  zig build test-integration -Dtardigrade-bin-path="$tardi_bin" \
    -Dintegration-test-filter='interop.h2.' --summary all --error-style verbose

run_step "native TLS/H2 listener rows" \
  zig build test-integration-native-tls -Dtardigrade-bin-path="$tardi_bin" \
    --summary all --error-style verbose

run_step "HTTP/3 deterministic QUIC/H3 rows and PR-safe resource soaks" \
  zig build test-quic --summary all --error-style verbose

if enabled "${HTTP_SWEEP_FULL_GATES:-}"; then
  run_step "full unit gate" \
    zig build test --summary all --error-style verbose

  run_step "full integration gate with selected artifact" \
    zig build test-integration -Dtardigrade-bin-path="$tardi_bin" \
      --summary all --error-style verbose
fi

run_step "native HTTP/3 interop tool build" \
  zig build build-h3-interop --summary all --error-style verbose

if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ] || [ -n "${QUICHE_EXAMPLES_DIR:-}" ] || [ -n "${AIOQUIC_PYTHON:-}" ]; then
  run_step "external HTTP/3 peer matrix" \
    scripts/interop/run-interop.sh
else
  say ""
  say "==> external HTTP/3 peer matrix"
  say "SKIP: set NGTCP2_EXAMPLES_DIR, QUICHE_EXAMPLES_DIR, or AIOQUIC_PYTHON to run external peers."
fi

say ""
say "release sweep completed"
