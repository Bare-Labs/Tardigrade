#!/usr/bin/env bash
set -euo pipefail

NGHTTP3_REF="${NGHTTP3_REF:-v1.18.0}"
NGTCP2_REF="${NGTCP2_REF:-v1.25.0}"
ROOT="${NGTCP2_INTEROP_WORKDIR:-${RUNNER_TEMP:-/tmp}/tardigrade-ngtcp2-interop}"
PREFIX="${NGTCP2_INTEROP_PREFIX:-$ROOT/prefix}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')}"

mkdir -p "$ROOT" "$PREFIX"

if [ ! -d "$ROOT/nghttp3/.git" ]; then
  git clone --depth 1 --branch "$NGHTTP3_REF" https://github.com/ngtcp2/nghttp3.git "$ROOT/nghttp3"
fi

cmake -S "$ROOT/nghttp3" -B "$ROOT/nghttp3/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DENABLE_LIB_ONLY=ON
cmake --build "$ROOT/nghttp3/build" --parallel "$JOBS"
cmake --install "$ROOT/nghttp3/build"

if [ ! -d "$ROOT/ngtcp2/.git" ]; then
  git clone --depth 1 --branch "$NGTCP2_REF" https://github.com/ngtcp2/ngtcp2.git "$ROOT/ngtcp2"
fi

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CMAKE_PREFIX_PATH="$PREFIX:${CMAKE_PREFIX_PATH:-}"
if command -v gcc-14 >/dev/null 2>&1 && command -v g++-14 >/dev/null 2>&1; then
  export CC="${CC:-gcc-14}"
  export CXX="${CXX:-g++-14}"
fi

cmake -S "$ROOT/ngtcp2" -B "$ROOT/ngtcp2/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
  -DENABLE_GNUTLS=ON \
  -DENABLE_OPENSSL=OFF
cmake --build "$ROOT/ngtcp2/build" --parallel "$JOBS"

GTLSCLIENT_PATH="$ROOT/ngtcp2/build/examples/gtlsclient"
test -x "$GTLSCLIENT_PATH"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'gtlsclient_path=%s\n' "$GTLSCLIENT_PATH" >> "$GITHUB_OUTPUT"
else
  printf '%s\n' "$GTLSCLIENT_PATH"
fi
