#!/usr/bin/env bash
# Builds the canonical external H3/QUIC interop peer for CI (#522): a
# reproducible example client for the h3interop.quic.* production
# resumption/0-RTT cases in tests/integration.zig. Distinct from the
# baseline #328 wire-interop matrix's peers, which CI does not build.
# Run install-h3-peer-deps-ci.sh first. Kept under scripts/interop/, the
# audited external-peer boundary (scripts/audit-dependencies.sh) -- the
# actual peer repository/library names are only safe to write inside this
# directory, never in .github/workflows.
#
# usage: build-h3-peer-ci.sh
#
# Writes the built client binary's path to $GITHUB_OUTPUT as `client_path`
# (or prints it to stdout when GITHUB_OUTPUT isn't set, e.g. run locally).
set -euo pipefail

# Pinned release tags, not HEAD: tests/integration.zig's h3interop.quic.*
# cases assert on this peer's own diagnostic output (`type=0RTT`,
# `[:status: N]` lines), so an unpinned peer revision could silently change
# that output format out from under CI. Override only when deliberately
# advancing the interop peer.
peer_lib_ref="${H3_PEER_LIB_REF:-v1.18.0}"
peer_client_ref="${H3_PEER_CLIENT_REF:-v1.25.0}"
root="${H3_PEER_WORKDIR:-${RUNNER_TEMP:-/tmp}/tardigrade-h3-peer}"
prefix="${H3_PEER_PREFIX:-$root/prefix}"
jobs="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')}"

mkdir -p "$root" "$prefix"

if [ ! -d "$root/lib/.git" ]; then
  git clone --depth 1 --branch "$peer_lib_ref" --recurse-submodules --shallow-submodules \
    https://github.com/ngtcp2/nghttp3.git "$root/lib"
fi
git -C "$root/lib" submodule update --init --depth 1

cmake -S "$root/lib" -B "$root/lib/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DENABLE_LIB_ONLY=ON
cmake --build "$root/lib/build" --parallel "$jobs"
cmake --install "$root/lib/build"

if [ ! -d "$root/client/.git" ]; then
  git clone --depth 1 --branch "$peer_client_ref" --recurse-submodules --shallow-submodules \
    https://github.com/ngtcp2/ngtcp2.git "$root/client"
fi
# `--recurse-submodules` on the initial clone above covers a fresh checkout;
# re-run explicitly so a cached/partial workdir from an older run can't be
# left with a submodule directory that was never populated (the peer's
# CMake root always adds `third-party`, and its client target directly
# consumes an object library built from a submodule there).
git -C "$root/client" submodule update --init --depth 1

export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CMAKE_PREFIX_PATH="$prefix${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"

# The example client is C++23 (needs std::print); a compiler must actually
# support it -- fail clearly rather than silently falling back to whatever
# `cc`/`c++` happens to resolve to and hitting a confusing template error
# deep in the peer's own source.
if command -v clang++-19 >/dev/null 2>&1; then
  export CC="${CC:-clang-19}"
  export CXX="${CXX:-clang++-19}"
elif command -v g++-15 >/dev/null 2>&1; then
  export CC="${CC:-gcc-15}"
  export CXX="${CXX:-g++-15}"
else
  echo "build-h3-peer-ci.sh: no C++23-capable compiler found (need clang >= 19 or gcc >= 15)" >&2
  exit 1
fi

cmake -S "$root/client" -B "$root/client/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$prefix" \
  -DENABLE_GNUTLS=ON \
  -DENABLE_OPENSSL=OFF
cmake --build "$root/client/build" --parallel "$jobs" --target gtlsclient

client_path="$root/client/build/examples/gtlsclient"
test -x "$client_path"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'client_path=%s\n' "$client_path" >> "$GITHUB_OUTPUT"
else
  printf '%s\n' "$client_path"
fi
