#!/usr/bin/env bash
# Builds a QUIC-capable h2load for macOS, for cross-machine H3 benchmarking
# (benchmarks/run-cross-machine-competitive.sh --with-h3) from the load-driver
# side (this machine), not the server side.
#
# Homebrew's `h2load` (from the `nghttp2` formula) accepts `--h3` syntactically
# but silently falls back to a plain TCP+TLS attempt with ALPN="h3" (which no
# real server will ever negotiate) -- it was built without QUIC support. This
# mirrors ensure_quic_h2load() in scripts/run-proxmox-performance-campaign.sh
# (the Linux/guest-side equivalent), pinned to the same nghttp2/nghttp3/ngtcp2
# refs, but with the extra dependencies and flags macOS's build actually needs
# (libev/libevent/jansson via Homebrew have no pkg-config-visible install by
# default; nghttp2's --without-libsystemd flag doesn't exist -- the real one
# is --without-systemd; GNU libtool must come from Homebrew's `libtool`
# formula's gnubin, not Apple's own /usr/bin/libtool, which is a different
# tool with the same name).
#
# Installs to ~/.tardigrade-h2load (no sudo required). Put
# ~/.tardigrade-h2load/bin first on PATH before running the cross-machine
# script with --with-h3.
#
# Usage: benchmarks/build-macos-quic-h2load.sh [install_prefix]

set -euo pipefail

PREFIX="${1:-$HOME/.tardigrade-h2load}"
NGHTTP2_REF="${H2LOAD_NGHTTP2_REF:-v1.69.0}"
NGHTTP3_REF="${H2LOAD_NGHTTP3_REF:-v1.18.0}"
NGTCP2_REF="${H2LOAD_NGTCP2_REF:-v1.25.0}"
SRC="$(mktemp -d /tmp/tardigrade-h2load-build-XXXXXX)"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

for pkg in automake libtool openssl@3 libevent jansson libev pkg-config; do
    brew list --versions "$pkg" >/dev/null 2>&1 || brew install "$pkg"
done

export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:$PATH"
mkdir -p "$PREFIX"

echo "==> building nghttp3 ($NGHTTP3_REF)"
git clone --depth 1 --branch "$NGHTTP3_REF" https://github.com/ngtcp2/nghttp3.git "$SRC/nghttp3"
(
    cd "$SRC/nghttp3"
    git submodule update --init --depth 1
    autoreconf -i
    ./configure --prefix="$PREFIX" --enable-lib-only
    make -j"$JOBS"
    make install
)

echo "==> building ngtcp2 ($NGTCP2_REF)"
git clone --depth 1 --branch "$NGTCP2_REF" https://github.com/ngtcp2/ngtcp2.git "$SRC/ngtcp2"
(
    cd "$SRC/ngtcp2"
    git submodule update --init --depth 1
    autoreconf -i
    PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:$PREFIX/lib/pkgconfig" \
        ./configure --prefix="$PREFIX" --enable-lib-only --with-openssl
    make -j"$JOBS"
    make install
)

echo "==> building nghttp2 ($NGHTTP2_REF, --enable-http3)"
git clone --depth 1 --branch "$NGHTTP2_REF" https://github.com/nghttp2/nghttp2.git "$SRC/nghttp2"
(
    cd "$SRC/nghttp2"
    git submodule update --init --depth 1
    autoreconf -i
    PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/libevent/lib/pkgconfig:/opt/homebrew/opt/jansson/lib/pkgconfig:$PREFIX/lib/pkgconfig" \
        CPPFLAGS="-I/opt/homebrew/opt/libev/include" \
        LDFLAGS="-L/opt/homebrew/opt/libev/lib -Wl,-rpath,$PREFIX/lib" \
        ./configure --prefix="$PREFIX" --enable-app --enable-http3 \
            --without-libxml2 --without-jemalloc --without-systemd --without-mruby
    make -j"$JOBS"
    make install
)

rm -rf "$SRC"

echo ""
echo "==> built: $PREFIX/bin/h2load"
"$PREFIX/bin/h2load" --version
echo ""
echo "Put this first on PATH before running the cross-machine script with --with-h3:"
echo "  export PATH=\"$PREFIX/bin:\$PATH\""
