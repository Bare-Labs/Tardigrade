#!/usr/bin/env bash
# Installs the canonical external H3/QUIC interop peer's build dependencies
# on a Debian/Ubuntu CI runner (#522). Paired with build-h3-peer-ci.sh; see
# README.md's "#522: production resumption/0-RTT interop" and "Building the
# peers" sections for what this peer is and why it's built here. Kept under
# scripts/interop/, the audited external-peer boundary
# (scripts/audit-dependencies.sh) -- the actual peer package/library names
# are only safe to write inside this directory.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y cmake libev-dev pkg-config wget gnupg lsb-release software-properties-common

# The peer's example client is C++23 and needs a newer compiler than
# Ubuntu's default repos carry at this pin; install a specific LLVM release
# from the official apt.llvm.org script instead of depending on whatever
# happens to be preinstalled on the runner image.
if ! command -v clang++-19 >/dev/null 2>&1; then
  wget -qO /tmp/llvm-install.sh https://apt.llvm.org/llvm.sh
  chmod +x /tmp/llvm-install.sh
  sudo /tmp/llvm-install.sh 19
fi

# clang links against the system libstdc++ by default (not libc++), and
# Ubuntu 24.04's default libstdc++ (gcc-13-based) predates <print> --
# confirmed directly: clang-19 alone fails `#include <print>` with "file not
# found" on this image, only succeeding once these newer standard-library
# headers are present too.
sudo apt-get install -y libstdc++-14-dev

sudo apt-get install -y libgnutls28-dev gnutls-bin
