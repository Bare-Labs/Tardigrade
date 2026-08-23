# Preparatory Homebrew formula source for Tardigrade.
#
# Do not copy this file into Bare-Systems/homebrew-tap yet. The currently
# published latest release, v0.5.0, predates the native #634 shipping cutover
# and uses the old release archive layout. Generate the real formula with
# scripts/update-homebrew-formula.sh only after a release publishes native
# audited archives with canonical tardi plus the tardigrade compatibility alias.

class Tardigrade < Formula
  desc "Small Zig edge server for static file serving, reverse proxying, and TLS termination"
  homepage "https://github.com/Bare-Systems/Tardigrade"
  license "Apache-2.0"

  def install
    odie "No release-backed native Tardigrade Homebrew formula has been published yet"
  end
end
