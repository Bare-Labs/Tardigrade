# Tardigrade Homebrew Formula

This directory contains the preparatory Homebrew formula source and renderer.
Do not copy `packaging/homebrew/tardigrade.rb` into `Bare-Systems/homebrew-tap`
until a release exists that satisfies the native #634 shipping contract and the
current archive layout.

Release publication flow:

1. Publish native Tardigrade release archives and `tardigrade-checksums.txt`.
2. Render the formula from that release tag:

   ```bash
   ./scripts/update-homebrew-formula.sh --tag vX.Y.Z
   ```

3. Validate the rendered formula:

   ```bash
   ruby -c packaging/homebrew/tardigrade.rb
   ./scripts/test-homebrew-release-formula.sh
   ./scripts/test-homebrew-formula.sh
   ```

4. Copy the formula and tap README into a checkout of
   `Bare-Systems/homebrew-tap`:

   ```bash
   ./scripts/update-homebrew-formula.sh \
     --tag vX.Y.Z \
     --tap-dir ../homebrew-tap
   ```

The renderer only emits platform/architecture branches whose archive names are
present in the release's checksum manifest and asset list. The current public
`v0.5.0` release predates the native cutover and must not be rendered into the
tap formula. Darwin branches must wait for a release manifest containing
`tardigrade-darwin-x86_64.tar.gz` and `tardigrade-darwin-arm64.tar.gz`.

The formula installs `tardi` and the packaged `tardigrade` compatibility alias.
It intentionally declares no `openssl@3` dependency; native release artifacts
are audited separately by `scripts/audit-release-binary.sh`.
