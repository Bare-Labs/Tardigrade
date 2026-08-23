# Tardigrade Homebrew Formula

This directory is the canonical source for the public
`Bare-Systems/homebrew-tap` formula. Do not maintain a second independent
formula in the tap repository.

Release publication flow:

1. Publish Tardigrade release archives and `tardigrade-checksums.txt`.
2. Render the formula from that release manifest:

   ```bash
   ./scripts/update-homebrew-formula.sh \
     --version 0.5.0 \
     --checksums-url https://github.com/Bare-Systems/Tardigrade/releases/download/v0.5.0/tardigrade-checksums.txt
   ```

3. Validate the rendered formula:

   ```bash
   ruby -c packaging/homebrew/tardigrade.rb
   ./scripts/test-homebrew-formula.sh
   ```

4. Copy the formula and tap README into a checkout of
   `Bare-Systems/homebrew-tap`:

   ```bash
   ./scripts/update-homebrew-formula.sh \
     --version 0.5.0 \
     --checksums-url https://github.com/Bare-Systems/Tardigrade/releases/download/v0.5.0/tardigrade-checksums.txt \
     --tap-dir ../homebrew-tap
   ```

The renderer only emits platform/architecture branches whose archive names are
present in the checksum manifest. The current public `v0.5.0` release has Linux
archives only, so the generated formula is Linux-only. Darwin branches must wait
for a release manifest containing `tardigrade-darwin-x86_64.tar.gz` and
`tardigrade-darwin-arm64.tar.gz`.

The formula installs `tardi` and the packaged `tardigrade` compatibility alias.
It intentionally declares no `openssl@3` dependency; native release artifacts
are audited separately by `scripts/audit-release-binary.sh`.
