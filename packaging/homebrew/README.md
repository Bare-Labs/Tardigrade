# Tardigrade Homebrew Formula

This directory contains the Homebrew formula source and renderer.
Tardigrade owns formula generation; `Bare-Systems/homebrew-tap` owns the public
tap documentation.

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
   zig build -Doptimize=ReleaseFast -Dversion=0.0.0-homebrew-smoke
   ./scripts/test-homebrew-formula.sh
   ```

4. Synchronize the generated formula into a checkout of
   `Bare-Systems/homebrew-tap`:

   ```bash
   ./scripts/update-homebrew-formula.sh \
     --tag vX.Y.Z \
     --tap-dir ../homebrew-tap
   ```

   `--tap-dir` updates only `Formula/tardigrade.rb`. It does not rewrite the
   tap-owned `README.md`; tap documentation should change only when public
   support policy or install instructions change.

The renderer only emits platform/architecture branches whose archive names are
present in the release's checksum manifest and asset list — a release missing
`tardigrade-darwin-x86_64.tar.gz`/`tardigrade-darwin-arm64.tar.gz` simply omits
the `on_macos` branch rather than failing.

The formula installs `tardi` and the packaged `tardigrade` compatibility alias.
It intentionally declares no `openssl@3` dependency; native release artifacts
are audited separately by `scripts/audit-release-binary.sh`.
