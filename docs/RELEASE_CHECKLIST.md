# Release Checklist

Use this checklist before tagging and distributing a Tardigrade release.

## Build and Validation

- [ ] `zig fmt --check build.zig src/ tests/`
- [ ] `zig build test --summary all --error-style verbose`
- [ ] `zig build test-integration`
- [ ] For any HTTP/3 support-status change, complete the closeout evidence
      contract in [HTTP3_VALIDATION_EVIDENCE.md](HTTP3_VALIDATION_EVIDENCE.md)

## Performance

- [ ] Capture the release baseline JSON with `./benchmarks/release-baseline.sh` on a stable, dedicated benchmark target, including the default `64 KiB` and `256 KiB` payload scenarios
- [ ] For HTTP/3 release evidence, run the existing H3 matrix on a dedicated
      host with a genuinely QUIC-capable client and retain the client
      capability proof, scenario-local QUIC deltas, soak results, and interop
      rerun summary
- [ ] Compare against the previous saved baseline JSON
- [ ] Generate the markdown report for the new baseline
- [ ] Refresh the README benchmark report block from the saved baseline data
- [ ] If a dedicated target was unavailable and a local fallback run was used, record that exception explicitly and do not treat it as the canonical release number
- [ ] Record any known benchmark caveats in the release notes

## Artifacts

- [ ] Confirm `scripts/release-metadata.sh` resolves the intended tag/version
- [ ] Update `docs/SUPPORT_MATRIX.md` when public behavior or maturity claims changed
- [ ] Run `./scripts/test-install.sh` against a ReleaseFast native build (`-Dtls-profile=native`)
- [ ] Render the Homebrew formula from this release tag with
      `./scripts/update-homebrew-formula.sh --tag <tag>`,
      run `ruby -c packaging/homebrew/tardigrade.rb`, and run
      `./scripts/test-homebrew-release-formula.sh` plus
      `./scripts/test-homebrew-formula.sh` on each Homebrew environment the
      release honestly supports
- [ ] Run `./scripts/test-deb-package.sh` on a Linux host with Docker
- [ ] Run `./scripts/test-rpm-package.sh` on a Linux host with Docker
- [ ] Verify release packaging paths and checksums, including the Linux
      (`tardigrade-linux-x86_64.tar.gz`, `tardigrade-linux-aarch64.tar.gz`) and
      Darwin (`tardigrade-darwin-x86_64.tar.gz`,
      `tardigrade-darwin-arm64.tar.gz`) archives plus published `.deb`/`.rpm`
      assets
- [ ] Verify every published archive's `dependency-inventory-*.json` reports
      `profile=native`, `reported_backend=native`, `links_openssl=false`, and
      no forbidden foreign TLS/crypto/QUIC/H3 dependency
- [ ] Verify published DEB/RPM metadata does not declare OpenSSL/libssl/libcrypto
      as a Tardigrade runtime dependency
- [ ] Copy the rendered Homebrew formula into `Bare-Systems/homebrew-tap` with
      `--tap-dir`, review the tap diff, and publish it only after the
      referenced release assets are visible and the install smoke passes.
      `homebrew-tap/README.md` is tap-owned; update it only when public
      support policy or install instructions change.
- [ ] Verify both Darwin archives have matching SPDX SBOMs and
      `dependency-inventory-*.json` artifacts, and verify archive provenance
      with `gh attestation verify <archive> --repo Bare-Systems/Tardigrade`
- [ ] On the first release containing #463, exercise `scripts/install.sh`
      against the published release on Intel and Apple Silicon macOS **without
      installing Homebrew OpenSSL for Tardigrade**, then verify `tardi version`,
      the `tardigrade -> tardi` compatibility alias, and a minimal real
      startup/request path from the installed artifact
- [ ] Close #463 only after the first published Darwin assets, checksums,
      inventories, SBOMs, attestations, native-only linkage, installer path,
      alias, and runtime smoke all verify on both macOS architectures
- [ ] Note any Homebrew platform limitation in the release notes; do not
      advertise macOS Homebrew until the published release includes Darwin
      archives and the tap formula references their real checksums
- [ ] Confirm changelog entries for operator-visible changes are complete

## Branch Hygiene

- [ ] After each PR merges (squash merge is standard for this repo), delete its head branch. Prefer enabling "Automatically delete head branches" in repo settings so this happens without a manual step.
- [ ] Periodically (at least once per release cycle), diff open remote branches against merged PRs and closed issues; delete or archive any branch whose work already landed on `main` or was abandoned in favor of a different branch.
- [ ] Never delete a branch backing an open PR, or the branch currently checked out for active work.
