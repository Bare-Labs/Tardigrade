# Bare Systems Homebrew Tap

Homebrew formulas for Bare Systems projects.

## Tardigrade

Tardigrade Homebrew publication is not generally supported yet. Do not publish
generic install instructions until the formula points at a release that passes
the native release-backed Homebrew smoke. The current public `v0.5.0` release
predates the native shipping cutover and must not be used as the tap formula
source; macOS Homebrew also remains unsupported until real Darwin archives are
published.

Expected shape after that release:

```bash
brew tap Bare-Systems/tap
brew install tardigrade

tardi version
```

The canonical formula source lives in the Tardigrade repository at
`packaging/homebrew/tardigrade.rb` and is copied here by
`scripts/update-homebrew-formula.sh`. Formula URLs and SHA-256 values are
generated from one release's `tardigrade-checksums.txt` manifest.
