# Tardigrade Packaging

Native packaging artifacts for Tardigrade. See the [main README](../README.md#install)
for the quick-start install path; this document covers every packaging
format in detail, including what is actually built and published today
versus what is a local-build-only tool.

## Current status

| Format | Status | Notes |
| --- | --- | --- |
| Linux release archives (`.tar.gz`, x86_64/aarch64) | **Supported, published** | Built and attached to every GitHub release by `.github/workflows/release.yml`, alongside `install.sh`, `tardigrade-checksums.txt`, per-arch SPDX SBOMs, dependency inventories, and provenance. Releases containing #476 build these official artifacts with the default `-Dtls-profile=general` (pure-Zig native since #649); older already-published releases may predate that cutover. |
| macOS release archives (`.tar.gz`, darwin x86_64/arm64) | **Implemented in #476; awaiting first release** | #476 adds `macos-15-intel` and `macos-15` release rows for `tardigrade-darwin-x86_64.tar.gz` and `tardigrade-darwin-arm64.tar.gz`, using the same archive/SBOM/inventory/provenance pipeline as Linux. Both rows build with the default `-Dtls-profile=general` (pure-Zig native since #649) without Homebrew OpenSSL, audit out foreign TLS/crypto/QUIC/H3 linkage, assert the Mach-O architecture, package/extract the archive, verify native build identity, run a real static-site startup/request smoke from the extracted artifact, and exercise the checksum-verifying installer path. The currently published latest release still predates #476, so these assets are not public until the first intentional release containing it. |
| DEB (`packaging/deb/build.sh`) | **Supported, published** | Built for `amd64`/`arm64` from the same release binaries as the `.tar.gz` archives and attached to every GitHub release; also usable as a local builder. Host-native builds infer dependency metadata from `tardi version`; cross-compiled binaries can declare `--tls-backend native|openssl-adapter` explicitly. Native binaries declare no OpenSSL runtime dependency, while a transitional local `general`/OpenSSL binary still gets the dependency it actually needs. |
| RPM (`packaging/rpm/build.sh`) | **Supported, published** | Same treatment as DEB, for `x86_64`/`aarch64`. Host-native builds infer the backend and cross-compiled builds can pass it explicitly. The spec's OpenSSL runtime dependency is conditional on the packaged binary/backend; official native release packages do not declare it. Built from the same Ubuntu-runner binary as the archives — see the glibc compatibility note below if targeting an older RHEL-family release. |
| systemd unit (`packaging/systemd/tardigrade.service`) | **Supported** | Installed and structurally validated (unit file text/layout, permissions) by both the DEB and RPM smoke tests. Neither test boots systemd or exercises a real start/status/reload/stop lifecycle — see [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md#the-systemd-units-pidcontrol-path-contract) for the unit contract these assertions check. |
| launchd plist (`packaging/launchd/io.baresystems.tardigrade.plist`) | **CI-validated user LaunchAgent template** | The Darwin release-smoke workflow renders the checked-in host-style `/usr/local/...` template into an isolated prefix on the `macos-15` Apple Silicon runner, stages the native Darwin archive's `tardi` binary plus `tardigrade -> tardi` compatibility alias, and proves a real `launchctl bootstrap` -> readiness/request -> `bootout` lifecycle in the current user's launchd domain. |
| Homebrew (`packaging/homebrew/tardigrade.rb`) | **Preparatory; awaiting native release** | `scripts/update-homebrew-formula.sh` renders the formula from one release tag and verifies the referenced archives exist in that same release. The current public `v0.5.0` release predates the native #634 shipping cutover and old/new archive-layout switch, so it must not be used for the public tap formula. Generate and publish the tap formula only after a release publishes native audited archives with canonical `tardi` plus the `tardigrade` alias. |
| Docker / OCI image | **Local build supported, not published** | Root [`Dockerfile`](../Dockerfile) and [`compose.yaml`](../compose.yaml) build a runtime image locally; smoke-tested via `scripts/test-docker-image.sh` in the `packaging-smoke` CI job. No registry-published image or container-publishing workflow exists. Docker's remaining OpenSSL cutover is tracked by #634 and is separate from the raw release/archive lane in #476. See [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the full workflow. |

## Official release implementation

Releases containing #476 explicitly build the general-purpose native Zig
shipping profile:

```bash
zig build -Doptimize=ReleaseFast -Dversion=<version>
```

The release workflow audits each produced binary with
`scripts/audit-release-binary.sh --profile native`. That audit fails if the
artifact links `libssl`, `libcrypto`, or another forbidden foreign
TLS/crypto/QUIC/H3 implementation and verifies that `tardi version` reports
`tls-profile=native, tls-backend=native`.

Linux DEB/RPM packages are built from that same audited host-native binary. The
package builders infer its backend from `tardi version`, and the release job then
inspects the resulting package metadata and fails if either native package
declares an OpenSSL/libssl/libcrypto runtime dependency. Local cross-compiled
packages can provide `--tls-backend native|openssl-adapter` explicitly when the
target binary cannot execute on the packaging host.

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

The currently published latest release resolves only for Linux
(`x86_64`/`aarch64`). After the first release containing #476, the same script
will also resolve native Intel and Apple Silicon macOS archives. Those new
Darwin artifacts do **not** require Homebrew OpenSSL for Tardigrade itself. The
release checklist requires verifying the first published Darwin assets on both
architectures before #463 closes.

### macOS Gatekeeper / unsigned binary note

The initial Darwin archives are unsigned and not notarized. Command-line
installation from GitHub Releases is supported once the first #476 release is
published, but a browser-downloaded archive may carry Apple's quarantine
attribute and trigger Gatekeeper. Signing/notarization is a separate future
distribution concern; do not describe these archives as notarized.

If an operator intentionally downloaded the official archive and Gatekeeper
blocks the extracted binary because of quarantine, inspect the attribute first
and remove it only from that trusted extracted binary when appropriate:

```bash
xattr -l ./tardi
xattr -d com.apple.quarantine ./tardi
```

Do not apply recursive quarantine removal to unrelated files.

## DEB (Debian / Ubuntu)

### Install from a release (recommended)

Every GitHub release publishes `tardigrade_<version>_amd64.deb` and
`tardigrade_<version>_arm64.deb` alongside the `.tar.gz` archives and
`tardigrade-checksums.txt`:

```bash
version=0.5.0   # match the release tag, without the leading "v"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade_${version}_amd64.deb"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-checksums.txt"
sha256sum --ignore-missing -c tardigrade-checksums.txt

sudo apt install ./tardigrade_${version}_amd64.deb
sudo systemctl enable --now tardigrade
```

Use `tardigrade_<version>_arm64.deb` on `arm64`/`aarch64` hosts.

### Build locally

Building your own `.deb` from a pre-built binary is still supported — useful
for architectures the release workflow doesn't cover, or a custom build. Use
the native profile for a shipping-equivalent package:

```bash
# 1. Build the binary first (cross-compile for the target arch as needed)
zig build -Doptimize=ReleaseFast

# 2. Build the DEB. Passing the backend explicitly also works when the target
#    binary is for a different architecture than the packaging host.
./packaging/deb/build.sh \
  --version 0.50 \
  --arch amd64 \
  --tls-backend native

# Output: dist/tardigrade_0.50_amd64.deb
```

Install:
```bash
sudo apt install ./dist/tardigrade_0.50_amd64.deb
sudo systemctl enable --now tardigrade
```

When `--tls-backend` is omitted, the DEB builder infers it from an executable
host-native binary's `tardi version` output. Native binaries have no OpenSSL
package dependency; a transitional local binary reporting
`tls-backend=openssl-adapter` gets `Depends: libssl3 | libssl1.1`. Unknown
backends fail rather than generating ambiguous dependency metadata. For a
foreign-architecture binary, pass `--tls-backend native` or
`--tls-backend openssl-adapter` explicitly.

The DEB package:
- Installs the binary to `/usr/bin/tardi`
- Installs a starter config at `/etc/tardigrade/tardigrade.conf`
- Creates a `tardigrade` system user
- Installs a systemd service unit at `/lib/systemd/system/tardigrade.service`
- Installs an env config template at `/etc/tardigrade/tardigrade.env` (mode 0640, owned by `root:tardigrade`)
- Installs a logrotate config at `/etc/logrotate.d/tardigrade`
- Creates `/var/lib/tardigrade` for the service working directory

## RPM (RHEL / Fedora / AlmaLinux)

### Install from a release (recommended)

Every GitHub release publishes `tardigrade-<version>-1.x86_64.rpm` and
`tardigrade-<version>-1.aarch64.rpm` alongside the `.tar.gz` archives and
`tardigrade-checksums.txt`:

```bash
version=0.5.0   # match the release tag, without the leading "v"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-${version}-1.x86_64.rpm"
curl -fsSLO "https://github.com/Bare-Systems/Tardigrade/releases/download/v${version}/tardigrade-checksums.txt"
sha256sum --ignore-missing -c tardigrade-checksums.txt

sudo dnf install ./tardigrade-${version}-1.x86_64.rpm
sudo systemctl enable --now tardigrade
```

Use `tardigrade-<version>-1.aarch64.rpm` on `aarch64` hosts. `rpm -i` works
identically to `dnf install` for a local file.

> **glibc compatibility note**: the published `.rpm` is built from the same
> binary as the Linux `.tar.gz` archives, compiled on the `ubuntu-latest` /
> `ubuntu-24.04-arm` GitHub-hosted runners. It links dynamically against that
> runner's glibc. This is fine for current Fedora and RHEL 10+ family
> distros; it may be *too new* for RHEL 9 / Rocky 9 / AlmaLinux 9 (glibc
> 2.34), which would need a binary built on a matching older glibc. If that
> matters for your target, build locally instead (below) on a host with a
> compatible glibc.

### Build locally

```bash
# 1. Install prerequisites
dnf install rpm-build

# 2. Build the binary
zig build -Doptimize=ReleaseFast

# 3. Build the RPM. Passing the backend explicitly also works for a
#    foreign-architecture binary.
./packaging/rpm/build.sh \
  --version 0.50 \
  --tls-backend native

# Output: dist/tardigrade-0.50-1.x86_64.rpm
```

Install:
```bash
sudo rpm -i dist/tardigrade-0.50-1.x86_64.rpm
sudo systemctl enable --now tardigrade
```

Like the DEB builder, the RPM builder auto-detects the backend for executable
host-native binaries and accepts an explicit backend for cross-compiled input.
Native binaries omit `Requires: openssl-libs`; a local transitional
OpenSSL-adapter binary retains it, and an unknown backend fails packaging.

Like the DEB package, the RPM installs a starter
`/etc/tardigrade/tardigrade.conf`, creates `/var/lib/tardigrade` (the
systemd unit's `WorkingDirectory`), creates a `tardigrade`-owned
`/var/log/tardigrade`, and installs the same SIGUSR1-reopen logrotate
policy at `/etc/logrotate.d/tardigrade`, so `systemctl enable --now
tardigrade` works immediately after a fresh install.

## Docker (local build)

There is no published Bare Systems container image. The root
[`Dockerfile`](../Dockerfile) and [`compose.yaml`](../compose.yaml) support
building and running Tardigrade in a container locally:

```bash
docker compose build
docker compose up -d
```

The current image is a multi-stage build (Zig toolchain in the build stage,
`tardi` plus its current runtime dependencies in the final stage) that runs as
a non-root `tardigrade` user. Docker's native-only shipping cutover is tracked
separately by #634; #476 does not claim that local image is already migrated.
See [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the complete Docker workflow
— build, config validation, start, reload, and graceful stop — alongside the
equivalent systemd path.

## Upgrading

After a package (or standalone binary) upgrade, use `systemctl restart`, not
`systemctl reload`:

```bash
sudo apt install ./new-package.deb   # or: dnf upgrade / rpm -U for RPM
sudo systemctl restart tardigrade
```

`systemctl reload` sends `SIGHUP`, which republishes the *existing running
process's* config — it does not exec the newly installed `tardi` binary, so
a package/binary upgrade needs a restart to actually take effect. Reserve
`reload` for edits to reloadable values in `tardigrade.conf` where neither
the binary nor `/etc/tardigrade/tardigrade.env` changed; env-file edits also
always require a restart (`SIGHUP` cannot change an already-running
process's environment). See
[docs/DEPLOYMENT.md#commands](../docs/DEPLOYMENT.md#commands) and
[docs/RELOAD_SHUTDOWN.md](../docs/RELOAD_SHUTDOWN.md) for the exact
reload/restart boundary, and why the standalone `tardi check` shown there
isn't a complete pre-flight check on its own (it doesn't load
`tardigrade.env`).

- DEB upgrades (`sudo apt install ./new-package.deb`) preserve
  `/etc/tardigrade/tardigrade.conf` and `/etc/tardigrade/tardigrade.env` as
  declared in `DEBIAN/conffiles`; `dpkg`/`apt` will prompt on conflicting
  local edits rather than silently overwriting them.
- RPM upgrades (`sudo rpm -U` or `dnf upgrade`) preserve
  `/etc/tardigrade/tardigrade.env` and `/etc/tardigrade/tardigrade.conf` via
  `%config(noreplace)`; an upgrade with local edits saves the new packaged
  version alongside as `.rpmnew` rather than overwriting your changes.
- For the plain release archive / `install.sh` path, replace the `tardi`
  binary, then run `tardi check <config>` against the existing config before
  restarting whatever process supervisor you are using.

## Homebrew (macOS and Linux)

Homebrew publication is intentionally preparatory. The currently published
latest release, `v0.5.0`, predates the native #634 shipping cutover and uses the
old archive layout, so it must not be used for the public tap formula even
though it has real Linux archive checksums.

The intended ownership model is:

```text
Tardigrade release tag
        -> scripts/update-homebrew-formula.sh
        -> packaging/homebrew/tardigrade.rb
        -> Bare-Systems/homebrew-tap/Formula/tardigrade.rb
```

The companion tap work must not keep an independent formula updater if this
repository remains canonical. If the tap becomes canonical instead, remove this
renderer and checked-in formula source so there are not two update paths.

Render and validate from the first published native release:

```bash
./scripts/update-homebrew-formula.sh \
  --tag vX.Y.Z
ruby -c packaging/homebrew/tardigrade.rb
```

`--tag` resolves that exact GitHub release, downloads its
`tardigrade-checksums.txt`, and verifies every emitted formula archive is
present in the same release before writing URLs and SHA-256 values.

Synchronize the generated formula into a tap checkout:

```bash
./scripts/update-homebrew-formula.sh \
  --tag vX.Y.Z \
  --tap-dir ../homebrew-tap
```

`--tap-dir` updates only `Bare-Systems/homebrew-tap/Formula/tardigrade.rb`.
The tap repository owns its public `README.md`; it is not rewritten during
normal Tardigrade version bumps. Change the tap documentation only when the
public support policy or install instructions actually change.

Run a host-native Homebrew install smoke against a local release-shaped archive
after building a native release binary:

```bash
zig build -Doptimize=ReleaseFast -Dversion=0.0.0-homebrew-smoke
./scripts/test-homebrew-formula.sh
```

After rendering `packaging/homebrew/tardigrade.rb` from a real native release
tag, run the release-backed smoke too. This installs the exact formula
URL/checksum bytes through Homebrew and audits the installed binary:

```bash
./scripts/test-homebrew-release-formula.sh
```

Once the tap has been updated for a release whose formula supports the target
host and the release-backed formula smoke passes, the public install shape is:

```bash
brew tap Bare-Systems/tap
brew install tardigrade

tardi version
```

## Service files

Pre-built service files for host-native installs:

| File | Purpose |
|---|---|
| [`systemd/tardigrade.service`](systemd/tardigrade.service) | systemd service unit (Linux) |
| [`launchd/io.baresystems.tardigrade.plist`](launchd/io.baresystems.tardigrade.plist) | launchd user LaunchAgent plist (macOS) validated by `.github/workflows/darwin-release-smoke.yml` on `macos-15` |

### launchd validation scope

The launchd plist is a host-style service template, not an automatic service
installer. Its checked-in paths assume an operator-created layout:

- `/usr/local/bin/tardigrade`
- `/usr/local/etc/tardigrade/tardigrade.conf`
- `/usr/local/var/tardigrade`
- `/usr/local/var/log/tardigrade/stdout.log`
- `/usr/local/var/log/tardigrade/stderr.log`

The Darwin release smoke consumes the same native Darwin archive contract used
by release packaging. That archive contains canonical `tardi` plus the supported
`tardigrade -> tardi` compatibility alias; the plist intentionally invokes the
alias because that is the host path existing installations are expected to
provide.

CI does not write into `/usr/local`. `scripts/test-launchd-service.sh` stages the
archive shape, config file, working directory, public fixture, log destinations,
and LaunchAgent plist under temporary paths, renders only the host-specific path
values from the canonical plist, then asserts the rendered `Label`,
`ProgramArguments`, `TARDIGRADE_CONFIG_PATH`, `KeepAlive`, `RunAtLoad`,
`WorkingDirectory`, and stdout/stderr redirection fields with native plist
tools. It also verifies the program-argument config path and
`TARDIGRADE_CONFIG_PATH` point to the same staged file, runs `tardi check` on
that exact config, bootstraps the service with real user-domain launchd
(`gui/$UID`), waits for the launchd-owned process to serve `/health` and a real
static response, boots it out, and verifies the job and captured process are
gone. Cleanup is idempotent and refuses to overwrite or boot out an unrelated
pre-existing `io.baresystems.tardigrade` LaunchAgent.

What this proves: deterministic plist rendering, plist syntax, user LaunchAgent
bootstrap, launchd-owned readiness and HTTP request handling, bootout, process
removal, and cleanup for the native Darwin archive/alias contract.

What this does not prove: automatic launchd installation by `scripts/install.sh`,
creation of the full `/usr/local` service layout, Homebrew publication (#466),
signing/notarization, `.pkg` or DMG installation, privileged machine-wide
LaunchDaemon behavior, or broad macOS performance. `scripts/install.sh` only
installs `tardi` and the `tardigrade` compatibility alias; operators must still
create writable config, working, and log paths for the prefix they choose before
loading the plist.

## Related docs

- [Main README — Install](../README.md#install)
- [Production deployment guide](../docs/DEPLOYMENT.md)
- [Release checklist](../docs/RELEASE_CHECKLIST.md)
- [Support matrix](../docs/SUPPORT_MATRIX.md)
