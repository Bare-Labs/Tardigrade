# Tardigrade Packaging

Native packaging artifacts for Tardigrade. See the [main README](../README.md#install)
for the quick-start install path; this document covers every packaging
format in detail, including what is actually built and published today
versus what is a local-build-only tool.

## Current status

| Format | Status | Notes |
| --- | --- | --- |
| Linux release archives (`.tar.gz`, x86_64/aarch64) | **Supported, published** | Built and attached to every GitHub release by `.github/workflows/release.yml`, alongside `install.sh`, `tardigrade-checksums.txt`, per-arch SPDX SBOMs, dependency inventories, and provenance. Built with the default `-Dtls-profile=general` (pure-Zig native since #649), an explicit portable CPU baseline (`-Dcpu=baseline`), and an explicit portable glibc floor (`-Dtarget=<arch>-linux-gnu.2.28`, matching the manylinux2014/RHEL8 floor) so the published binary runs on real hardware and distros beyond the exact CI runner that built it, not just wherever a plain native build happened to link against. |
| macOS release archives (`.tar.gz`, darwin x86_64/arm64) | **Supported, published** | `macos-15-intel` and `macos-15` release rows build `tardigrade-darwin-x86_64.tar.gz` and `tardigrade-darwin-arm64.tar.gz`, using the same archive/SBOM/inventory/provenance pipeline as Linux, with the default `-Dtls-profile=general` (pure-Zig native since #649) without Homebrew OpenSSL. Both rows audit out foreign TLS/crypto/QUIC/H3 linkage, assert the Mach-O architecture, package/extract the archive, verify native build identity, run a real static-site startup/request smoke from the extracted artifact, and exercise the checksum-verifying installer path. |
| DEB (`packaging/deb/build.sh`) | **Supported, published** | Built for `amd64`/`arm64` from the same release binaries as the `.tar.gz` archives and attached to every GitHub release; also usable as a local builder. The packaged binary's native identity is always proven with `scripts/audit-release-binary.sh` — self-audited when the binary is host-executable, or via a SHA-256-bound `--audit-inventory` file for cross-architecture packaging — never by a caller-supplied backend flag (#650). Every package declares no OpenSSL runtime dependency; there is no other production backend to package. |
| RPM (`packaging/rpm/build.sh`) | **Supported, published** | Same treatment as DEB, for `x86_64`/`aarch64`, including the native-identity audit and no OpenSSL runtime dependency (#650). Built from the same Linux release binary as the archives. The release workflow pins Linux builds to glibc 2.28 and gates the exact x86_64 archive on Ubuntu 22.04 and Rocky Linux 9 before publication. |
| systemd unit (`packaging/systemd/tardigrade.service`) | **Supported** | Installed and structurally validated (unit file text/layout, permissions) by both the DEB and RPM smoke tests. Neither test boots systemd or exercises a real start/status/reload/stop lifecycle — see [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md#the-systemd-units-pidcontrol-path-contract) for the unit contract these assertions check. |
| launchd plist (`packaging/launchd/io.baresystems.tardigrade.plist`) | **CI-validated user LaunchAgent template** | The Darwin release-smoke workflow renders the checked-in host-style `/usr/local/...` template into an isolated prefix on the `macos-15` Apple Silicon runner, stages the native Darwin archive's `tardi` binary plus `tardigrade -> tardi` compatibility alias, and proves a real `launchctl bootstrap` -> readiness/request -> `bootout` lifecycle in the current user's launchd domain. |
| Homebrew (`packaging/homebrew/tardigrade.rb`) | **Rendered from a native release** | `scripts/update-homebrew-formula.sh --tag <tag>` renders the formula from one release tag, verifies the referenced archives exist in that release, and validates each platform's dependency inventory proves native, OpenSSL-free artifact status before writing anything. `packaging/homebrew/tardigrade.rb` here is the canonical rendered source; publishing it to `Bare-Systems/homebrew-tap/Formula/tardigrade.rb` is a separate, explicit step. #466, not this document, owns the public tap. |
| Docker / OCI image | **Local build supported, not published** | Root [`Dockerfile`](../Dockerfile) and [`compose.yaml`](../compose.yaml) build a runtime image locally; smoke-tested via `scripts/test-docker-image.sh` in the `packaging-smoke` CI job, which extracts the exact runtime binary and audits it with `scripts/audit-release-binary.sh` rather than trusting the Dockerfile text. Neither build stage installs OpenSSL/libcrypto for Tardigrade (#650). No registry-published image or container-publishing workflow exists. See [docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the full workflow. |

## Official release implementation

Releases explicitly build the general-purpose native Zig
shipping profile:

```bash
zig build -Doptimize=ReleaseFast -Dversion=<version>
```

The release workflow audits each produced binary with
`scripts/audit-release-binary.sh --profile general`. That audit fails if the
artifact links `libssl`, `libcrypto`, or another forbidden foreign
TLS/crypto/QUIC/H3 implementation and verifies that `tardi version` reports
`tls-profile=general, tls-backend=native`.

Linux DEB/RPM packages are built from that same audited host-native binary.
`packaging/deb/build.sh`/`packaging/rpm/build.sh` self-audit the binary with
`scripts/audit-release-binary.sh` (rather than inferring its backend from
`tardi version` or trusting a caller-supplied flag), and the release job then
inspects the resulting package metadata and fails if either native package
declares an OpenSSL/libssl/libcrypto runtime dependency. Local
cross-architecture packages — where the target binary cannot execute on the
packaging host — provide `--audit-inventory` with a
`scripts/audit-release-binary.sh --output` inventory already generated for
that exact binary (matched by SHA-256) instead of asserting a backend
directly.

## Quick install (recommended)

Use the official install script which downloads the correct prebuilt binary and verifies its SHA-256 checksum:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
```

The currently published latest release resolves for Linux
(`x86_64`/`aarch64`) and native Intel and Apple Silicon macOS archives. The
Darwin artifacts do **not** require Homebrew OpenSSL for Tardigrade itself.

### macOS Gatekeeper / unsigned binary note

The Darwin archives are unsigned and not notarized. Command-line
installation from GitHub Releases is supported, but a browser-downloaded
archive may carry Apple's quarantine attribute and trigger Gatekeeper.
Signing/notarization is a separate future distribution concern; do not
describe these archives as notarized.

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
# 1. Install prerequisites
apt install jq

# 2. Build the binary first (cross-compile for the target arch as needed)
zig build -Doptimize=ReleaseFast

# 3. Build the DEB.
./packaging/deb/build.sh \
  --version 0.50 \
  --arch amd64

# Output: dist/tardigrade_0.50_amd64.deb
```

Install:
```bash
sudo apt install ./dist/tardigrade_0.50_amd64.deb
sudo systemctl enable --now tardigrade
```

The DEB builder always proves the packaged binary is Tardigrade's sole native
production implementation with `scripts/audit-release-binary.sh` — it never
trusts a caller-supplied backend flag. When `--binary` is executable on the
packaging host, the builder self-audits it directly. For a foreign-architecture
binary that cannot run on the packaging host, generate an inventory for it
first (e.g. on the target architecture, or under emulation) and pass it in:

```bash
./scripts/audit-release-binary.sh \
  --binary path/to/foreign-arch/tardi \
  --profile general \
  --output /tmp/tardi-inventory.json

./packaging/deb/build.sh \
  --version 0.50 \
  --arch arm64 \
  --binary path/to/foreign-arch/tardi \
  --audit-inventory /tmp/tardi-inventory.json
```

The inventory is matched to `--binary` by SHA-256, so it must have been
generated for that exact artifact. Every produced package has no OpenSSL
package dependency; there is no other production backend to package.

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

> **glibc compatibility note**: the published Linux archives, DEBs, and RPMs
> are built with `-Dcpu=baseline` and an explicit Zig target of
> `*-linux-gnu.2.28`. The release workflow then executes the exact
> `tardigrade-linux-x86_64.tar.gz` candidate on both `ubuntu:22.04` and
> `rockylinux:9` before publishing it. RHEL-family systems older than the
> glibc 2.28 floor still need a local or separately targeted build, but Rocky
> Linux 9 compatibility is part of the current release gate and serves as the
> RHEL-family 9 compatibility representative; RHEL 9 is not executed directly
> by CI.

### Build locally

```bash
# 1. Install prerequisites
dnf install rpm-build jq

# 2. Build the binary
zig build -Doptimize=ReleaseFast

# 3. Build the RPM.
./packaging/rpm/build.sh \
  --version 0.50

# Output: dist/tardigrade-0.50-1.x86_64.rpm
```

Install:
```bash
sudo rpm -i dist/tardigrade-0.50-1.x86_64.rpm
sudo systemctl enable --now tardigrade
```

Like the DEB builder, the RPM builder always proves the packaged binary's
native identity with `scripts/audit-release-binary.sh` instead of trusting a
caller-supplied backend flag: self-audited when `--binary` is host-executable,
or via a SHA-256-matched `--audit-inventory` file (see the DEB section above)
for cross-architecture packaging. Every produced package omits
`Requires: openssl-libs`; there is no other production backend to package.

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
a non-root `tardigrade` user. Neither stage installs OpenSSL/libcrypto for
Tardigrade (#650); `scripts/test-docker-image.sh` extracts the exact runtime
binary and audits it with `scripts/audit-release-binary.sh` rather than
inferring composition from the Dockerfile text. See
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for the complete Docker workflow
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

`packaging/homebrew/tardigrade.rb` in this repository is rendered from a
real native release tag by `scripts/update-homebrew-formula.sh --tag <tag>`,
which verifies the referenced archives exist in that release and validates
each platform's dependency inventory (native, OpenSSL-free) before writing
anything.

The ownership model is:

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

Validate the published tap itself after release publication with the black-box
public-tap smoke:

```bash
./scripts/test-public-homebrew-tap.sh --install-mode qualified --expected-version X.Y.Z
./scripts/test-public-homebrew-tap.sh --install-mode tap-short --expected-version X.Y.Z
```

The first mode runs `brew install bare-systems/tap/tardigrade`. The second mode
runs the explicit tap/trust flow Homebrew currently requires for non-official
taps before `brew install tardigrade`. Both modes run from a temporary directory
outside the checkout, verify `tardi` and the `tardigrade` alias resolve under
the Homebrew prefix, check the public tap formula and installed binary against
the expected release identity, audit installed-binary linkage, and exercise
`init static`, `check`, `run`, a static GET, `/health`, and clean SIGINT
shutdown. If `--expected-version` is omitted, the script resolves the latest
stable GitHub release independently of the tap under test.
`.github/workflows/public-homebrew-smoke.yml` runs this as a manual/scheduled
post-release smoke on macOS and Linux.

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
