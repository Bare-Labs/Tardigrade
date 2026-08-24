# Production Deployment

This is the canonical operator guide for running Tardigrade outside a
development shell: host-native Linux with systemd, or a locally built Docker
image. It covers filesystem layout, permissions, process control, logs, and a
hardening checklist for both paths.

## Maturity boundary

Tardigrade supports practical operator-managed deployments of its stable
core. It is **not** claimed to be generic "production-ready", "battle-tested",
or a drop-in nginx/Envoy replacement. The supported/stable runtime surface is
defined by the [Core v1 support matrix](SUPPORT_MATRIX.md) — anything listed
there as `experimental` stays experimental regardless of how you deploy it.

Read this guide alongside:

- [Configuration reference](CONFIGURATION.md) — every config directive and
  environment variable.
- [Reload, drain, and shutdown](RELOAD_SHUTDOWN.md) — the full hot-reload and
  graceful-shutdown contract; this guide only covers the operator commands
  that trigger it.
- [Observability](OBSERVABILITY.md) — logging and metrics fields in detail.
- [Support matrix](SUPPORT_MATRIX.md) — the stable/experimental contract.
- [packaging/README.md](../packaging/README.md) — what's actually built and
  published (DEB/RPM/archives) versus local-build-only (Docker).
- [examples/production-baseline/](../examples/production-baseline/README.md)
  — a hardened *configuration* example (TLS, rate limiting, headers). This
  guide covers the *service/container* layer around that config.

Two supported deployment paths:

1. [Host-native Linux + systemd](#host-native-linux--systemd) — the more
   deeply integrated path, via published DEB/RPM packages.
2. [Docker, built locally from this repository](#docker) — a local-build-only
   workflow; no image is published to a registry today.

## Host filesystem layout

The two paths converge on the same *directory* layout, but different pieces
of it come from different places and at different times — not everything
below is created by the package install step. Three categories:

- **Created by the DEB/RPM package install** (`postinst`/`%post`): the
  binary, a starter `/etc/tardigrade/tardigrade.conf`, an
  `/etc/tardigrade/tardigrade.env` template, `/var/lib/tardigrade`,
  `/var/log/tardigrade`. The Docker image creates only the *directories*
  (binary, `/var/lib/tardigrade`, `/var/log/tardigrade`) at build time — it
  does **not** create a `tardigrade.conf` or `tardigrade.env`; see
  [Docker](#docker) below for how config and environment values reach the
  container instead.
- **Created at service start, not install**: `/run/tardigrade` is created by
  systemd's `RuntimeDirectory=` when the unit starts (see
  [below](#the-systemd-units-pidcontrol-path-contract)), not by the package.
  Under Docker it's a `tmpfs` mount you supply in `compose.yaml`.
- **Operator-created, only if you use them**: neither package nor image
  creates `/etc/tardigrade/tls/` or `/var/lib/tardigrade/public/` — you
  create these (or bind-mount them, under Docker) only if your config
  actually references TLS material or a static root.

```text
Package install:              /usr/bin/tardi                     binary (/usr/local/bin/tardi in the Docker image)
                               /etc/tardigrade/tardigrade.conf    routing/runtime configuration
                               /etc/tardigrade/tardigrade.env     environment-only settings / secret references
                               /var/lib/tardigrade/                service working/state directory
                               /var/log/tardigrade/                 file-log directory
Service start (systemd RuntimeDirectory= / Docker tmpfs mount):
                               /run/tardigrade/tardigrade.pid      ephemeral process PID
Operator-created when used:   /etc/tardigrade/tls/fullchain.pem
                               /etc/tardigrade/tls/privkey.pem
                               /var/lib/tardigrade/public/          optional static root
```

Under Docker, the image only creates the directories themselves. You supply
`tardigrade.conf` and any TLS material as bind mounts, since `tardi` reads
those from disk either way. `tardigrade.env` is different: `tardi` never
parses that filename itself — it only reads `TARDIGRADE_*` values from its
own **process environment**. Under systemd, `EnvironmentFile=` is what turns
the file's contents into that process environment; Docker has no built-in
equivalent, so bind-mounting `tardigrade.env` into the container does
nothing — `tardi` won't read it. Use Compose's `env_file:` (which reads the
file on the host and injects its contents as real container environment
variables) or `environment:` instead. See [Docker](#docker) below for the
exact shape.

### Permissions and ownership

The package `postinst`/`%post` scripts are the source of truth for this on a
host-native install. The Docker image creates the equivalent directories at
build time, owned by a **fixed, pinned** non-root UID/GID (`10001:10001`,
the `tardigrade` user/group — see the [`Dockerfile`](../Dockerfile)); this
value is a documented part of the image contract, not an incidental
distro-allocated ID, and `compose.yaml`/`scripts/test-docker-image.sh` both
depend on it matching exactly.

| Path | Owner | Mode | Notes |
| --- | --- | --- | --- |
| `/etc/tardigrade/tardigrade.conf` | `root:root` | `0644` | Not secret; readable by the service via world-read. |
| `/etc/tardigrade/tardigrade.env` | `root:tardigrade` | `0640` | May hold secret references; not world-readable. |
| `/etc/tardigrade/tls/privkey.pem` | `root:tardigrade` (or narrower) | `0640` or tighter | Readable only by the service account/group. Never world-readable. |
| `/run/tardigrade/` | `tardigrade:tardigrade` | `0750` | Ephemeral; recreated at start by systemd's `RuntimeDirectory=` or the container's tmpfs mount. |
| `/var/lib/tardigrade/` | `tardigrade:tardigrade` | `0755` | Writable service state directory. |
| `/var/lib/tardigrade/public/` | read-only to the service where possible | — | Static roots and mounted config don't need write access; mount `:ro`. |
| `/var/log/tardigrade/` | `tardigrade:tardigrade` | `0755` | Writable file-log directory; created by the package/image but not persistent in Docker unless volume-mounted (see [Logs](#logs)). |

The service always runs as the dedicated non-root `tardigrade` user, both
under systemd and in the container.

**Bind-mounted TLS material and container UID/GID**: a host file owned
`root:tardigrade 0640` is only readable inside the container if the
container's `tardigrade` group *numerically* matches the host group that
owns the file — group and user *names* don't cross the container boundary,
only the numeric IDs do. The image's `tardigrade` group is a fixed
`10001`; if your host's `tardigrade` group (created by the DEB/RPM package
via `useradd --system`, so its GID is whatever the distro allocated) isn't
also `10001`, you cannot fix this with `chmod 0644` — a bind mount exposes
the *same host inode* inside the container, so `chmod` changes the mode on
the host file too and makes the key world-readable there, not just "within
the container." That fails the never-world-readable requirement outright.

Instead, give the container access to the correct numeric group without
loosening the host file's mode. Create (or reuse) a host group whose GID
owns the TLS key at `0640`, and add the container to that group with
Compose's `group_add`:

```yaml
services:
  tardigrade:
    group_add:
      - "${TARDIGRADE_TLS_GID}"   # numeric GID of the host group that owns the key
```

The key stays `root:<that-group> 0640` on the host; the container gains
read access via the matching numeric supplementary group rather than
through a mode change. An alternative is staging a copy of the key into a
volume you initialize with owner/group `10001` directly, if you'd rather
not add a supplementary group.

If your config references additional roots, Unix sockets, or upstream
sockets outside this layout, they need their own filesystem access —
extend the systemd unit's directory allowlist or the container's mounts
deliberately for that specific path rather than weakening sandboxing
globally (for example, don't drop `ProtectSystem=full` or `ProtectHome=true`
just to reach one extra path).

## Host-native Linux + systemd

Install via the published DEB or RPM package — see
[packaging/README.md](../packaging/README.md) for exact install commands and
current publish status. The package installs the binary, a starter config,
the systemd unit, and creates the `tardigrade` system user and
`/var/lib/tardigrade`.

### The systemd unit's PID/control-path contract

The shared unit at
[`packaging/systemd/tardigrade.service`](../packaging/systemd/tardigrade.service)
gives every fresh install a deterministic, self-contained control path:

```ini
EnvironmentFile=-/etc/tardigrade/tardigrade.env
Environment=TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid
RuntimeDirectory=tardigrade
RuntimeDirectoryMode=0750

ExecStartPre=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi check /etc/tardigrade/tardigrade.conf
ExecStart=/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid /usr/bin/tardi run -c /etc/tardigrade/tardigrade.conf
ExecReload=/usr/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid
ExecStop=/usr/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid

TimeoutStopSec=35s
```

- `RuntimeDirectory=tardigrade` makes systemd create and own
  `/run/tardigrade` (mode `0750`, owned by the `tardigrade` service user) on
  every start — no manual directory setup needed.
- The PID path is forced three times, deliberately: `Environment=TARDIGRADE_PID_FILE=...`
  sets a default, but systemd gives `EnvironmentFile=` values **higher**
  precedence than unit-level `Environment=` values — so a stray
  `TARDIGRADE_PID_FILE=` line in `tardigrade.env` would otherwise silently
  win and desync the running process's actual PID file from what
  `ExecReload`/`ExecStop` target. Both `ExecStartPre` and `ExecStart` wrap
  their command in `/usr/bin/env TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid ...`,
  which sets that variable at exec time and always wins, regardless of
  what's in `tardigrade.env`. `tardi` still runs directly (`env` execs it),
  so systemd tracks the same process for `ExecStart`. This exact
  conflicting-env-file scenario is covered by a regression check in
  `scripts/test-docker-image.sh`.
- `ExecStartPre` runs `tardi check` against the config before the listener
  binds, so a bad edit fails the start instead of taking down a working
  process. It's forced to the same PID value as `ExecStart` for the same
  reason both commands need it: without the explicit `env` wrapper on both,
  `ExecStartPre` would validate against whatever conflicting
  `TARDIGRADE_PID_FILE` happens to be in `tardigrade.env` (the shipped
  production-baseline example intentionally sets one, for its own
  standalone-run instructions) while `ExecStart` runs with the forced
  value — silently validating a different effective configuration than the
  one that actually starts.
- `TimeoutStopSec=35s` is set above the default 30s graceful-drain window
  (`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`, see
  [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md)) so systemd doesn't escalate to
  `SIGKILL` before the drain finishes. If you raise the drain timeout,
  raise `TimeoutStopSec` to match.

Adjust the built-in hardening directives (`NoNewPrivileges`, `PrivateTmp`,
`ProtectHome`, `ProtectSystem=full`, `UMask=0027`) if testing shows one
breaks a deployment you rely on (extra static roots, Unix sockets, etc.), but
keep the service non-root, the PID path deterministic, and `ExecStartPre`
config validation.

### Commands

```bash
# Validate the config file itself before publishing an edit
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf

sudo systemctl start tardigrade
sudo systemctl status tardigrade
sudo systemctl reload tardigrade    # hot reload: SIGHUP, no dropped connections
sudo systemctl restart tardigrade   # full restart: needed for process-owned settings
sudo systemctl stop tardigrade

sudo journalctl -u tardigrade
sudo journalctl -u tardigrade -f
```

**This standalone `tardi check` does not validate the same effective
configuration the service runs with.** Run outside the unit, it doesn't load
`/etc/tardigrade/tardigrade.env`, and [`CONFIGURATION.md`](CONFIGURATION.md)
defines process environment as higher precedence than config-file values —
so an invalid or changed value that only exists in `tardigrade.env` (a
secret bootstrap reference, an overridden port, a TLS path override, etc.)
can pass this check and still fail at start. The unit's own `ExecStartPre`
is the check that sees the same merged `EnvironmentFile=`/`Environment=`
environment as `ExecStart` (both are wrapped with the same forced
`TARDIGRADE_PID_FILE`, per [above](#the-systemd-units-pidcontrol-path-contract)),
and is the real pre-flight gate on `start`/`restart`.

Reload vs. restart — the two are not interchangeable:

- **`tardigrade.conf` edits to reloadable values** (request routing, TLS
  credentials, and other reload-owned config — see
  [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md) for the exact boundary):
  validate, then `systemctl reload tardigrade`.
- **`tardigrade.conf` edits to process-owned values** (listener shard
  topology, HTTP/3 listener-owned settings, etc.): reload rejects these;
  use `systemctl restart tardigrade`.
- **`tardigrade.env` edits, of any kind**: always `systemctl restart
  tardigrade`. `SIGHUP` reloads the published config; it cannot change the
  environment of an already-running process, so a `tardigrade.env` edit has
  no effect until the process is restarted and re-reads it at exec time.

**Master/worker mode**: every control-path example in this guide assumes
single-process mode, which is the default (`master_process false;`). If you
run with `master_process true;`, what breaks depends on the supervisor —
systemd and Docker are **not** equivalent here:

- **Reload — affects both.** The `systemctl reload`/PID-file workflow above
  (and the equivalent `tardi reload --pid-file ...` under Docker) targets
  the PID file's process with `SIGHUP`. Per
  [`CONFIGURATION.md`](CONFIGURATION.md#field-reference)'s `master_process`
  entry, master/worker mode does not yet provide coherent PID-file/SIGHUP
  reload control across all workers, regardless of supervisor — use restart
  semantics instead (`systemctl restart tardigrade`, or recreate the
  container) rather than `reload`.
- **USR1 log-reopen after rotation — main-only paths only.** Each worker
  opens its own error-log file descriptor independently at startup, and
  nothing forwards `SIGUSR1` to them from the master's own reopen handler.
  This specifically affects the **packaged systemd logrotate policy**
  (`systemctl kill --kill-who=main --signal=USR1 ...`, deliberately
  main-only) and **Docker's `docker kill --signal=USR1 <container>`**
  (which only ever reaches container PID 1). It does *not* affect a manual
  `systemctl kill --signal=USR1 tardigrade.service` run without
  `--kill-who=main` — `systemctl kill`'s default target is *all* processes
  in the unit's cgroup, so that specific manual command reaches the workers
  too.
- **The 35s stop window — Docker (and other master-only-signal
  supervisors), not the packaged systemd unit.** Tardigrade's own
  `runMaster` shutdown loop stops workers one at a time (kill, wait for
  exit, then the next), so under a supervisor that only signals the master
  process directly — Docker's `docker stop`, which reaches container PID 1
  — total shutdown time scales with worker count rather than being bounded
  by a single drain window. The packaged systemd unit does not have this
  problem: it leaves `KillMode=` at systemd's default `control-group`, so
  once `ExecStop` returns, systemd delivers the stop signal to *every*
  process in the service's cgroup concurrently — workers receive `SIGTERM`
  directly from systemd rather than waiting on the master's serial loop. Do
  not "fix" this by setting `KillMode=process`; systemd's docs explicitly
  discourage that because child processes can then escape service lifecycle
  management entirely.

Until coherent multi-worker reload/log-rotation fan-out lands, keep
`master_process false;` (the default) if you rely on reload or main-only
USR1 log rotation from this guide. The 35s-stop-window concern is Docker
(and other master-only-signal-path) specific — the packaged systemd unit's
default `control-group` kill mode already avoids it.

## Docker

Docker support here is **local-build support**: `docker build`/`docker
compose build` from the [`Dockerfile`](../Dockerfile) in this repository.
There is no published Bare Systems image on any registry today — see
[packaging/README.md](../packaging/README.md#current-status).

The image is a multi-stage build: a build stage compiles `tardi` with the
pinned Zig toolchain (matching `.github/workflows/ci.yml`) and the default
"general" TLS profile — pure-Zig native since #649, no OpenSSL required to
build or run `tardi` itself (see
[TLS_DEPENDENCY_POLICY.md](TLS_DEPENDENCY_POLICY.md)); the runtime stage
contains only `tardi`, CA-certificate data, and a non-root `tardigrade`
user. No Zig toolchain, source tree, OpenSSL package, or other foreign
implementation library ships in the final image.

### Build

```bash
docker compose build
```

### Validate config before startup

```bash
docker compose run --rm tardigrade \
  check /etc/tardigrade/tardigrade.conf
```

### Start

```bash
docker compose up -d
```

### Inspect

```bash
docker compose ps
docker compose logs -f tardigrade
```

### Validate + reload

```bash
docker compose exec tardigrade \
  tardi check /etc/tardigrade/tardigrade.conf

docker compose exec tardigrade \
  tardi reload --pid-file /run/tardigrade/tardigrade.pid
```

> **Single-process mode only.** This targets the PID file's process with
> `SIGHUP`, same as the systemd path. With `master_process true;`, this does
> not reload workers coherently — see [Master/worker mode](#commands) above,
> which applies here too.

### Graceful stop

```bash
docker compose stop
```

`tardi` runs as PID 1 in the container (exec-form `ENTRYPOINT`), so Docker's
`SIGTERM` reaches Tardigrade's graceful shutdown path directly — no init
shim swallowing or relaying the signal.

### compose.yaml

[`compose.yaml`](../compose.yaml) at the repo root is a copy/paste-runnable
local example: builds the image, mounts a read-only config (and optional
static root / TLS directory), supplies `/run/tardigrade` as a `tmpfs` mount
owned by the container's non-root user, maps the port, and sets a graceful
`stop_grace_period` longer than the drain timeout. The `tmpfs` entry needs
explicit `uid=10001,gid=10001` mount options matching the image's fixed
`tardigrade` user (see [Permissions and ownership](#permissions-and-ownership)
above) — a plain tmpfs mount defaults to `root:root` and the process can't
write its PID file into it.

**Environment values (`tardigrade.env` equivalent)**: `tardi` reads
`TARDIGRADE_*` values from the process environment, not from a parsed
config file — see the note in [Host filesystem
layout](#host-filesystem-layout) above. Under Docker, use Compose's
`env_file:` to inject an operator env file's contents as real container
environment variables:

```yaml
services:
  tardigrade:
    # Optional operator environment values, injected as real container
    # environment variables (tardi does not read this path as a file):
    # env_file:
    #   - ./deploy/tardigrade.env
    environment:
      # Keep these explicit: Compose `environment:` overrides `env_file:`,
      # so even a baseline env file setting a conflicting PID path cannot
      # desync the runtime from the control commands below.
      TARDIGRADE_PID_FILE: /run/tardigrade/tardigrade.pid
      TARDIGRADE_REQUIRE_UNPRIVILEGED_USER: "true"
```

The bundled healthcheck runs `tardi status --pid-file ...` inside the
container. Note its limitation: `tardi status` always exits `0` once the
config loads, whether or not the process is actually reachable — it reports
`status: stopped` in text rather than failing the check. It's still useful
signal (it proves the entrypoint, working directory, and PID path are wired
correctly), but it will not, by itself, flip a container unhealthy if the
listener stops responding while the process is still alive. If you need a
liveness check on the actual HTTP path, add `curl` or `wget` to the runtime
image and point it at `/health` instead.

## Ports and privilege model

- The example/default listener port is `8069` (unprivileged, works for both
  systemd and Docker without extra capabilities).
- Put a frontend load balancer, NAT, or reverse proxy in front to expose
  `80`/`443` rather than binding them directly, where that fits your
  environment.
- If Tardigrade must bind `80`/`443` directly under systemd, grant
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` (plus
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`) on the service unit instead
  of running the process as root.
- Keep Docker deployments non-root and use host port publishing
  (`ports: ["80:8069"]`, etc.) rather than elevating the container just to
  bind a low port.

## Logs

Two logging surfaces, both covered in full by
[OBSERVABILITY.md](OBSERVABILITY.md):

- **Container/service stderr** — under systemd, `journalctl -u tardigrade`;
  under Docker, `docker compose logs -f tardigrade`. Runtime and JSON
  access logs are written to stderr (not stdout) unless `error_log`/
  `TARDIGRADE_ERROR_LOG_PATH` redirects fd 2 to a configured file.
  `journalctl`/`docker compose logs` still work as the collection surface
  either way, since both capture stderr.
- **Configured file logs** — set `error_log` (or
  `TARDIGRADE_ERROR_LOG_PATH`) to write to `/var/log/tardigrade/*.log`
  instead. Both the DEB and RPM packages create a `tardigrade`-owned
  `/var/log/tardigrade` and install the same logrotate config at
  `/etc/logrotate.d/tardigrade`, which signals `SIGUSR1` after rotation;
  Tardigrade has a real SIGUSR1 log-reopen handler, so log files reopen
  cleanly on the existing rotation cadence. That packaged logrotate +
  `SIGUSR1` flow is the supported mechanism for **ongoing** rotation while
  the process stays up. Separately, `TARDIGRADE_LOG_ROTATE_MAX_BYTES`/
  `TARDIGRADE_LOG_ROTATE_MAX_FILES` perform a one-time size-triggered
  rotation check during process **startup** only — not a periodic runtime
  rotator. Don't invent a third mechanism beyond these two.

  The Docker image creates the same `tardigrade`-owned `/var/log/tardigrade`
  directory, but nothing inside the container persists or rotates it. Using
  `error_log` under Docker needs two things, not just a mount:

  1. **A pre-owned host path or named volume.** A bind mount such as
     `- ./logs:/var/log/tardigrade` *replaces* the image's `10001:10001`
     directory with whatever is at `./logs` on the host. A freshly created
     (often root-owned) host directory will make `error_log` fail with
     `EACCES`. Prepare it first:
     ```bash
     sudo install -d -o 10001 -g 10001 -m 0755 ./logs
     ```
     or use a named volume and let the container's own directory-creation
     step own it on first start.
  2. **Rotation that reopens the file, not just renames it.** The DEB/RPM
     logrotate policy sends `SIGUSR1` for exactly this reason — Tardigrade
     keeps writing to the old (now-renamed) inode otherwise. A host-side
     `logrotate` `postrotate` needs the equivalent signal delivered to the
     container, e.g. `docker kill --signal=USR1 <container>` (or the
     `docker compose` equivalent), not just a `copytruncate`/rename step.

  Without a persistent mount, `docker compose logs` on stdout/stderr is the
  default log surface — but don't treat it as inherently durable either;
  retention depends on the configured Docker logging driver and container
  lifecycle, the same as any other container's stdout.

> **Operator note discovered while writing this guide**: the starter config
> matches on `server_name localhost;`. A bare `curl http://<host>:8069/health`
> against an IP or a mismatched `Host` header returns `404`, not `200` —
> match the `Host` header (or your config's `server_name`) when
> smoke-testing, or use `server_name _;`/a real hostname in your own config.

## Production hardening checklist

- [ ] Run as the dedicated non-root `tardigrade` user (default for both
      paths — don't override it).
- [ ] Validate `tardigrade.conf` edits with `tardi check` before reload when
      practical — `ExecStartPre` does not run on `systemctl reload`, only on
      `start`/`restart`; hot reload runs its own validation and leaves the
      previously published config active if the candidate is rejected (see
      [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md)).
- [ ] TLS private key permissions: never world-readable; restrict to the
      service account/group.
- [ ] Mount static roots, config, and TLS material read-only where the
      service doesn't need to write them.
- [ ] Expose only the ports you intend to serve.
- [ ] Restrict `/status/metrics` to trusted scrapers/network paths, or set
      `TARDIGRADE_METRICS_REQUIRE_AUTH=true` (see
      [CONFIGURATION.md](CONFIGURATION.md)).
- [ ] Tune rate limits and connection/request limits for your workload
      (`TARDIGRADE_RATE_LIMIT_RPS`, `TARDIGRADE_MAX_ACTIVE_CONNECTIONS`,
      `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS`).
- [ ] Configure upstream health checks where you proxy to origins.
- [ ] Set `TimeoutStopSec` (systemd) / `stop_grace_period` (Docker) above
      `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`.
- [ ] Retain and review logs and reload-failure metrics
      (`tardigrade_reload_failure_total`, `/tardigrade/reload/status`).
- [ ] Use firewall/load-balancer controls around operator-only paths.
- [ ] Never commit live secrets or bake them into container image layers —
      externalize config, certs, and secrets.
- [ ] Back up any operator-managed persistent state your specific deployment
      relies on.

See [examples/production-baseline/](../examples/production-baseline/README.md)
for a config-level pre-production checklist covering TLS, HSTS, and rate
limiting values.

## Known limitations

- Docker support here is local-build only. No image is published to any
  registry unless and until a separate distribution ticket adds that.
- This guide targets Linux containers; other container runtimes (Podman,
  etc.) aren't tested against it.
- The Docker image bakes in no config, certificates, or secrets at all —
  operators mount/inject everything. Native DEB/RPM packages differ: they
  install a non-secret starter `tardigrade.conf` and an env template, which
  operators are expected to replace or edit; certificates, static content,
  and live secrets remain operator-supplied either way.
- `/status/metrics` is not automatically restricted; apply the checklist
  item above before exposing a deployment publicly.
- DEB/RPM remain the more deeply integrated host-native Linux install path
  (user creation, logrotate, systemd wiring all handled by the package).
- `master_process true;` is not coherently supported by every control path
  in this guide, and the gaps differ by supervisor — see
  [Commands](#commands) above for the full breakdown. In short: PID-file/
  `SIGHUP` reload targets one process and isn't coherent across workers
  under either systemd or Docker; main-only `SIGUSR1` log-reopen (the
  packaged systemd logrotate policy and Docker's `docker kill`) doesn't
  reach worker file descriptors, though a non-main-only manual
  `systemctl kill --signal=USR1` does; and the 35s graceful-stop window is
  only a real concern under Docker (or another supervisor that signals only
  the master process) — the packaged systemd unit's default
  `KillMode=control-group` already delivers the stop signal to every worker
  concurrently. Keep `master_process false;` (the default) if you rely on
  reload or main-only log rotation. See
  [CONFIGURATION.md](CONFIGURATION.md#field-reference) for the underlying
  `master_process` contract.
- Every experimental protocol/feature in the [support matrix](SUPPORT_MATRIX.md)
  stays experimental regardless of deployment method — deploying via
  Docker or systemd does not change a feature's maturity level.
