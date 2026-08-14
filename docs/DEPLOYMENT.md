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

Both deployment paths converge on the same layout. The DEB/RPM packages
create this automatically; the Docker image creates the container-local
equivalent under `/etc/tardigrade`, `/var/lib/tardigrade`, and
`/run/tardigrade`.

```text
/usr/bin/tardi                         binary
/etc/tardigrade/
    tardigrade.conf                    routing/runtime configuration
    tardigrade.env                     environment-only settings / secret references
    tls/
        fullchain.pem
        privkey.pem
/run/tardigrade/
    tardigrade.pid                     ephemeral process PID
/var/lib/tardigrade/                   service working/state directory
/var/lib/tardigrade/public/            optional static root
/var/log/tardigrade/                   optional file logs
```

### Permissions and ownership

The package `postinst`/`%post` scripts are the source of truth for this on a
host-native install; the same properties apply inside the Docker image.

| Path | Owner | Mode | Notes |
| --- | --- | --- | --- |
| `/etc/tardigrade/tardigrade.conf` | `root:root` | `0644` | Not secret; readable by the service via world-read. |
| `/etc/tardigrade/tardigrade.env` | `root:tardigrade` | `0640` | May hold secret references; not world-readable. |
| `/etc/tardigrade/tls/privkey.pem` | `root:tardigrade` (or narrower) | `0640` or tighter | Readable only by the service account/group. Never world-readable. |
| `/run/tardigrade/` | `tardigrade:tardigrade` | `0750` | Ephemeral; recreated at start by systemd's `RuntimeDirectory=` or the container's tmpfs mount. |
| `/var/lib/tardigrade/` | `tardigrade:tardigrade` | `0755` | Writable service state directory. |
| `/var/lib/tardigrade/public/` | read-only to the service where possible | — | Static roots and mounted config don't need write access; mount `:ro`. |

The service always runs as the dedicated non-root `tardigrade` user, both
under systemd and in the container.

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
Environment=TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid
RuntimeDirectory=tardigrade
RuntimeDirectoryMode=0750

ExecStartPre=/usr/bin/tardi check /etc/tardigrade/tardigrade.conf
ExecStart=/usr/bin/tardi run -c /etc/tardigrade/tardigrade.conf
ExecReload=/usr/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid
ExecStop=/usr/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid

TimeoutStopSec=35s
```

- `RuntimeDirectory=tardigrade` makes systemd create and own
  `/run/tardigrade` (mode `0750`, owned by the `tardigrade` service user) on
  every start — no manual directory setup needed.
- `Environment=TARDIGRADE_PID_FILE=...` and the `--pid-file` flags on
  `ExecReload`/`ExecStop` all point at the same path the running process
  writes, so `systemctl reload`/`stop` can always find it.
- `ExecStartPre` runs `tardi check` against the config before the listener
  binds, so a bad edit fails the start instead of taking down a working
  process.
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
# Validate a config edit before publishing it
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf

sudo systemctl start tardigrade
sudo systemctl status tardigrade
sudo systemctl reload tardigrade    # hot reload: SIGHUP, no dropped connections
sudo systemctl restart tardigrade   # full restart: needed for process-owned settings
sudo systemctl stop tardigrade

sudo journalctl -u tardigrade
sudo journalctl -u tardigrade -f
```

Reload vs. restart:

- A config change that only affects request routing, TLS credentials, or
  other reload-owned settings: validate, then `systemctl reload tardigrade`.
- A change to listener shard topology, HTTP/3 listener-owned settings, or
  other process-owned settings: `systemctl restart tardigrade` (reload
  rejects these; see [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md) for the exact
  boundary).

## Docker

Docker support here is **local-build support**: `docker build`/`docker
compose build` from the [`Dockerfile`](../Dockerfile) in this repository.
There is no published Bare Systems image on any registry today — see
[packaging/README.md](../packaging/README.md#current-status).

The image is a multi-stage build: a build stage compiles `tardi` with the
pinned Zig toolchain (matching `.github/workflows/ci.yml`) and the default
"general" TLS profile (OpenSSL adapter — see
[TLS_DEPENDENCY_POLICY.md](TLS_DEPENDENCY_POLICY.md)); the runtime stage
contains only `tardi`, its OpenSSL/CA-certificate runtime dependencies, and a
non-root `tardigrade` user. No Zig toolchain or source tree ships in the
final image.

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
explicit `uid`/`gid` mount options matching the image's `tardigrade` user —
a plain tmpfs mount defaults to `root:root` and the process can't write its
PID file into it.

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

- **Container/service stdout** — under systemd, `journalctl -u tardigrade`;
  under Docker, `docker compose logs -f tardigrade`. This is where runtime
  and JSON access logs land unless `error_log`/`TARDIGRADE_ERROR_LOG_PATH`
  is configured.
- **Configured file logs** — set `error_log` (or
  `TARDIGRADE_ERROR_LOG_PATH`) to write to `/var/log/tardigrade/*.log`
  instead. The DEB/RPM packages already install a logrotate config at
  `/etc/logrotate.d/tardigrade` that signals `SIGUSR1` after rotation;
  Tardigrade has a real SIGUSR1 log-reopen handler, so log files reopen
  cleanly on the existing rotation cadence. Don't invent a second rotation
  mechanism.

> **Operator note discovered while writing this guide**: the starter config
> matches on `server_name localhost;`. A bare `curl http://<host>:8069/health`
> against an IP or a mismatched `Host` header returns `404`, not `200` —
> match the `Host` header (or your config's `server_name`) when
> smoke-testing, or use `server_name _;`/a real hostname in your own config.

## Production hardening checklist

- [ ] Run as the dedicated non-root `tardigrade` user (default for both
      paths — don't override it).
- [ ] Validate config before every start/reload (`tardi check`; the systemd
      unit already does this via `ExecStartPre`).
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
- Operators supply their own config, certificates, static roots, and secrets
  — none of these are baked into the image or package.
- `/status/metrics` is not automatically restricted; apply the checklist
  item above before exposing a deployment publicly.
- DEB/RPM remain the more deeply integrated host-native Linux install path
  (user creation, logrotate, systemd wiring all handled by the package).
- Every experimental protocol/feature in the [support matrix](SUPPORT_MATRIX.md)
  stays experimental regardless of deployment method — deploying via
  Docker or systemd does not change a feature's maturity level.
