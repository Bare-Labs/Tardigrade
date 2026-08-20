# Reload, Drain, and Shutdown

Tardigrade has three distinct lifecycle paths:

- **Hot reload** (`tardi reload`, `SIGHUP`) validates and publishes a new runtime
  configuration without stopping the process.
- **Graceful shutdown** (`tardi stop`, `SIGTERM`, `SIGINT`, or `SIGUSR2` upgrade)
  stops accepting new work and drains worker jobs before exit.
- **Hard termination** (`SIGKILL`, process crash, or an external supervisor kill
  after its own timeout) is outside Tardigrade's graceful path; the OS closes
  sockets and in-flight requests can be interrupted.

## Commands

Use a PID file in production so control commands can find the running process:

```bash
TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf \
TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid \
./zig-out/bin/tardi run
```

Validate config edits before publishing them:

```bash
./zig-out/bin/tardi check /etc/tardigrade/tardigrade.conf
./zig-out/bin/tardi reload --pid-file /run/tardigrade/tardigrade.pid
./zig-out/bin/tardi status --pid-file /run/tardigrade/tardigrade.pid
./zig-out/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid
```

`tardi reload` sends `SIGHUP`. `tardi stop` sends `SIGTERM`. Both commands also
accept `--pid <pid>` when a PID file is not available.

For systemd installs, validate first and then let the unit's `ExecReload` run:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
sudo systemctl reload tardigrade
sudo systemctl stop tardigrade
```

This standalone `tardi check` validates `tardigrade.conf` only — it doesn't
load `/etc/tardigrade/tardigrade.env`, so it isn't a complete pre-flight
check of everything the running service uses. See
[DEPLOYMENT.md#commands](DEPLOYMENT.md#commands) for the full
validation/reload/restart contract, including why `tardigrade.env` edits
need a restart rather than a reload, and the current single-process-only
scope of this control path (`master_process true;` doesn't yet get coherent
SIGHUP/PID-file reload across workers).

Set systemd `TimeoutStopSec` slightly above
`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` so systemd does not escalate to a hard
kill before Tardigrade's drain has finished.

## Hot Reload

On `SIGHUP`, the gateway handles reload on the maintenance tick:

1. Load the new config from the configured source.
2. Validate it.
3. Prepare reload-owned runtime resources, such as reloadable TLS credentials.
4. Reject the reload if it changes process-owned settings that require a
   restart, such as listener shard topology, HTTP/3 listener-owned settings,
   native early-data replay mode/capacity, native ticket-key source mode, or
   (see "TLS Credential Identity" below) a certificate/key/SNI change on a
   build where that would leave two TLS surfaces on different identities.
5. Publish the new config through the lease-counted config store.

New requests acquire the newly published config after step 5. In-flight requests
retain their original config lease for request-scoped config reads. Reload also
updates some process-shared runtime policy, so an in-flight request is not a
fully isolated snapshot of the previous runtime configuration. Reload does not
drain worker jobs, stop the listener, or close active client connections.

If reload fails before config publication, the previously published config
remains active for request routing and config leases. Reload-owned runtime
resources are not fully transactional: a runtime update performed before a later
failure may remain in effect even though the new config is not published.
Operators can inspect the last result through:

```bash
curl http://127.0.0.1:8080/tardigrade/reload/status
```

The endpoint returns JSON in this shape:

```json
{"ok":false,"at_ms":1780000000000,"error":"validation rejected: InvalidConfigValue"}
```

Expected reload logs include:

```text
configuration hot-reload starting
configuration hot-reload applied
config reload failed during load: ...
config reload rejected by validation: ...
config reload rejected: ... restart the process ...
```

### TLS Credential Identity

Tardigrade has two TLS credential owners, depending on build profile and
which protocols a deployment serves:

- The **OpenSSL adapter** (`http.tls_termination.TlsTerminator`), used for
  stable TCP (H1/H2) on the default `general` build (`tls-profile=general`).
  Its certificate/key context is loaded once at startup and is **never**
  rebuilt by `SIGHUP` — only protocol-policy fields (ALPN/H1/H2 enablement)
  are reload-owned. A separate, independent file-content watcher
  (`TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS`) can pick up byte changes at
  the *same, already-configured* certificate/key paths on its own timer —
  that is not part of `SIGHUP` reload and does not respond to a changed
  `TLS_CERT_PATH`/`TLS_KEY_PATH` value.
- The **native credential store** (`http.native_tls_connection.NativeCredentialStore`
  or, on the appliance profile, `ApplianceCredentials`), used for native
  HTTP/3 always, and for native TCP too on any build that does not link the
  OpenSSL adapter (`tls-profile=appliance` today; the long-term direction
  for the default published artifact is pure Zig with no OpenSSL). This
  store supports a real prepare/commit hot-swap of certificate, key, and SNI
  identity from the proposed reload paths.

**On a build with no OpenSSL adapter linked**, native TCP and native HTTP/3
share the same credential store, so a `SIGHUP` that changes
`TLS_CERT_PATH`/`TLS_KEY_PATH`/SNI certificates reloads both protocols onto
the new identity together, atomically. This is the "reloadable or rebuilt in
place" row of [CONFIGURATION.md's reload matrix](CONFIGURATION.md#reload-behavior).

**On the default `general` build with the OpenSSL adapter linked**, stable
TCP owns its identity via `TlsTerminator` (startup-owned, as above) while
native HTTP/3 — if also enabled — owns a separate `NativeCredentialStore`
capable of live reload. Letting native HTTP/3 alone pick up a changed
credential path would leave the two protocols presenting different
certificates for the same hostname until a full restart. To prevent that
split identity, `hotReloadConfig` rejects the whole reload outright when
`TLS_CERT_PATH`/`TLS_KEY_PATH`/SNI certificates change and both a
`TlsTerminator` and a `NativeCredentialStore` are present — the previous
config stays active on both surfaces, and an operator must restart the
process to rotate credentials ([#629](https://github.com/Bare-Systems/Tardigrade/issues/629)).
A general-profile build serving TCP only (no HTTP/3, or HTTP/3 without a
resolvable TLS identity) is unaffected by this rejection; it keeps the
existing "config publishes, live OpenSSL context stays on the old identity"
behavior.

Every other reload-eligible field — routing, rate limits, headers, and the
rest of the "reloadable or rebuilt in place" row — reloads normally
regardless of TLS credential identity; only the credential-affecting fields
above trigger this rejection.

## Active Connections

Tardigrade tracks accepted client connections separately from requests:

- A keep-alive connection holds one connection slot while it is parked between
  requests.
- Parked keep-alive connections do not occupy a worker thread.
- When a parked connection sends another request, it is resumed and submitted to
  the worker pool.
- On hot reload, parked and active client connections stay open. Their next
  request uses whichever config version they acquire at handler entry.
- On graceful shutdown, new accepts stop and keep-alive is disabled for requests
  already being handled, so connections close instead of being re-parked.
- Already-parked idle keep-alive connections are not worker jobs. They remain in
  the parked registry during worker drain and are closed when the downstream
  runtime is torn down; they do not extend the worker-pool drain deadline.

The main related knobs are:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` | `5000` | Idle parked downstream keep-alive timeout. |
| `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` | `100` | Maximum requests served before closing a downstream connection. |
| `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | `0` | Optional global accepted-connection cap (`0` means unlimited). |
| `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | `0` | Optional in-flight request cap (`0` means unlimited). |

See [TIMEOUTS.md](TIMEOUTS.md) for request phase timeout semantics.

## Worker Jobs and Drain

Graceful shutdown is the path that uses the drain timeout. Once shutdown is
requested, the accept loop exits and the TCP worker pool drains with
`TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` (default `30000` ms).

Drain behavior:

- Active, already-dispatched handlers are allowed to finish naturally.
- Requests whose handler/lifecycle starts after shutdown has been requested cap
  their request deadline to the drain window when no stricter deadline exists.
  Requests already executing when shutdown is requested keep their existing
  lifecycle and phase deadlines.
- Queued, not-yet-started connection jobs wait until the drain deadline.
- If the drain deadline expires, remaining queued file descriptors owned by the
  worker queue are closed and counted as forced closes.
- A drain timeout of `0` skips the wait and abandons queued jobs immediately.
  Queue-owned unstarted accepted sockets are closed, while non-owning
  resume/poll work is discarded and cleaned up by its owning runtime state.

For TCP worker jobs, the drain timeout is a soft worker-drain cap: active
handlers are not killed inside the process. Their own phase deadlines,
downstream disconnects, or the supervisor's external stop timeout bound the
final exit.

Native HTTP/3 uses the same shutdown timeout as a QUIC/H3 drain deadline.
Shutdown refuses new QUIC connections, sends H3 GOAWAY, and rejects new request
streams past the drain boundary. Existing H3 work may complete before the
deadline; remaining H3 connections are closed when the deadline expires.

Expected TCP worker-pool shutdown logs include:

```text
Shutdown requested; draining active connection work (timeout=30000ms active_connections=...)
drain timeout elapsed; force-closed N queued connection(s)
Graceful shutdown complete (forced_closes=N drain_timed_out=true)
```

Related knobs:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | `30000` | TCP worker-pool drain window and native HTTP/3 drain deadline for graceful shutdown. The final shutdown path uses the startup value; hot reload can publish a different request-scoped value, but the process drain/H3 deadline still requires restart to change coherently today. |
| `TARDIGRADE_WORKER_THREADS` | `0` | Startup-owned worker thread count; `0` uses the runtime default. Restart required to change. |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | `1024` | Startup-owned worker queue capacity. Restart required to change. |
| `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` | `0` | Startup-owned optional per-worker queue depth cap (`0` means unlimited beyond queue capacity behavior). Restart required to change. |

Related references:

- [TIMEOUTS.md lifecycle table](TIMEOUTS.md#lifecycle--operations) for timeout
  semantics of `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`.
- [examples/graceful-reload/tardigrade.env.example](../examples/graceful-reload/tardigrade.env.example)
  for commented PID-file and drain-timeout configuration.

## Upstream Keepalive Pools

Upstream pools are origin-side keepalive caches. They are independent from the
downstream client connection lifecycle:

- Hot reload keeps existing upstream idle and active pooled connections alive.
- Requests already using an upstream connection finish under their current
  request/config lease.
- New requests use the current request config, but they may still reuse an
  existing pooled connection governed by the pool policy installed at startup.
- Idle upstream connections are evicted by the maintenance tick when they exceed
  idle or lifetime limits.
- Shutdown closes idle upstream pool connections during runtime teardown after
  worker drain.

Hot reload does not reconfigure the process-owned upstream pool policy. Changes
to pool enablement, capacity, idle timeout, lifetime, or active checkout limits
require a restart today; existing pool instances and their startup policy remain
in effect. Reloaded proxy-buffer limits are the exception and are applied through
the pool's runtime setters.

Related knobs:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_UPSTREAM_POOL_ENABLED` | `true` | Enables HTTP/1 upstream keepalive reuse. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST` | `32` | Maximum idle upstream HTTP/1 connections per origin. |
| `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | `90000` | Idle upstream pool eviction age. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS` | `0` | Maximum pooled connection lifetime (`0` means unlimited). |
| `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` | `0` | Optional fail-fast active checkout cap per origin. |

See [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) for the complete pool contract.

## Observability

Lifecycle logs are emitted through the runtime logger. Metrics are exposed at
the configured metrics path, `/status/metrics` by default:

| Metric | Meaning |
| --- | --- |
| `tardigrade_reload_attempts_total` | Reloads started. |
| `tardigrade_reload_success_total` | Reloads successfully installed. |
| `tardigrade_reload_failure_total` | Reloads rejected; previous config kept. |
| `tardigrade_drain_total` | Graceful-shutdown drains started. |
| `tardigrade_drain_timeouts_total` | TCP worker-pool drains that reached a positive drain deadline before worker jobs finished; does not report native H3 deadline expiry. |
| `tardigrade_drain_forced_closes_total` | Queue-owned unstarted TCP accepted sockets closed on worker drain expiry or an immediate zero-timeout shutdown. |
| `tardigrade_active_connections` | Currently accepted downstream connections. |
| `tardigrade_worker_active_jobs` | Worker jobs currently running. |
| `tardigrade_worker_queued_jobs` | Worker jobs waiting in queues. |

See [OBSERVABILITY.md](OBSERVABILITY.md) for full metric and logging details,
and [examples/graceful-reload](../examples/graceful-reload/README.md) for a
copy/paste runnable local workflow.
