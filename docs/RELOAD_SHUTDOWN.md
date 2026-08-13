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
   native early-data replay mode/capacity, or native ticket-key source mode.
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

Expected shutdown logs include:

```text
Shutdown requested; draining active connection work (timeout=30000ms active_connections=...)
drain timeout elapsed; force-closed N queued connection(s)
Graceful shutdown complete (forced_closes=N drain_timed_out=true)
```

Related knobs:

| Env var | Default | Effect |
| --- | ---: | --- |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | `30000` | TCP worker-pool drain window and native HTTP/3 drain deadline for graceful shutdown. |
| `TARDIGRADE_WORKER_THREADS` | `0` | Worker thread count; `0` uses the runtime default. |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | `1024` | Worker queue capacity. |
| `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` | `0` | Optional per-worker queue depth cap (`0` means unlimited beyond queue capacity behavior). |

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
| `tardigrade_drain_timeouts_total` | Drains that reached the drain timeout. |
| `tardigrade_drain_forced_closes_total` | Queued connections force-closed after drain timeout. |
| `tardigrade_active_connections` | Currently accepted downstream connections. |
| `tardigrade_worker_active_jobs` | Worker jobs currently running. |
| `tardigrade_worker_queued_jobs` | Worker jobs waiting in queues. |

See [OBSERVABILITY.md](OBSERVABILITY.md) for full metric and logging details,
and [examples/graceful-reload](../examples/graceful-reload/README.md) for a
copy/paste runnable local workflow.
