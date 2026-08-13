# Graceful Reload / Drain

Hot-reloads configuration without dropping in-flight requests and drains connections on shutdown.

## What it demonstrates

- Hot reload via `tardi reload` (SIGHUP): new requests use the updated config immediately; existing in-flight requests finish on the old config.
- Graceful shutdown via `tardi stop`: stops accepting new connections and waits up to `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` for worker jobs to drain.
- PID file for signal-based process management with init systems.

## Quick start

```bash
# Start a backend
python3 -m http.server 8081 &

# Build and run Tardigrade
zig build
TARDIGRADE_CONFIG_PATH=examples/graceful-reload/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8081 \
TARDIGRADE_PID_FILE=/tmp/tardigrade.pid \
./zig-out/bin/tardi &

# Confirm it is running
curl http://localhost:8080/health

# Edit this config file, then hot-reload — no downtime
./zig-out/bin/tardi reload --pid-file /tmp/tardigrade.pid

# Graceful stop — waits for worker jobs to drain
./zig-out/bin/tardi stop --pid-file /tmp/tardigrade.pid
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_PID_FILE` | `""` | Path to the PID file. Required for `tardi reload` and `tardi stop`. |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | `30000` | Max time in ms to wait for worker jobs to drain on shutdown. |

See `tardigrade.env.example` for the full list with comments.

## Reload vs restart

| Action | Command | Behavior |
|--------|---------|---------|
| Hot reload | `tardi reload --pid-file <path>` | Applies config changes; in-flight requests finish on the old config. Zero downtime. |
| Graceful stop | `tardi stop --pid-file <path>` | Stops accepting new connections; drains in-flight requests up to the drain timeout. |
| Status check | `tardi status --pid-file <path>` | Prints running/stopped state, PID or PID-file information, and the effective config summary. |

For the full lifecycle contract, including failed reloads, upstream pools,
queued worker jobs, and hard termination, see
[docs/RELOAD_SHUTDOWN.md](../../docs/RELOAD_SHUTDOWN.md).

## systemd integration

The included drain timeout works with `TimeoutStopSec=` in a systemd unit file. Set both to the same value so systemd does not kill Tardigrade before the drain completes:

```ini
[Service]
TimeoutStopSec=35
ExecStop=/usr/local/bin/tardi stop --pid-file /run/tardigrade/tardigrade.pid
Environment=TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS=30000
Environment=TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid
```
