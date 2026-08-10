# Graceful Reload / Drain

Hot-reloads configuration without dropping in-flight requests and drains connections on shutdown.

## What it demonstrates

- Hot reload via `tardi reload` (SIGHUP): new requests use the updated config immediately; existing in-flight requests finish on the old config.
- Graceful shutdown via `tardi stop`: waits up to `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` for in-flight requests to complete before closing connections.
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
./zig-out/bin/tardi reload -c examples/graceful-reload/tardigrade.conf

# Graceful stop — waits for in-flight requests to finish
./zig-out/bin/tardi stop -c examples/graceful-reload/tardigrade.conf
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_PID_FILE` | `""` | Path to the PID file. Required for `tardi reload` and `tardi stop`. |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | `30000` | Max time in ms to wait for in-flight requests to finish on shutdown. |

See `tardigrade.env.example` for the full list with comments.

## Reload vs restart

| Action | Command | Behavior |
|--------|---------|---------|
| Hot reload | `tardi reload -c <config>` | Applies config changes; in-flight requests finish on the old config. Zero downtime. |
| Graceful stop | `tardi stop -c <config>` | Stops accepting new connections; drains in-flight requests up to the drain timeout. |
| Status check | `tardi status -c <config>` | Prints the current process state (config path, uptime, worker count). |

## systemd integration

The included drain timeout works with `TimeoutStopSec=` in a systemd unit file. Set both to the same value so systemd does not kill Tardigrade before the drain completes:

```ini
[Service]
TimeoutStopSec=35
ExecStop=/usr/local/bin/tardi stop -c /etc/tardigrade/tardigrade.conf
Environment=TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS=30000
```
