# Upstream Health Checks

Removes unhealthy backends from rotation automatically and restores them when they recover.

## What it demonstrates

- Pool of multiple upstream replicas via `TARDIGRADE_UPSTREAM_BASE_URLS`.
- Active health probing: Tardigrade periodically sends a probe request to each
  upstream and tracks its status.
- Automatic failover: a backend that fails the configured threshold of
  consecutive probes is removed from the pool until it recovers.

## Quick start

```bash
# Start two simple upstreams
python3 -m http.server 3001 &
python3 -m http.server 3002 &

# Build and run Tardigrade with health checking enabled
zig build
TARDIGRADE_CONFIG_PATH=examples/health-checks/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URLS=http://127.0.0.1:3001,http://127.0.0.1:3002 \
TARDIGRADE_UPSTREAM_PROBE_PATH=/ \
TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=5000 \
./zig-out/bin/tardi

# Stop one upstream and watch Tardigrade route around it
kill %2
curl http://localhost:8080/   # still served by the remaining backend
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_UPSTREAM_BASE_URLS` | — | Comma-separated list of upstream base URLs. |
| `TARDIGRADE_UPSTREAM_PROBE_PATH` | `/` | Path probed on each upstream for liveness. |
| `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS` | `0` (disabled) | Interval between probes in milliseconds. |
| `TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS` | `2000` | Timeout for a single probe in milliseconds. |
| `TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD` | `1` | Consecutive failures before a backend is removed. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD` | `1` | Consecutive successes before a backend is restored. |
| `TARDIGRADE_UPSTREAM_LB_ALGORITHM` | `round_robin` | Load-balancing algorithm (`round_robin`, `least_connections`, `ip_hash`, `random_two_choices`). |

See `tardigrade.env.example` for the complete list with comments.

## Notes

- Setting `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=0` disables active health checking; requests still fail-fast on connection errors.
- The conf file itself does not configure the upstream pool; use `TARDIGRADE_UPSTREAM_BASE_URLS` (comma-separated) or `TARDIGRADE_UPSTREAM_BASE_URL` (single URL).
