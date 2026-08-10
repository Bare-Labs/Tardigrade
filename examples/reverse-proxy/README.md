# Reverse Proxy

Forwards HTTP requests to a local application server without TLS.

## What it demonstrates

- Plain-HTTP listener acting as a reverse proxy.
- Edge-side `/health` liveness probe with no upstream hop.
- Prefix-based routing: `/api/` forwards to the upstream `/api/` path.
- Fallback `location /` routes everything else to the upstream root.

## Quick start

```bash
# Start a simple upstream on port 3000
python3 -m http.server 3000 &

# Build and run Tardigrade
zig build
TARDIGRADE_CONFIG_PATH=examples/reverse-proxy/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:3000 \
./zig-out/bin/tardi

# Smoke-test
curl http://localhost:8080/health   # → 200 ok (served from edge)
curl http://localhost:8080/         # → proxied to upstream
```

## Key directives

| Directive | Purpose |
|-----------|---------|
| `proxy_pass /path/;` | Forward the request to the upstream at the given path. |
| `return 200 ok;` | Respond immediately without hitting the upstream. |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_UPSTREAM_BASE_URL` | `http://127.0.0.1:8080` | Base URL of the upstream application. |
| `TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS` | `2000` | Max time to establish a connection to the upstream. |
| `TARDIGRADE_PROXY_READ_TIMEOUT_MS` | `30000` | Max time to read a complete upstream response. |

## Notes

- For TLS termination in front of this pattern, see [examples/tls-termination](../tls-termination/README.md).
- For upstream health checks, see [examples/health-checks](../health-checks/README.md).
- The upstream URL is set via `TARDIGRADE_UPSTREAM_BASE_URL`; it is not embedded in the conf file so that the same config works across environments.
