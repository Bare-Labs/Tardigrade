# Virtual Hosts / Routes

Routes traffic to different upstreams based on the `Host` header using named server blocks.

## What it demonstrates

- Multiple `server {}` blocks each bound to a specific hostname (`server_name`).
- Per-host document roots, upstream URLs, and location routing rules.
- A shared edge-level `/health` liveness endpoint.
- Prefix routing within each virtual host (`/v1/`, `/api/`).

## Quick start

```bash
# Start two dummy upstreams
python3 -m http.server 9001 &
python3 -m http.server 9002 &

# Build and run Tardigrade
zig build
TARDIGRADE_CONFIG_PATH=examples/virtual-hosts/tardigrade.conf \
./zig-out/bin/tardi &

# Smoke-test each virtual host
curl -H 'Host: api.example.com' http://localhost:8080/health
curl -H 'Host: app.example.com' http://localhost:8080/health
```

## Key directives

| Directive | Scope | Purpose |
|-----------|-------|---------|
| `server { ... }` | block | Groups settings for a single virtual host. |
| `server_name <hostname>;` | server block | The `Host` header value this block matches. |
| `upstream_base_url <url>;` | server block | The upstream to proxy requests to for this host. |
| `root <path>;` | server block | Document root for static file serving. |
| `try_files $uri /index.html;` | server block | Fallback routing for SPAs. |

## Notes

- Each server block can have its own TLS certificate for SNI-based HTTPS. Add `tls_cert_path` and `tls_key_path` inside the `server {}` block.
- For a single-host HTTPS deployment, see [examples/tls-termination](../tls-termination/README.md).
- Server blocks without `tls_cert_path`/`tls_key_path` serve HTTP only (or inherit the global TLS config if `listen <port> ssl;` is used).
