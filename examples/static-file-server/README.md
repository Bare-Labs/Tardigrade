# Static File Server

Serves static files from a local directory over plain HTTP.

## What it demonstrates

- Plain-HTTP listener on port 8080 (no TLS).
- Document root with `root` and `try_files` for SPA-style fallback routing.
- Edge-side health check at `/health` with no upstream hop.

## Quick start

```bash
# Create a minimal document root
mkdir -p ./public
echo '<h1>Hello from Tardigrade</h1>' > ./public/index.html

# Build and run
zig build
TARDIGRADE_CONFIG_PATH=examples/static-file-server/tardigrade.conf ./zig-out/bin/tardi

# Smoke-test
curl http://localhost:8080/
curl http://localhost:8080/health
curl http://localhost:8080/missing  # falls back to ./public/index.html
```

## Key directives

| Directive | Purpose |
|-----------|---------|
| `listen 8080;` | Bind on port 8080, plain HTTP. |
| `root ./public;` | Document root for file serving. |
| `try_files $uri /index.html;` | Fall back to `index.html` when the file is not found. |
| `return 200 ok;` | Reply immediately from the edge without an upstream hop. |

## Notes

- No TLS, no upstream — suitable for internal or local development serving.
- For HTTPS, see [examples/tls-termination](../tls-termination/README.md).
- For reverse proxying to a local app, see [examples/reverse-proxy](../reverse-proxy/README.md).
