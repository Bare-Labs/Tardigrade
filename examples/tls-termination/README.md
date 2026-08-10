# TLS Termination

Terminates HTTPS at the edge and forwards plain HTTP to an upstream application.

## What it demonstrates

- HTTPS listener on port 443 using `listen 443 ssl;`.
- TLS certificate and private key configured in the conf file.
- Forwarding decrypted traffic to an upstream over plain HTTP.
- Edge-side `/health` liveness probe (no upstream hop).

## Quick start

Generate a self-signed certificate for local testing:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/server.key -out /tmp/server.crt -days 1 -nodes \
  -subj '/CN=localhost'
```

Start a backend on port 8080:

```bash
python3 -m http.server 8080 &
```

Run Tardigrade:

```bash
zig build
TARDIGRADE_TLS_CERT_PATH=/tmp/server.crt \
TARDIGRADE_TLS_KEY_PATH=/tmp/server.key \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080 \
TARDIGRADE_CONFIG_PATH=examples/tls-termination/tardigrade.conf \
./zig-out/bin/tardi
```

Smoke-test:

```bash
curl -k https://localhost/health   # → 200 ok
curl -k https://localhost/         # → proxied upstream response
```

## Key directives

| Directive | Purpose |
|-----------|---------|
| `listen 443 ssl;` | Bind on port 443 with TLS enabled. |
| `tls_cert_path <path>;` | Path to the PEM certificate chain (leaf + intermediates). |
| `tls_key_path <path>;` | Path to the PEM private key. |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_TLS_CERT_PATH` | `""` | Overrides `tls_cert_path` in the conf file. |
| `TARDIGRADE_TLS_KEY_PATH` | `""` | Overrides `tls_key_path` in the conf file. |
| `TARDIGRADE_TLS_MIN_VERSION` | `1.2` | Minimum accepted TLS version (`1.2` or `1.3`). |
| `TARDIGRADE_UPSTREAM_BASE_URL` | `http://127.0.0.1:8080` | Upstream application base URL. |

See `tardigrade.env.example` for the full set of tunable knobs.

## Notes

- For a production HTTPS deployment, obtain a certificate from a public CA (e.g. Let's Encrypt) and replace the self-signed cert.
- TLS 1.0 and 1.1 are not supported. The minimum accepted version is 1.2.
- For multiple virtual hosts with per-host certificates, see [examples/virtual-hosts](../virtual-hosts/README.md).
