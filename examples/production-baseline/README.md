# Production-Hardened Baseline

A complete edge deployment combining TLS, security headers, rate limiting, structured access logging, Prometheus metrics, upstream health checks, and graceful drain.

## What it demonstrates

- HTTPS on unprivileged port 8443 for local testing, with TLS 1.2+ enforcement.
- HSTS (`Strict-Transport-Security`) and standard security response headers.
- Rate limiting at 100 rps per client with a burst allowance of 30.
- JSON access logs buffered for throughput.
- Prometheus metrics at `/status/metrics`.
- Active upstream health checking with fail/recovery thresholds.
- PID file and configurable drain timeout for init-system integration.

## Quick start

Generate a self-signed certificate for local testing:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/server.key -out /tmp/server.crt -days 1 -nodes \
  -subj '/CN=localhost'
```

Start a backend:

```bash
python3 -m http.server 8080 &
```

Run Tardigrade with the baseline environment values:

```bash
zig build
cp examples/production-baseline/tardigrade.env.example /tmp/tardigrade-production.env
set -a && source /tmp/tardigrade-production.env && set +a
TARDIGRADE_TLS_CERT_PATH=/tmp/server.crt \
TARDIGRADE_TLS_KEY_PATH=/tmp/server.key \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080 \
TARDIGRADE_CONFIG_PATH=examples/production-baseline/tardigrade.conf \
./zig-out/bin/tardi &
```

Smoke-test:

```bash
curl -k https://localhost:8443/health          # → 200 ok
curl -k https://localhost:8443/status/metrics  # → Prometheus text
```

## Pre-production checklist

- [ ] Replace `/etc/tardigrade/tls/fullchain.pem` and `privkey.pem` with a real certificate from a public CA.
- [ ] Change `listen 8443 ssl;` or `TARDIGRADE_LISTEN_PORT=8443` to `443` once the service has permission to bind privileged ports.
- [ ] Set `TARDIGRADE_HSTS_ENABLED=true` after confirming TLS works.
- [ ] Set `TARDIGRADE_RATE_LIMIT_RPS` and `TARDIGRADE_RATE_LIMIT_BURST` to match your traffic profile.
- [ ] Restrict `/status/metrics` with a firewall rule or `TARDIGRADE_METRICS_REQUIRE_AUTH=true`.
- [ ] Set `TARDIGRADE_PID_FILE` to a path your init system can write to (e.g. `/run/tardigrade/tardigrade.pid`).
- [ ] Set `TimeoutStopSec` slightly above `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` in your systemd unit.

## Notes

- Do not commit the live `tardigrade.env.example` copy — it contains path references that differ per host and may contain future credential additions.
- TLS 1.0 and 1.1 are not supported. The minimum accepted version is 1.2.
- For multiple virtual hosts with per-host certificates, see [examples/virtual-hosts](../virtual-hosts/README.md).
- For a complete systemd service file, see [packaging/systemd/tardigrade.service](../../packaging/systemd/tardigrade.service).
