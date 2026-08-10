# Prometheus Metrics

Exposes a Prometheus-compatible metrics endpoint for monitoring and alerting.

## What it demonstrates

- Built-in Prometheus text-format metrics endpoint at `/status/metrics`.
- Configurable path and optional auth protection.
- Metrics include request counts, latency histograms, upstream pool health, and TLS statistics.

## Quick start

```bash
# Start a backend
python3 -m http.server 8081 &

# Build and run Tardigrade
zig build
TARDIGRADE_CONFIG_PATH=examples/prometheus-metrics/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8081 \
./zig-out/bin/tardi &

# Scrape the metrics endpoint
curl http://localhost:8080/status/metrics
```

Example output:

```
# HELP tardigrade_requests_total Total number of requests handled
# TYPE tardigrade_requests_total counter
tardigrade_requests_total{method="GET",status="200"} 42
...
```

## Prometheus scrape config

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: tardigrade
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /status/metrics
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_METRICS_PATH` | `/status/metrics` | Path where metrics are served. Set to `""` to disable. |
| `TARDIGRADE_METRICS_REQUIRE_AUTH` | `false` | Require authentication before serving metrics. |

See `tardigrade.env.example` for the full list with comments.

## Notes

- The metrics endpoint is served on the same listener as application traffic. Restrict access to it with a firewall rule or by setting `TARDIGRADE_METRICS_REQUIRE_AUTH=true` in production.
- To move metrics to a dedicated internal port, run a second Tardigrade instance on a loopback-only listener with `TARDIGRADE_LISTEN_HOST=127.0.0.1` and point your Prometheus scraper there.
