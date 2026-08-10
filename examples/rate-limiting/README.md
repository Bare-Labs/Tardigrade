# Rate Limiting

Caps the request rate per client identity to protect upstreams from traffic spikes.

## What it demonstrates

- Per-client rate limiting via a token-bucket algorithm.
- Identity-aware keying: authenticated requests (JWT/bearer token) are limited by identity; unauthenticated requests are limited by IP address.
- Burst allowance so short spikes do not trigger immediate 429 responses.

## Quick start

```bash
# Start a backend
python3 -m http.server 8081 &

# Build and run Tardigrade with rate limiting enabled
zig build
TARDIGRADE_CONFIG_PATH=examples/rate-limiting/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8081 \
TARDIGRADE_RATE_LIMIT_RPS=60 \
TARDIGRADE_RATE_LIMIT_BURST=20 \
./zig-out/bin/tardi &

# Trigger the rate limit
for i in $(seq 1 100); do curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/; done
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_RATE_LIMIT_RPS` | `10` | Sustained ceiling in requests per second. Set to `0` to disable. |
| `TARDIGRADE_RATE_LIMIT_BURST` | `20` | Burst headroom above the RPS ceiling. |

## Notes

- Rate limiting is keyed on the resolved client identity for authenticated requests and on the source IP for unauthenticated traffic.
- Clients that exceed the limit receive `429 Too Many Requests`.
- Idle token-bucket state is evicted automatically so memory stays bounded under high-churn client populations.
- The default RPS is 10. Set `TARDIGRADE_RATE_LIMIT_RPS=0` to disable rate limiting entirely (not recommended in production).
