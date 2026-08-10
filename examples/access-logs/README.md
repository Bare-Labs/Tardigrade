# Access Logs

Emits structured JSON access logs for every request.

## What it demonstrates

- JSON access logging to stdout (compatible with log shippers such as Fluent Bit, Vector, and Promtail).
- Status-based filtering to suppress healthy-request noise.
- Optional syslog UDP forwarding for centralized log aggregation.
- Custom log format via template strings.

## Quick start

```bash
# Start a backend
python3 -m http.server 8081 &

# Build and run Tardigrade with JSON access logs
zig build
TARDIGRADE_CONFIG_PATH=examples/access-logs/tardigrade.conf \
TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8081 \
TARDIGRADE_ACCESS_LOG_FORMAT=json \
TARDIGRADE_ACCESS_LOG_MIN_STATUS=400 \
./zig-out/bin/tardi &

# Generate a few requests; successful responses are filtered from the log
curl http://localhost:8080/
curl http://localhost:8080/health
curl http://localhost:8080/missing
```

Example JSON log line:

```json
{"ts":"2026-01-01T00:00:00.000Z","method":"GET","uri":"/missing","status":404,"bytes":42,"ms":1.2,"id":"abc123","remote":"127.0.0.1","upstream":"127.0.0.1:8081"}
```

## Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARDIGRADE_ACCESS_LOG_FORMAT` | `json` | Log format: `json`, `plain`, or `custom`. |
| `TARDIGRADE_ACCESS_LOG_MIN_STATUS` | `0` (all) | Only log responses at or above this status code. |
| `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` | `0` (unbuffered) | Write-buffer size in bytes. |
| `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP` | `""` (disabled) | Syslog UDP endpoint (`host:port`). |
| `TARDIGRADE_ACCESS_LOG_TEMPLATE` | `""` | Template string for `custom` format. |

See `tardigrade.env.example` for the full list with comments.

## Notes

- Unbuffered output (`TARDIGRADE_ACCESS_LOG_BUFFER_SIZE=0`) is safest under systemd journald, which already buffers writes.
- To suppress `/health` noise, set `TARDIGRADE_ACCESS_LOG_MIN_STATUS=400` to log only errors.
- Log output goes to stdout; redirect or capture it with your init system or container runtime.
