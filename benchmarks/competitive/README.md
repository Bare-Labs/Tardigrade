# Competitive Benchmarks

This directory contains the local competitive benchmark suite for comparing
Tardigrade against representative NGINX, HAProxy, and Caddy configurations.

The suite is designed for repeatability, not for publishing laptop-local claims.
Run canonical comparisons on a dedicated, idle host with the same load tool,
connection count, duration, kernel limits, and server versions for every target.

## Quick Start

```bash
# Full local comparison, fails if any selected competitor is missing.
./benchmarks/competitive/run.sh

# Print exact manual steps without starting processes.
./benchmarks/competitive/run.sh --print-manual

# Reduced single-pass smoke path suitable for optional CI wiring.
./benchmarks/competitive/run.sh --smoke
```

The default suite uses `wrk` through `benchmarks/run.sh`, starts one server at a
time, and writes:

- `competitive-results.json`
- `competitive-results.csv`
- `competitive-summary.md`
- one normalized JSON file per server
- raw per-pass JSON files for debugging

Use `--out-dir <dir>` to choose a stable output location.

## Prerequisites

Required for all runs:

- `jq`
- `curl`
- `python3`
- one load tool, `wrk` by default
- Zig 0.16.0 when the Tardigrade binary must be built

Required for full non-smoke runs:

- `k6`, used for the idle keep-alive clients plus active traffic scenario
- `openssl` and `nghttpd`, used for the upstream TLS handshake/reuse phase

Required for the full default competitor set:

- `nginx`
- `haproxy`
- `caddy`

Use `--allow-missing` for exploratory local runs that should skip missing
competitors. Do not treat skipped-target results as a complete comparison.

## Scenario Matrix

The automated suite records these HTTP/1.1 scenarios for each selected server:

| Scenario | Purpose |
| --- | --- |
| `static-tiny-http1` | Tiny static file throughput. |
| `static-tiny-keepalive` | Tiny static file keep-alive reuse. |
| `static-large-http1` | 1 MiB static file transfer throughput. |
| `proxy-small-http1` | Reverse proxy small response throughput. |
| `proxy-large-http1` | Reverse proxy 1 MiB response throughput. |
| `proxy-slow-client-download` | Reverse proxy download through rate-limited clients. |
| `connection-churn-http1` | Tiny static file throughput with `Connection: close`. |

The full suite also runs this auxiliary k6 scenario independent of the primary
throughput tool:

| Scenario | Purpose |
| --- | --- |
| `idle-keepalive-active-traffic` | Many idle keep-alive clients plus active traffic. |

Connection churn is automated for the default `wrk` tool. Other load tools skip
that scenario and print the manual workflow.

`--smoke` intentionally runs a single Tardigrade-only static pass so CI can
validate process startup, measurement, normalization, and output generation
without requiring competitor binaries.

HAProxy does not emit a comparable `static-large-http1` row because the
representative `http-request return file` path is bounded by HAProxy response
buffer size and is not valid for a 1 MiB static file. The suite records that row
as unsupported instead of manufacturing a misleading number.

Full Tardigrade runs also write `upstream-pool-matrix.json` and embed the same
data in `competitive-results.json`, `competitive-results.csv`, and
`competitive-summary.md`. The matrix covers the #147 workloads absorbed by
#149: uneven route traffic, many low-volume origins, one hot origin with many
workers, upstream TLS handshake/reuse, local vs cross-worker reuse, new upstream
connections/sec, CPU/request, p99 latency, and higher-worker contention
evidence. `p99_ttfb_ms` remains null until a first-byte-capable load tool is
wired into that path.

## Configs

Representative config templates live under `configs/`:

- `tardigrade.conf.in`
- `nginx.conf.in`
- `haproxy.cfg.in`
- `Caddyfile.in`

The runner renders these templates into a temporary directory with a shared
static root and shared upstream fixture. Keep changes minimal and explain any
non-default tuning in the template or this README. The goal is fair comparison,
not benchmark-specialized tuning.

## Interpreting Results

The combined JSON shape is:

```json
{
  "_meta": { "suite": "competitive" },
  "servers": {
    "tardigrade": {
      "static-tiny-http1": {
        "rps": 1234,
        "p50_ms": 1.2,
        "p95_ms": 2.3,
        "p99_ms": 3.4,
        "p999_ms": 4.5,
        "throughput_mbps": 10.1,
        "cpu_pct_avg": 50.0,
        "rss_mb_peak": 25.0,
        "open_fds_peak": 128,
        "errors": 0
      }
    }
  },
  "upstream_pool_matrix": { "scenarios": {} }
}
```

Only compare rows from the same output directory. Cross-run comparisons are
valid only when host load, tool versions, server versions, ulimits, loopback
metadata, build flags, and run parameters match.
