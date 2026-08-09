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

When run with `--tool k6`, the full suite also includes:

| Scenario | Purpose |
| --- | --- |
| `idle-keepalive-active-traffic` | Many idle keep-alive clients plus active traffic. |

Connection churn is automated for the default `wrk` tool. Other load tools skip
that scenario and print the manual workflow.

`--smoke` intentionally runs a single Tardigrade-only static pass so CI can
validate process startup, measurement, normalization, and output generation
without requiring competitor binaries.

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
        "errors": 0
      }
    }
  }
}
```

Only compare rows from the same output directory. Cross-run comparisons are
valid only when host load, tool versions, server versions, and run parameters
match.
