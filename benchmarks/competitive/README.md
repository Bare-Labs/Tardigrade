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
- `openssl`, used to generate the local certificate for the upstream TLS
  handshake/reuse phase

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
evidence. `p99_ttfb_ms` is collected with k6 for the rows that require
first-byte timing evidence.

## Configs

Representative config templates live under `configs/`:

- `tardigrade.conf.in` — plaintext HTTP/1.1, used for the cross-server comparison.
- `tardigrade-http3.conf.in` — TLS + HTTP/3 enabled, used only for the
  Tardigrade-only H3 matrix (see [HTTP/3/QUIC Benchmarking](#http3quic-benchmarking-256-g)).
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

`host.network.udp_buffers` records the host-wide ceilings on per-socket UDP
buffers (`net.core.rmem_max`/`wmem_max` on Linux, `kern.ipc.maxsockbuf` on
macOS and the BSDs) alongside whatever `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES`
/ `TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES` asked for. A QUIC run whose receive
buffer filled shows up as loss in the results, so the limit that bounded it
belongs next to the numbers it explains — and a request the kernel clamped
makes two runs incomparable even with identical configuration. The size the
listener actually got is read back with `getsockopt` and logged by the runtime
at startup; only the process can see it. See `docs/HTTP3_ROLLOUT.md`.

## HTTP/3/QUIC Benchmarking (#256-G)

This extends the same framework above with H3/QUIC-specific rows — it is not
a second benchmark runner. Everything in [Quick Start](#quick-start),
[Prerequisites](#prerequisites), and [Interpreting Results](#interpreting-results)
still applies; this section only covers what's different for HTTP/3.

Transport-level guidance (datagram sizing, DPLPMTUD, black-hole fallback,
socket buffer tuning, ECN, pacing, and future batching/GSO/GRO plans) lives in
[docs/HTTP3_ROLLOUT.md](../../docs/HTTP3_ROLLOUT.md) — it is not repeated here.

### Requirements

- An **H3-capable `h2load`** build: nghttp2 built with QUIC support against
  ngtcp2 + nghttp3. The stock `apt`/`brew` `nghttp2` package usually is not
  this build. Verify with:

  ```bash
  h2load --h3 --help >/dev/null && echo "h2load supports HTTP/3" || echo "h2load does NOT support HTTP/3"
  ```

  Without it, every H3 row is recorded as `"supported": false` with a
  `"reason"` explaining why — never silently skipped, never a fabricated
  number.
- `openssl`, to generate a **benchmark-only local TLS identity** fresh for
  each run via `scripts/interop/gen-certs.sh` (never a checked-in or
  developer-machine certificate path).

### What the H3 matrix does

`benchmarks/competitive/run.sh` starts a **second**, dedicated Tardigrade
listener — TLS + HTTP/3 enabled, a deterministic QUIC port
(`LISTEN_BASE + 250` by default), a static route, a reverse-proxy route, and
`/status/metrics` enabled — alongside whatever plaintext HTTP/1.1 comparison
is already running. Starting the process is not treated as proof HTTP/3
works: after the TLS/TCP side answers `/health`, the runner sends one real
HTTP/3 request through `h2load --h3` and only records H3 results if that
succeeds.

Client capability and Tardigrade's own H3 health are checked, and reported,
separately:

- **`h2load` cannot speak HTTP/3 at all** (no QUIC-enabled build on this
  host) is checked *first*, before Tardigrade's H3 listener is even
  started. This is a legitimate environment limitation, not a Tardigrade
  problem — every H3 row for the run is written as `"supported": false`
  with the reason, and the run continues normally (exit 0).
- **`h2load` supports HTTP/3, but Tardigrade's listener doesn't come up or
  doesn't answer a real request** (TLS/TCP side never opens, or the H3
  readiness request fails) is a product regression, not an environment
  limitation. It is never written as a soft `"supported": false` row — the
  listener's `server.log`/`error.log` are dumped for diagnosis and the run
  fails outright, so a real H3 regression can't hide behind a green run.
  The same split applies to the opt-in tuned-buffer listener: once the
  baseline H3 pass has already proven client capability and a working
  listener, a tuned-listener failure is also a hard failure, not a skipped
  row.

This runs for the `tardigrade` server whenever it's selected — including
under `--smoke`, where it's bounded to a single short `static-small-http3`
pass (config renders, Tardigrade launches with TLS+H3, one real H3 request
succeeds) with the large/proxy/tuned rows skipped.

### Canonical H3 rows

| Scenario | Purpose |
| --- | --- |
| `static-small-http3` | Small static object (`/tiny.txt`, 3 bytes) — request/response overhead. |
| `static-large-http3` | Large static object (`/large.bin`, 1 MiB). |
| `proxy-large-http3` | 1 MiB reverse-proxied response, client-facing HTTP/3, streamed through the existing proxy path to the local origin fixture (not fully buffered). |
| `static-small-http3-tuned` | Same as `static-small-http3`, but the listener was started with explicit larger `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES`/`_SEND_BUFFER_BYTES`. Only recorded with `--tune-comparison`. |

Each supported H3 row carries a `quic` sub-object (scraped from
`/status/metrics` right after the pass finishes):

```json
{
  "rps": 1234,
  "p99_ms": 3.4,
  "quic": {
    "packets_sent": 50000,
    "packets_received": 49998,
    "packets_lost": 2,
    "pto_total": 0,
    "bytes_sent": 62914560,
    "bytes_received": 1500,
    "effective_plpmtu": { "last_bytes": 1452, "lifetime_min_bytes": 1200, "lifetime_max_bytes": 1452 },
    "pmtu_probes": 3,
    "pmtu_black_holes": 0,
    "ecn": { "enabled": true, "marked_sent": 50000, "paths_validated": 8, "paths_disabled": 0, "ce_received": 0 },
    "udp_buffers": {
      "recv": { "requested_bytes": 0, "effective_bytes": 212992, "granted_bytes": 0, "status": "default" },
      "send": { "requested_bytes": 0, "effective_bytes": 212992, "granted_bytes": 0, "status": "default" }
    }
  }
}
```

`effective_plpmtu.lifetime_min_bytes`/`lifetime_max_bytes` are named that way
deliberately: they never reset and are **not** scoped to any single
scenario or pass — the same H3 listener is reused across the small/large/
proxy rows in one run, so `lifetime_min_bytes` reads 1200 forever after the
first connection's startup fold regardless of what every later path
converged to. Do not read them as evidence that paths converged (or didn't)
within one benchmark row; `last_bytes` (the active-path PLPMTU of whichever
connection most recently folded) is the closer proxy for "what this pass
saw." See [docs/HTTP3_ROLLOUT.md](../../docs/HTTP3_ROLLOUT.md#path-mtu-discovery).

`requested_bytes`/`effective_bytes`/`granted_bytes` are never inferred from
each other — `effective_bytes` is the raw `getsockopt` readback,
`granted_bytes` restates it in requested units (see
[docs/HTTP3_ROLLOUT.md#socket-buffers](../../docs/HTTP3_ROLLOUT.md#socket-buffers)
for why Linux needs that distinction), and `status` says whether the request
was granted, clamped, refused, or nothing was requested at all. `0` in a
`_bytes` field means "not requested" or "not read back," never a real socket
buffer size. The combined `competitive-results.csv`/`.md` also carry a subset
of these fields as columns/a dedicated "H3/QUIC Transport State" table.

### Before/after transport-tuning comparison

```bash
./benchmarks/competitive/run.sh --servers tardigrade --tune-comparison
```

Adds `static-small-http3-tuned`, restarting the H3 listener with explicit
4 MiB `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES`/`_SEND_BUFFER_BYTES` requests.
Compare its `quic.udp_buffers.*.status` against the baseline
`static-small-http3` row to see whether the larger request was actually
granted (`applied`) or clamped by a host ceiling — and compare `rps`/
`p99_ms`/`cpu_ms_per_request`/`quic.packets_lost`/`quic.pto_total` to see
whether it mattered. "No meaningful improvement" is a valid, expected result
on an idle loopback host with a small BDP; the comparison exists to show
that, not to manufacture a win.

### Controlled loss and reordering

Linux-only, manual, and never run in default or scheduled CI —
`benchmarks/competitive/netem-impair.sh` wraps a command with a `tc netem`
qdisc, requires root/`CAP_NET_ADMIN` (reports the scenario as **not
executed**, not a fabricated result, if that's missing), records the exact
`tc` command used, and always removes the qdisc on exit — including on
failure or Ctrl-C:

```bash
sudo benchmarks/competitive/netem-impair.sh \
  --loss 1 --reorder 25 --delay 20 --interface lo \
  --evidence-file benchmarks/competitive/results/netem-loss-reorder.json \
  -- benchmarks/competitive/run.sh --servers tardigrade
```

`--reorder` requires `--delay` (netem defines reordering relative to a
delayed stream). The evidence file records `loss_percent`, `reorder_percent`,
`delay_ms`, `interface`, and the exact `tc` command — cross-reference it with
the benchmark JSON's `quic.packets_lost`/`pto_total` from the same run.

### High-bandwidth / dedicated-host runs

For stressing the H3 syscall/packet path at high throughput — belongs on a
dedicated, idle host (a Beelink-class box or comparable), not shared CI
hardware:

```bash
./benchmarks/competitive/run.sh --servers tardigrade \
  --duration 60 --connections 200 --threads 8 --tune-comparison
```

`_meta.host` in the combined JSON records what the numbers are scoped to:
CPU model/cores, OS/kernel, loopback interface, `tardigrade.build_flags`
(release mode), and — per-scenario — `h2load.version`/`h2load.h3_supported`,
concurrency/duration, host UDP sysctls, and every Tardigrade transport
setting captured in `quic`. Do not publish a throughput claim from this
without that metadata attached; it describes one host and one configuration,
not Tardigrade in general.

### CI execution model

Default PR CI (`.github/workflows/ci.yml`'s `perf-smoke` job, driven by
`benchmarks/ci-smoke.sh`) stays HTTP/1.1-only and does not invoke any of the
above against a live server — it has no H3-capable `h2load` installed and is
not the place for QUIC evidence. `benchmarks/competitive/run.sh --smoke` (see
above) is a bounded, manually-triggered H3 sanity check against a real
process, not a default CI gate. Full throughput, loss/reordering,
high-bandwidth, and tuned-comparison runs are scheduled/manual only — see the
GitHub Actions workflow for the manual H3 matrix job.

The `perf-smoke` job does run `benchmarks/test-h3-benchmark.sh` on every PR,
though: it stubs `h2load`/`tc`/Tardigrade throughout, so it never starts a
real server or touches the network, and instead proves the harness's own
logic stays correct — H3 config rendering, scenario-local QUIC delta
computation (not listener-lifetime cumulative totals), `--runs > 1`
aggregation, the unsupported-h2load-vs-broken-listener distinction, pass
renaming, and CSV/Markdown output. The Lint job's shellcheck step also covers
`benchmarks/run.sh`, `benchmarks/competitive/run.sh`,
`benchmarks/competitive/netem-impair.sh`, and `benchmarks/test-h3-benchmark.sh`
(the rest of `benchmarks/` is not swept yet).
