# HTTP/3 Validation Evidence

This document is the closeout map for #247. It connects release-critical
QUIC/H3 failure and lifecycle invariants to their proof of record, then defines
the remaining evidence runs that must be attached before native HTTP/3 can be
promoted beyond the current experimental support status.

This is not a second interop runner, fuzz framework, benchmark harness, or
transport implementation. Use the existing owners:

- deterministic QUIC/H3 parser and state proof:
  [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md)
- production rollout, drain, GOAWAY, UDP sizing, PLPMTUD, ECN, and socket
  diagnostics: [HTTP3_ROLLOUT.md](HTTP3_ROLLOUT.md)
- external peer matrix: [scripts/interop/README.md](../scripts/interop/README.md)
- H3 benchmark harness and result schema:
  [benchmarks/README.md](../benchmarks/README.md) and
  [benchmarks/competitive/README.md](../benchmarks/competitive/README.md)
- opt-in qlog/keylog behavior: [OBSERVABILITY.md](OBSERVABILITY.md) and
  [QUIC_QLOG.md](QUIC_QLOG.md)

## Failure and Lifecycle Matrix

| Invariant | Proof of record | Level | #247 status | Remaining composition gap |
| --- | --- | --- | --- | --- |
| Packet loss and reordering do not corrupt packet number, ACK, or retransmission state | `src/quic/packet.zig`, `src/quic/frame.zig`, `src/quic/connection.zig`; summarized in [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md) | property | mapped | Dedicated-host impairment run must show the production UDP listener reports loss/recovery progress through scenario-local QUIC metrics. |
| PTO and retransmission progression remain bounded and attributable | `src/quic/connection.zig`; `tardigrade_quic_pto_total`; H3 benchmark `quic.pto_total` deltas | property / runtime | mapped | Controlled loss/delay run must retain before/after metrics and qlog only when diagnosis needs it. |
| `RESET_STREAM` / `STOP_SENDING` lifecycle is idempotent and cleans stream accounting | `src/quic/stream.zig`, `src/quic/connection.zig`, `src/http3/conn.zig`; summarized in [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md) | unit / property | mapped | Soak should include honest cancellation/reset traffic when the available H3 client can generate it without test-only protocol shortcuts. |
| QPACK blocked-stream unblock, cancellation, and malformed instruction handling stay bounded | `src/http3/qpack.zig`; summarized in [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md) | property | mapped | No production wire gap today while nonzero dynamic QPACK request settings are not exposed by the production H3 config. Reopen only when that surface is enabled. |
| Critical stream failures preserve the required HTTP/3 close code | `src/http3/conn.zig`; duplicate/closed/reset critical-stream regressions | unit / property | mapped | Production-path protocol-error capture is useful only if it proves close-class propagation through the real runtime before teardown. |
| Release-critical QUIC/H3/QPACK close code preservation survives malformed input | `src/quic/connection.zig`, `src/http3/conn.zig`, `src/http3/qpack.zig`; external peer failures under `scripts/interop/run-interop.sh` | unit / property / external | mapped | Final interop rerun must publish required rows or explicit environment exceptions. |
| H3 graceful drain and GOAWAY do not accept new work past the advertised boundary | [HTTP3_ROLLOUT.md](HTTP3_ROLLOUT.md), `src/edge_gateway.zig`, `src/http/http3_runtime.zig`, integration drain/reload tests | runtime | mapped | Soak must include active H3 requests across drain/reload and record post-settle resource counters. |
| Connection close and teardown release connection, timer, CID, path, stream, and QPACK state | Retry/path/migration/CID coverage from #387 plus `src/quic/connection.zig`, `src/http/http3_runtime.zig`, and H3 runtime metrics | unit / runtime | mapped | Bounded soak must prove after-settle state returns to baseline or to a documented high-water plateau. |
| NAT rebinding, active migration, Retry tokens, anti-amplification, and spoofed addresses remain bounded | #387 runtime regressions plus `src/quic/path.zig`; summarized by existing security and rollout docs | runtime / property | mapped | No duplicate #247 test unless a production-composition scenario under impairment exposes a new gap. |

## PR-Safe Evidence Tier

Run this tier in ordinary PR validation or before opening a #247 evidence PR:

```bash
zig fmt --check build.zig src/ tests/
zig build test --summary all --error-style verbose
zig build test-quic --summary all --error-style verbose
./benchmarks/test-h3-benchmark.sh
```

When external peer tooling is already installed, also run:

```bash
zig build build-h3-interop
NGTCP2_EXAMPLES_DIR=/path/to/ngtcp2/build/examples \
  scripts/interop/run-interop.sh
```

PR-safe evidence may record `"supported": false` H3 benchmark rows when the
local `h2load` is not genuinely QUIC-capable. That proves the harness rejects a
false-positive client; it is not final performance evidence.

## Dedicated-Host Evidence Tier

Final #247 closeout requires a controlled host with a genuinely QUIC-capable
H3 load generator. Accepting an `--h3` flag is not sufficient; retain the
client name, version, build/linkage proof, and a successful QUIC/UDP readiness
exchange in the evidence bundle.

Run the existing harness rather than creating a parallel one:

```bash
./benchmarks/competitive/run.sh \
  --servers tardigrade \
  --duration 30 \
  --connections 50 \
  --threads 4 \
  --tune-comparison \
  --out-dir benchmarks/competitive/results/h3-release
```

The canonical result set must include:

- `static-small-http3`
- `static-large-http3`
- `proxy-large-http3`
- UDP-buffer baseline versus tuned comparison
- one sufficiently high-bandwidth/concurrency row that exercises the transport
  beyond startup
- controlled loss/reordering/delay where the host permits `tc`/netem

For impairment runs on Linux hosts with the required privileges, use
`benchmarks/competitive/netem-impair.sh` and retain the exact command line:

```bash
sudo ./benchmarks/competitive/netem-impair.sh apply --loss 1% --reorder 2% --delay 20ms
./benchmarks/competitive/run.sh --servers tardigrade --out-dir benchmarks/competitive/results/h3-impairment
sudo ./benchmarks/competitive/netem-impair.sh clear
```

Shared GitHub runners without `CAP_NET_ADMIN` are an environment exception, not
a product pass or failure.

## Bounded Soak Contract

The soak must exercise the real production H3 listener/runtime. It should have
a short PR-safe profile and a heavier scheduled/manual profile. Across those
profiles cover:

- repeated connect, request, clean close
- multiple requests per connection
- concurrent H3 connections
- reconnect/resumption where the production config supports it
- active drain/reload while H3 requests are in flight
- cancellation/reset traffic where the client can generate it honestly
- controlled loss/reordering in the heavy tier

Each soak report must capture before, peak, and after-settle observations for
the available counters:

- RSS and open file descriptors
- UDP sockets
- active QUIC connections and request streams
- worker or runtime queue depth
- recovery/PTO live state where exposed
- retained CIDs and path-validation state where exposed
- QPACK dynamic table bytes/entries and blocked streams
- queued or buffered transport/application bytes
- qlog/keylog artifact counts only when explicitly enabled

The pass condition must name the settle window and the expected baseline or
tolerance. State that intentionally retains bounded high-water capacity must
plateau inside a fixed bound; state that should drain completely must return to
baseline. Do not describe the result only as "looked stable."

## Final Evidence Bundle

Attach or link a concise report with:

- Tardigrade SHA, Zig/build mode, OS/kernel, CPU topology, memory, and runtime
  config
- load-generator name, version, and QUIC capability proof
- duration, connections, threads, worker/listener settings, UDP/sysctl state,
  effective socket buffers, PLPMTU, and ECN state
- per-scenario throughput, p95/p99 latency, errors/timeouts, CPU/RSS/open-FD
  observations where available, and scenario-local QUIC metric deltas
- external interop rows for the required native/ngtcp2 and native/quiche
  directions, with optional peers and missing-tool exceptions reported
  explicitly
- qlog/keylog paths only when deliberately enabled for diagnosis; keylog files
  must be treated as sensitive and never uploaded to public artifacts
- focused issue or fix disposition for every material correctness or resource
  regression discovered, plus rerun evidence for the affected row

#247 can close only when this matrix, the bounded soak, the real-client
controlled-host H3 evidence, and the final external interop rerun are complete
with no unresolved evidence-backed correctness or resource blocker.
