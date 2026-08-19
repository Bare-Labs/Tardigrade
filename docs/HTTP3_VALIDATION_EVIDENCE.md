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
| `RESET_STREAM` / `STOP_SENDING` lifecycle is idempotent and cleans stream accounting | `src/quic/stream.zig`, `src/quic/connection.zig`, `src/http3/conn.zig`; summarized in [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md) | unit / property | closed | Closed by `soak.h3.bounded_cancelled_requests` (`tests/http3_soak.zig`), full-duplex: real client-issued `resetStream` **and** `stopSending` over real UDP, proven at the production runtime via `quic_transport_metrics_cb`'s `stream_resets` delta, plus repeated same-connection follow-up requests proving the connection stays usable across multiple cancel cycles. This soak's own strengthening found and fixed two real bugs: (1) `Stream.state()` checked `reset_received`/`reset_sent` before checking `send_closed && recv_closed`, so a stream closed via reset in both directions (as this leg's `stopSending` triggers via the peer's RFC 9000 SS3.5 auto-`RESET_STREAM`) never reported `.closed` and `maybeClose()` never updated `active_streams`/`closed_streams` for it; (2) the RFC 9000 SS3.5 automatic-reset transition `sendResetStream` drives was not itself idempotent, so a retransmitted `STOP_SENDING` (its ACK lost, redelivered in a new packet) queued and counted a second `RESET_STREAM` for a stream already in Reset Sent. Both fixed with dedicated regressions: a `stream.zig` manager-level test asserting `active_streams`/`closed_streams` move exactly once, a `stream.zig` manager-level test asserting a second `sendResetStream` call is a pure no-op, and a `connection.zig` test delivering the same `STOP_SENDING` frame twice and asserting no second local reset event, queued frame, or metric increment. |
| Peer stream-count credit (MAX_STREAMS) replenishes as peer-initiated streams close | `src/quic/stream.zig` (`StreamManager.maybeClose`), `src/quic/connection.zig` (`pollMaxStreamsCredit`, `buildAppFrames`) | unit | mapped | `soak.h3.bounded_cancelled_requests`'s own strengthening (persistent connection, repeated cancel cycles instead of one cycle per fresh connection) surfaced that the native transport never sent outbound MAX_STREAMS at all: a long-lived connection would permanently exhaust the initial `initial_max_streams_bidi` allowance (100 by default) and could never accept stream N+1, even with every earlier stream long closed. Fixed: `maybeClose` grants one unit of credit per closed peer-initiated stream (mirroring `applyMaxStreams`'s identical mutation for the opposite, outbound-credit direction), and `Connection` queues/encodes/re-arms-on-loss the resulting MAX_STREAMS frame the same way `pending_max_data` already does. Proven by a deterministic `connection.zig` regression (a tiny `initial_max_streams_bidi = 2`, two full request/response cycles, confirms the original limit is real, then confirms both the server's own credit and the client's wire-visible allowance grow past it) and, at soak scale, by `soak.h3.bounded_cancelled_requests`'s heavy tier deliberately running 60 cancel cycles (120 request streams) on one persistent connection -- comfortably past the default 100-stream ceiling this fix removes. **Explicitly not done in this PR:** closed streams are never removed from `StreamManager.streams` (or the parallel `Connection` per-stream maps), so this replenishes the stream *count* ceiling without reclaiming the small, bounded-per-request memory each closed stream still holds; a genuinely unbounded-lifetime connection would eventually accumulate that. Attempting removal during development produced real use-after-free crashes in existing tests/production code that read a stream's state immediately after the very call that closed it -- a pervasive, previously-safe idiom this reflects a fully-correct fix would need to audit throughout the codebase, not just in the newly-touched paths. Tracked as explicit follow-up rather than shipped half-verified. |
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
sudo ./benchmarks/competitive/netem-impair.sh \
  --loss 1 --reorder 2 --delay 20 --interface lo \
  --evidence-file benchmarks/competitive/results/h3-netem.json \
  -- ./benchmarks/competitive/run.sh --servers tardigrade \
     --out-dir benchmarks/competitive/results/h3-impairment
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

### Implemented: repeated-connection soak (`tests/http3_soak.zig`)

`soak.h3.bounded_repeated_connections` runs `http.http3_runtime.Runtime` -- the
same module `edge_gateway.zig` wires into the live listener -- over real
loopback UDP sockets with four concurrent clients, each doing repeated
connect, two requests, clean close cycles (6 rounds PR-safe, 40 rounds with
`TARDIGRADE_SOAK_HEAVY=1`). It runs by default under `zig build test` /
`zig build test-quic`, so it is already part of the PR-safe evidence tier
above; no separate invocation is required. Its pass condition:

- every planned request across every worker/round completed (a stall fails
  loudly instead of reporting fewer requests as "stable")
- after a bounded settle window (`waitRuntimeSnapshot`, 5s), tracked
  connections, active CID routes, and native connections return to exactly
  zero
- open file descriptors after settle do not exceed the pre-soak baseline
  (measured with a short bounded retry window to absorb the probe
  subprocess's own transient teardown noise, not the soak's own state)
- resident memory growth in the second half of the workload -- the true
  50%-of-requests midpoint, not "half the workers finished every round",
  which can land much later -- does not exceed first-half growth by more
  than a fixed, deliberately generous margin (`ps`-reported RSS is
  page-granular and noisy; the PR-safe tier's low round count makes this a
  coarse smoke bound, and the heavy tier is the meaningful signal). "Peak" is
  a genuine max-of-samples across 25/50/75%-of-workload checkpoints plus the
  end-of-workload sample, not just whatever the run looked like when the
  workers happened to finish.
- runtime connection/native-connection/CID-route state does not exceed a
  fixed high-water margin in the second half of the workload versus the
  first half (sampled every loop iteration from `runtime.snapshot()`, split
  at the same true midpoint): the settle-to-zero check above proves state
  eventually drains, but not that it stayed bounded while traffic was still
  flowing, so this is the check that would catch a bug that keeps retaining
  every prior connection/CID mid-run and only releases them once traffic
  stops
- both RSS/FD probe helpers fail closed: a launch failure, timeout, signal,
  non-zero exit, or empty/malformed probe output is a hard test error, never
  silently read back as `0` (which would let "the probe didn't run" pass as
  "measured zero resource usage")

This closes the "repeated connect/request/close", "multiple requests per
connection", and "concurrent H3 connections" workload rows, plus the RSS/FD/
connection/CID observation rows, above. It deliberately does **not** cover:

- **active drain with an in-flight request** -- already proven by "udp smoke:
  HTTP/3 runtime drain lets admitted work finish and rejects new work" in
  `tests/quic_h3_udp_smoke.zig`; duplicating it here would prove nothing new
  (see this document's own reuse rule).
- **controlled loss/reordering** -- needs a dedicated host with netem/
  `CAP_NET_ADMIN` (`benchmarks/competitive/netem-impair.sh`), not a portable
  unit test.
- **QPACK dynamic-table bytes/entries/blocked-streams, PTO totals, and
  worker/runtime queue depth** -- these are recorded onto `http.metrics.Metrics`
  only by the `GatewayState` composition layer above `http3_runtime.Runtime`;
  a bare-`Runtime` harness cannot observe them. Reopen only if `GatewayState`'s
  own tests reveal a composition-specific gap this harness could close.

### Implemented: resumption soak (`tests/http3_soak.zig`)

`soak.h3.bounded_resumed_reconnects` wires a real
`tls_core.resumption_runtime.Runtime` into the server `Config` (the same
field `edge_gateway.zig`'s production composition uses) and runs two
concurrent clients through repeated connect/request/close cycles (4 rounds
PR-safe, 10 rounds with `TARDIGRADE_SOAK_HEAVY=1`), where every round after
the first offers the ticket captured from the previous round instead of
performing a full handshake. It runs by default under `zig build test` /
`zig build test-quic`, alongside the primary soak above. Both soaks share a
`WorkloadMonitor` helper for the checkpoint sampling, peak computation, and
runtime-state plateau logic, so the two evidence rows below and above cannot
silently drift apart. Its pass condition:

- every reconnect (every round past the first) actually resumed, proven two
  independent ways: client-side, `psk_authenticated` is set from
  ServerHello's `selected_identity` before EncryptedExtensions even arrives
  (RFC 8446), not inferred from "the reconnect worked" (which would also be
  true of a full fresh handshake); server-side, the production resumption
  runtime's own `ResumptionDecisionObserver` -- wired automatically onto
  every accepted connection once `resumption_runtime` is configured, the
  same seam #247's "existing resumption observer" language asks this leg to
  exercise -- records exactly one `.accepted` outcome per resumed round, and
  zero `.miss`/`.incompatible`/`.fatal`/`.full_handshake` outcomes
- every planned request completed
- the same RSS-slope, genuine-peak, and connection/CID-state plateau checks
  as the primary soak above (same `WorkloadMonitor`, same margins scaled to
  this leg's smaller two-worker workload), plus the same exact-zero
  connection/CID settle and FD-baseline checks
- resumption-cache occupancy (`server_resumption`'s and `client_resumption`'s
  ticket caches, both intentionally still alive when the after-settle sample
  is taken -- this is state the primary soak above never exercises at all)
  never exceeds the cache's own configured per-origin capacity, and is
  non-zero after settle -- proving retention actually happened, the opposite
  contract from connection/CID state, which correctly drains to zero. Unlike
  connection/CID state, this is a hard capacity ceiling rather than a
  first-half/second-half plateau margin: an empty cache filling steadily
  toward capacity over the *entire* run, with nothing to evict until that
  capacity is reached, is expected, correct behavior

This closes the "reconnect/resumption where the production config supports
it" workload row above. It deliberately does **not** cover 0-RTT: that would
need its own early-data-specific admission assertions and is not required by
this row's "reconnect/resumption" text.

### Implemented: cancellation soak (`tests/http3_soak.zig`)

`soak.h3.bounded_cancelled_requests` proves the "cancellation/reset traffic
where the client can generate it honestly" workload row: the real client
already can drive this without test-only protocol shortcuts --
`H3.sendRequest` returns the real request stream ID, native
`Connection.resetStream`/`stopSending` are public, and production `pump()`'s
server-side request handling already handles `error.StreamReset` on a
request stream by removing it from the tracked request map. Two concurrent
clients each establish **one** H3 connection and run repeated cancel cycles
on it (4 cycles PR-safe, 60 cycles -- 120 request streams on one connection,
comfortably past the native transport's default 100-stream
`initial_max_streams_bidi` ceiling -- with `TARDIGRADE_SOAK_HEAVY=1`) --
deliberately not a fresh connection per cycle like the other two soaks,
since per-stream accounting needs to be observed while the connection stays
alive, not erased by teardown. Each cycle: open a request, immediately
cancel it full-duplex with the H3 request-cancel error code (`resetStream`
for the client->server direction, `stopSending` for the server->client
direction) before the next transmit flush (so the request and both
cancellation frames leave together -- the realistic "changed my mind
immediately" shape), then send a normal follow-up request on the same,
still-open connection. It runs by default under `zig build test` /
`zig build test-quic`, alongside the other two soaks, and shares the same
`WorkloadMonitor` helper. Its pass condition:

- every cycle's cancelled request was actually reset in both directions at
  the production runtime, not merely offered by the client:
  `Runtime.Config`'s `quic_transport_metrics_cb` is wired to a counter, and
  the accumulated `QuicTransportDelta.stream_resets` delta equals exactly
  twice the planned cycle count -- once from the server receiving the
  client's `RESET_STREAM`, once from the server's own RFC 9000 SS3.5
  auto-`RESET_STREAM` in response to the client's `STOP_SENDING`
- every cycle's follow-up request on the same, still-open connection
  completed with a normal 200 response -- proof repeated cancellation does
  not poison the connection, not just once before teardown
- the cancelled requests never reached the application handler:
  `handler_state.requests` equals exactly the planned follow-up count, never
  more
- the same RSS-slope, genuine-peak, connection/CID-state plateau, exact-zero
  settle, and FD-baseline checks as the other two soaks (same
  `WorkloadMonitor`, margins scaled to this leg's two-worker workload)
- (heavy tier) the persistent connection keeps working past the native
  transport's default 100-request-stream lifetime ceiling: every one of the
  60 cycles' follow-up requests completes normally, proving
  `StreamManager`'s RFC 9000 SS4.6 MAX_STREAMS replenishment (see the
  failure matrix row above) under real soak conditions, not just the
  deterministic single-connection `connection.zig` unit regression

This closes the "cancellation/reset traffic where the client can generate it
honestly" workload row above. The existing deterministic `quic_h3_e2e` reset
test already proves QUIC-level reset propagation between two directly-pumped
connections; this leg proves the distinct thing that test cannot -- repeated,
full-duplex reset ownership/cleanup through the full `http3_runtime.Runtime`
composition over real UDP while a connection stays alive, under the same
bounded-resource contract as the other soaks. Strengthening this leg to
repeated full-duplex cycles on a live connection (rather than one
`resetStream` per fresh connection) surfaced two real bugs this PR also
fixes -- see the failure matrix row above, `src/quic/stream.zig`'s
`Stream.state()` and `sendResetStream`, and `src/quic/connection.zig`'s
duplicate-`STOP_SENDING` regression. This soak does not itself simulate
packet loss/retransmission (out of scope per the netem exclusion above); the
retransmitted-`STOP_SENDING` idempotency case those bugs live in is proven
at the unit level instead, directly against the frame-handling code path.

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
