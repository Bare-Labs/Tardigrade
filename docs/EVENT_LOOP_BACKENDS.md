# Event-loop backend evaluation (#148)

Status: **Phase 1 — readiness-only `io_uring` prototype landed, unbenchmarked.**
Phase 0's comparison (below) is unchanged and still records why `epoll`/`kqueue`
remains the default. What has changed is that the narrowly scoped, Linux-only,
feature-flagged prototype this document specified now exists in
`src/http/event_loop.zig`, behind `TARDIGRADE_EVENT_LOOP_BACKEND=io_uring`.

**Default behavior is unchanged on every platform.** The prototype is off
unless an operator explicitly names it, and it is deliberately shipped without
performance claims: no benchmark evidence has been gathered for it, so the
"Recommendation" section's bar for adopting `io_uring` as a default is **not**
met. See "Phase 1 prototype" below for exactly what was and was not validated.

This document satisfies the design-doc acceptance criteria from #148 and from
the consolidated architecture-evaluation scope folded in from #213. It does not
benchmark an `io_uring` (or other) backend.

## Why

#148 asks Tardigrade to evaluate an optional Linux `io_uring` backend behind
an event-loop abstraction, and #213 broadened that into a comparison of the
current epoll/kqueue model against `libxev`, `std.Io` evented/proactor
facilities, and direct `io_uring`, for the repository's pinned Zig toolchain
(`minimum_zig_version = 0.16.0`, see `build.zig.zon`).

#148 explicitly scopes itself as a second-order optimization: "research
suggests this is a second-order optimization after listener sharding,
buffering/backpressure, and upstream connection economics," and states it
"should be tackled after #137, #138, #139, #140, and #141 provide stronger
baseline wins."

## Dependency status (checked 2026-08-10, updated after #600 merged)

| Issue | Title | Status |
|---|---|---|
| #136 | Benchmark harness and telemetry | Closed |
| #137 | Per-core listener sharding (`SO_REUSEPORT`) | Closed |
| #138 | Park idle keepalive connections outside workers | Closed |
| #139 | Streaming reverse proxy with bounded buffering | Closed |
| #140 | Watermark-based backpressure for proxy/connection buffers | Closed — PR #600 (per-origin HTTP/1 relay buffer bounding, merged after #595/#599/#418) |
| #141 | Upstream connection pooling redesign | Closed |

All five prerequisite baseline-wins issues named in #148's own stated
ordering ("should be tackled after #137, #138, #139, #140, and #141 provide
stronger baseline wins") are now closed. That clears the *ordering*
precondition — it does not by itself supply the profiling evidence #148's
acceptance criteria still require before a prototype is justified (see
"Recommendation" below); it removes the one concrete reason this doc
previously gave for not starting that evidence-gathering yet.

## Current architecture and poller assumptions

Tardigrade uses a **blocking I/O, thread-per-request** model, audited in
detail in [`docs/CONCURRENCY.md`](CONCURRENCY.md):

- `src/http/event_loop.zig` (`EventLoop`) wraps `epoll` on Linux and `kqueue`
  on BSD/macOS behind a small `add`/`modify`/`remove`/`wait` interface keyed
  on raw fds, with `Interest{ read, write }` and a fixed-capacity `Event`
  output array. `EventLoop.init()` picks the backend from `builtin.os.tag`,
  and that remains what runs unless an operator sets
  `TARDIGRADE_EVENT_LOOP_BACKEND` to name one explicitly (Phase 1; see
  "Phase 1 prototype" below). This section describes the default path, which
  the prototype does not alter.
- The single shared `EventLoop` instance in `edge_gateway.zig`'s main loop
  currently has **three** roles, not one:
  1. **Unsharded listener accept readiness** — only when listener sharding
     (#137) is off. The main loop's `event_loop.wait()` result checks
     `ev.fd == listen_fd and !sharding_enabled` before calling
     `gaccept.acceptReadyConnections`.
  2. **Parked HTTP/1 keepalive readiness** for the legacy blocking
     OpenSSL/plaintext path (`src/http/keepalive_park.zig`'s
     `ParkedRegistry`, #138) — the idle gap between requests on a
     keep-alive connection served by a worker.
  3. **Active managed/native downstream readiness and drive scheduling**
     for the optional pure-Zig (`native_tls_provider`) TLS path
     (`src/http/downstream_connection.zig`'s `ActiveRegistry` /
     `ManagedConnection`): the main loop checks `active.contains(ev.fd)`
     before the listener/park checks and dispatches
     `worker_pool.submitActiveSocketReady`. A native connection is
     registered here while waiting for TLS handshake bytes
     (`native_handshake` phase) and again for the idle gap between
     requests once negotiated (`native_http1`/`native_http2` phases,
     `rearmActiveConnection`); `active.reapExpired` and
     `active.dueDrivePollFds`, driven from the same periodic maintenance
     tick as `keepalive_park`'s reaper, handle handshake-deadline expiry
     and scheduled re-drives. **Actual per-request I/O for a checked-out
     native connection still blocks** — `advanceNativeHttp1`/
     `advanceNativeHttp2` call `serveOneRequest` through a
     `WaitingEncryptedHttpConnection` adapter whose `waitFor` does its own
     local, per-call `std.posix.poll()` rather than looping back through
     the shared `EventLoop`. So the shared loop's role for this path,
     like for parked keepalive, is bounding idle/handshake wait time off
     a worker thread — not driving the request hot path.
  Request processing on the default OpenSSL/plaintext path is unaffected by
  any of this: it never touches `EventLoop` and blocks on the worker thread
  for its full lifecycle.
- When listener sharding (#137) is enabled
  (`TARDIGRADE_LISTENER_SHARDS > 1` on a platform with
  `SO_REUSEPORT`/`SO_REUSEPORT_LB`), accept readiness for **all** shards is
  handled entirely outside the shared `EventLoop`: each shard thread runs
  its own independent blocking `poll()` loop
  (`gaccept.runShardAcceptLoop`/`acceptReadyConnectionsShard` in
  `src/gateway_accept.zig`) against its own listener fd, and the shared
  `EventLoop` registers no listener fd at all in that mode — it still
  handles roles 2 and 3 above. Accepted fds from every shard still enter
  the same bounded worker pool.
- Accepted connections are dispatched to a bounded `WorkerPool`
  (`src/http/worker_pool.zig`) of OS threads, but "one worker owns the whole
  connection lifecycle uninterrupted" is only accurate for the legacy
  OpenSSL/plaintext path — there a worker does own one connection's full
  synchronous lifecycle (TLS handshake, HTTP parse, proxy/serve, response
  write) using **blocking** socket calls
  (`read`/`write`/`poll`/`SO_RCVTIMEO`/`SO_SNDTIMEO`) with no handoff back to
  `EventLoop` until an idle keepalive gap. For the native-TLS path, a worker
  instead owns *active request/handshake processing*: a connection can yield
  out of `native_handshake` (or the idle gap after a response) back to
  `EventLoop`/`ActiveRegistry` and be re-dispatched to a different worker
  later, so no single worker owns that connection's end-to-end lifecycle —
  only each checked-out slice of it, which is itself still blocking work.
  `worker_pool.zig`
  documents why this is deliberate: `std.Io.Group` (Zig 0.16) and the removed
  `std.Thread.Pool` both assume non-blocking, async-style work items, and
  Tardigrade needs direct control over thread count, work-stealing, CPU
  affinity, and drain-before-shutdown semantics for a production reverse
  proxy.
- `docs/CONCURRENCY.md` already states the project's standing position on
  this exact question: *"Do not start an `io_uring` or async-runtime rewrite
  from this boundary. Any new backend must be benchmark-justified and fit
  behind the same socket/protocol ownership rules."* This design doc does not
  change that position; it documents the comparison the maintainer status
  block on #148 asked for so the position is backed by a written rationale
  rather than only a one-line rule.
- `tardigrade_event_loop_iterations_total` (a counter of timer-tick
  iterations) is already exported in Prometheus and JSON metrics
  (`src/http/metrics.zig`); the event-loop backend name (`"epoll"` /
  `"kqueue"`) is already logged once at startup
  (`src/edge_gateway.zig:576`) but is not yet attached as a metric label.
  Adding a `backend` label to the existing counter (mirroring the
  `{backend=...}` pattern already used by the TLS buffer metrics) is a small,
  low-risk follow-up independent of the rest of this evaluation — see
  "Small independent follow-up" below.

## Backend abstraction boundary

For the purposes of this comparison, the "event-loop backend" boundary is
exactly the surface `src/http/event_loop.zig` already exposes:

- register/modify/remove readiness interest for a fd (`add`, `modify`,
  `remove`)
- block for a bounded time and return ready events (`wait`)
- report a stable backend identifier for logs/metrics (`backendName`)

This is a **readiness-poller** abstraction, not an operation/completion
abstraction: it has no submission-token model, no way to submit an
accept/read/write/timeout operation, and no way to return an operation
result (an accepted fd, a byte count). That shape is a deliberate choice for
Phase 0, not an oversight — see the explicit call-out at the end of this
section.

Any alternative backend considered below is evaluated against whether it can
sit behind this same four-operation boundary without forcing a rewrite of the
blocking, thread-per-request handler code that currently owns TLS, HTTP
framing, and proxy streaming.

**This constrains what a future `io_uring` backend may be, and this doc picks
the narrower of the two honest options:** a future `io_uring` backend
targeting this boundary is a **readiness-only poller replacement** —
`IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` plus `IORING_OP_TIMEOUT` (for
`wait`'s bounded-block behavior) standing in for `epoll_wait`/`kqueue`, with
`accept()` and all request I/O staying exactly where they are today: outside
the ring, as blocking calls on worker threads. It is **not** a wider
operation/completion abstraction using `IORING_OP_ACCEPT`, registered
buffers/files, or multishot variants — adopting those would require
widening this boundary to typed submissions/completions (e.g. `submitAccept`,
`submitRead`, `submitWrite`, `submitTimer`, `cancel`, `waitCompletions` with
opaque tokens) and defining how `epoll`/`kqueue` implement or adapt that
wider contract, which is a materially larger design than Phase 0 scopes and
is explicitly out of scope here. A later doc revision would need to make
that adoption case explicitly, including why the readiness-only version was
insufficient. Under the readiness-only choice, the sharded per-shard accept
`poll()` loops (`gateway_accept.zig`) are **not** exercised by this boundary
at all unless a separate future change first migrates them onto the shared
`EventLoop` — they stay on `std.posix.poll()` either way.

## Alternatives compared

### A. Current model — direct `epoll`/`kqueue`, thread-per-request workers

- **Linux fast path:** Mature, well-understood, level-triggered epoll used
  for unsharded listener accept, parked-keepalive readiness, and native-TLS
  active-connection handshake/idle readiness (see "Current architecture"
  above for all three roles) — in every case bounding idle wait time off a
  worker thread, not driving per-request I/O, which stays synchronous
  blocking calls on worker threads. No known syscall-count problem has been
  measured in this role; #148's own research basis frames `io_uring`'s
  syscall-reduction pitch as most valuable for I/O-heavy async runtimes,
  which this readiness-only loop is not.
- **macOS/kernel requirements:** `kqueue` is available on every supported
  BSD/macOS target with no minimum-version gymnastics. No portability
  fallback logic needed — it already covers both `SUPPORT_MATRIX.md`
  platforms.
- **Complexity / maintenance:** Already implemented, tested, and in
  production use (398 lines, unit-tested for both backends via CI matrix).
  Zero incremental maintenance cost to keep it.
- **TLS/encrypted-stream integration:** Already fully integrated for both
  TLS paths — `keepalive_park.zig` moves the legacy blocking `TlsConnection`
  (OpenSSL) state off the worker stack across the idle gap, and
  `downstream_connection.ActiveRegistry`/`ManagedConnection` does the
  analogous thing for the optional pure-Zig native TLS path (handshake wait
  and idle-between-requests wait). In both cases the event loop only tracks
  fd readiness; it never touches TLS record state or drives handshake/record
  processing itself.
- **Proxy streaming / backpressure:** Already integrated with #139's
  streaming relay and #140's (now closed) watermark/buffer-accounting work,
  which are both built on synchronous blocking reads/writes, not on
  event-loop readiness
  callbacks.
- **Timers, cancellation, keepalive parking, graceful drain:** Already
  implemented (`keepalive_park.zig` idle reaper on the maintenance tick,
  `gateway_shutdown.zig` drain, per-phase `poll(2)`/`SO_*TIMEO` deadlines on
  worker threads).
- **Prototype needed?** No — this is the shipped baseline.

### B. Cleaner direct epoll/kqueue abstraction (refactor only, same backends)

- Would not change Linux/macOS support or kernel requirements at all — same
  syscalls, same platforms.
- Only credible motivation is code-quality (e.g., unifying edge- vs
  level-triggered handling, or widening the event loop's role beyond
  accept/park). #148 does not identify a concrete pain point in the current
  abstraction that blocks other roadmap work, and `CONCURRENCY.md`'s
  "Follow-up work" table (h1/h2/h3 stream transport boundary, QUIC UDP
  endpoint) tracks the actual seams that need boundary work next (#241,
  #242, #248), not `event_loop.zig` itself.
- **Verdict:** No action item here beyond normal refactoring hygiene; not a
  distinct backend decision.

### C. `libxev`

- Not vendored or referenced anywhere in this repository today (`libxev`
  search returns no hits).
- Would require adopting `libxev`'s completion-based async model
  (`io_uring` or epoll on Linux, `kqueue` on macOS, and WASM, per upstream
  `mitchellh/libxev` docs; Windows/IOCP is documented upstream as
  planned/upcoming rather than a currently shipped backend), which is
  fundamentally callback/completion-oriented — a different concurrency shape
  than
  Tardigrade's blocking-thread-per-request handler. Adopting it for real gain
  would mean rewriting the request handler to be non-blocking end-to-end
  (TLS, HTTP parsing, proxy relay, FastCGI/SCGI/uWSGI transports), which
  `worker_pool.zig`'s design rationale explicitly warns against doing without
  first replacing the blocking I/O model throughout the connection handler
  and capturing an expected throughput/latency delta.
- Pulling in `libxev` as a dependency also cuts against the project's
  documented "core Zig only" direction for the data plane (see
  `docs/UPSTREAM_POOLING.md`'s HTTP/2 upstream work, which built h2 framing
  in-repo rather than take an external dependency, keeping OpenSSL as the
  one intentional exception).
- **Verdict:** Not justified now. Revisit only if/when the handler model
  itself is being redesigned around non-blocking I/O for other reasons.

### D. `std.Io` evented/proactor facilities

- `zig_compat.zig` and `CONCURRENCY.md` already draw this exact line:
  high-level, non-socket-path code uses `std.Io`/`zig_compat`; the
  listener/gateway/proxy/H2/H3 socket path deliberately stays on raw
  `std.posix`/`std.c` because Zig 0.16's `std.Io` does not yet expose
  stable, production-grade semantics for `accept`, `poll`, non-blocking
  toggles, `SO_*TIMEO`, and peer-address extraction on the data plane.
- `worker_pool.zig` already tried and rejected `std.Io.Group` for the exact
  reason relevant here: it expects non-blocking, async-style work items, and
  a blocking call on a Group-managed thread stalls the whole group. FastCGI
  pooling (`docs/UPSTREAM_POOLING.md` Phase 2) hit this directly in
  production — FastCGI/SCGI/uWSGI over `std.Io` event-loop streams **hung**
  against `php-fpm`'s blocking request/response exchange, and had to be
  switched to raw blocking sockets to fix it.
- **Verdict:** Not viable as a socket-path backend on the pinned Zig 0.16
  toolchain today, independent of `io_uring` specifically. This is a
  toolchain-maturity blocker, not a design preference, and should be
  re-evaluated only if a future Zig release stabilizes proactor-style I/O for
  the primitives the data plane needs (`accept`, bounded `poll`/timeout
  reads and writes, peer address extraction).

### E. Direct `io_uring`

- **Linux fast path / kernel requirements:** Real syscall-batching and
  completion-based I/O upside exists, but it is most valuable for
  high-fan-out non-blocking I/O (many concurrent reads/writes multiplexed
  through one submission/completion queue), which is exactly the shape
  Tardigrade's worker pool does *not* have — each worker already does one
  blocking `read`/`write` at a time on its own thread. The event loop's
  actual `io_uring`-addressable surface today spans three readiness roles
  (unsharded listener accept, legacy-TLS/plaintext parked keepalive, and
  native-TLS active-connection handshake/idle readiness — see "Current
  architecture" above), plus the sharded per-shard accept `poll()` loops if
  those were also moved onto it, but in every case it is readiness/idle-wait
  scheduling, not the request hot path itself: per-request reads/writes stay
  synchronous blocking calls on worker threads (including within the
  native-TLS path's own `WaitingEncryptedHttpConnection.waitFor`, which polls
  locally rather than through the shared loop). Per the "Backend abstraction
  boundary" section above, a backend targeting this boundary is
  **readiness-only** (`IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` plus
  `IORING_OP_TIMEOUT`) — it does not use `IORING_OP_ACCEPT`, registered
  buffers/files, or multishot variants, since those require widening the
  boundary to an operation/completion abstraction, which is explicitly out
  of scope for Phase 0. `POLL_ADD`/`POLL_REMOVE` exist from the original
  `io_uring` interface (Linux 5.1), but this readiness-only prototype's
  actual minimum is **Linux 5.4**, because `EventLoop.wait(timeout_ms)`'s
  bounded-block behavior is implemented with `IORING_OP_TIMEOUT`, which is
  not present in 5.1; see "Failure modes and fallback policy" below for how
  kernel-requirement documentation should be structured if a wider
  abstraction is ever proposed instead.
- **macOS support:** None — `io_uring` is Linux-only, so this would always
  need to stay behind a compile-time/feature-flag gate with `epoll`/`kqueue`
  as the portable default, exactly as #148 already proposes.
- **Complexity / maintenance:** High. A correct `io_uring` integration means
  new submission/completion-queue lifecycle code, a second set of
  cancellation/timeout semantics, and (per Envoy's and Monoio's own
  documented experience, cited in #148's research basis) materially more
  operational surface than epoll for a readiness/idle-wait role — even
  spanning all three current `EventLoop` responsibilities — that never
  drives per-request I/O in this codebase's current architecture.
- **TLS/encrypted-stream integration:** Would not change — TLS record
  handling (both the legacy OpenSSL path and the native pure-Zig path)
  happens inside the blocking worker once a connection is checked out, not
  in the event loop, so `io_uring` adoption at the readiness/idle-wait
  boundary described above would not touch TLS state machines either way.
- **Proxy streaming and backpressure:** No expected interaction with #139
  (streaming relay) or #140 (watermark backpressure) as currently designed,
  since both operate on synchronous blocking reads/writes inside worker
  threads, not on event-loop-driven readiness.
- **Timers, cancellation, keepalive parking, graceful drain:** Unchanged at
  the readiness-only boundary chosen above. The retained API is still just
  `add`/`modify`/`remove` plus one bounded `wait(timeout_ms)` — it has no
  per-connection timer-submission or cancellation operation.
  `IORING_OP_TIMEOUT` is used only to implement that single bounded
  `wait()`, not a per-connection deadline; `keepalive_park.zig`'s
  `ParkedRegistry` maintenance-tick reaper and `gateway_shutdown.zig`'s
  drain behavior are unaffected and unchanged either way. `io_uring` *can*
  express native per-operation timeouts and cancellation in general, but
  using that to actually simplify the reaper would require the wider
  operation/completion abstraction this doc explicitly defers (see "Backend
  abstraction boundary"), not the readiness-only prototype scoped here.
- **Prototype needed to resolve the decision?** Built (Phase 1, opt-in and
  unbenchmarked) — see "Phase 1 prototype" and "Recommendation." Its existence
  does not resolve the decision; the profiling/benchmark evidence still does.

## Comparison matrix

| Dimension | A. Current (epoll/kqueue) | B. Cleaner direct abstraction | C. `libxev` | D. `std.Io` proactor | E. Direct `io_uring` |
|---|---|---|---|---|---|
| Linux fast path today | Proven, readiness-only role (accept/park/native-active) | Same as A | Needs non-blocking rewrite to pay off | Not production-ready on 0.16 for socket path | Real upside only for non-blocking, high-fan-out I/O Tardigrade doesn't have yet |
| macOS support | Native (`kqueue`) | Native | Native (kqueue backend) | Blocked on 0.16 maturity | None — Linux-only, needs feature-flag gate |
| Complexity / maintenance | Already paid for | Refactor cost, no new capability | New dependency + handler rewrite | Blocked, not a maintenance question yet | High — new SQ/CQ lifecycle, cancellation model |
| TLS integration | Done for both OpenSSL (park) and native (active registry) paths, out of event loop's path | Unaffected | Would need rework if handler goes non-blocking | Unaffected until viable | Unaffected (TLS stays in worker) |
| Proxy streaming/backpressure (#139/#140) | Built on blocking relay, already integrated | Unaffected | Would require redesign | Already broke FastCGI in production (Phase 2) | No interaction as currently designed |
| Timers/cancellation/parking/drain | Implemented, no known bottleneck | Unaffected | Would move into libxev's model | Unaffected until viable | Unchanged at readiness-only boundary — reaper/drain untouched |
| Prototype required to decide? | N/A (shipped) | No | Only if handler model changes | No — blocked on toolchain, not on prototyping | Built, opt-in, unbenchmarked (Phase 1) |

## Recommendation

### Short-term (now)

- **No change to the default backend.** `epoll`/`kqueue` remains the backend
  selected on every platform when `TARDIGRADE_EVENT_LOOP_BACKEND` is unset or
  `default`, exactly as `docs/CONCURRENCY.md` already directs. The Phase 1
  `io_uring` prototype is opt-in only and carries no performance claim.
- **Ordering precondition cleared; evidence precondition is not.** #140
  (watermark-based backpressure) merged via PR #600, closing out the last of
  #148's named prerequisites (#137, #138, #139, #140, #141 are all now
  closed). That removes the *specific* reason this doc previously gave for
  not starting `io_uring` work yet — the risk of throwaway design work while
  #140's buffer-accounting model was still moving. It does **not** supply
  the separate thing #148's acceptance criteria actually require before a
  prototype is justified: profiling evidence, gathered against the
  `benchmarks/` harness (#136) on real hardware, showing the shared
  `EventLoop`'s readiness/idle-wait role is a measurable bottleneck (see
  "Long-term" below for the exact bar). Nothing in #600's scope changes that
  bar or supplies that evidence — #600 bounds HTTP/1 relay memory per
  origin, which is orthogonal to whether the accept/park/native-TLS
  readiness loop is a bottleneck.
- **The `io_uring` prototype now exists; `libxev` and `std.Io` proactor still
  do not, and should not.** The prototype was built ahead of the profiling
  evidence rather than after it, as a deliberate call to make the option
  concrete and measurable. That ordering does not retire the evidence
  precondition — it only means the thing to be measured now exists. Nothing
  about the prototype's existence argues for changing the default; see
  "Phase 1 prototype" for what is still missing. `libxev` and `std.Io`
  proactor mode remain rejected for the reasons in sections C and D, which
  the prototype does not affect.
- **Small independent follow-up (optional, not gated on the rest of this
  doc):** attach a `backend` label to the existing
  `tardigrade_event_loop_iterations_total` counter (the backend name is
  already computed via `EventLoop.backendName()` and already logged once at
  startup), so operators can see the active backend in
  `/status/metrics` without parsing startup logs. This can land
  independently of the architecture prototype work; this Phase 0 PR does not
  implement it, and it remains follow-up work under #148 before closure,
  per #148's "Metrics to add or verify" section (event-loop backend
  identifier in logs/metrics, `tardigrade_event_loop_iterations_total{backend=...}`).

### Long-term

- **`io_uring` is a "later, and only if measured" candidate, not a "now" or
  "never."** With #140 now closed, the remaining condition for revisiting it
  is a profiling pass (`perf record -g` per `CONCURRENCY.md`'s "How to
  measure" section) against the `benchmarks/` harness (#136) that shows the
  shared `EventLoop`'s
  readiness/idle-wait role (unsharded accept, parked keepalive, and/or
  native-TLS active-connection scheduling — see "Current architecture"
  above) — not worker-thread blocking I/O — is a measurable bottleneck under
  realistic high-churn or many-idle-keepalive workloads. Given that role is
  readiness/idle-wait scheduling rather than the request hot path, that
  evidence does not exist yet and this doc does not manufacture it.
- **`libxev` and `std.Io` proactor mode are "not now" for a different
  reason each:** `libxev` requires a handler-model rewrite this project has
  explicitly deferred (`worker_pool.zig`); `std.Io`'s proactor facilities are
  not yet production-ready for the raw socket primitives the data plane
  needs on the pinned Zig 0.16 toolchain (demonstrated in production by the
  Phase 2 FastCGI stall). Re-evaluate `std.Io` specifically on each Zig
  toolchain bump.
- The narrowly scoped, Linux-only, feature-flagged prototype described here —
  limited to the shared `EventLoop`'s existing readiness/idle-wait roles, and
  not a rewrite of worker I/O or of the native-TLS path's own local
  `poll()`-based per-request wait — is what Phase 1 built, matching #148's
  original "Prototype Linux `io_uring` support behind a feature flag"
  proposal. What it still owes is benchmark evidence gathered on real
  hardware (per the project's standing practice — see
  `docs/UPSTREAM_POOLING.md` and `CONCURRENCY.md`, both of which note that
  benchmark numbers must be captured on real hardware, not in a sandboxed
  dev/CI environment). Until that exists, the prototype stays opt-in and the
  default is unchanged. See "Failure modes and fallback policy" below for the
  policy it implements.

## Phase 1 prototype (implemented)

The readiness-only prototype specified by this document is implemented in
`src/http/event_loop.zig` as `Backend.io_uring`. It sits behind the existing
`add`/`modify`/`remove`/`wait` seam with no change to that seam's shape, and
implements the policy in "Failure modes and fallback policy" below.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TARDIGRADE_EVENT_LOOP_BACKEND` | `default` | `default` keeps the platform backend (`epoll`/`kqueue`). `io_uring` selects the prototype. `epoll`/`kqueue` may be named explicitly and fail closed if they are not this platform's backend. `auto` is rejected — the auto-detect-with-fallback mode sketched below is deliberately not implemented. |
| `TARDIGRADE_EVENT_LOOP_IO_URING_ENTRIES` | `256` | Submission-queue depth; ignored by the other backends. Bounded to 64–4096. |

The 256-entry default is chosen so the ring's mmap'd SQ/CQ memory (~24 KiB)
fits inside the 64 KiB `RLIMIT_MEMLOCK` soft limit common on stock hosts;
kernels before 5.12 charge ring memory against that limit, so a much deeper
default would fail `io_uring_setup` with `ENOMEM` on exactly the 5.4-era
kernels this prototype targets.

### What it uses, and what it deliberately does not

Only `IORING_OP_POLL_ADD`, `IORING_OP_POLL_REMOVE`, and `IORING_OP_TIMEOUT`
(the last solely to implement `wait(timeout_ms)`'s bounded block). No
`IORING_OP_ACCEPT`, no registered buffers or files, no multishot variants —
adopting those requires the wider operation/completion abstraction that the
"Backend abstraction boundary" section rules out of scope. Accordingly:

- `accept()` and all per-request reads/writes stay outside the ring, as
  blocking calls on worker threads, byte for byte as before.
- The sharded per-shard accept `poll()` loops in `gateway_accept.zig` are
  untouched and stay on `std.posix.poll()`.
- `keepalive_park.zig`'s `ParkedRegistry` reaper, its maintenance-tick logic,
  and `gateway_shutdown.zig`'s drain are untouched. As this document argued
  after review, a readiness-only boundary exposes no per-connection
  timer/cancellation operation, so there is nothing here that could simplify
  them.

The backend serves all three of the shared `EventLoop`'s roles identically to
`epoll`: unsharded listener accept readiness, parked HTTP/1 keepalive
readiness, and native-TLS `ActiveRegistry`/`ManagedConnection` handshake and
idle readiness.

### Behavioural differences from `epoll` that the adapter has to absorb

These are the three places where the ring is not a drop-in for level-triggered
`epoll`, and they are the parts most worth reviewing:

1. **`POLL_ADD` is one-shot.** `epoll` in level-triggered mode keeps reporting
   a fd until it is drained or removed, and callers depend on that — the
   listener fd is registered once and never re-added. Every delivered
   completion is therefore re-armed inside `wait` before it returns.
2. **A completion carries the mask from when the poll fired**, not the fd's
   readiness at `wait` time. A fd registered for read and write can be
   reported writable on one iteration and readable on the next, where `epoll`
   would have coalesced both. No readiness is lost — the fd is re-armed
   immediately — but a caller may need one extra loop iteration. Closing this
   gap needs `IORING_POLL_ADD_LEVEL`, which is Linux 5.13+ and therefore above
   this prototype's 5.4 floor.
3. **Closing a fd does not unregister it.** `epoll` drops a fd from every set
   when it is closed, and this codebase relies on that:
   `parkedConnectionCloseHook` and `activeConnectionCloseHook` only release
   accounting slots, so the keepalive idle reaper and the active-connection
   reaper close registered fds without unregistering them. The ring has no
   equivalent implicit cleanup, so `add` treats a surviving table entry for a
   fd it is asked to register as a stale registration for a recycled fd
   number: it cancels the stale poll and takes the fd over, rather than
   reporting the `EEXIST` that `EPOLL_CTL_ADD` would.

A fourth difference is internal rather than behavioural: `epoll_ctl` is
kernel-synchronized and safe to call from any thread while another sits in
`epoll_wait`, which `removeReadFd` documents worker threads doing. The io_uring
submission queue is plain shared memory, so every userspace ring mutation is
taken under a mutex, and submitting threads call `io_uring_enter` themselves
with `min_complete = 0` so a poll armed from a worker takes effect even while
the loop thread is blocked in its own `io_uring_enter`. Registrations carry a
monotonic token in the high half of `user_data` so that a completion racing
with a `POLL_REMOVE` is discarded rather than reported against a fd the caller
has already removed and possibly closed.

### Capability probing

`IoUring.init` succeeding only proves the 5.1 ring baseline, so the three
opcodes are established explicitly at startup rather than inferred from a
compile-time Linux check. `IORING_REGISTER_PROBE` is used where available and
checks all three opcodes directly — but that register opcode is itself only
present from 5.6, so kernels in the 5.1–5.5 window instead get a functional
probe that submits an already-expired `IORING_OP_TIMEOUT` and requires the
kernel to complete it with `-ETIME` rather than reject it. That functional
probe is what actually enforces this prototype's 5.4 floor.

### Validation status — read this before citing the prototype

- **Unit tests:** the `epoll`/`kqueue` behaviour tests in `event_loop.zig` are
  mirrored for the `io_uring` backend (write readiness, `modify` replacing
  interest, re-arm persistence, removal, recycled-fd re-registration), plus
  fail-closed tests for an unavailable backend and an unusable ring size. The
  behaviour tests skip themselves when `io_uring_setup` is unavailable —
  container seccomp profiles, Docker's default among them, block it outright —
  since that is an environment property, not a defect in the backend.
- **Executed on Linux by CI, not by the author.** The development host for
  this change was macOS/arm64, where the io_uring path compiles out entirely;
  it was validated there only by cross-compiling for `x86_64-linux-gnu` and by
  review. The Linux CI jobs were the first actual execution, and all six
  io_uring tests ran and passed there on both `ubuntu-latest` (x86_64) and
  `ubuntu-24.04-arm` (aarch64) — confirmed by skip-count differential: the
  macOS job skips 7 tests where the Linux jobs skip 1, and the difference of 6
  is exactly this backend's tests. So `io_uring_setup` is not blocked on those
  runners, the capability probe succeeds, and the readiness, `modify`,
  re-arm, removal, and recycled-fd paths all behave as intended on a live
  kernel.
- **The 5.1–5.5 probe fallback is still unexercised.** CI runners are on
  modern kernels where `IORING_REGISTER_PROBE` is available, so probing always
  takes the register path. The functional `-ETIME` fallback — the branch that
  actually enforces the documented 5.4 floor — has never run. Anyone
  validating this prototype against a 5.4-era kernel should treat that path as
  unverified.
- **No benchmark evidence of any kind.** No profiling pass has shown the
  shared `EventLoop`'s readiness/idle-wait role to be a bottleneck, and no
  throughput or latency comparison against `epoll` has been run. Per
  `docs/CONCURRENCY.md` and `docs/UPSTREAM_POOLING.md`, such numbers must come
  from real hardware, not a sandboxed dev or CI environment. Nothing in this
  change should be cited as evidence that `io_uring` is faster, slower, or
  equivalent for this workload.
- **Not recommended for production use.** It is a prototype whose purpose is
  to make the option measurable.

### What would close #148

Running the `benchmarks/` harness (#136) on representative hardware against
both backends under high-churn and many-idle-keepalive workloads, plus the
`perf record -g` pass described under "Long-term". If that evidence shows no
measurable win, the honest outcome is to remove this prototype rather than
carry it, and this document should say so.

## Failure modes and fallback policy for the `io_uring` backend

#148 requires failure modes, kernel/toolchain requirements, and fallback
behavior to be documented as part of the design, not deferred to whenever a
prototype is written. This section stated that policy before any prototype
existed; the Phase 1 prototype implements it, and the policy below is now the
contract that backend is held to:

- **Default unchanged.** `epoll`/`kqueue` remains the only backend selected
  by default on every platform, in every mode (including when listener
  sharding is enabled, where the shards' own `poll()` loops are separate
  from `EventLoop` entirely — see "Current architecture" above).
- **Explicit opt-in fails closed, not open.** If an operator explicitly
  requests an `io_uring` backend (`TARDIGRADE_EVENT_LOOP_BACKEND=io_uring`)
  and required kernel
  capabilities cannot be established at startup — unsupported kernel version,
  missing opcodes, seccomp/container restrictions blocking `io_uring_setup`,
  or resource exhaustion (`RLIMIT_MEMLOCK`, ring allocation failure) — the
  process must fail startup with a clear error, not silently fall back to
  epoll. An operator who explicitly asked for `io_uring` needs to know their
  deployment target doesn't support it, not discover a silent downgrade
  later during an incident.
- **A future `auto` mode, if ever added, fails safe before accepting
  traffic.** If a later revision adds an auto-detect mode, capability
  probing must happen during startup, before the listener(s) start
  accepting connections; a failed probe logs/increments a metric with the
  failure reason and falls back to `epoll`, never mid-flight.
- **No runtime hot-switching.** Once a backend is selected at startup, the
  process does not switch backends while running. Runtime SQ/CQ errors
  (e.g. a ring entering a bad state after `io_uring_enter` failures) are not
  a live-migration trigger back to epoll; they surface through the same
  error/drain semantics `gateway_shutdown.zig` already uses for other fatal
  runtime conditions (log, drain, exit), consistent with how the current
  `EventLoop.wait()` error path already just logs and continues rather than
  trying to self-heal by rebuilding the poller.
- **Kernel/toolchain requirements, if pursued:** separate the **historical
  ring/poll baseline** from **this prototype's actual minimum**, rather than
  citing one number for "basic support." `io_uring` itself — the
  `io_uring_setup`/`io_uring_enter`/`io_uring_register` syscalls, and with
  them `IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` — landed in Linux
  **5.1**. But the readiness-only prototype this doc actually scopes to (see
  "Backend abstraction boundary") also relies on `IORING_OP_TIMEOUT` to
  implement `EventLoop.wait(timeout_ms)`'s bounded-block behavior, and that
  opcode is not present in 5.1 — it landed in Linux **5.4**. So **this
  prototype's real minimum is Linux 5.4**, not 5.1, unless a future revision
  explicitly chooses a different, non-`IORING_OP_TIMEOUT` bounded-wait
  mechanism instead. Individual capabilities this doc explicitly excludes
  from the readiness-only prototype have their own, later floors if a future
  wider abstraction ever adopts them: `IORING_OP_ACCEPT` (5.5), multishot
  poll (5.13), and multishot accept (5.19, per upstream `liburing` docs) are
  commonly cited examples, not an exhaustive list. A prototype must pin and
  document the exact minimum kernel version it targets **for the specific
  opcodes/features it actually uses** — 5.4 for the operation set chosen
  here — and probe for those capabilities explicitly at startup rather than
  assuming availability from a compile-time Linux check or from the 5.1 ring
  baseline alone.

This policy applies to whichever `EventLoop` role(s) a future prototype
targets (unsharded accept, parked keepalive, and/or native-TLS active
readiness); it does not change based on which of those roles is chosen.

## Metrics

No new metrics are added by this doc. The event-loop metrics already in
place:

- `tardigrade_event_loop_iterations_total` — timer-tick iteration counter
  (`src/http/metrics.zig`).
- Backend name (`epoll`/`kqueue`) logged once at startup
  (`src/edge_gateway.zig`).
- Per-shard accept metrics from #137
  (`tardigrade_listener_shards`-equivalent gauges and
  `accepts_total`/`accept_errors_total{shard=...}`, `src/http/metrics.zig`).

`tardigrade_event_loop_wakeups_total{backend=...}` from #148's proposed
metrics list is not added here — it would require instrumenting the
epoll/kqueue `wait()` call sites themselves, which is more naturally scoped
to whichever PR first needs wakeup-count evidence (e.g. a future profiling
or prototype effort), not to a design-only doc.

## Relation to other open issues

- Depends on / informed by: #136 (closed, benchmark harness exists), #137
  (closed, listener sharding), #138 (closed, keepalive parking), #139
  (closed, streaming proxy), #140 (closed, watermark/buffer-accounting
  model), #141 (closed, upstream pooling). All five of #148's named
  prerequisites are now closed.
- Not blocked on any other open issue. The remaining precondition is
  profiling evidence, not another issue's completion — see "Recommendation"
  above.
- No follow-up implementation issues are opened by this doc, per #148's own
  acceptance criterion that "focused follow-up implementation issues are
  created only if a migration or additional backend is approved" — this doc
  approves neither. #148 itself stays open to track the still-missing
  profiling/benchmark evidence and the eventual prototype decision.
