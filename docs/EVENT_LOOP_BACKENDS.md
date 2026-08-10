# Event-loop backend evaluation (#148)

Status: **Phase 0 — design doc only.** No runtime behavior changes. This
document satisfies the design-doc acceptance criteria from #148 and from the
consolidated architecture-evaluation scope folded in from #213. It does not
implement, prototype, or benchmark an `io_uring` (or other) backend.

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

## Dependency status (checked 2026-08-10)

| Issue | Title | Status |
|---|---|---|
| #136 | Benchmark harness and telemetry | Closed |
| #137 | Per-core listener sharding (`SO_REUSEPORT`) | Closed |
| #138 | Park idle keepalive connections outside workers | Closed |
| #139 | Streaming reverse proxy with bounded buffering | Closed |
| #140 | Watermark-based backpressure for proxy/connection buffers | **Open** — PR #600 (HTTP/1 relay buffer bounding) in flight |
| #141 | Upstream connection pooling redesign | Closed |

Four of the five prerequisite baseline-wins issues are closed; #140 is not.
Per #148's own stated ordering, this is not yet the point at which a
prototype or migration should start. This doc proceeds only as far as the
design/comparison work, and defers the prototype/benchmark decision until
#140 lands (see "Recommendation" below).

## Current architecture and poller assumptions

Tardigrade uses a **blocking I/O, thread-per-request** model, audited in
detail in [`docs/CONCURRENCY.md`](CONCURRENCY.md):

- `src/http/event_loop.zig` (`EventLoop`) wraps `epoll` on Linux and `kqueue`
  on BSD/macOS behind a small `add`/`modify`/`remove`/`wait` interface keyed
  on raw fds, with `Interest{ read, write }` and a fixed-capacity `Event`
  output array. `EventLoop.init()` picks the backend from `builtin.os.tag` at
  compile/runtime; there is no runtime backend override today.
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
`IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` (plus a ring-native timeout for
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
  streaming relay and #140's (in-progress) watermark work, which are both
  built on synchronous blocking reads/writes, not on event-loop readiness
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
  **readiness-only** (`IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` plus a
  ring-native timeout) — it does not use `IORING_OP_ACCEPT`, registered
  buffers/files, or multishot variants, since those require widening the
  boundary to an operation/completion abstraction, which is explicitly out
  of scope for Phase 0. The readiness-only operation set is available from
  the original `io_uring` interface (Linux 5.1); see "Failure modes and
  fallback policy" below for how kernel-requirement documentation should be
  structured if a wider abstraction is ever proposed instead.
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
- **Timers, cancellation, keepalive parking, graceful drain:** `io_uring`
  can express timeouts and cancellation natively, which could simplify
  `keepalive_park.zig`'s reaper in principle, but the current reaper (a
  periodic scan under one mutex) is not a known bottleneck — no profiling
  evidence in this repo suggests it needs replacing.
- **Prototype needed to resolve the decision?** Not yet — see
  "Recommendation."

## Comparison matrix

| Dimension | A. Current (epoll/kqueue) | B. Cleaner direct abstraction | C. `libxev` | D. `std.Io` proactor | E. Direct `io_uring` |
|---|---|---|---|---|---|
| Linux fast path today | Proven, readiness-only role (accept/park/native-active) | Same as A | Needs non-blocking rewrite to pay off | Not production-ready on 0.16 for socket path | Real upside only for non-blocking, high-fan-out I/O Tardigrade doesn't have yet |
| macOS support | Native (`kqueue`) | Native | Native (kqueue backend) | Blocked on 0.16 maturity | None — Linux-only, needs feature-flag gate |
| Complexity / maintenance | Already paid for | Refactor cost, no new capability | New dependency + handler rewrite | Blocked, not a maintenance question yet | High — new SQ/CQ lifecycle, cancellation model |
| TLS integration | Done for both OpenSSL (park) and native (active registry) paths, out of event loop's path | Unaffected | Would need rework if handler goes non-blocking | Unaffected until viable | Unaffected (TLS stays in worker) |
| Proxy streaming/backpressure (#139/#140) | Built on blocking relay, already integrated | Unaffected | Would require redesign | Already broke FastCGI in production (Phase 2) | No interaction as currently designed |
| Timers/cancellation/parking/drain | Implemented, no known bottleneck | Unaffected | Would move into libxev's model | Unaffected until viable | Could simplify parking reaper, unproven need |
| Prototype required to decide? | N/A (shipped) | No | Only if handler model changes | No — blocked on toolchain, not on prototyping | Not yet (see recommendation) |

## Recommendation

### Short-term (now)

- **No backend change.** Keep the existing `epoll`/`kqueue` `EventLoop` as
  the only backend, exactly as `docs/CONCURRENCY.md` already directs.
- **No `io_uring`, `libxev`, or `std.Io` proactor prototype in this PR or in
  the immediate next one.** #148's own dependency ordering says this issue
  should follow stronger baseline wins from #137–#141, and #140
  (watermark-based backpressure) is still open with PR #600 in flight. Since
  #140's design directly shapes how proxy buffers would interact with any
  future async I/O model, starting an `io_uring` prototype before it lands
  risks throwaway work.
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
  "never."** The condition for revisiting it: #140 lands, and a profiling
  pass (`perf record -g` per `CONCURRENCY.md`'s "How to measure" section)
  against the `benchmarks/` harness (#136) shows the shared `EventLoop`'s
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
- If a future profiling pass does justify pursuing `io_uring`, the correct
  next step is a narrowly scoped, Linux-only, feature-flagged prototype
  limited to the shared `EventLoop`'s existing readiness/idle-wait roles
  (not a rewrite of worker I/O or of the native-TLS path's own local
  `poll()`-based per-request wait), matching #148's original "Prototype
  Linux `io_uring` support behind a feature flag" proposal, with its own
  follow-up issue and its own benchmark evidence gathered on real hardware
  (per the project's standing practice — see `docs/UPSTREAM_POOLING.md` and
  `CONCURRENCY.md`, both of which note that benchmark numbers must be
  captured on real hardware, not in a sandboxed dev/CI environment). See
  "Failure modes and fallback policy" below for the minimum policy such a
  prototype must define before it lands.

## Failure modes and fallback policy for a future `io_uring` backend

#148 requires failure modes, kernel/toolchain requirements, and fallback
behavior to be documented as part of the design, not deferred to whenever a
prototype is written. This section states that policy now so a future
feature-flagged prototype has a contract to implement against, even though
no prototype exists yet:

- **Default unchanged.** `epoll`/`kqueue` remains the only backend selected
  by default on every platform, in every mode (including when listener
  sharding is enabled, where the shards' own `poll()` loops are separate
  from `EventLoop` entirely — see "Current architecture" above).
- **Explicit opt-in fails closed, not open.** If an operator explicitly
  requests an `io_uring` backend (e.g. a future
  `TARDIGRADE_EVENT_LOOP_BACKEND=io_uring`-style flag) and required kernel
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
- **Kernel/toolchain requirements, if pursued:** separate the **ring
  baseline** from the **prototype's exact operation set**, rather than citing
  one number for "basic support." `io_uring` itself — the
  `io_uring_setup`/`io_uring_enter`/`io_uring_register` syscalls, and with
  them `IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE` (the readiness-only
  operation set this doc scopes a prototype to, per "Backend abstraction
  boundary" above) — landed in Linux **5.1**. Individual capabilities this
  doc explicitly excludes from a readiness-only prototype have their own,
  later floors if a future wider abstraction ever adopts them:
  `IORING_OP_ACCEPT` (5.5), multishot poll (5.13), and multishot accept
  (5.19, per upstream `liburing` docs) are commonly cited examples, not an
  exhaustive list. A prototype must pin and document the exact minimum
  kernel version it targets **for the specific opcodes/features it actually
  uses**, and probe for those capabilities explicitly at startup rather than
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
  (closed, streaming proxy), #141 (closed, upstream pooling).
- Blocked on: #140 (open) for the buffer-accounting model any future async
  I/O design would need to interact with.
- No follow-up implementation issues are opened by this doc, per #148's own
  acceptance criterion that "focused follow-up implementation issues are
  created only if a migration or additional backend is approved" — this doc
  approves neither.
