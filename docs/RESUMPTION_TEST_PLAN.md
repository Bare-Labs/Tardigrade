# Resumption / 0-RTT Test Plan

Tracks test coverage for the session-resumption and 0-RTT epic (#326) against
the validation scope in issue #369 (326-J). #369 itself is XL and spans
external interop, restart/rotation soak runs, and CI wiring — too large for
one PR, so it is being landed in slices. This doc records what each slice
covers so gaps are visible instead of implied.

## Slice 1 (this PR): in-repo scenario tests

Fast, deterministic, single-process Zig tests exercising the resumption/
0-RTT/anti-replay code already landed by #365–#368. No external process, no
real OpenSSL/QUIC peer, no CI/soak changes.

- **Ticket expiry**: `src/tls/tls13_backend_tests.zig` — `"a ticket past its
  lifetime is rejected and falls back to a full handshake (#369)"` drives a
  real ClientHello/PSK-offer against a resolved-but-expired ticket end to
  end. (Pure-logic expiry boundaries were already covered by
  `src/tls/session.zig` and `src/tls/ticket_protection.zig`.)
- **Key rotation**: `src/tls/ticket_protection.zig` —
  `"rotation: a resolve against a decrypt-only grace-window key still
  succeeds, and new seals use the new key (#369)"` and `"rotation: a fully
  removed key rejects old tickets with unknown_key instead of crashing
  (#369)"` cover both the grace-window and full-removal rotation shapes
  against `ReloadableKeyRing`/`Protector` directly.
- **Process restart / lost cache (in-process/unit coverage only — not
  #369's full restart obligation)**: `src/tls/resumption_runtime.zig` —
  `"restart: a stateless identity issued by one process is unresolvable by a
  fresh process with no shared state (#369)"` and the stateful-cache
  equivalent construct two independent `Runtime`s as a deterministic *model*
  of lost ephemeral state (no shared ephemeral key or cache). This proves
  the resolve-side fail-closed behavior in isolation; it does not exercise
  an actual process restart, composition re-init, or the operational
  lifecycle #369 owns — see the deferred restart/rotation matrix below.
- **ALPN / cipher-suite mismatch on resumption**: `src/tls/
  tls13_backend_tests.zig` — `"an ALPN mismatch falls back..."` and `"a
  cipher-suite mismatch falls back..."`, alongside the pre-existing SNI-
  mismatch and certificate-change tests, so every `session.ResumeMismatch`
  variant now has an end-to-end (not just unit-level) regression.
- **0-RTT replay rejection, anti-replay capacity, fallback to 1-RTT/full
  handshake, and no-double-execution on 425 retry (unit/integration
  coverage only — not #369's process-level assurance)**: already
  extensively covered by #368/#367's own test suites
  (`src/tls/early_data_replay.zig`, `src/tls/tls13_backend_tests.zig`,
  `src/gateway_proxy_runtime.zig`, `src/gateway_handlers.zig`,
  `src/edge_gateway.zig`). No new tests added here in this slice — see the
  file-level docs on those tests for the existing matrix. #326 assigns the
  cross-layer, process-level version of this assurance to #369, which those
  predecessor suites do not exercise — see the deferred matrix below.

## Slice 2 (this PR): process-level 0-RTT replay / anti-replay / 425 assurance

Moves assurance one layer outward from Slice 1: exercises the real
production TLS/replay-store/HTTP-early-data/gateway-retry code composed
together, rather than each layer's own unit tests in isolation, and rather
than scripted stand-ins where production code was reachable.

A review pass on the first draft of this slice found that its TLS-layer
tests paired each real TLS/replay decision with a same-process "application
executed" counter incremented directly from that same decision
(`server_backend.earlyDataAccepted()`) — tautological, since it could never
catch the actual cross-layer bug #369 cares about (HTTP/gateway dispatch
ignoring a correct TLS decision), and, worse, unfalsifiable for the native
TCP/H1 transport today: see "Confirmed production gap" below. The review
also found a real test-only deadlock risk (an unbounded `accept()` a
regression could block on forever, joined in the wrong order relative to
socket teardown) and a test that special-cased itself around a decision
function without actually invoking any dispatch path. All of these are
fixed in the current state of this slice, described below.

- **`src/tls/tls13_backend_tests.zig`** — TLS / replay-store layer only
  (real `DirectHarness` ClientHello/PSK-offer/binder handshakes and a real
  `tls_core.early_data_replay.LocalStore`/`GateAdapter`, each scenario
  additionally asserting a real `Observer`/`Event` delta — the same
  observer seam production composition installs
  (`nativeEarlyDataReplayMetricsObserver`), asserted directly on the closed
  `Event` vocabulary since this module has no dependency on `http.metrics`):
  - `rt0.accept.first_use` — accepted 0-RTT records the replay claim, emits
    exactly one real `.accepted` event, and a diagnostic-formatting check
    confirms the raw ticket identity never appears in what a log line
    would show (the candidate type has no PSK field at all, so that leak
    is impossible by construction, not merely untested).
  - `rt0.reject.duplicate` — an exact-duplicate claim on a second,
    independent connection emits a real `.duplicate` event (not a second
    `.accepted`); the resumed connection remains usable and a later,
    distinct 1-RTT request round-trips real application data.
  - `rt0.reject.capacity` — a store configured with one live slot emits a
    real `.capacity_rejected` event for a second, otherwise-valid claim,
    occupancy stays bounded, and a later request on the same connection
    still succeeds.
  - `rt0.reject.startup_quarantine` — a fresh store (modeling lost replay
    history after a restart) emits a real `.startup_quarantine` event
    (distinguishable from `.duplicate`) during quarantine, and the
    connection remains usable for an ordinary request; the exact
    quarantine boundary is exercised against #368's existing
    (exclusive-end) semantics (`now < quarantine_end` rejects,
    `now == quarantine_end` is ordinary eligibility, and does emit a real
    `.accepted` event) with a deterministic injected clock, not a sleep.
  - `rt0.reject.cross_worker_duplicate` — two independent per-connection
    `DirectHarness` instances ("worker A"/"worker B") share one real
    `LocalStore`; worker A's claim emits `.accepted`, and worker B's replay
    of the same identity emits `.duplicate`. See the "true OS-thread/
    worker-routing seam" note below.
- **`src/edge_gateway.zig`** (two new tests alongside its existing H1
  dispatch tests, reusing the same `executeH1PostPreflightOrchestration` +
  probe-hooks and composition-decision seams those tests already use —
  reachable only from this file, since both are private to it):
  - `rt0.reject.unsafe_request` — an unsafe method (POST) with current-hop
    early data is driven through the real, private
    `executeH1PostPreflightOrchestration` orchestration (the same function
    production H1 dispatch calls) with the existing
    `H1CountingPostPreflightHooks` probe; asserts the probe's route hook —
    where any upstream dispatch would originate — never runs. Isolates the
    method-safety gate specifically, distinct from the file's pre-existing
    mirror-rule and origin-capability-off tests.
  - `rt0.reject.store_unavailable` — drives the same
    `nativeEarlyDataReplayComposition` helper used by `run()` with explicit,
    deterministic inputs: replay mode disabled, native resumption present,
    and a native TCP provider present. The helper withholds both store and
    gate options even though a native path otherwise exists, and a real
    `NativeTlsConnection` built with that returned option retains
    `Tls13Backend`'s fail-closed default
    (`early_data_replay_gate.decideFn == null`). This proves the disabled
    helper/default-backend boundary without depending on ambient
    `TARDIGRADE_*` env vars; true record-TLS → H1 provenance → safety-gate
    process coverage remains deferred below and is tracked by #510.
- **`src/process_early_data_integration_tests.zig`** (new file, wired into
  `zig build test` via `edge_gateway.zig`'s existing `test { _ = @import(...) }`
  aggregator pattern) — the one scenario that needs neither module's
  private internals:
  - `rt0.retry.425_exactly_once` — drives the real
    `gateway_proxy_runtime.runBufferedProxyAttempts` retry/425 state
    machine and the real production TCP HTTP client
    (`executeBufferedDataPlaneProxyRequest`) against an actual loopback
    upstream test server with an atomic execution counter that itself
    returns a real `425 Too Early` whenever it sees a real `Early-Data: 1`
    header. Proves: the retried request no longer carries the header, the
    upstream executes exactly once total, the response returned to the
    caller is the successful retry, and real
    `http.metrics.Metrics.recordHttpEarlyDataUpstream425`/
    `recordHttpEarlyDataRetry` deltas distinguish the initial 425 from the
    successful retry — no parallel test-only metrics model. Every wait in
    the loopback origin (`acceptBounded`/`readRequestHeadBounded`) is
    poll-bounded rather than a raw blocking `accept()`/`read()`, and the
    responder thread is joined (establishing a real happens-before
    relationship) before any of its observations are read, so a regression
    in the retry logic fails the test with a useful assertion instead of
    hanging the test binary.

### Confirmed production gap: native TCP/H1 does not yet wire `Tls13Backend.earlyDataAccepted()` into HTTP dispatch

While addressing review feedback, inspection of `edge_gateway.zig`'s
request-context setup found this existing comment and hardcoded value:

```zig
// #367 slice 2 keeps this as request-scoped handoff state. The production
// #366 H1 record provenance carrier is not present on this branch yet, so
// H1 transport provenance stays false rather than using connection state.
ctx.early_data.transport_early = false;
```

That is: for the native record/TCP transport, **no production code path
today reads the real TLS backend's `earlyDataAccepted()`/`earlyDataDecision()`
and forwards it into `ctx.early_data.transport_early`** for the H1 request
that follows. `transport_early` only ever becomes `true` for H1 in
production via this hardcoded-`false` assignment (i.e. never); the only
other `.transport_early = true` assignments in `edge_gateway.zig` are
either H2 frame-provenance propagation (already set from elsewhere, not
derived from the TLS backend) or test-only fixtures. Wiring this is tracked
by #510 as a `#366`/`#367` follow-up, not this slice's scope — but it means no test,
here or otherwise, can currently prove "an accepted real 0-RTT record over
TCP results in a real early HTTP dispatch," because that composition does
not exist in production yet to prove. This slice's tests are scoped
accordingly: the TLS/replay-store decision is proven with real production
code, and the *given an early context, does dispatch correctly gate on
it* question is proven with a directly-constructed `EarlyDataContext` (the
shape the real wiring would eventually produce), not by claiming to
exercise the (currently nonexistent) wiring itself.

### Known gap: no deterministic worker-thread-routing test seam

The cross-worker test above proves the process-shared-store guarantee
using two independent per-connection state instances (the same object
`edge_gateway.zig`'s real composition actually shares by reference across
every native TCP worker and QUIC/H3 — see `initNativeEarlyDataReplayStore`/
`GateAdapter.init` there), not two real OS worker threads. There is
currently no API to pin a connection to a specific worker thread
deterministically for testing, so a stronger proof (issue the accepted
claim through worker thread A, replay it through worker thread B) is not
available today. A future slice could add a small, explicit worker-id test
seam to `WorkerContext` to close this gap; until then this is a
documented, intentional limitation of this slice's assurance, not a
weakening of the "workers share one store" guarantee itself.

## Explicitly deferred to a later slice

- **External interop** with OpenSSL (`s_client`/`s_server` ticket
  round-trips) and an independent QUIC peer for H3 resumption/0-RTT. Needs
  subprocess-driven test harnesses, not covered here.
- **Operational restart/rotation matrix** (the part of #369's restart
  obligation the in-process `Runtime` model above does not reach):
  - Old ticket issued → actual process restart / composition re-init →
    resolver miss on the old ticket → connection still completes as a
    usable full handshake → fresh ticket issuance succeeds with bounded
    metrics recorded for the miss and the reissue.
  - A persistent-overlap restart: generation N retained decrypt-only
    alongside a newly current generation N+1 (or, for the stateless
    keyring, a fresh non-overlapping nonce lease on reload), proving live
    traffic straddling the reload never double-uses a nonce or drops a
    still-valid ticket.
  - Exact lifecycle boundaries (not-yet-active, active, decrypt-only grace,
    fully retired) driven through a real reload/composition path rather
    than direct `ReloadableKeyRing` calls.
  - A failed reload retains the prior snapshot rather than leaving the
    runtime with no usable key.
  - Concurrent / cross-worker restart and rotation cases.
- **Deterministic worker-thread-pinning test seam** — see "Known gap"
  above. #369 Slice 2 proves process-shared-store sharing across
  independent per-connection state; it does not drive that proof through
  real OS worker threads, because no seam exists yet to pin a connection to
  one deterministically.
- **Soak scenarios**: repeated reconnect/rotation loops with memory/metrics
  checks over long runs.
- **CI wiring**: a smoke subset plus an optional nightly/soak job.
- **QUIC-transport-specific 0-RTT-rejection-falls-back-to-1-RTT variant.**
  The record-transport matrix is thoroughly covered
  (`src/tls/tls13_backend_tests.zig`); an equivalent pass explicitly over
  `Transport.quic` has not been added yet.
- **True end-to-end native TCP/H1 record-provenance dispatch coverage**
  (#510): a real accepted/rejected TLS 0-RTT record must flow through
  native TCP/H1 request parsing into `RequestContext.early_data` and the
  production H1 safety gate before #369's process-level H1 path is complete.
  The current slice proves the TLS/replay-store decision and the constructed
  H1 dispatch context on either side of that gap; it does not close the
  missing production handoff itself.

Acceptance criteria for #369 as a whole (interop reliability, safe
fallback/rejection under mismatch, no double execution, bounded soak
memory/cache growth, reproducible artifacts without leaking ticket keys)
remain open until the deferred items above land in follow-up slices. #369
is not complete after this slice.
