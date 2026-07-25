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
together, rather than each layer's own unit tests in isolation. Two new
test areas, both reusing existing production code and harness patterns
rather than scripted stand-ins:

- **`src/tls/tls13_backend_tests.zig`** (real `DirectHarness`
  ClientHello/PSK-offer/binder handshakes, a real
  `tls_core.early_data_replay.LocalStore`/`GateAdapter`, and an atomic
  "application executed" counter driven strictly by the real
  `earlyDataAccepted()` outcome — not a re-derivation of the TLS decision
  itself):
  - `rt0.accept.first_use` — accepted 0-RTT records the replay claim,
    executes the application exactly once, and a diagnostic-formatting
    check confirms the raw ticket identity never appears in what a log
    line would show (the candidate type has no PSK field at all, so that
    leak is impossible by construction, not merely untested).
  - `rt0.reject.duplicate` — an exact-duplicate claim on a second,
    independent connection never executes the application; the resumed
    connection remains usable and a later, distinct 1-RTT request executes
    normally (total: one execution for the accept, one more for the
    intentionally distinct later request).
  - `rt0.reject.capacity` — a store configured with one live slot rejects a
    second, otherwise-valid claim with the typed capacity outcome, no
    application side effect, occupancy stays bounded, and a later request
    on the same connection still succeeds.
  - `rt0.reject.startup_quarantine` — a fresh store (modeling lost replay
    history after a restart) rejects early execution during quarantine
    without any application side effect, and the connection remains usable
    for an ordinary request; the exact quarantine boundary is exercised
    against #368's existing (exclusive-end) semantics
    (`now < quarantine_end` rejects, `now == quarantine_end` is ordinary
    eligibility) with a deterministic injected clock, not a sleep.
  - `rt0.reject.cross_worker_duplicate` — two independent per-connection
    `DirectHarness` instances ("worker A"/"worker B") share one real
    `LocalStore`; worker A's accepted claim executes once, and worker B's
    replay of the same identity is rejected and never executes. See the
    "true OS-thread/worker-routing seam" note below.
- **`src/process_early_data_integration_tests.zig`** (new file, wired into
  `zig build test` via `edge_gateway.zig`'s existing `test { _ = @import(...) }`
  aggregator pattern):
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
    successful retry — no parallel test-only metrics model.
  - `rt0.reject.unsafe_request` — an unsafe method (POST) with current-hop
    early data is rejected by the real, `pub`
    `gateway_handlers.earlyDataDecisionForRequest` (the same function
    `edge_gateway.zig`'s H1 dispatch calls) before any upstream dispatch is
    attempted at all — the configured `proxy_pass` target is deliberately
    nothing that listens, so the only way the test can pass is by the real
    gateway decision short-circuiting before any network I/O, not by
    racing a responder thread.
  - `rt0.reject.store_unavailable` — ties two independently-proven facts
    together: `edge_config.loadFromEnv`'s default configuration leaves
    native 0-RTT replay mode `disabled` and defines no location routes at
    all, and `tls13_backend.EarlyDataReplayGate`'s default (no gate
    configured) fails closed to `.unavailable` for 0-RTT while leaving
    ordinary 1-RTT resumption untouched (both already proven individually
    by `edge_config.zig`'s and `tls13_backend_tests.zig`'s own suites) — so
    a freshly started process with no operator configuration cannot accept
    0-RTT anywhere, without needing any replay backend present.

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

Acceptance criteria for #369 as a whole (interop reliability, safe
fallback/rejection under mismatch, no double execution, bounded soak
memory/cache growth, reproducible artifacts without leaking ticket keys)
remain open until the deferred items above land in follow-up slices. #369
is not complete after this slice.
