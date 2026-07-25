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

### Confirmed production gap: native TCP/H1 is not yet production-enabled end to end for real 0-RTT dispatch

While addressing review feedback, inspection of `edge_gateway.zig`'s
request-context setup found one visible gap in this existing comment and
hardcoded value:

```zig
// #367 slice 2 keeps this as request-scoped handoff state. The production
// #366 H1 record provenance carrier is not present on this branch yet, so
// H1 transport provenance stays false rather than using connection state.
ctx.early_data.transport_early = false;
```

That final H1 handoff is not the only missing production wiring. Native TCP
also does not yet advertise early-capable tickets from production
`NativeTlsConnection.issueSessionTicket()` because its
`prepareNewSessionTicket(...)` call does not pass `max_early_data_size`, and
`NativeTlsConnection.createWithOptions()` does not install an enabled
`Tls13Backend.ServerEarlyDataPolicy` (whose default is disabled). Together,
those gaps mean a production native TCP client cannot currently receive a
server-issued early-capable ticket, have the server accept a real
`early_data` attempt, and then carry that record-read provenance into H1
dispatch.

Wiring those prerequisites and the final `ctx.early_data.transport_early`
handoff is tracked by #510 as a `#366`/`#367` follow-up, not this slice's
scope. This means no test here or otherwise can currently prove "a
production-issued native TCP ticket leads to accepted real 0-RTT records
whose provenance gates H1 dispatch," because that composition does not
exist in production yet to prove. This slice's tests are scoped accordingly:
the TLS/replay-store decision is proven with real production code, and the
*given an early context, does dispatch correctly gate on it* question is
proven with a directly-constructed `EarlyDataContext` (the shape the real
wiring would eventually produce), not by claiming to exercise the
currently nonexistent production-issued-ticket → server-policy →
record-provenance → H1-safety-gate chain.

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

## Slice 3 (this PR): external OpenSSL interop, real process restart, and soak

This slice is explicitly **not** the final #369 slice, and #369 stays
open after it. Two premises the original plan for a final slice assumed
turned out to be false once actually checked against current `main`,
before any test code was written:

1. **#510's remaining scope is not "wire three call sites."** Its issue
   text was written on the assumption that `NativeTlsConnection`'s
   record-read early-data provenance accessor already worked and just
   needed plumbing into H1. Inspection found
   `PureZigRecordStream.currentReadTransportEarly()` is a stub that always
   returns `false`, `record_epoch_bridge.Bridge` rejects the `.zero_rtt`
   epoch everywhere (`error.UnsupportedRecordEpoch`), and
   `feedHandshakeToDriver` hard-fails any pre-handshake `application_data`
   record — meaning real 0-RTT decryption does not exist at all for the
   record (TCP) transport, not merely "isn't wired to HTTP yet". Native
   QUIC 0-RTT is also unconditionally rejected in code, independent of
   configuration. So 0-RTT does not exist end-to-end on **any** transport
   today, and no amount of wiring closes that — it needs new record-layer
   capability comparable in size to the #366–#368 QUIC slices. #510's
   issue text has been corrected with this finding; it remains open as its
   own, larger effort, and is not attempted in this PR.
2. **#338/#358 (the external OpenSSL interop harness this slice was told
   to reuse) do not exist yet either.** Both issues are open; the repo has
   `tests/crypto_openssl_diff.zig`/`pki_openssl_diff.zig` (differential
   crypto fixtures, not a live TLS-over-TCP subprocess harness) and a real
   external QUIC/H3 harness (`scripts/interop/run-interop.sh` +
   `tests/h3_interop_tool.zig`), but no `s_client`/`s_server` abstraction.
   This slice adds the minimal, resumption-scoped subprocess helpers it
   needs directly in `tests/integration.zig` (`runOpenssl`, a
   `bounded_process.zig` stdin extension) rather than building a second
   generic OpenSSL interoperability framework — #338/#358 still own that
   broader effort.

Given both, this slice proves everything that is honestly achievable
against the *actual* current production surface — real 1-RTT resumption
end to end — and leaves every 0-RTT-specific external/production
acceptance-criteria row explicitly open, tracked against #510's corrected
scope rather than faked with test-only configuration.

### A previously undiscovered, unrelated production bug found and fixed first

Pointing a real `openssl s_client` at the native TLS listener for the
first time (for the H1 interop case below) failed every single time with
`error.InvalidRecordType` immediately after the client's final handshake
flight — before any resumption logic was even reachable. Root cause:
`record_codec.parseHeader`'s ciphertext-mode parser required every
record's outer wire type to be `application_data`, with no exception for
the unprotected, single-byte `change_cipher_spec` record that TLS 1.3
middlebox-compatibility mode sends during the handshake (RFC 8446 Appendix
D.4) — which OpenSSL, and most other real-world TLS 1.3 stacks, send by
default. This is a universal external-interop bug, unrelated to
resumption, that self-testing (Tardigrade's own client against its own
server) never exercised. Fixed in `record_codec.zig`/
`encrypted_stream.zig` (see that commit) with new unit coverage; every
interop case in this slice runs against the fixed code and would not have
passed before it.

### External OpenSSL interop (`tests/integration.zig`, real `openssl` subprocess)

- `interop.openssl.h1.resume` — real native TLS listener, real
  `openssl s_client`, full handshake, OpenSSL's own `-sess_out`
  session-file capture, resumed reconnect via `-sess_in`, a real HTTP
  request over the resumed connection, and cross-checked authoritative
  indicators from **both** sides: OpenSSL's own `Reused`/`New` line
  (backed by `SSL_session_reused()`) and Tardigrade's
  `tardigrade_tls_resumption_outcome_total{outcome="accepted"}` metric —
  not merely a second successful handshake.
- `interop.openssl.h2.resume` — the same proof scoped to the TLS layer
  under the h2 ALPN path (handshake, ticket, resumed reconnect, ALPN
  renegotiated to h2 again). Hand-rolling HPACK/frame encoding through raw
  `s_client` stdin to drive one real h2 request was judged out of
  proportion to what this case needs to prove, given H1 above already
  proves resumption carries a real served request end to end and
  production H2 dispatch has its own independent coverage; documented in
  the test itself rather than silently narrowed.
- `interop.openssl.ticket.expired` — 1-second ticket lifetime, a real
  2-second sleep past it (there is no injectable clock at this external
  boundary), reconnect falls back to a full handshake, connection remains
  usable, a fresh ticket is issued afterward, and the expired-ticket
  attempt never counts as `accepted`.
- `interop.openssl.sni_mismatch` — the appliance TLS profile (the only
  profile the native listener builds under) supports exactly one identity
  and rejects `TARDIGRADE_TLS_SNI_CERTS` outright, so the only honest
  externally-observable case is: any SNI other than the configured one,
  ticket or not, is a deterministic `handshake_failure` alert — no request
  is ever served, no secret material appears in the failure diagnostics,
  and the listener remains fully usable via the correct SNI immediately
  afterward.
- `interop.openssl.alpn_mismatch` — ticket obtained under `h2`, reconnect
  offering only `http/1.1`: falls back to a full handshake under the new
  ALPN, old ticket never silently reused.
- `interop.openssl.ticket.tampered` — flips one byte inside the real
  `ticket_protection` AEAD envelope (stateless mode; located by its public,
  non-secret `"TDTK"` magic via a minimal DER walk of the OpenSSL session
  file, landing the flip inside the OCTET STRING's declared length rather
  than a tag/length byte a blind offset would otherwise corrupt — which
  would only break OpenSSL's own local session-file parser and prove
  nothing about the server). No crash, safe fallback to a full handshake,
  and the still-authentic ciphertext fingerprint next to the flipped byte
  never appears in the server's log or the client's own stdout/stderr.
- **`interop.openssl.cipher_mismatch` deliberately not shipped.** Ad hoc
  verification found the reconnect still negotiated the *original* cipher
  suite despite the client restricting itself via `-ciphersuites` to a
  disjoint one — behavior that needs its own investigation before a test
  can assert on it honestly. Shipping a test that silently asserts nothing
  useful would be worse than not shipping one; left as a known gap.

### Real process restart (`tests/integration.zig`, real separate OS processes)

- `restart.ephemeral.ticket_miss` / `restart.ephemeral.fresh_ticket` — a
  real process A (not `Runtime.deinit()`/`Runtime.init()` reused inside
  one test object) issues a stateless ticket, is terminated, and a real
  fresh process B with the same operator configuration proves: the old
  ticket resolves as a miss rather than authenticating, the connection
  still completes via a full handshake, B issues its own fresh ticket that
  genuinely resumes within B's own lifetime, and neither process's log
  ever contains the raw ticket ciphertext.
- `restart.cert_change.ticket_rejected` — process B boots with a
  different, test-generated throwaway credential under the same
  `server_name`; the old ticket must not (and does not) bypass the new
  authentication binding.
- Both use the ephemeral **stateless** ticket-key policy specifically —
  the currently supported restart-safety policy per #369 section 6.
  Stateful mode's cache-miss shape after a restart is a different,
  already-covered concern (an empty cache, not a key-loss question).

### Reconnect soak (`tests/integration.zig`, in-process client against one long-lived server)

- `soak.reconnect_resumption` — a bounded loop of full handshake → ticket
  → resumed reconnect against one process, using the fast in-process
  `PureZigTlsClient` rather than spawning `openssl` per iteration (that
  external proof is already covered by the interop cases above). Tracks
  iteration count and asserts the required invariant exactly —
  application executions equal legitimate requests expected to execute,
  never derived from a TLS-layer decision function itself — plus that
  every resumed reconnect actually resumed. `TARDIGRADE_SOAK_HEAVY=1`
  scales the default 40-iteration run up to 2000 for the scheduled heavy
  workflow; both sizes verified locally (2000 iterations: ~27s,
  `accepted=2000 executions=4000`, exact match, no failures).
- **Known gap**: there is no exposed gauge for server-side
  resumption-cache occupancy today (only issuance/outcome counters), so
  "memory/cache growth converges to configured bounds" is proven only via
  the cache's own existing bounded-capacity unit tests
  (`test-session-cache`, #364) plus this loop never regressing the counted
  invariants over many iterations — not via a live occupancy sample.
  Documented rather than asserted against a metric that doesn't exist.

### CI

- `zig build test-integration-resumption-interop` (new build step,
  filtered to the `interop.`/`restart.`/`soak.` case-ID prefixes) is wired
  into the existing appliance-profile CI job's Linux-only tier — the same
  scoping that job already applies to the full integration suite, since
  this new suite is similarly more prone to runner-scheduling variance
  (real subprocesses, real process spawn/kill, bounded real-time sleeps)
  than the pure in-process native-TLS suite.
- `.github/workflows/resumption-soak.yml` runs the same suite with
  `TARDIGRADE_SOAK_HEAVY=1` on a weekly schedule plus manual dispatch,
  mirroring `pki-differential.yml`'s existing pattern.

## Explicitly deferred beyond this slice

- **0-RTT external/production interop, entirely** (the largest remaining
  gap): accepted 0-RTT, rejected-0-RTT-falls-back-to-1-RTT, and any
  related metrics/replay assertions against real external peers, for
  every transport. Blocked on #510's corrected (large) scope — see above
  — not merely "not yet wired." Do not close #369 by treating any
  in-process/constructed-context 0-RTT test (Slices 1–2) as equivalent to
  this.
- **Independent QUIC/H3 external interop for resumption/0-RTT.** The repo
  has real external QUIC/H3 tooling (`scripts/interop/run-interop.sh` +
  `tests/h3_interop_tool.zig`, driving ngtcp2/quiche/aioquic peers) that a
  future slice should extend with resumption-specific scenarios, but this
  slice does not add them. H3/QUIC 0-RTT is additionally blocked by the
  same production gap as native TCP (see above) plus native QUIC's own
  unconditional 0-RTT rejection.
- **Rotation / persistent-overlap key policy — Outcome B.** Inspected
  `edge_gateway.zig`/`native_tls_connection.zig`: `ReloadableKeyRing`
  (`src/tls/ticket_protection.zig`) is not referenced by production
  composition at all. Persistent-overlap rotation is not a production
  capability today, full stop — not partially wired, not test-only
  reachable. Per #369 section 7 Outcome B, this slice does **not** build a
  test-only persistent-key system to manufacture rotation coverage; the
  actual supported policy is ephemeral-only restart invalidation, which
  the restart cases above cover. If persistent-overlap rotation is still
  required for #326/#369's closure, that needs its own production issue
  before it can be tested here.
- **`interop.openssl.cipher_mismatch`** — see above; needs investigation
  of an observed discrepancy before it can be shipped as a real assertion.
- **Deterministic worker-thread-pinning test seam** (carried over from
  Slice 2, unchanged): #369 Slice 2 proves the process-shared replay-store
  guarantee across independent per-connection state, not through real OS
  worker threads, because no seam exists yet to pin a connection to one
  deterministically.
- **Concurrent publication/rotation soak** (#369 section 8): not
  applicable while rotation itself is Outcome B — nothing to soak-test
  concurrently yet.
- **Multi-worker/process-scoped anti-replay assurance beyond Slice 2**
  (#369 section 10): unchanged from Slice 2; still blocked on the same
  worker-pinning seam gap above, and separately on the 0-RTT production
  gap (there is no accepted early-data claim to route between workers
  without it).

Acceptance criteria for #369 as a whole that depend on 0-RTT (accepted/
rejected-0-RTT interop, replay-store cross-worker proof under real
routing) or on persistent rotation remain open. #369 is not complete
after this slice; the honest remainder is the corrected #510 scope plus
the items above.
