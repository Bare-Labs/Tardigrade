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

### Native TCP/H1 production 0-RTT coverage (#510)

PR #513 adds the native TCP production path that was previously documented
as absent here: production ticket issuance advertises `max_early_data_size`
only when the composed server early-data policy is enabled, the record layer
installs and retires `.zero_rtt` keys, accepted plaintext carries sticky
byte-accurate provenance into H1 request context creation, and unsafe early
requests reach the real H1 safety gate before route/upstream side effects.

`tests/integration.zig` now includes
`#510 native tcp production 0-rtt reaches h1 safety gate and replay fallback`.
That test starts a real Tardigrade process with native TLS, native
resumption, and process-local replay protection enabled; obtains an
early-capable ticket from `NativeTlsConnection.issueSessionTicket()`; sends
real resumed TLS 0-RTT H1 bytes; asserts a safe early request executes
exactly once; asserts an unsafe early request receives `425 Too Early`
without upstream execution; then replays the same ticket and proves rejected
early bytes do not dispatch while a subsequent ordinary 1-RTT request on
the resumed connection still succeeds.

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

1. **#510's remaining scope was larger than "wire three call sites."** Its
   issue text was written on the assumption that `NativeTlsConnection`'s
   record-read early-data provenance accessor already worked and just
   needed plumbing into H1. Inspection found the record layer also needed
   real `.zero_rtt` key installation, decryption, `EndOfEarlyData`
   handling, byte-accurate provenance, and bounded discard behavior. PR
   #513 implements and tests that native TCP/H1 production path; native
   QUIC 0-RTT remains outside this TCP/H1 issue.
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
- `interop.openssl.h2.tls_resume` — #521 closes the application-level
  resumed-H2 gap: the first OpenSSL `h2` connection obtains a real ticket,
  the second OpenSSL `h2` connection authoritatively reports `Reused`, the
  Tardigrade `outcome="accepted"` resumption metric increments, and a
  deterministic H2 request/response is driven over that resumed connection
  to a dedicated upstream route exactly once.
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
  `ticket_protection` AEAD envelope (stateless mode; located by a plain
  byte search for its public, non-secret `"TDTK"` magic — not a DER TLV
  walk of the surrounding OpenSSL session structure — then offset by the
  envelope's own fixed 36-byte header so the flip lands inside the actual
  AEAD ciphertext rather than the nonce or, with a naive fixed offset, a
  DER length/tag byte, which would only break OpenSSL's own local
  session-file parser and prove nothing about the server). No crash, safe
  fallback to a full handshake, and the still-authentic ciphertext
  fingerprint next to the flipped byte never appears in the server's log
  or the client's own stdout/stderr.
- **`interop.openssl.cipher_mismatch` deliberately not shipped.** #521
  closes this row as externally unreachable under the production native TLS
  profile today. The listener advertises only `TLS_AES_128_GCM_SHA256` and
  negotiates the connection cipher before PSK/session compatibility is
  evaluated. If an OpenSSL reconnect still offers that suite, there is no
  resumption-specific cipher mismatch; if it excludes that suite, ordinary
  cipher negotiation fails before the stored session can reach
  `session.evaluateCompatibility`. Deterministic in-repo coverage for
  `ResumeMismatch.cipher_suite_mismatch` remains in `src/tls/session.zig`;
  no test-only second cipher or protected-session mutation is introduced to
  manufacture an impossible external case.

### Real process restart (`tests/integration.zig`, real separate OS processes)

- `restart.ephemeral.ticket_miss` / `restart.ephemeral.fresh_ticket` — a
  real process A (not `Runtime.deinit()`/`Runtime.init()` reused inside
  one test object) issues a stateless ticket, is terminated, and a real
  fresh process B with the same operator configuration proves: the old
  ticket resolves as a real server-side **miss** (asserted via
  `resumption_outcome_total{outcome="miss"}`, not merely inferred from the
  reconnect succeeding for some other reason) rather than authenticating,
  the connection still completes via a full handshake, B issues its own
  fresh ticket that genuinely resumes within B's own lifetime, and neither
  process's log ever contains the raw ticket ciphertext.
- `restart.restart_and_credential_change.ticket_rejected` — process B boots
  with a different, test-generated throwaway credential under the same
  `server_name`. **This does not prove certificate/auth-binding-change
  rejection**: both processes are `stateless`, so B constructs its own
  fresh ephemeral ticket key regardless of which credential it serves,
  meaning B can't decrypt A's ticket at all — for the same reason as
  `restart.ephemeral.ticket_miss` above, before any certificate-binding
  field could even be inspected. What it does prove is that swapping the
  served credential across a restart is *also* safe, with the same real
  server-side miss (not merely "the reconnect happened to not authenticate
  for an unspecified reason"). True certificate/auth-binding-change
  coverage needs a live credential-reload path that preserves the
  resumption runtime across the swap — the appliance profile this suite
  builds under forbids dynamic TLS reload outright — or a persistent
  keyring surviving a restart, neither of which exists in production today
  (see the rotation section below). Deferred until one does.
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
  filtered to the `interop.`/`restart.`/`soak.` case-ID prefixes) lives in
  the same `tests/integration.zig` the existing unfiltered full
  integration suite already runs. The appliance-profile CI job runs that
  full suite on Linux only (an existing, unrelated scoping decision for
  timing-sensitive assertions) — so on Linux this filtered step is
  deliberately *not* run there too, since it would just repeat tests the
  full suite already covers; on non-Linux (macOS), where the full suite is
  skipped, this filtered step runs instead, so that platform isn't left
  with zero coverage of this slice.
- `.github/workflows/resumption-soak.yml` runs the same filtered suite
  with `TARDIGRADE_SOAK_HEAVY=1` on a weekly schedule plus manual dispatch,
  mirroring `pki-differential.yml`'s existing pattern.

## Explicitly deferred beyond this slice

- **0-RTT external/production interop, entirely** (the largest remaining
  gap): accepted 0-RTT, rejected-0-RTT-falls-back-to-1-RTT, and any
  related metrics/replay assertions against real external peers, for
  every transport. Blocked on #510's corrected (large) scope — see above
  — not merely "not yet wired." Do not close #369 by treating any
  in-process/constructed-context 0-RTT test (Slices 1–2) as equivalent to
  this.
- **Certificate/auth-binding-change rejection.**
  `restart.restart_and_credential_change.ticket_rejected` only proves a
  combined restart-plus-credential-swap is safe via the same ephemeral-key
  miss as an ordinary restart; it cannot exercise the certificate-binding
  check on a ticket that could otherwise still decrypt. Needs a live
  credential-reload path that preserves the resumption runtime (currently
  forbidden under the appliance profile) or a persistent keyring across
  restart (not a production capability today — see Rotation below).
  **Closed by #519's `rotation.persistent.certificate_binding_change`**,
  once the persistent keyring became a real production capability (#513).
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
  the restart cases above cover. #326 explicitly requires ticket-key
  rotation ("without invalid memory access, nonce reuse, or indefinite
  validity"), so this is not merely optional scope — **#512** is the
  narrowly-scoped production-composition follow-up this needs before
  #369's rotation rows can close; #369's operational rotation matrix stays
  blocked on it, the same way #369's 0-RTT rows stay blocked on #510.
  **Closed by #512/#513 (production composition) and #519 (this doc's
  Slice 4, the composed operational proof against it)** — kept here
  unedited as the historical record of what was true when this slice
  shipped.
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

## Slice 4 (#519): persistent ticket-key restart, rotation, reload
atomicity, and certificate binding

This slice closes the "Rotation / persistent-overlap key policy" gap Slice
3 documented above as Outcome B: **#513** landed the actual production
composition (`TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH`, `ReloadableKeyRing`
wired into the shared native resumption runtime, SIGHUP reload of the
snapshot). #519 is the operational proof against that real, running
composition — real process restarts and real SIGHUPs, not the
`resumption_runtime.zig`/`ticket_protection.zig` unit suites `#512` already
added (which this slice reuses, not duplicates).

All four new cases live in `tests/integration.zig`, gated by
`requireNativeTlsProfile()` like every other case in this section — they
only run under the appliance TLS profile build, the only profile with a
native (non-OpenSSL-adapter) resumption runtime today.

- **`restart.persistent.ticket_survives`** — a real process A issues a
  stateless ticket under a persistent snapshot; a real process B, started
  from the *same* on-disk snapshot with no manual lease editing, durably
  reserves its own disjoint nonce-lease window before issuing anything
  (asserted directly against the file's own `nonce_lease.start`/
  `end_exclusive`, before and after each process starts), resumes A's
  still-valid ticket, and issues its own fresh ticket whose (key_id, nonce)
  is asserted distinct from every A-issued tuple — proven structurally via
  the disjoint lease windows, not merely "happened to differ once".
- **`rotation.persistent.n_to_n_plus_1`** — a real SIGHUP drives generation
  N → N+1: the old N ticket resumes during the overlap grace window, a
  freshly issued ticket uses only N+1, and — composing the live
  `encrypt_until`/`decrypt_until` boundary pair, not just asserting the
  reload succeeded — a bounded real sleep past N's `decrypt_until` proves N
  stops resolving at all afterward (`miss`, not a second `accepted`). Two
  further live-process phases, added after review, compose the remaining
  boundaries directly rather than relying only on `#512`'s unit coverage:
  - **`not_before`**: a further reload to generation N+2 introduces a key
    whose `not_before` is a few seconds in the future while N+1 remains
    encryption-capable right up to that exact instant (a clean,
    non-overlapping handoff — `Snapshot.activeEncryptionKey` rejects two
    simultaneously-eligible keys outright as `AmbiguousActiveEncryptionKey`,
    so N+1's `encrypt_until` is set to exactly N+2's `not_before`). Fresh
    issuance stays on N+1 until the boundary, then switches to N+2 once it
    arrives — both observed directly on issued tickets' key ids.
  - **`session.issued_at + lifetime`**: with a short (10s) process-wide
    ticket lifetime, a ticket resumes before it elapses and falls back to a
    full handshake after. `ticket_protection.Protector.resolveInner` checks
    session expiry *inside* the resolve/decrypt step itself, and
    `resumption_runtime.resolverResolve` folds every resolve rejection —
    expired, retired key, or unknown key alike — into the same `miss`
    outcome; there is no separate metrics bucket distinguishing them. So
    attribution to session lifetime specifically (not key retirement) comes
    from the phase's own construction, verified concretely: N+1's
    `decrypt_until` is kept 60s out (only ~12s elapses), and a fresh ticket
    issued immediately after the rejected offer is asserted to still seal
    under N+1 — proof the key itself was never in question.
  - **Real production hazard found while writing this**: naively carrying
    a retiring or still-active key forward into a new generation by
    replaying its *currently declared* `nonce_lease` range (whether the
    stale original or the file's own current one, read back unmodified) is
    rejected with `OverlappingNonceLease` — `ReloadableKeyRing`'s per-key-id
    ledger permanently remembers the full declared width of every lease a
    key was ever installed with as that key's high-water mark, not merely
    how far its counter actually advanced, so any re-declared range at or
    below that mark collides. A key that will never encrypt again needs no
    lease at all (`nonce_lease: null`, matching the shape
    `resumption_runtime.zig`'s own `#512` rotation unit test already uses
    for the rotated-out key); a key that must keep encrypting across the
    reload needs its range *advanced past* the ledger's mark (the same
    doubling-by-width advance `reserveNonceLeasesInFile` itself performs),
    not merely replayed.
- **`rotation.persistent.failed_reload_keeps_old_state`** — four
  representative rejected-reload classes each leave a previously issued
  ticket still resuming and the reload metrics recording a bounded,
  secret-free failure outcome, checked per attempt (a labeled-metric
  before/after delta via a bounded poll, not a fixed settle sleep and not a
  cumulative running-total check that an earlier sub-case's rejection could
  mask a later regression behind): an *unreadable* replacement (the
  configured path replaced with a directory -- deterministic on every
  environment regardless of permissions, unlike an earlier permission-bit
  draft a root/rootless-container CI job could silently fail to enforce,
  and semantically distinct from a size-limit rejection, which an
  intermediate draft of this sub-case substituted and review correctly
  flagged as not the same failure class), malformed JSON, a semantically
  invalid keyring via an invalid nonce lease, and a stale generation
  number. A ticket issued only *after* all four rejections still seals
  under the original key id, proving
  nothing was partially applied across any of them.
  - **Finding**: this test does *not* additionally bundle a TLS credential
    change into a failing SIGHUP. Inspecting
    `edge_gateway.run`/`gateway_shutdown.hotReloadConfig` shows the
    appliance TLS profile's real served identity
    (`appliance_credentials.ApplianceCredentials`) is loaded once at
    startup and is never touched by any reload path — the
    `NativeCredentialStore` two-phase prepare/commit mechanism this
    criterion was written against exists, but only on the non-appliance
    (general) profile, and there only for QUIC/H3, so it is never reachable
    under `requireNativeTlsProfile()` regardless of what this test attempts.
    `rotation.persistent.quic_credential_reload_atomicity` below exercises
    that real path instead. What this test does show, honestly: every one
    of its sub-cases leaves the one credential this process ever serves —
    and the ticket bound to it — both visibly untouched, even though none
    of them ever attempts to change it.
- **`rotation.persistent.quic_credential_reload_atomicity`** — the
  general-profile counterpart, gated by `requireGeneralTlsProfile()` +
  `requireNgtcp2Client()` (skips without a built `H3_INTEROP_CLIENT_PATH`
  peer, the same `gtlsclient` subprocess the `h3interop.quic.*` cases use).
  Bundles a credential swap with a broken ticket-key candidate in one
  SIGHUP against real QUIC/H3: `native_credentials.prepareReloadFromFiles`
  genuinely reads and validates credential B (the general profile has no
  appliance-only path/name guard to reject this reload outright), but
  `commitPreparedReload` is only reached after the ticket-key step
  succeeds, which this SIGHUP deliberately fails. Reconnecting with the
  pre-reload session against the real external ngtcp2/GnuTLS peer resumes
  authoritatively (the peer's own decrypted Handshake CRYPTO trace) —
  proof the previous ticket state is live *and*, since a resumed
  connection's auth-binding check would otherwise reject it, that the
  served certificate is still credential A. Verifying the served
  certificate directly (e.g. the peer's negotiated leaf certificate) is not
  attempted: `gtlsclient` does not currently expose it, only handshake
  CRYPTO bytes and the resumption outcome, so this is the honest scope —
  credential-unchanged is verified through the auth-binding mechanism, not
  an independent second channel. Not executable in every environment (a
  built ngtcp2/GnuTLS peer, `scripts/interop/build-h3-peer-ci.sh`, is a
  from-source C++23 build not attempted in every dev environment); CI
  builds and runs it via the same wiring `h3interop.quic.*` already uses.
- **`rotation.persistent.certificate_binding_change`** — closes the gap
  Slice 3's `restart.restart_and_credential_change.ticket_rejected` doc
  comment explicitly left open ("[proving certificate/auth-binding
  rejection] needs ... a persistent keyring surviving a restart, [which does
  not exist] in production today"). It now does (#513), so this is a
  restart (not reload, per the finding above): process A issues a ticket
  under credential A; process B restarts from the *same* ticket-key
  snapshot under a different credential B. B can genuinely decrypt A's
  ticket (unlike the ephemeral-key restart cases), so the rejection is
  provably `session.evaluateCompatibility`'s `auth_binding` check, not an
  unknown-key miss: `tls13_backend.selectPsk` only records the
  `incompatible` resumption outcome (as opposed to `miss`) for an identity
  that actually resolved, and this run's `tardigrade_tls_ticket_resolve_total
  {result="success"}` confirms the decrypt itself succeeded. The connection
  still completes via a safe full handshake.

### CI

`build.zig`'s `test-integration-resumption-interop` step's filter list
gained a `rotation.` prefix alongside the existing `interop.`/`restart.`/
`soak.` ones, so these cases get the same macOS coverage (where the full
`test-integration` suite is deliberately skipped — see `ci.yml`) the
`restart.*` cases already had.

## Explicitly deferred beyond this slice (still open after #519)

- **Persistent-key rotation soak / worker-thread-pinning / cross-worker
  anti-replay under real routing** — the persistent-key rotation *soak*
  portion is now covered: **#520** (Slice 5, below) proves concurrent
  multi-process nonce-safety and rotation soak against a shared snapshot.
  Worker-thread-pinning and cross-worker anti-replay *under real routing*
  remain open — #520 deliberately keeps `TARDIGRADE_WORKER_THREADS=1` per
  process (its subject is multiple real OS processes, not deterministic
  worker-thread scheduling within one), and its replay-locality proof is
  process-local by construction, not a load-balancer-routed cross-worker
  scenario.
- **General (non-appliance) profile credential-reload two-phase atomicity**
  — `gateway_shutdown.hotReloadConfig`'s `NativeCredentialStore` prepare/
  commit path is real production code, but exercising it needs a non-
  appliance native-TLS test configuration this file's persistent-ticket-key
  cases don't build under (`requireNativeTlsProfile()` is appliance-only).
  Not attempted here; a future slice targeting the general profile
  specifically would need its own harness path.

## Slice 5 (#520): multi-process persistent-key nonce safety and
replay-locality soak

Slice 4 (#519) proved a single process's own restart/rotation/reload/
certificate-binding lifecycle against a persistent ticket-key snapshot.
This slice closes the remaining **multi-process** rows from #369's
resumption/0-RTT validation matrix: the same snapshot, `${path}.lock`
sidecar, and `ReloadableKeyRing`/SIGHUP-reload composition, but with two
real, live Tardigrade processes genuinely contending them at once, plus
the process-local scope of early-data replay protection proven across two
independent processes rather than asserted only in
`docs/OBSERVABILITY.md`'s prose.

A prerequisite harness change landed alongside these cases:
`TardigradeProcess.start()` was split into `spawn()` (creates the child,
does not wait) and `waitReady()` (blocks until healthy), with `start()`
kept as a thin, behavior-preserving wrapper for every existing caller.
Calling `start()` twice in sequence only ever proves *sequential*
reservation; calling `spawn()` twice before `waitReady()`-ing either
process lets two real processes race the same `${path}.lock` concurrently,
which every case below depends on.

- **`soak.persistent.multi_process_nonce_safety`** — two real processes
  `spawn()`ed back-to-back (not `start()`ed sequentially) and only then
  waited on, both reserving from the same freshly-written generation-1
  snapshot. The file's lease window is asserted to have advanced *exactly
  twice* under generation 1 (`[2w, 3w)` from an initial `[0, w)`, per
  #520's own worked example), and each process's real issued tickets are
  asserted structurally inside exactly one of the two disjoint reserved
  windows — resolved from each process's own first sample rather than
  assumed, since which process wins the lock race first is scheduling-
  dependent. A bounded number of further rounds (2 smoke / 6 heavy) then
  drive concurrent SIGHUP rotation on both processes at once: each round
  retires the active key (`nonce_lease = null`, per #519's own rotation-
  lease rule) and installs a fresh successor, polls each process
  independently for its own `reload_accepted` metric step, proves a
  retained sample ticket from the outgoing generation still resumes on
  *both* processes during the overlap window, and asserts every freshly
  issued ticket across the whole run — both processes, every round — has
  a unique `(key_id, nonce)` tuple.
- **`soak.persistent.nonce_lease_exhaustion`** — kept separate from the
  case above so a failure says exactly what broke. Two processes reserve
  disjoint windows from a deliberately tiny (`width = 16`) shared lease. A
  bounded batch of ordinary full-handshake connections against process A
  drives its own reservation to exhaustion (a before/after metric delta
  across batches, not a poll after every single connection — the metrics
  endpoint is itself reached over a real TLS connection that can attempt
  its own best-effort issuance). `NonceLeaseExhausted` is proven
  operationally safe: `tardigrade_tls_ticket_issue_total{result="failed"}`
  increases, but every connection that hit it still completed with `200
  OK`, a ticket issued before exhaustion still resumes afterward, a brand
  new ordinary handshake to A still succeeds, and process B's own disjoint
  reservation and zero failure count are untouched throughout.
- **`soak.replay.process_local_scope`** — two processes share one
  persistent snapshot (so either can decrypt a ticket the other issued)
  but run independent `process_local` early-data replay stores. Both are
  `spawn()`ed concurrently and the real ~60s startup quarantine
  (`age_skew_tolerance_ms`) is paid once, together — not shortened, and
  not paid twice. The exact same ticket identity (cloned before each
  offer, since `ClientPskOfferSet.push` moves its argument) is then
  offered as early data four ways: accepted once by A, rejected as a
  duplicate on A-replay, accepted once by B (B's own store has never seen
  it — the documented scope, proven live), and rejected as a duplicate on
  B-replay. Each duplicate rejection is shown to block only the early
  request reaching upstream while leaving the PSK/session itself valid —
  an explicit ordinary request on the same connection afterward still
  succeeds.

### CI

No new build filter was needed: all three cases use the existing `soak.`
case-ID prefix `build.zig`'s `test-integration-resumption-interop` step
already filters on. `TARDIGRADE_SOAK_HEAVY=1` scales
`soak.persistent.multi_process_nonce_safety`'s rotation-round and
per-round ticket-sample counts and `soak.replay.process_local_scope`'s
replay-identity count, the same way it already scaled
`soak.reconnect_resumption`'s iteration count.

## Explicitly deferred beyond this slice (still open after #520)

- **Three-or-more-process contention, deterministic worker-thread pinning,
  and cross-worker anti-replay under real routing** — unchanged from
  Slice 4's equivalent bullet above; #520 deliberately scopes to two
  processes (`ticket_key_snapshot.reserveNonceLeasesInFile` serializes
  entirely on one exclusive file lock, so a third contender races the same
  lock, not a qualitatively different one) and process-local replay
  scope, not a distributed or cross-worker replay store.
- **Final #369 matrix/docs reconciliation** — left to #522, per that
  issue's own scope; this slice adds its own coverage notes above rather
  than redoing the epic closeout.
