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
- **Process-level 0-RTT/replay/425 matrix** (the cross-layer assurance #326
  assigns to #369, distinct from the unit/integration tests #367/#368
  already carry):
  - Drive the real gateway/native TLS or H3 path end to end with a
    `process_local` (in-process, not distributed) anti-replay store; prove
    a duplicate 0-RTT claim is rejected while the underlying PSK connection
    still completes as ordinary 1-RTT.
  - Prove anti-replay capacity exhaustion and startup-quarantine both
    reject only the early-data attempt, never the resumed/full-handshake
    connection.
  - Drive a real 425 early-retry through an upstream request-execution
    counter and prove it lands at exactly one execution, through the actual
    proxy path rather than a scripted attempt executor.
  - Validate the store's documented scope directly: it is process-local
    (each worker/process anti-replay state is independent), and it is
    *not* cluster-wide — #368 explicitly scoped out a real distributed
    backend (Redis/etcd/similar) as out of contract for this epic, so that
    remains this repo's committed behavior, not a gap to close. This slice
    should validate the process-local/multi-worker guarantee and the
    documented non-cluster-wide limitation, not require implementing a
    distributed backend.
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
remain open until the deferred items above land in follow-up slices.
