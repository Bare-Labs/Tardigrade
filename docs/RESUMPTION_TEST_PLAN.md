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
- **Process restart / lost cache**: `src/tls/resumption_runtime.zig` —
  `"restart: a stateless identity issued by one process is unresolvable by a
  fresh process with no shared state (#369)"` and the stateful-cache
  equivalent construct two independent `Runtime`s to model a real restart
  (no shared ephemeral key or cache), not just a resolver returning miss.
- **ALPN / cipher-suite mismatch on resumption**: `src/tls/
  tls13_backend_tests.zig` — `"an ALPN mismatch falls back..."` and `"a
  cipher-suite mismatch falls back..."`, alongside the pre-existing SNI-
  mismatch and certificate-change tests, so every `session.ResumeMismatch`
  variant now has an end-to-end (not just unit-level) regression.
- **0-RTT replay rejection, anti-replay capacity, fallback to 1-RTT/full
  handshake, and no-double-execution on 425 retry**: already extensively
  covered by #368/#367's own test suites
  (`src/tls/early_data_replay.zig`, `src/tls/tls13_backend_tests.zig`,
  `src/gateway_proxy_runtime.zig`, `src/gateway_handlers.zig`,
  `src/edge_gateway.zig`). No new tests added here in this slice — see the
  file-level docs on those tests for the existing matrix.

## Explicitly deferred to a later slice

- **External interop** with OpenSSL (`s_client`/`s_server` ticket
  round-trips) and an independent QUIC peer for H3 resumption/0-RTT. Needs
  subprocess-driven test harnesses, not covered here.
- **A real distributed anti-replay backend.** `src/tls/
  early_data_replay.zig`'s `Store` contract (`GateAdapter`) is proven against
  `LocalStore` and a scripted single-threaded fake
  (`FakeDistributedOutcome`) only — see that file's module doc. True
  cross-node atomicity, network partition/timeout handling, and TTL honoring
  require an actual backend (Redis/etcd/similar) and are unimplemented, not
  just untested.
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
