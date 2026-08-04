# CryptoProvider / record / ticket-protection benchmarks (#378, epic #327-I)

Repeatable component benchmarks for the shared cryptographic provider and
crypto-facing machinery: enough to explain where larger-system performance
comes from, without duplicating the end-to-end TLS/QUIC/PKI/HTTP benchmark
work owned elsewhere (see "Ownership boundaries" below).

Every workload drives `pure_zig.Provider` directly through
`provider.CryptoProvider` — the same pattern
`tests/crypto_provider_fuzz.zig` uses (own-stack-frame provider, never
shared, never a protocol state machine) — or, for the record/ticket
suites, the same `tls_core.record_protection` / `tls_core.ticket_protection`
modules the native TLS stack calls in production.

## Commands

```bash
# Fast correctness smoke check (tiny iteration counts; not a timing signal).
# Part of the default `zig build test` and CI, so a broken workload or API
# drift fails the build immediately rather than silently going stale.
zig build test-crypto-bench --summary all --error-style verbose

# Full benchmark run: prints one JSON report to stdout.
zig build bench-crypto -Doptimize=ReleaseFast
```

`bench-crypto` is not wired into `zig build test` or `test_step` — like
`bench-allocations`, it is a standalone report generator, not a pass/fail
gate, so it never makes the default build flaky.

## What is covered

- **Hash / HKDF** — SHA-256/SHA-384 (provider-independent, explanatory
  only), HKDF-Extract, HKDF-Expand-Label across representative
  output/context sizes, and a repeated key+iv derivation pattern matching a
  record-layer epoch change.
- **AEAD** — AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305: seal and open
  measured separately across small/typical/near-max payload sizes, plus a
  dedicated authentication-failure workload.
- **Key exchange** — X25519 and secp256r1: key-share generation,
  shared-secret derivation, and invalid-peer-key rejection.
- **Signatures** — Ed25519, ECDSA-P256/SHA-256, RSA-PSS-RSAE/SHA-256: sign,
  verify, and invalid-signature rejection, kept separate rather than
  averaged.
- **Secret-container/helper overhead** — `FixedSecret` replace+deinit,
  `BoundedSecret` init+deinit (with allocation counts), `secureZero`, and
  `constantTimeEqual` across representative sizes.
- **TLS record cryptographic component** — traffic key/IV derivation,
  record AEAD seal/open across all three cipher suites and record sizes, and
  the authentication-failure path, through `record_protection`.
- **Resumption/ticket cryptographic component** — `ServerRecoverableState`
  codec encode/decode at small/medium/large sizes; for every ticket AEAD:
  `Protector.seal` end to end, public envelope parse only, and complete
  `Protector.resolve`; resolver-miss paths for malformed, unknown-key, and
  invalid-tag identities; and keyring/nonce-lease overhead (snapshot build
  at 1/2/4/8/16 keys, install with and without an in-flight reader,
  active-snapshot acquire/release, and nonce reservation under real
  multi-threaded contention).

Not covered: a standalone "AEAD open with a pre-parsed envelope" step.
`ticket_protection` does not expose its AAD-construction helper publicly,
and issue #378 itself guards that bullet with "where the API permits it" —
reimplementing private framing logic in the benchmark would risk silently
drifting from the real implementation. `resolve` covers the combined
parse+open+decode cost end to end instead.

## Benchmark contract / metadata

Every measurement in the JSON report carries `suite`, `name`, `algorithm`,
`input_bytes`, `iterations`, `ns_total`/`ns_per_op`/`ops_per_sec`, and (where
relevant) `allocations_per_op`/`bytes_allocated_per_op`. The report's
`_meta` object carries the exact Tardigrade source commit (`git rev-parse
HEAD` at build time, overridable with `-Dcommit`, or `"unknown"` for a
non-git source tree — see `gitCommitSha` in `build.zig`) plus the
Tardigrade version, Zig version, OS/architecture, build mode, and provider
kind — the environment facts issue #378's benchmark contract requires for
comparability. The commit is tracked separately from the version because a
version string is not unique per commit; without it, two artifacts built
from different commits of the same release would be indistinguishable. No
production secrets, keys,
nonces, or ticket identities are logged; every workload uses fixed
non-secret fixture material generated in-process.

## Budgets

Provider-primitive operations (HKDF, AEAD, key exchange, verify) are
allocation-free **by construction**, not by runtime sampling:
`primitives.assertProviderVtableIsAllocatorFree` is a compile-time check
that no `CryptoProvider.VTable` method takes an `std.mem.Allocator`
parameter, so no backend can allocate on that path regardless of
implementation. Ticket/session-codec workloads, which do allocate, report
actual allocation counts and bytes via a counting allocator instead.

Latency/throughput budgets are advisory trend ceilings
(`root.latency_budgets`) on a handful of core repeated workloads (AEAD
seal, KEX shared-secret derivation, signature verify, ticket seal/resolve).
They are deliberately generous — meant to catch a gross regression, not to
gate CI on shared-hardware noise — and only print a warning to stderr when
exceeded; they never fail `bench-crypto` or the build, matching issue
#378's "budgets may be advisory/trend-based" allowance.

A note on nanosecond-scale numbers: a few of the smallest leaf operations
(`constantTimeEqual`, `FixedSecret` replace/deinit, `secureZero` on tiny
buffers) are cheap enough, and simple enough for LLVM to fully inline, that
naive benchmarking risks the optimizer proving the loop body invariant
across iterations and collapsing thousands of iterations into one. Each of
those workloads forces a memory-clobbering `std.mem.doNotOptimizeAway` on
its input immediately before the operation under measurement (see the
comments in `primitives.zig`) specifically to defeat that; treat any
future addition of a similarly tiny, fully-inlinable workload as needing
the same treatment.

## Ownership boundaries (not duplicated here)

Per issue #378: whole-TLS/PKI/QUIC/H3/HTTP application benchmarks, full
handshake/resumption latency, encrypted-stream throughput, and generic HTTP
server competitive benchmarks all belong to their owning protocol/perf
stories (#323/#324/#325/#326/#369/#247/#149/#150 and the root
`benchmarks/` HTTP suite), not to this component-benchmark suite.

Two pieces are explicitly deferred, per the issue's own text:

- **QUIC cryptographic component** (Initial secret/key derivation, packet
  AEAD seal/open, header-protection mask, key-update derivation) — the
  issue ties this to #490 reconciling provider ownership for QUIC's crypto
  seam. Add it as a follow-on once that lands, following the same pattern
  as `record.zig`.
- **OpenSSL/reference comparison** — the issue frames this as optional
  ("where a fair independent comparison is stable and useful"), and the
  approved test/benchmark-only OpenSSL adapter path this would need is
  worth its own follow-on rather than folding into the initial suite.

## Closeout

Per issue #378's closeout rule, this suite covers the *current* shared
crypto/provider surface with repeatable component benchmarks and practical
budgets. Future algorithm additions should extend the matrix here as part
of their own owning implementation story rather than reopening #378.
