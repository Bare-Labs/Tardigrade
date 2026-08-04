# Shared crypto fuzzing contract and provider targets (#376, epic #327-G)

This is the shared fuzzing contract for the native TLS program's crypto
surfaces. It defines the rules every fuzz target under epic #327-G must
follow, and owns the standalone targets for the `CryptoProvider` boundary
itself (AEAD, key exchange, signature verification, signing keys, and the
shared secret containers). Protocol-specific fuzzing is owned by the epics
that own those protocol surfaces and must consume this contract rather than
inventing incompatible rules:

- #491 — shared TLS handshake / negotiation / transcript / reassembly (#323)
- #492 — DER / PEM / X.509 / path validation (#324)
- #493 — TLS record / protection / encrypted-stream (#325)
- #494 — session / PSK / ticket / resumption state (#326)
- #247 — QUIC/H3 packet/frame/transport/QPACK/H3 validation

This story does not re-implement those targets. Its own targets stop at the
provider seam (`src/crypto/provider.zig`, `src/crypto/pure_zig.zig`,
`src/crypto/rsa.zig`, `src/crypto/secrets.zig`): malformed input that can
reach `CryptoProvider` directly, without needing a protocol state machine.

## Existing fuzzing pattern in this repo

There is no separate `fuzz/` tree. Fuzzing is inline `test "fuzz: ..."`
blocks using Zig 0.16's built-in `std.testing.fuzz`/`std.testing.Smith`,
next to the code they exercise or in a focused `tests/*.zig` file, each with
a checked-in seed corpus passed as `.corpus = &.{...}`. Under a normal
`zig build test` this deterministically replays only the seed corpus; under
`zig build <step> -Doptimize=ReleaseFast --fuzz=<N>` it becomes real
coverage-guided mutation. This mirrors `docs/QUIC_H3_FUZZ_MATRIX.md`'s
program for QUIC/H3 (#247/#537); this document is the equivalent for the
shared crypto surfaces.

## Commands

```bash
# Deterministic smoke coverage (seed corpus replay only) — part of the
# default `zig build test` and CI.
zig build test-crypto --summary all --error-style verbose

# The standalone provider-boundary targets owned by this story:
zig build test-crypto-provider-fuzz --summary all --error-style verbose

# Longer local/scheduled coverage-guided runs:
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: AEAD open" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: deriveSharedSecret" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: verify" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: generateKeyShare" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: FixedSecret" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: BoundedSecret" --fuzz=10M --summary all --error-style verbose
```

`-Dcrypto-test-filter` (added alongside the existing `-Dquic-test-filter`)
gives explicit target selection for the `test-crypto-provider-fuzz` step; the
`--fuzz=<runs>` limit keeps scheduled runs bounded (`K`/`M`/`G` suffixes
scale it). #491–#494 should add their own protocol-scoped test steps and
`-D<area>-test-filter` options following the same pattern rather than
growing this one.

## Seed-corpus and regression update procedure

This is the concrete workflow #491–#494 should follow too, rather than each
inventing their own.

1. **Capture the exact crash input, not a description of it.** A `--fuzz=<N>`
   run that finds a failure persists the exact failing `Smith` byte input
   through Zig's own fuzz engine (the memory-mapped/corpus-backed input the
   coverage-guided runner uses to recover crashing values, per the [Zig
   0.16 release notes' fuzzer
   section](https://ziglang.org/download/0.16.0/release-notes.html#Fuzzer)).
   The `test "fuzz: <name>"` name Zig prints identifies the *target*, and a
   `FUZZING REPORT` run count is not a stable case ID — re-running the same
   coverage-guided command is exploration, not an exact replay. Do not
   substitute a `std.debug.print` of the *values sampled from* the Smith
   stream (lengths, enum choices, etc.): those are derived data, not the
   input itself, and cannot be fed back into `.corpus` to reproduce the
   same run deterministically. Copy the crash input file Zig's fuzzer
   reports into a stable checked-in fixture instead:
   `tests/vectors/fuzz/crypto/<target-slug>/<sha256-of-the-file>.bin`, where
   `<target-slug>` is a short slug for the target (e.g. `aead-open`,
   `derive-shared-secret`, `verify`, `fixed-secret`, `bounded-secret`). The
   SHA-256 digest is both the filename and the deterministic case ID/
   provenance record — identical bytes always hash to the same fixture name,
   so a duplicate find is a no-op rather than a second copy.
2. **Wire it back in with `@embedFile`, always.** Every checked-in crash
   fixture is added to its target's `.corpus` as `@embedFile`, never
   hand-transcribed as a string literal (transcription is exactly the kind
   of lossy transcription step 1 rules out):
   ```zig
   try std.testing.fuzz({}, fuzzAeadOpen, .{ .corpus = &.{
       "",
       // Found 2026-08-04, zig build test-crypto-provider-fuzz
       // -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: AEAD open ..." --fuzz=50M
       @embedFile("vectors/fuzz/crypto/aead-open/1f3c9a7e...bin"),
   } });
   ```
   Replay it immediately with the *same* target's filtered non-`--fuzz`
   command (below) to confirm it reproduces deterministically before doing
   anything else with it.
3. **Minimize, then decide what to keep.** Reduce the fixture by repeatedly
   trimming/simplifying its bytes and re-running the same filtered replay
   command until it stops reproducing the failure, keeping the last input
   that still did (manual delta-debugging; Zig 0.16 does not ship an
   automatic minimizer for this workflow). Once the minimal failing input is
   understood:
   - If it has a clean semantic story (a specific field's wrong length, a
     specific tamper, a specific boundary value), translate it into a named
     deterministic `test` block next to the target — this is what every
     regression in `tests/crypto_provider_fuzz.zig` already is, and it
     stays reviewable in a way a byte blob does not. Only remove the raw
     `.corpus`/`@embedFile` fixture once that named regression has been
     confirmed to fail against the pre-fix code and pass against the fix
     (i.e. it exercises the same defect, not a superficially similar one).
   - If it has no clean semantic story (the exact bytes matter and cannot be
     reduced to a short description), keep the minimized fixture itself as
     the permanent regression via `@embedFile`, re-hashing and renaming the
     file to match its minimized content.
4. **Never store real secret material.** Every target in this file
   synthesizes or derives its own key material per case from injected
   deterministic entropy — callers never hand it a real production secret —
   so a captured fixture is inherently synthetic/malformed wire-shaped
   input, never a real private key, certificate, or traffic capture. Corpus
   fixtures and regression tests must stay that way: hand-crafted or
   fuzzer-found malformed input only, never copied from a real deployment.
5. **Record provenance.** Add a one-line comment directly above the new
   `.corpus`/`@embedFile` entry or regression test (see the example in step
   2) noting when it was found and which command found it, so a future
   reader can tell a hand-written edge case from a fuzzer-discovered one;
   the SHA-256 filename itself is the immutable half of that record.
6. **Verify before committing, and pick the right command for the artifact.**
   A raw `.corpus`/`@embedFile` fixture is replayed by the *fuzz test's own*
   filter; a named deterministic regression is a separate `test` and needs
   its *own* name filtered instead (or the whole step, unfiltered) — the
   fuzz-target filter will not run it:
   ```bash
   # Corpus/@embedFile fixture: filter on the fuzz target that owns it.
   zig build test-crypto-provider-fuzz -Dcrypto-test-filter="fuzz: <exact target name>" --summary all --error-style verbose
   # Named deterministic regression: filter on the regression's own name.
   zig build test-crypto-provider-fuzz -Dcrypto-test-filter="<exact regression test name>" --summary all --error-style verbose
   # Always, regardless of artifact type:
   zig build test --summary all --error-style verbose
   ```
   The first confirms the new corpus entry or regression reproduces
   deterministically under plain (non-`--fuzz`) replay; the second confirms
   no other target regressed. Run `zig fmt --check build.zig src/ tests/`
   too, matching every other change in this repo.

## The shared contract

Every target under epic #327-G — this story's provider targets and
#491–#494's protocol targets alike — must satisfy the following.

### Deterministic reproduction

Every failure must identify:

- the target name (the `test "fuzz: ..."` name Zig's runner already prints);
- a deterministic case ID — the SHA-256 digest of the checked-in
  `@embedFile` fixture, or the named regression `test`'s own name; a
  `FUZZING REPORT` run count is not one (see "Seed-corpus and regression
  update procedure" above);
- input length;
- a typed stage/failure class (which operation and which error variant, not
  a bare panic message);
- the exact local reproduction command (the filtered commands in "Seed-corpus
  and regression update procedure" above, chosen by artifact type).

Identical input/configuration must produce identical target behavior unless
the target explicitly injects a deterministic clock/entropy stream. Every
target in this file drives `pure_zig.Provider` through the injected
`provider.Entropy` seam only (`pure_zig.DeterministicEntropy` in tests) —
never ambient randomness. Case isolation matters as much as determinism
here: each test and each fuzz callback constructs its own
`DeterministicEntropy`/`Provider` pair on its own stack frame (the
`TestProvider` helper in `tests/crypto_provider_fuzz.zig`) rather than
sharing one process-global instance. A shared stream would advance
differently depending on how many earlier cases already ran in the same
process, so a case minimized during a full run and later replayed alone
(e.g. via `-Dcrypto-test-filter`) would see a different entropy position
than it had during discovery — reproducible in aggregate, but not
per-case. Constructing fresh state per case removes that dependency
entirely.

### Bounded work

Every target defines explicit limits for the dimensions it can amplify. For
the provider targets in this file that means: input bytes are read from
`std.testing.Smith` into fixed-capacity stack buffers (never an unbounded
`ArrayList`), so a target cannot be driven into an unbounded allocation by
attacker-controlled length fields. There is no nesting/recursion, no graph
exploration, and no allocation inside the hot path of AEAD/KEX/verify calls
— the provider's own contract keeps those operations O(input length). The
`BoundedSecret` property targets are the one place with real allocation, and
they bound capacity to a small fixed maximum (see the test file) and always
`deinit` before the next iteration.

### Arithmetic safety

Provider inputs are lengths and byte buffers, not wire-encoded variable-width
integers, so most of the classic overflow-adjacent boundaries reduce to
buffer-length boundaries. Targets and their deterministic regressions cover:

- zero-length keys/nonces/tags/AD/plaintext/ciphertext and zero-length
  signatures/public keys;
- exact, one-under, and one-over the algorithm's required length for every
  fixed-size field (AEAD key/nonce/tag, key-exchange public value/private
  scalar/shared secret, fixed-length signature encodings);
- a harness-chosen bounded "maximum" plaintext/message length, since AEAD and
  signing have no wire-defined upper bound the way a DER length or QUIC
  varint does.

Checked add/subtract/multiply around offsets, padding, and record/ticket/DER
lengths belongs to #491–#494 and #492 (those are the modules that actually
compute such offsets); this file's targets never perform that arithmetic —
`CryptoProvider` calls take already-sliced buffers.

### Lifetime / borrowed-slice safety

The provider boundary is explicit about this in its own doc comment
(`src/crypto/provider.zig`, "Secrets are borrowed, never retained"): every
slice a caller hands in is valid only for the call's duration, and the sole
provider-owned secret is the opaque `SigningKey` handle. This file's targets
exercise that contract:

- `deinit`/destruction after both success and failure leaves no usable
  private key: `SoftwareSigningKey`/`SoftwareEcdsaP256SigningKey` wipe
  `key_pair.secret_key` in place (stack-resident, directly inspectable after
  `deinit`); `SoftwareRsaSigningKey`/`rsa.PrivateKey` route through
  `secrets.secureZeroAndFree` (heap-resident, inspected via a
  `FixedBufferAllocator` the same way `src/crypto/secrets.zig`'s own
  `BoundedSecret` tests do);
- owned results (a returned shared secret, a returned signature) remain
  stable in the caller's buffer after the call returns — nothing the
  provider does later can invalidate them, because the provider retains no
  pointer into caller-owned output;
- borrowed results are never used outside their owner's lifetime — this is
  structurally enforced here because every provider operation is a single
  synchronous call with no retained borrow, not a stateful handle;
  `SigningKey` is the one exception and it is the type these `deinit` tests
  target;
- allocation-failure and early-return cleanup: the `BoundedSecret` property
  target injects allocator failure at random points via
  `std.testing.FailingAllocator` and asserts no leak (`std.testing.allocator`
  wraps every non-injecting path) and no partially-initialized secret escapes
  a failed `init`;
- partial outputs are not retained after a failed transactional operation:
  AEAD `open` never leaves usable plaintext after `error.AuthenticationFailed`
  (see below), and every `SigningKey.sign` implementation checks the output
  buffer length *before* drawing entropy or computing anything, so a rejected
  call never partially fills `out`.

### Read/write/reentrancy separation

Not applicable to this story's own targets: every `CryptoProvider` operation
is a single synchronous, non-reentrant call with no network I/O, no output
event carrier, and no partial-progress state to resume. State machines with
this shape (TLS transcript, QUIC CRYPTO reassembly, H3 request state) are
owned by #491/#493/#494/#247, which must apply this rule themselves.

### Secret-safe diagnostics

No target in this file ever formats or logs a `SigningKey`, `FixedSecret`,
`BoundedSecret`, private scalar, or shared secret — `format` is a compile
error on every secret-bearing type already (`@compileError("secret values
must not be formatted or logged")` in `secrets.zig` and each
`Software*SigningKey`), so a target that tried would fail to compile, not
just fail to review-catch. Failure output uses case IDs, public lengths,
algorithm/scheme names, and typed error variants, matching #375's audit
posture (`docs/CRYPTO_SECURITY_AUDIT.md`).

### Regression minimization

Every deterministic crash, panic, invariant violation, lifetime failure, or
semantic bug this story's targets find is checked in as a permanent
regression, in the form the "Seed-corpus and regression update procedure"
above prefers for it: normally an inline deterministic `test` block next to
the fuzz target in `tests/crypto_provider_fuzz.zig` (the same pattern
`docs/QUIC_H3_FUZZ_MATRIX.md` uses), or — only when the failure has no clean
semantic story and the exact bytes matter — a checked-in
`tests/vectors/fuzz/crypto/<target-slug>/<sha256>.bin` fixture wired back in
through `@embedFile`. There is no generic top-level `regression/` directory
in this repo; `tests/vectors/fuzz/crypto/` and PKI's
`tests/vectors/pki/reduced/` manifest pattern (reserved for #492's semantic
certificate corpus) are the two directory-backed exceptions to the
inline-`test`-block default. Do not fix a reproducible deterministic failure
by adding a skip; fix the defect or the test's understanding of the
contract.

## Provider targets owned here

`tests/crypto_provider_fuzz.zig` drives the real `pure_zig.Provider` (never a
mock) through `provider.CryptoProvider`, following the same three-tier shape
`tests/security/request_parser_corpus.zig` established: deterministic
regression tests for named edge cases, plus a `std.testing.Smith`-driven
generative `fuzz:` target with a seed corpus for each surface below. It
complements rather than duplicates the deep existing deterministic coverage
already in `src/crypto/pure_zig.zig`, `src/crypto/rsa.zig`, and
`src/crypto/secrets.zig` (key-share buffer sizing, ECDSA/RSA entropy-failure
and malformed-scalar rejection, `BoundedSecret` allocator-observable
zeroization, etc.) — this file adds the pieces that were missing: the
generative fuzz harnesses themselves, plus a small number of genuine
deterministic gaps identified while wiring them up.

| Area | Target | Properties covered | Open follow-up |
| --- | --- | --- | --- |
| AEAD seal/open | `tests/crypto_provider_fuzz.zig` `fuzz: AEAD open never leaves unauthenticated plaintext on arbitrary key/nonce/tag/ciphertext/AD`; deterministic wrong-length, tamper-zeroization, and zero/max-length regressions | Wrong key/nonce/tag length, ciphertext/plaintext length mismatch, truncated/mutated ciphertext/tag/AD rejected as `AuthenticationFailed` with the plaintext buffer fully zeroed, zero-length and harness-bounded maximum-length plaintext round-trip, for all three supported AEADs. | Overlap/alias behavior between `ciphertext` and `plaintext` buffers is not part of the documented provider contract today (`provider.zig`'s `aeadSeal`/`aeadOpen` doc comments are silent on aliasing); add coverage once that contract is decided rather than asserting undocumented behavior. |
| Key exchange | `tests/crypto_provider_fuzz.zig` `fuzz: deriveSharedSecret never panics on arbitrary scalar and peer-public bytes`; `fuzz: generateKeyShare never panics on arbitrary output-buffer lengths`; deterministic wrong-length and output-buffer-bound regressions | Wrong-length private scalars, peer public keys, and output buffers rejected as `InvalidInput` for X25519 and secp256r1; output-buffer-length fuzzing for key-share generation. Complements the existing low-order/all-zero-point and malformed-scalar coverage already in `pure_zig.zig`. | Positive round-trip and deterministic/failing-entropy-during-keygen coverage already exists in `pure_zig.zig` (`"X25519 key shares agree..."`, `"secp256r1 key-share generation rejects bad buffers before entropy and handles entropy failure"`); not duplicated here. |
| Signature verification | `tests/crypto_provider_fuzz.zig` `fuzz: verify never panics on arbitrary public key, message, and signature bytes`; deterministic malformed-key, malformed-signature, tampered-signature, and wrong-message/key regressions | Malformed public-key and signature encodings, structurally-valid single-bit-modified signatures, wrong message, and wrong key rejected without panic for Ed25519, ECDSA-P256/SHA-256, and RSA-PSS-RSAE/SHA-256, using `rsa.testdata`'s fixed RSA-2048 fixture as seed/provenance material rather than re-deriving key material. | None for the current provider `verify` surface. |
| Signing-key boundary | `tests/crypto_provider_fuzz.zig` deterministic undersized-output-buffer and deinit-wipe regressions for all three software signing-key types | Undersized output buffers rejected before any entropy draw or computation, output buffer left untouched, for Ed25519 (new — the ECDSA/RSA equivalents already existed in `pure_zig.zig`); `deinit` wipes the retained private key bytes for `SoftwareSigningKey` and `SoftwareEcdsaP256SigningKey` (RSA's equivalent already exists as `rsa.zig`'s `"PrivateKey.deinit wipes the retained private exponent"`). | Malformed constructor/import input and entropy-failure coverage already exists per-type in `pure_zig.zig`/`rsa.zig`; not duplicated here. |
| Shared secret helpers | `tests/crypto_provider_fuzz.zig` `fuzz: FixedSecret replace/eql/deinit preserve invariants under arbitrary overlapping and non-overlapping input`; `fuzz: BoundedSecret replace/eql/deinit preserve invariants under arbitrary capacity and allocator-failure injection` | `FixedSecret`/`BoundedSecret` `replace`/`copy`/`eql`/`deinit` across randomized capacities, content, and self-overlapping slices; `BoundedSecret` allocation-failure injection via `std.testing.FailingAllocator` with no leak under `std.testing.allocator` and no partially-initialized secret escaping a failed `init`. | `constantTimeEqual`'s functional behavior (equal/unequal/length-mismatch) and the `format`-is-a-compile-error guard are already covered deterministically in `secrets.zig` and `provider.zig`; not duplicated here. |

## Ownership boundaries

Same boundaries as the parent issue, restated for anyone landing on this
document directly:

- **#491** owns handshake message/extensions, canonical negotiation/policy,
  transcript/HRR/ClientHello2 state, and shared TLS reassembly.
- **#492** owns DER/PEM/X.509 semantic parsing, path building/validation,
  graph/resource bounds, and hostile certificate seed reuse.
- **#493** owns record codec/protection, epoch lifecycle, encrypted-stream
  buffering/progression, partial I/O, and authentication-failure record
  behavior.
- **#494** owns `NewSessionTicket`, PSK/binder handling, session
  codecs/cache, protected ticket envelopes/keyrings, resolver/runtime
  selection, and resumption state lifetime.
- **#247** owns QUIC packet/frame/transport-parameter/token/CRYPTO/ACK/
  stream/QPACK/H3 transport fuzzing and related interop/benchmark harnesses.

Do not pull those concerns back into this story merely because their
implementation consumes cryptography, and do not have this story re-fuzz a
protocol module's own state machine — call `CryptoProvider` directly instead.

## CI model

`zig build test` (and therefore every CI job that runs it, per
`.github/workflows/ci.yml`) already includes `test-crypto-provider-fuzz`'s
deterministic seed-corpus replay — no separate CI job was added. Longer
coverage-guided runs use the `-Doptimize=ReleaseFast --fuzz=<N>` commands
above as scheduled or manual local runs, the same model
`docs/QUIC_H3_FUZZ_MATRIX.md` uses; they are not wired into required PR CI
because they are unbounded by design. Coordinate future OSS-Fuzz/OpenSSF
onboarding with #121 rather than making external service integration a
blocker here.

## Protocol-scoped fuzz steps built on this contract

Per the "Commands" section above, #491–#494 do not grow this file's own
`test-crypto-provider-fuzz` step; each adds its own protocol-scoped step
and `-D<area>-test-filter` option instead. This section records the
stable step/filter names as those stories land, so a reader here does not
have to go hunting through `build.zig`.

### #494 — session / PSK / ticket / resumption state (epic #326-K)

Unlike this file's own targets, #494's targets are inline `test "fuzz:
..."` blocks inside the production modules themselves
(`src/tls/new_session_ticket.zig`, `src/tls/session.zig`,
`src/tls/pre_shared_key.zig`, `src/tls/ticket_protection.zig`) — not a
separate `tests/*.zig` root — so they already replay their deterministic
seed corpus under plain `zig build test-tls` / `zig build test`. The
`test-tls-resumption-fuzz` step exists to give them a stable,
individually filterable/long-runnable name, the same shape as
`-Dcrypto-test-filter` above:

```bash
# Deterministic smoke coverage for every #494 fuzz target (seed corpus
# replay only, "fuzz: " test-name prefix) — also covered by plain
# `zig build test-tls` / `zig build test` since tls_core's test binary
# already includes these files.
zig build test-tls-resumption-fuzz --summary all --error-style verbose

# Longer local/scheduled coverage-guided runs, one target at a time:
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: NewSessionTicket wire decode and owned-state construction never panic or corrupt output" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: session codec raw decode never panics and owns its decoded state" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: session codec generated client/server records round-trip and reject cross-kind decode" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: PSK wire codec" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: PSK binder derivation" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: parseEnvelope is allocation-free" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: parseEnvelope single-field mutation" --fuzz=10M --summary all --error-style verbose
```

`-Dtls-resumption-test-filter` defaults to `"fuzz: "` (every #494 target,
none of the much larger surrounding deterministic TLS suite); pass an
exact `test "fuzz: ..."` name to scope a long `--fuzz=<N>` run to one
target, matching the reproduction-command shape "Seed-corpus and
regression update procedure" above requires. #494-A (this pass) covers
`NewSessionTicket` wire/owned-state construction, the session client/
server codec, PSK modes/`OfferedPsks`/binder primitives, and allocation-
free ticket-envelope parsing (`parseEnvelope`); authenticated ticket open,
key-snapshot/keyring publication, session-cache/lease state machines, and
backend/runtime composition follow in #494-B/C/D per the issue's PR
decomposition.
