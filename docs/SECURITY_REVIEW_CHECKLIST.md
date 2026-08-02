# Security-Sensitive-Code Review Checklist

Use this checklist for any change that adds, moves, or touches secret,
authentication, or attacker-observable comparison/branching logic — TLS,
QUIC, PKI, record protection, ticket/resumption, and provider/credential
code. It is the durable deliverable required by #375 and complements (does
not replace) `docs/CODE_REVIEW_CHECKLIST.md`.

Reference: `docs/CRYPTO_SECURITY_AUDIT.md` is the checked-in audit matrix
this checklist keeps current. A change that introduces a new
secret-bearing owner, a new comparison against secret-derived material, or a
new peer-visible failure path should add or update a row there, not just
pass this checklist silently.

---

## 1. Value classification

- [ ] Is each new or touched value **public**, **attacker-controlled**,
      **secret-derived**, or **secret**? State this explicitly in the PR
      description or a code comment — do not leave it implicit.
- [ ] Public routing/protocol values (algorithm IDs, cipher/group/signature
      selections, connection IDs, key IDs used only for lookup, lengths,
      framing/version/flags) are not mechanically upgraded to constant-time
      treatment merely because they sit near secret material.

## 2. Constant-time comparison

- [ ] Does comparison or branching on this value require constant-time
      treatment? If the value is secret or secret-derived (MACs, Finished
      values, PSK binders, authentication tags, fingerprints of key
      material), the comparison uses the canonical helper —
      `crypto.secrets.constantTimeEqual` / `crypto.provider.constantTimeEqual`
      — never a raw `std.crypto.timing_safe.*` call or `std.mem.eql`.
- [ ] Public-length validation (wire length, count, size bound) happens as
      an ordinary branch *before* the constant-time comparison, not folded
      into it.
- [ ] No new ad hoc constant-time primitive is introduced when the shared
      helper already covers the case.

## 3. Secret ownership and lifetime

- [ ] Who owns every copy of this secret, and when do they destroy it? A
      secret must be owned by exactly one of: a `crypto.secrets.FixedSecret`
      / `BoundedSecret`, a connection/session-scoped struct with an explicit
      `deinit`, or a caller-supplied buffer whose lifetime contract is
      documented at the call site.
- [ ] No secret slice is returned, stored, or captured with an ambiguous or
      shorter-than-consumer lifetime (borrowed-until-next-call, stack-backed
      past its frame, etc.).

## 4. Cleanup on every exit path

- [ ] What happens to this secret on success, failure, replacement,
      rotation, cache eviction, and teardown? Each applicable path wipes the
      value via `crypto.secrets.secureZero` / `secureZeroAndFree` before the
      backing memory is freed, reused, or dropped.
- [ ] Cleanup (`errdefer`/`defer`) is armed *before* the fallible operation
      that fills the buffer, not after — a callee that writes a partial
      result and then errors must not leave that partial write unwiped.
- [ ] No custom/manual zero-and-free path is added when
      `crypto.secrets.secureZeroAndFree` already provides the guarantee.

## 5. Observability

- [ ] Can logs, traces, metrics, error values, or crash/panic output expose
      this value? Ordinary diagnostics may carry algorithm names, public
      lengths, typed failure stages, and sanitized counters — never raw
      private keys, traffic secrets, RMS/PSKs/binder keys, ticket encryption
      keys, decrypted bearer/session state, raw session tickets, or
      secret-derived fingerprints where logging them would aid an attacker.
- [ ] Any new struct holding secret bytes exposes a non-formatting API
      (no `format`, or a `format` that `@compileError`s), consistent with
      `crypto.secrets.FixedSecret`/`BoundedSecret`.

## 6. Provider/ownership boundary

- [ ] Does this code bypass `crypto.provider.CryptoProvider` or
      `crypto.secrets` ownership rules by calling a concrete `std.crypto`
      primitive directly for a keyed operation? Check the operation against
      `docs/CRYPTO_PROVIDER_AUDIT.md`'s allowed/forbidden table for the file
      before adding a new direct call; extend that document (and, if the
      file is covered by it, `scripts/audit_crypto_boundary.zig`) rather than
      quietly adding an exception.

## 7. Peer-visible failure behavior (oracle risk)

- [ ] For any peer-controlled parse/decrypt/lookup/authenticate path
      (ticket resolution, PSK binder/identity selection, record
      decryption, certificate/signature verification): do distinct failure
      causes (malformed envelope, unknown key ID, retired/future key, wrong
      algorithm, tag/authentication failure, expired state) collapse to the
      same externally observable result — same alert/error class, same
      response shape, no distinguishing log line or metric label keyed on
      the failure cause — rather than leaking which case occurred?
- [ ] Key-ID/routing lookups may branch on public data, but a lookup miss
      alone never marks an identity "selected" or advances transcript/binder
      state.

## 8. Toolchain and platform assumptions

- [ ] Does this change rely on a constant-time or zeroization property that
      is target/compiler-dependent, or not guaranteed by `std.crypto`'s own
      documentation? If so, state the assumption explicitly (see
      `docs/CRYPTO_SECURITY_AUDIT.md`'s toolchain-assumptions section)
      instead of implying a stronger guarantee than the implementation
      supports.
- [ ] No claim is made that this change eliminates microarchitectural
      (cache/speculation) side channels on arbitrary hardware — only that it
      removes a software-level timing or lookup dependency on secret data.

---

## Quick reference: the eight questions (#375)

1. Is this value public, attacker-controlled, secret-derived, or secret?
2. Does comparison/branching require constant-time treatment?
3. Who owns every secret copy and when is it wiped?
4. What happens on failure, replacement, rotation, eviction, and teardown?
5. Can logs/traces/metrics/crash output expose the value?
6. Does the code bypass `CryptoProvider`/`crypto.secrets` ownership rules?
7. Is peer-visible failure behavior creating an oracle?
8. Are platform/toolchain assumptions documented?
