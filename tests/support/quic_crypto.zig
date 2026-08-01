//! Test-only QUIC/H3 crypto composition helpers (#490).
//!
//! Owns concrete `pure_zig.Provider` construction for tests and tools that
//! exercise the QUIC seam without the native HTTP/3 runtime composition root.
//! `build.zig` wires this module into `src/quic/`, `src/http/http3_runtime.zig`,
//! and the QUIC/H3 test tools so their `test` blocks and in-file test fixtures
//! can reach it, but no production (non-test) code path may call it —
//! concrete backend selection for the live runtime belongs solely to
//! `src/http/http3_runtime.zig`'s `Runtime` composition root, which builds
//! its own provider from real OS entropy instead.

const crypto = @import("crypto");

const test_entropy_context: u8 = 0;

fn testEntropyFill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
    _ = buffer;
    return error.EntropyFailure;
}

const test_provider_backing: crypto.pure_zig.Provider = crypto.pure_zig.Provider.init(.{
    .context = @constCast(&test_entropy_context),
    .fillFn = testEntropyFill,
});

/// Deterministic, capability-valid provider for QUIC/H3 unit tests and the
/// interop tool's composition root when OS entropy is not required. A
/// comptime-known backing value (not a lazily-initialized `var`) so this is
/// itself comptime-evaluable and usable as a struct field default.
pub fn testDefaultProvider() crypto.provider.CryptoProvider {
    return test_provider_backing.cryptoProvider();
}

// ---------------------------------------------------------------------------
// Handshake-capable provider storage (#490)
// ---------------------------------------------------------------------------
//
// `testDefaultProvider` above deliberately fails every entropy draw — correct
// for its existing callers, QUIC packet-protection-only paths that derive
// AEAD/header-protection keys from already-negotiated TLS secrets and must
// never need ambient randomness. Ephemeral X25519 key-share generation is
// different: it is itself a real entropy draw, now routed through the same
// injected `CryptoProvider` (#490's native TLS engine migration), so a QUIC/H3
// test that constructs a full `Tls13Backend` end-to-end needs a provider
// whose entropy source actually produces bytes.
//
// There is deliberately no shared/global `testHandshakeProvider()` helper
// here (#490 review — an earlier revision had one, backed by one process-wide
// mutable `DeterministicEntropy` stream every caller advanced together): a
// test's captured key share/traffic-secret bytes would then depend on which
// other tests ran before it in the same process, and on whether a test
// filter skipped some of them — order- and filter-dependent, not hermetic.
// Every caller instead owns a `HandshakeProviderStorage` (a struct field for
// a harness/backend pair that outlives one call, a local variable for a
// single self-contained test), so a given seed reproduces byte-for-byte
// regardless of what else runs in the process.

/// Per-instance deterministic `CryptoProvider` storage for a caller that
/// drives a full TLS handshake end-to-end and needs its own independent
/// entropy stream — e.g. a seeded simulation harness, or a client/server
/// backend pair in a single test. Backed by `pure_zig.DeterministicEntropy`
/// (explicitly not a CSPRNG, matching the convention `src/crypto/pure_zig.
/// zig`'s own tests use). Zero-initializable (`= .{}`) so it can be embedded
/// as a struct field default or declared as a plain local; call `init` with
/// the caller's own seed before use. `self` must have a stable address for
/// as long as the returned `CryptoProvider` is used (same rule as
/// `production_crypto.StackProviderStorage`), since the provider erases to a
/// view that borrows `self` — a struct field (stable for the owning
/// instance's lifetime) or a local in the same function that uses the
/// resulting backend (stable for that function's own stack frame), never a
/// local inside a separate factory function that returns before the backend
/// is done being used.
pub const HandshakeProviderStorage = struct {
    entropy: crypto.pure_zig.DeterministicEntropy = crypto.pure_zig.DeterministicEntropy.init(0),
    provider: crypto.pure_zig.Provider = undefined,

    pub fn init(self: *HandshakeProviderStorage, seed: u64) crypto.provider.CryptoProvider {
        self.entropy = crypto.pure_zig.DeterministicEntropy.init(seed);
        self.provider = crypto.pure_zig.Provider.init(self.entropy.entropy());
        return self.provider.cryptoProvider();
    }
};
