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
// Handshake-capable provider (#490)
// ---------------------------------------------------------------------------
//
// `testDefaultProvider` above deliberately fails every entropy draw — correct
// for its existing callers, QUIC packet-protection-only paths that derive
// AEAD/header-protection keys from already-negotiated TLS secrets and must
// never need ambient randomness. Ephemeral X25519 key-share generation is
// different: it is itself a real entropy draw, now routed through the same
// injected `CryptoProvider` (#490's native TLS engine migration), so a QUIC/H3
// test or tool that constructs a full `Tls13Backend` end-to-end needs a
// provider whose entropy source actually produces bytes.

var handshake_entropy_state = crypto.pure_zig.DeterministicEntropy.init(0x71a5_c0de);
var handshake_provider_backing: crypto.pure_zig.Provider = crypto.pure_zig.Provider.init(handshake_entropy_state.entropy());

/// A working (non-failing) deterministic pure-Zig provider for QUIC/H3 tests
/// and tools that drive a native TLS handshake end-to-end. Backed by
/// `pure_zig.DeterministicEntropy` (explicitly not a CSPRNG, matching the
/// convention `src/crypto/pure_zig.zig`'s own tests use) over one shared,
/// persistent byte stream: safe for multiple backends (a client and a server,
/// say) drawing from it in sequence within one single-threaded test, since
/// each draw simply consumes the stream's next bytes rather than needing to
/// be independent of any other caller's draws.
pub fn testHandshakeProvider() crypto.provider.CryptoProvider {
    return handshake_provider_backing.cryptoProvider();
}

/// Per-instance deterministic `CryptoProvider` storage, for a caller that
/// needs its own independent entropy stream instead of sharing
/// `testHandshakeProvider`'s single global one — e.g. a seeded simulation
/// harness where a given seed must reproduce byte-for-byte regardless of what
/// else in the process draws from the shared stream. Zero-initializable
/// (`= .{}`) so it can be embedded as a struct field default; call `init`
/// with the caller's own seed before use. `self` must have a stable address
/// for as long as the returned `CryptoProvider` is used (same rule as
/// `production_crypto.StackProviderStorage`), since the provider erases to a
/// view that borrows `self`.
pub const HandshakeProviderStorage = struct {
    entropy: crypto.pure_zig.DeterministicEntropy = crypto.pure_zig.DeterministicEntropy.init(0),
    provider: crypto.pure_zig.Provider = undefined,

    pub fn init(self: *HandshakeProviderStorage, seed: u64) crypto.provider.CryptoProvider {
        self.entropy = crypto.pure_zig.DeterministicEntropy.init(seed);
        self.provider = crypto.pure_zig.Provider.init(self.entropy.entropy());
        return self.provider.cryptoProvider();
    }
};
