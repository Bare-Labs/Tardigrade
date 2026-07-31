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
