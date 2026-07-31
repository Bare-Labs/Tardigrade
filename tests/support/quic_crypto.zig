//! Test-only QUIC/H3 crypto composition helpers (#490).
//!
//! Owns concrete `pure_zig.Provider` construction for tests and tools that
//! exercise the QUIC seam without the native HTTP/3 runtime composition root.
//! Production protocol code under `src/quic/` must never import this module.

const crypto = @import("crypto");

const test_entropy_context: u8 = 0;

fn testEntropyFill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
    _ = buffer;
    return error.EntropyFailure;
}

var test_provider_backing: crypto.pure_zig.Provider = undefined;
var test_provider_initialized = false;

/// Deterministic, capability-valid provider for QUIC/H3 unit tests and the
/// interop tool's composition root when OS entropy is not required.
pub fn testDefaultProvider() crypto.provider.CryptoProvider {
    if (!test_provider_initialized) {
        test_provider_backing = crypto.pure_zig.Provider.init(.{
            .context = @constCast(&test_entropy_context),
            .fillFn = testEntropyFill,
        });
        test_provider_initialized = true;
    }
    return test_provider_backing.cryptoProvider();
}
