const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const tls13_backend = @import("tls13_backend.zig");

pub const Provider = crypto.pure_zig.Provider;

/// Stateless OS entropy callback context. `fill` ignores `context`, so the
/// pointer need not refer to a live `OsEntropy` value — avoiding a dangling
/// self-reference when a `Provider` outlives a copied/moved `Runtime`.
const os_entropy_context: u8 = 0;

pub const OsEntropy = struct {
    pub fn entropy(_: *OsEntropy) crypto.provider.Entropy {
        return .{ .context = @constCast(&os_entropy_context), .fillFn = fill };
    }

    fn fill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
        fillSecure(buffer) catch return error.EntropyFailure;
    }
};

/// Stack-stable pure-Zig provider storage for tests and short-lived composition
/// roots. Keeps `entropy` and `provider` in one struct so the provider vtable
/// context remains valid for the storage lifetime.
pub const StackProviderStorage = struct {
    entropy: OsEntropy = .{},
    provider: Provider = undefined,
};

pub fn stackProvider(storage: *StackProviderStorage) crypto.provider.CryptoProvider {
    storage.provider = Provider.init(storage.entropy.entropy());
    return storage.provider.cryptoProvider();
}

/// Fresh entropy for one handshake's `Tls13Backend.Entropy`. Only
/// `hello_random` (the TLS ClientHello/ServerHello `random` field) lives
/// here: ephemeral X25519 key-share generation draws from the injected
/// `CryptoProvider`'s own entropy source instead (#490) — see `OsEntropy`
/// above, which composition roots pass to the pure-Zig `Provider` they hand
/// to `Tls13Backend`'s `crypto_provider` parameter.
pub fn freshHandshakeEntropy() crypto.provider.EntropyError!tls13_backend.Entropy {
    var entropy: tls13_backend.Entropy = undefined;
    try fillSecure(&entropy.hello_random);
    return entropy;
}

test "fresh handshake entropy fills the backend's hello_random input" {
    const entropy = try freshHandshakeEntropy();
    try std.testing.expect(!allZero(&entropy.hello_random));
}

fn fillSecure(buffer: []u8) crypto.provider.EntropyError!void {
    if (buffer.len == 0) return;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var offset: usize = 0;
        while (offset < buffer.len) {
            const rc = linux.getrandom(buffer[offset..].ptr, buffer.len - offset, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.EntropyFailure;
                    offset += rc;
                },
                .INTR => {},
                else => return error.EntropyFailure,
            }
        }
        return;
    }
    if (@TypeOf(std.c.arc4random_buf) != void) {
        std.c.arc4random_buf(buffer.ptr, buffer.len);
        return;
    }
    return error.EntropyFailure;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}
