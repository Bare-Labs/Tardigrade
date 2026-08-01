//! Dedicated test-only root for `key_schedule_tests.zig` (#490 review).
//!
//! This file exists solely so `build.zig` can compile `key_schedule_tests.zig`
//! as its own test artifact, structurally separate from the production
//! `tls_core` module (`src/tls/root.zig`): `key_schedule_tests.zig` carries
//! direct-crypto fixtures (a cross-check against `std.crypto.auth.hmac.sha2.
//! HmacSha256`, raw `CryptoProvider` vtable construction) that `scripts/
//! audit_crypto_boundary.zig` intentionally never scans, on the understanding
//! that no production code path can ever resolve the file that carries them.
//! `src/tls/root.zig` — the actual root of the `tls_core` module every
//! production consumer (native TLS/QUIC/HTTP, the `tardi` executable) depends
//! on — must never import this file or `key_schedule_tests.zig`, directly or
//! transitively; this file's own module (see `key_schedule_test_root_mod` in
//! `build.zig`) is wired only into `zig build test-tls`/`test-crypto`/`test`'s
//! test artifacts, never into `quic_mod`/`exe_mod`/the shipped build.

pub const key_schedule_tests = @import("key_schedule_tests.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
