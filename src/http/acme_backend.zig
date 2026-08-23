//! ACME client backend selector (#379, epic #327, #634).
//!
//! Mirrors `tls_backend.zig`: `-Dtls-profile=general` selects the
//! OpenSSL-backed ACME client; the adapter-free profiles
//! (`-Dtls-profile=appliance` and `-Dtls-profile=native`, i.e.
//! `tls_openssl_adapter=false`) select the no-OpenSSL stub, so those
//! binaries never analyze the ACME client's `@cImport("openssl/...")` and
//! never link OpenSSL through the ACME path. The pure-Zig `ChallengeStore`
//! is identical in both backends.

const selected = if (@import("build_options").tls_openssl_adapter)
    @import("acme_client.zig")
else
    @import("acme_client_stub.zig");

pub const AcmeError = selected.AcmeError;
pub const ChallengeStore = selected.ChallengeStore;
pub const AcmeOptions = selected.AcmeOptions;
pub const daysUntilExpiry = selected.daysUntilExpiry;
pub const runOnce = selected.runOnce;

test {
    _ = selected;
}
