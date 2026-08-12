//! Compatibility re-export: TLS key logging is transport-neutral and owned by
//! `src/tls/keylog.zig`.

const shared = @import("tls_core").keylog;

pub const client_random_len = shared.client_random_len;
pub const Context = shared.Context;
pub const Endpoint = shared.Endpoint;
pub const Entry = shared.Entry;
pub const Label = shared.Label;
pub const Sink = shared.Sink;
pub const labelFor = shared.labelFor;
pub const writeLine = shared.writeLine;
