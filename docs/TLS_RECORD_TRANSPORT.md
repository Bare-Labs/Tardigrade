# TLS handshake transport contract

`src/tls/transport.zig` defines the single canonical contract between a TLS
1.3 handshake backend and any transport that carries it. QUIC's adapter
(`src/quic/tls_handshake.zig`) and TCP record mode
(`src/tls/record_epoch_bridge.zig`) both instantiate
`transport.Contract`/`transport.ContractWithOptions` directly with their own
epoch and transport-parameter payload types; neither owns a parallel copy of
the event/sink/driver machinery.

> An earlier record-mode-only contract, `record_transport.zig`, duplicated
> this module's guarantees (secure zeroization, driver teardown) without a
> production consumer — `record_epoch_bridge.zig` used the generic contract
> from the start. It has been removed; this file now documents the one
> contract both transports use (#408 finding 1).

## Events and ownership

The handshake backend emits events tagged with the caller's own `Epoch` type:
handshake bytes to send, traffic-secret installation (read/write, per epoch),
transport-owned peer parameters, negotiated ALPN, peer certificate state,
epoch discard, completion, and a fatal alert.

Event byte slices are copied into the driver-owned `EventSink`. They remain
valid only until the next drive call — `Driver.start`, `Driver.receive`,
`Driver.startOutcome`, or `Driver.receiveOutcome` — all four reset the sink
before invoking the backend. Resetting or deinitializing the sink securely
zeroes the used scratch range, so a copied traffic secret does not survive
past that event lifetime. Event emission is atomic: a rejected emit
(event-count or byte overflow) never leaves a partial payload in scratch or a
phantom event in `items`.

`Driver.deinit()` wipes the sink's final contents. Every owner of a `Driver`
must call it exactly once at teardown, regardless of whether the handshake
completed, failed, or was abandoned mid-flight — QUIC's `Connection.deinitPartial`
does this via `Handshake.deinit()`.

## Terminal error plus events

`Driver.start`/`Driver.receive` return `Transport.Error!*EventSink`: on
backend failure they return only the error, discarding whatever the backend
already emitted into the sink before failing (for example a fatal alert, or
handshake bytes queued ahead of it). That is the right shape for QUIC's
`try`-based happy path, where a failure always tears the connection down
regardless of what else was emitted.

A caller that needs the backend's terminal output — for example TCP record
mode, which must still serialize a fatal alert the backend emitted right
before failing — uses `Driver.startOutcome`/`Driver.receiveOutcome` instead.
Both return `Driver.Outcome`, `{ sink: *EventSink, terminal_error: ?Transport.Error }`,
so the sink and the error are always available together rather than one
discarding the other. This restores the terminal-error-plus-events guarantee
the removed `record_transport.zig` carried (#408 finding 1); once a driver has
failed, repeated `startOutcome`/`receiveOutcome` calls keep returning the same
terminal error and sink contents without re-invoking the backend.

## Fatal alerts

The contract's `Event` union can carry a fatal alert
(`Event.fatal_alert: alerts.AlertDescription`) so a transport can serialize
one before closing. The contract only carries it; deciding *when* to
synthesize an alert from a handshake failure — and the rest of alert /
`close_notify` / truncation policy — is transport-specific and, for TCP record
mode, tracked by #354.

## Record-stream buffer limits

`PureZigRecordStream` keeps its hot path allocation-free: inbound carrier
ciphertext, decrypted application plaintext, outbound ciphertext, and inbound
handshake bytes live in fixed-capacity queues owned by the stream. Runtime
`BufferLimits` add effective low/high/hard watermarks inside those compile-time
capacities; they do not replace the queues with dynamically growing buffers.

Validation rejects zero or nonsensical watermarks (`low < high <= hard` is
required), hard limits above the fixed queue capacity, and policies that cannot
hold a maximum legal TLS fragment or the complete borrowed handshake event batch
that record mode must serialize atomically. Existing constructors use safe
defaults derived from the fixed capacities; callers that need tighter appliance
profiles can use the explicit `init*WithLimits` constructors.

Readiness uses latched hysteresis. Carrier reads pause when inbound ciphertext,
plaintext, or handshake ownership reaches the relevant high watermark, and they
resume only after all inbound queues drain to their low watermarks. Plaintext
writes pause when outbound ciphertext reaches its high watermark and resume
only after the ciphertext queue drains to or below low. `wants_write` remains
true while queued ciphertext can drain.

The backend-neutral `EncryptedStream.bufferSnapshot()` reports allocation-free
state for metrics and HTTP integration: current and peak owned bytes by queue,
peak total owned bytes, optional configured limits plus whether those limits are
enforced by the backend, pause state, pause/resume counters, hard-limit counters,
and stalled-drive count. The pure-Zig record stream reports complete owned bytes
and enforced limits. An OpenSSL adapter must report only measurable adapter/BIO
state, leave unknown limits unset, and mark opaque internal OpenSSL memory as
outside the complete stream-owned accounting boundary rather than describing
unknown memory as zero.

Pure-Zig application writes seal accepted plaintext directly into the outbound
ciphertext queue; there is no hidden pending-plaintext staging queue. HTTP/1.1
and HTTP/2 consumers should use `can_write_plaintext`, `can_read_plaintext`,
`wants_read`, `wants_write`, and the buffer snapshot to register only socket
readiness that can make progress.

Production native TLS listeners receive an immutable `BufferLimits` policy from
validated edge configuration. The environment keys are
`TARDIGRADE_TLS_{INBOUND_CIPHERTEXT,INBOUND_PLAINTEXT,OUTBOUND_CIPHERTEXT,HANDSHAKE}_{LOW_WATERMARK_BYTES,HIGH_WATERMARK_BYTES,HARD_LIMIT_BYTES}`;
omitted values use `BufferLimits.defaults()`. Reload rejects invalid ordering,
capacity, or atomic-reserve violations before replacing the active config.

For encrypted HTTP transports, application readiness and raw fd readiness are
intentionally separate. `can_read_plaintext` and `can_write_plaintext` allow
immediate application work; raw socket registration is derived only from
`wants_read` and `wants_write`. A plaintext read blocked on a TLS write retry
therefore registers only write interest, and a plaintext write blocked on a TLS
read retry registers only read interest.

## Record sizing and padding (#359)

Two independent knobs sit on the record path. They are easy to confuse and do
opposite things, so this section names them apart explicitly.

### `record_size_limit` — negotiated, bounds memory

RFC 8449's `record_size_limit` extension (type 28) is a *negotiated* bound.
Each endpoint advertises the largest `TLSInnerPlaintext` it is willing to
**receive**; the peer must not send a protected record larger than that.
The value covers the complete inner plaintext — content, the content-type
byte, and any padding — which is why the TLS 1.3 maximum is 2^14+1 (16385)
rather than 2^14, and why usable content is always one byte less than the
advertised limit.

* Record transport only. TLS-over-QUIC has no TLS records, so the QUIC profile
  never offers the extension and never reads one. A QUIC **server** ignores a
  client that offers it — without even validating the value — because RFC 8446
  §4.1.2 has a server ignore an unsupported ClientHello extension, and
  GnuTLS-based QUIC clients do send it. A **client** still rejects one in
  EncryptedExtensions with `unsupported_extension`, which is the opposite
  case and the one RFC 8446 §4.2 requires aborting on: a server must not answer
  an extension the client never requested.
* The server's EncryptedExtensions answer is **conditional on the client having
  offered**, for that same reason. RFC 8449 §4 says where the server's value
  goes; it does not exempt it from RFC 8446 §4.2's request/response rule, and a
  conforming client that does not implement RFC 8449 aborts on an unsolicited
  response.
* Offering is not negotiating. Our own advertised bound becomes enforceable
  only once the round trip completes — the client on receiving the server's
  answer, the server on writing it. Against a peer that ignores the extension,
  RFC 8449 §4 leaves ordinary protocol record sizes permitted, so a configured
  limit of 512 must not make us reject a legal 8 KiB record. `Limits.local`
  therefore reports the configured value only when the extension actually
  negotiated, and the protocol maximum otherwise.
* That split leaves one window, and it is closed retroactively. A client cannot
  apply its bound to the server's *first* protected flight: until
  EncryptedExtensions is parsed it does not know whether the server answered at
  all, and pre-rejecting would break every server that did not. Those
  handshake-epoch records are therefore opened against the protocol maximum and
  their inner lengths retained as a high-water mark (EncryptedExtensions may
  itself be fragmented, so it is a mark across the flight, not one record).
  `Bridge.setRecordSizeLimits` judges them the moment the bound becomes known: a
  server that answered extension 28 and then exceeded the value it just agreed
  to fails with `record_overflow`. When the extension does not negotiate, the
  bound stays at the protocol maximum and the mark can never exceed it, so the
  measurement clears itself.
* **0-RTT is exempt from the bound entirely**, not merely from the retroactive
  settle. RFC 8449 §4 renegotiates the limit on resumption and governs records
  by the limits of the handshake that produced their protection keys; RFC 8446
  §4.2.10 puts early data in the client's first flight, so it is created — and
  may already be buffered in flight — before the server's answer exists. A
  server activates its bound when it *writes* EncryptedExtensions, which is
  before the handshake completes, so an early record can legitimately arrive at
  a server already enforcing 512. Judging it against that value would reject
  early data a conforming client had no way to size correctly.

  The fuller answer would be to honor the *previous* session's bound, but
  `ResumableSessionCommon` persists no record-size limit today, so there is no
  PSK-associated value to apply. Until one exists, early records keep the
  protocol maximum, which `record_codec` already enforces. The exemption is
  scoped to the epoch, not the connection: the same record size is refused as
  soon as it arrives at the handshake or application epoch.
* The client offers it in ClientHello (in both ClientHello1 and ClientHello2,
  at the same position, so an HRR's "ClientHello2 is a legal mutation of
  ClientHello1" check still passes). The server answers in
  EncryptedExtensions, on the full and PSK-resumed flights alike.
* Configured by `policy.Policy.record_size_limit`. The default is the
  protocol maximum: the extension is offered but constrains nothing, which is
  the most interoperable choice and avoids inflating per-record overhead for
  connections that never needed smaller records. Lowering it is a deliberate
  memory/latency tradeoff.
* Values below 64 are rejected as `illegal_parameter` by both roles. Above
  the protocol maximum the handling is asymmetric, exactly as RFC 8449 §4
  requires: a **server clamps** (a client may be advertising a size a future
  version enables, and a server must not enforce the restriction), while a
  **client rejects** — by EncryptedExtensions the negotiated version is
  already settled, so no such reading is available.
* Enforcement is symmetric in `record_epoch_bridge`. Outbound, every
  protected write and every protected handshake fragment is sized by
  `Bridge.outboundContentMax()`; sealing more than that fails closed with
  `RecordSizeLimitExceeded` rather than silently truncating. Inbound, a
  record whose inner plaintext would exceed our own advertisement is refused
  *before* the AEAD open — the point of the bound is to cap the work an
  unauthenticated peer can cause — and maps to the `record_overflow` alert.
* Unprotected records are exempt (RFC 8449 §4). The initial-epoch plaintext
  ClientHello/ServerHello keeps the full protocol fragment.

A very small advertised limit interacts with the fixed outbound queue: a large
server flight (certificate chain plus CertificateVerify) split into 63-byte
fragments pays per-record overhead on every fragment. The exact requirement is
preflighted by `sealedHandshakeLen`, so the failure mode is a deterministic
refusal to progress, never an overflow — but an operator choosing a limit near
RFC 8449's floor should size the certificate chain accordingly.

### Padding — local, buys privacy, costs bandwidth

RFC 8446 §5.4 record padding is *not* negotiated and has no wire signal. It
appends zero bytes to the inner plaintext so that an on-path observer cannot
read the true content length out of the record length. It is a
traffic-analysis countermeasure, and it is the only thing here that is.

* Configured per stream with `PureZigRecordStream.setRecordPadding`. Off by
  default: every padding byte costs bandwidth and AEAD work and buys nothing
  except length uniformity.
* The only policy is `.block = N`, which rounds each inner plaintext up to a
  multiple of `N`. A fixed target size was rejected because it cannot pad a
  record that is already larger and inflates a small-record stream by a
  constant factor; rounding degrades smoothly.
* Applied only to `application_data`. Handshake messages have protocol-fixed
  lengths that are already visible in the transcript, so padding them inflates
  a latency-critical flight for no privacy; alerts are two bytes and their size
  should not vary at all.
* Padding is bounded by the negotiated limit, never the other way around: the
  target length is clamped to `record_size_limit` before the padding is
  derived from it, so `content + type + padding` is within the cap for every
  input, including a record that is already at the cap (which gets none).

Neither knob is record *coalescing*. Coalescing — merging several small
application writes into one record to amortize the 22-byte header/tag
overhead — is a throughput optimization that changes when bytes leave, and it
is not implemented here: `writePlaintext` seals exactly what it accepts, one
record per call. Padding makes records *larger* on purpose and never merges
them; a smaller `record_size_limit` makes them *more numerous*. Reading either
as a performance feature gets the tradeoff backwards.

### Observability

`PureZigRecordStream.recordSizeLimits()` reports the negotiated state and
`recordSizeCounters()` the effects: writes narrowed by the peer's limit,
records that carried padding, total padding bytes, inbound records refused for
exceeding our own advertisement, how many protected records were sealed, and
the high-water inner-plaintext size in each direction.

The two high-water marks answer different questions and neither substitutes for
the other: `max_sent_inner_len` against the peer's advertised bound shows *we*
honored *theirs*, while `max_recv_inner_len` against `Limits.local` shows the
peer honored *ours*. The interop rows in `docs/TLS_INTEROP_MATRIX.md` assert one
of each against GnuTLS.
