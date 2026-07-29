# QUIC/H3 Fuzz and Property Matrix

This matrix tracks the deterministic parser/state-machine fuzz coverage for
#247/#537. Default smoke coverage is run by `zig build test` and the focused
QUIC/H3 subset by:

```bash
zig build test-quic --summary all --error-style verbose
```

For longer local or scheduled coverage-guided runs, use the same offline test
targets with Zig's fuzz runner against the target-local `std.testing.fuzz`
cases:

```bash
zig build test-quic -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: packet parser" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: frame decoder" --fuzz=10M --summary all --error-style verbose
```

The `--fuzz=<runs>` limit keeps scheduled runs bounded; suffixes `K`, `M`, and
`G` scale the run count. The optional `-Dquic-test-filter` gives explicit target
selection, and the failing fuzz case is reported by Zig's unit-test runner with
the test name and minimized input needed for deterministic reproduction. Keep
external peers out of these loops; ngtcp2/nghttp3, quiche, and aioquic remain under
`scripts/interop/run-interop.sh`.

Use `-Doptimize=ReleaseFast` for coverage-guided runs with Zig 0.16.0; the
ordinary deterministic smoke tests continue to run in the default Debug mode.

| Area | Existing or New Target | Properties Covered | Open Follow-Up |
| --- | --- | --- | --- |
| QUIC varints | `src/quic/varint.zig` `fuzz: varint decode and minimal re-encode never panic`; `fuzz: varint encode round-trips arbitrary in-range values` | Minimal re-encode, in-range encode/decode round-trip, truncation rejection. | None for the current varint codec surface. |
| QUIC packet numbers | `src/quic/packet.zig` `fuzz: packet number truncation reconstructs recent sends`; upper-bound deterministic regressions | Packet-number length selection, truncation, and reconstruction across the legal `2^62 - 1` range, including exact values near `max_packet_number`. | Add recovered packet-number comparisons from loss/reordering driver state when that state exposes a narrow property API. |
| QUIC packet/header/coalescing | `src/quic/packet.zig` `fuzz: packet parser preserves bounded slice and progress invariants`; `fuzz: packet writers round-trip public parser fields`; deterministic coalesced invalid-tail regression tests | Empty/truncated inputs, fixed-bit failures, long/short header CID boundaries, version-negotiation length boundaries, Initial token/Length cursor handling, Retry token/tag split, short-header caller CID length, coalesced progress, parsed slices staying inside the input, nonzero bounded `packet_len`, and canonical long-header, short-header, and Retry writer/parser public-field round-trips. | None for the current packet/header codec surface. |
| QUIC frame and ACK ranges | `src/quic/frame.zig` `fuzz: frame decoder preserves bounded consumption and slice invariants`; `fuzz: canonical frame encoders round-trip supported families`; ACK boundary regressions | Supported frame families, unknown type handling, varint truncation, STREAM/CRYPTO payload slices, fixed-size PATH frames, NEW_CONNECTION_ID length/token boundaries, CONNECTION_CLOSE reason slices, parser monotonicity including typed malformed-tail termination, ACK underflow and range-length arithmetic, and semantic encode/decode round-trips for supported canonical encoders. | Add encode coverage for ACK ECN and NEW_TOKEN if/when production encoders are added. |
| Transport parameters | `src/quic/tls_adapter.zig` and TLS transport-extension tests currently exercise composed decode/validation paths. | Stable handshake tests cover legal extension exchange and maximum transport extension length. | Add a raw parameter decoder/validator property target for duplicate singleton rejection, unknown skippable parameters, truncated ID/length/value varints, and semantic bounds. |
| Retry/public token boundary | `src/quic/packet.zig` covers Retry packet integrity tag construction/verification and parser split. Runtime invalid-token acceptance remains in #387 coverage. | Retry packet tag verification rejects wrong ODCID and packet tampering without logging token contents. | Add offline Retry token envelope mutation against `src/quic/path.zig` `RetryTokens` with deterministic keys, clock, address, version, expiry, and wrong-binding cases. |
| CRYPTO reassembly | QUIC connection-driver tests exercise ordinary CRYPTO delivery through handshake progress. | Composed smoke/e2e paths prove in-order and fragmented handshake bytes at the connection boundary. | Add a narrow reassembler command-sequence target for overlap, duplicate, gap-fill, capacity, large-offset, zero-length, and reset/deinit accounting. |
| Streams and flow control | `src/quic/stream.zig`, `src/quic/connection.zig`, and `tests/quic_h3_e2e.zig` cover deterministic stream/flow-control scenarios. | Deterministic driver cases cover normal request/response stream accounting and teardown. | Add bounded command-sequence properties for open/receive/send/ack/lose/reset/stop_sending/max_data/max_stream_data/max_streams/close. |
| QPACK decoder | `src/http3/qpack.zig` `fuzz: QPACK static decoder never panics on arbitrary field sections`; `fuzz: QPACK static-table selections round-trip through encoder` | Static table index boundaries, malformed prefixes/string lengths on static-only blocks, field-count and scratch bounds, static encode/decode round-trip. | Extend to stateful encoder/decoder instruction streams, dynamic table capacity/eviction, blocked stream registration, acknowledgements, and cancellations. |
| HTTP/3 frame and control stream | `src/http3/frame.zig` `fuzz: frame decoder never panics on arbitrary bytes`; `fuzz: SETTINGS decoder never panics on arbitrary payloads`; `fuzz: control stream ingestion never panics or leaks` | Frame parse bounds, SETTINGS duplicate/boolean validation, frame-size limits, fragmented control-stream ingest, duplicate critical stream detection. | Add bounded session/connection state-machine fuzz for request-stream DATA/HEADERS ordering, illegal frames per stream class, GOAWAY ordering, reset/STOP_SENDING interaction, and exact H3/QPACK error-code preservation. |
| External H3 interop | `tests/h3_interop_tool.zig`; `scripts/interop/run-interop.sh`; integration `h3interop.*` filters | Native-to-external and external-to-native peer proof outside fuzz loops. | Keep separate from parser/property fuzzing; do not fold network peers into fuzz targets. |
