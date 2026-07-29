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
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: transport parameter decoder" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: transport parameters canonical" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: Retry token issue validate" --fuzz=10M --summary all --error-style verbose
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
| QUIC packet/header/coalescing | `src/quic/packet.zig` `fuzz: packet parser preserves bounded slice and progress invariants`; `fuzz: packet writers round-trip public parser fields`; deterministic coalesced invalid-tail and boundary-matrix regression tests | Empty/truncated inputs, fixed-bit failures, long/short header CID boundaries, version-negotiation empty/misaligned/exact-list boundaries, Initial token/Length cursor handling including exact/under/huge values, Retry token/tag split, short-header caller CID length, coalesced valid+invalid and multiple-valid-prefix progress, parsed slices staying inside the input, nonzero bounded `packet_len`, and canonical long-header, short-header, and Retry writer/parser public-field round-trips. | None for the current packet/header codec surface. |
| QUIC frame and ACK ranges | `src/quic/frame.zig` `fuzz: frame decoder preserves bounded consumption and slice invariants`; `fuzz: canonical frame encoders round-trip supported families`; ACK boundary and decoder-only family regressions | Supported frame families, unknown type handling, varint truncation, STREAM/CRYPTO payload slices, NEW_TOKEN empty/non-empty handling, DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED decoding, fixed-size PATH frames, NEW_CONNECTION_ID length/token boundaries, CONNECTION_CLOSE reason slices, parser monotonicity including typed malformed-tail termination, ACK and ACK_ECN exact consumption, underflow, overlap, huge-gap arithmetic, and semantic encode/decode round-trips for supported canonical encoders. | Add encode coverage for ACK ECN and NEW_TOKEN if/when production encoders are added. |
| Transport parameters | `src/quic/tls_backend.zig` `fuzz: transport parameter decoder preserves bounded structural contract`; `fuzz: transport parameters canonical encode and binding round-trip`; deterministic structural, semantic, and CID-binding regressions | Empty blocks, truncated ID/length/value varints, declared length overrun, integer trailing bytes, duplicate known and tracked-unknown IDs, best-effort unknown duplicate tracking that keeps more than 64 distinct well-formed unknown IDs skippable, `max_udp_payload_size`, `active_connection_id_limit`, `ack_delay_exponent`, `max_ack_delay`, initial flow-control values including symmetric decode/config/encode enforcement of `initial_max_streams_* <= 2^60`, `disable_active_migration`, CID binding zero/max/max+1 lengths, stateless reset-token exact/short/long lengths, bounded successful decode invariants, and canonical encode/decode preservation of supported `TransportParameters` and `CidBinding` fields. | None for the current raw transport-parameter codec/validation surface. |
| Retry/public token boundary | `src/quic/path.zig` `fuzz: Retry token issue validate and mutation boundary is deterministic`; deterministic issue/validate, mutation, authenticated-malformed-plaintext, key-rotation, address-binding, and time-boundary regressions. Runtime invalid-token acceptance remains in #387 coverage. | Offline `RetryTokens.issueRetry`/`validateRetry` preserves ODCID, Retry SCID, and QUIC version across IPv4/IPv6 including scope IDs; validates retained old keys and rejects retired/unknown keys; rejects nonce, ciphertext, and tag mutations; rejects short/oversized/truncated tokens; maps authenticated wrong-kind and malformed plaintext to public token errors; enforces address/port binding and exact expiry/future-skew boundaries including `u64` saturation behavior. Retry SCID and version comparisons are exposed in `RetryContext`; the connection layer owns comparing them to the active Retry packet and transport-parameter binding. No explicit temporary-plaintext zeroization contract exists on this owner today; token buffers are bounded stack slices and no diagnostics include token plaintext, keys, nonces, or reusable material. | None for the current offline Retry token codec/state boundary. |
| CRYPTO reassembly | QUIC connection-driver tests exercise ordinary CRYPTO delivery through handshake progress. | Composed smoke/e2e paths prove in-order and fragmented handshake bytes at the connection boundary. | Add a narrow reassembler command-sequence target for overlap, duplicate, gap-fill, capacity, large-offset, zero-length, and reset/deinit accounting. |
| Streams and flow control | `src/quic/stream.zig`, `src/quic/connection.zig`, and `tests/quic_h3_e2e.zig` cover deterministic stream/flow-control scenarios. | Deterministic driver cases cover normal request/response stream accounting and teardown. | Add bounded command-sequence properties for open/receive/send/ack/lose/reset/stop_sending/max_data/max_stream_data/max_streams/close. |
| QPACK decoder | `src/http3/qpack.zig` `fuzz: QPACK static decoder never panics on arbitrary field sections`; `fuzz: QPACK static-table selections round-trip through encoder` | Static table index boundaries, malformed prefixes/string lengths on static-only blocks, field-count and scratch bounds, static encode/decode round-trip. | Extend to stateful encoder/decoder instruction streams, dynamic table capacity/eviction, blocked stream registration, acknowledgements, and cancellations. |
| HTTP/3 frame and control stream | `src/http3/frame.zig` `fuzz: frame decoder never panics on arbitrary bytes`; `fuzz: SETTINGS decoder never panics on arbitrary payloads`; `fuzz: control stream ingestion never panics or leaks` | Frame parse bounds, SETTINGS duplicate/boolean validation, frame-size limits, fragmented control-stream ingest, duplicate critical stream detection. | Add bounded session/connection state-machine fuzz for request-stream DATA/HEADERS ordering, illegal frames per stream class, GOAWAY ordering, reset/STOP_SENDING interaction, and exact H3/QPACK error-code preservation. |
| External H3 interop | `tests/h3_interop_tool.zig`; `scripts/interop/run-interop.sh`; integration `h3interop.*` filters | Native-to-external and external-to-native peer proof outside fuzz loops. | Keep separate from parser/property fuzzing; do not fold network peers into fuzz targets. |
