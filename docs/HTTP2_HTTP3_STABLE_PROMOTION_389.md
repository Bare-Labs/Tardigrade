# HTTP/2 and HTTP/3 Stable Promotion Evidence (#389)

This is the final evidence map for promoting downstream HTTP/2 and HTTP/3/QUIC
to `stable` in [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md). It does not introduce
new protocol behavior; it reconciles the retained release, benchmark, packaging,
and operator evidence already accepted in #389.

## Promotion Result

| Protocol | Status | Stable contract |
| --- | --- | --- |
| HTTP/2 | `stable` | Downstream TLS/ALPN `h2` for static serving, reverse proxying, HEAD/POST, multiplexing, flow control, malformed-frame/HPACK failure scope, reload/shutdown/GOAWAY/RST behavior, and bounded resource-settle behavior. |
| HTTP/3 / QUIC | `stable` | Native Zig QUIC/H3 over UDP with QUIC v1/TLS 1.3/ALPN `h3`, static serving, reverse proxying, Alt-Svc enable/withdraw, independent external-peer proof, cancellation/recovery, GOAWAY/drain, soak/resource-settle, and controlled-host H3 performance evidence. |

## Evidence Map

| Requirement | Evidence of record |
| --- | --- |
| H2 baseline | [#389 comment](https://github.com/Bare-Systems/Tardigrade/issues/389#issuecomment-5480769050) records the retained `static-http2` and `proxy-http2` native baseline from [PR #735](https://github.com/Bare-Systems/Tardigrade/pull/735): tested SHA `7afc1b4920c83f48ce404bfbf9309796fa8f4583`, binary SHA-256 `076a096bed56868bd489d259b9a5e80c2d3b2ab84bef1bd6a2d37abd8ee7161f`, Zig `0.16.0`, `h2load nghttp2/1.69.0`, 3 runs per row, zero errors, ALPN `h2` probes retained. Results: `static-http2` 14628.667 req/s, p95 0.165 ms, p99 0.175 ms; `proxy-http2` 6139.333 req/s, p95 0.352 ms, p99 0.416 ms. |
| #593 / #699 H3 baseline | [PR #699](https://github.com/Bare-Systems/Tardigrade/pull/699) merged the Proxmox/cross-machine performance harness and retained canonical real-H3 rows using a QUIC-capable `h2load`. #389 records the accepted H3 baseline: `static-http3` about 3575 req/s with p95 about 15.4 ms and p99 about 16.2 ms, and `proxy-http3` about 2755 req/s with p95 about 16.3 ms and p99 about 17.5 ms, both with zero errors and exact native Tardigrade/SUT/tool metadata. |
| v0.6.5 installed-artifact sweep | [#389 comment](https://github.com/Bare-Systems/Tardigrade/issues/389#issuecomment-5482736063) records `/opt/homebrew/Cellar/tardigrade/0.6.5/bin/tardi`, `0.6.5 (tls-profile=general, tls-backend=native)`, binary SHA-256 `7fff73a80a2184b64a35276643165afcb8fd18c9251e9ee8464b943cd08ffcb5`, macOS 26.3 arm64, and a passing black-box rerun on 2026-08-31T18:31:31Z. |
| ngtcp2 + aioquic black-box closeout | The same v0.6.5 closeout records ngtcp2/GnuTLS `gtlsclient` with ngtcp2 `1.25.0`, nghttp3 `1.18.0`, GnuTLS `3.8.13`, plus aioquic `1.3.0` on Python `3.14.3`. Passing rows include QUIC v1/TLS 1.3/ALPN `h3` application exchange, RESET_STREAM/STOP_SENDING cancellation with same-connection recovery, GOAWAY/drain boundary, and disabled-H3 Alt-Svc withdrawal. |
| Public Homebrew Smoke #4 | The fourth `Public Homebrew Smoke` run listed for 2026-08-31 completed successfully on `main` (`5772f1f86500cded8c376d5d6be6331634281972`): <https://github.com/Bare-Systems/Tardigrade/actions/runs/33423212434>. Earlier manual public-smoke evidence for #670 also passed after the harness landed. |

## Operator Limitations

HTTP/2 and HTTP/3/QUIC are stable within the documented deployment contract, not
generic replacements for every protocol topology:

- HTTP/2 downstream support is TLS/ALPN `h2`. Plaintext downstream h2c is not
  supported; HTTP/2-only downstream listeners require TLS. Cleartext h2c
  remains an upstream-origin option, not a downstream listener mode.
- HTTP/3 requires `TARDIGRADE_HTTP3_ENABLED=true`, TLS credentials, a UDP
  listener on `TARDIGRADE_QUIC_PORT`, and firewall/load-balancer rules that
  pass UDP to that port. TCP reachability alone does not prove H3 reachability.
- `Alt-Svc` is gateway-owned. `auto` advertises only when the runtime is ready;
  withdrawal uses `Alt-Svc: clear`; upstream `Alt-Svc` is stripped so stale
  backend advertisements do not leak through the edge.
- HTTP/3 listener-owned settings require restart, including enablement, QUIC
  port, 0-RTT, migration, Retry, max datagram size, UDP socket buffers, ECN,
  qlog, and keylog destinations. Advertisement-only `Alt-Svc` settings can hot
  reload.
- The supported H3 topology is one Tardigrade process owning one UDP runtime
  and its in-process Destination Connection ID routing table. Multi-process
  `SO_REUSEPORT`, eBPF, or external DCID steering is outside the current
  support promise.
- `TARDIGRADE_HTTP3_RETRY_POLICY=off` remains the default; `address_validation`
  enables stateless QUIC Retry before connection allocation. Active migration is
  off by default; the default supports hardened NAT rebinding behavior.
- qlog and keylog output remain opt-in debug artifacts. Keylog output decrypts
  traffic and must be treated as sensitive.

## Closeout

The final #389 close rule is satisfied by the evidence above: both support
matrix rows are stable, the stable claim refers to the native implementation in
the installed v0.6.5 artifact, public/operator/release docs agree, known
limitations are explicit, and no unresolved evidence-backed blocker remains.
