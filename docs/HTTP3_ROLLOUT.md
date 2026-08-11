# HTTP/3 rollout and lifecycle

HTTP/3 uses QUIC over UDP on `TARDIGRADE_QUIC_PORT`; HTTP/1.1 and HTTP/2 remain
on the configured TCP listener. Firewalls, security groups, and load balancers
must explicitly permit UDP to the QUIC port. Allowing TCP/443 does not make
HTTP/3 reachable.

The supported v1 deployment model is one Tardigrade process owning one UDP
runtime and one in-process Destination Connection ID routing table. NAT
rebinding and the configured migration policy are handled inside that process.
Multi-process `SO_REUSEPORT`, eBPF, or external DCID steering is not part of the
current support promise.

## Advertisement

`TARDIGRADE_HTTP3_ENABLED=true` starts the native listener when TLS credentials
are available and the UDP socket can bind. It does not advertise HTTP/3 by
itself.

`TARDIGRADE_HTTP3_ALT_SVC=auto` advertises only while the runtime is actually
ready to accept QUIC/H3 connections. `TARDIGRADE_HTTP3_ALT_SVC=off` keeps the
listener running without emitting an active `Alt-Svc` alternative. When a hot
reload changes an actively advertised listener from `auto` to `off`, TCP
responses emit `Alt-Svc: clear` to withdraw cached alternatives.

`TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS` controls the bounded `ma` value
emitted with active advertisements. Values above 86400 are rejected.

During drain or rollback withdrawal, eligible TCP responses emit
`Alt-Svc: clear` so clients can discard cached alternatives. Tardigrade strips
upstream `Alt-Svc` response headers and emits at most one gateway-owned
`Alt-Svc` value.

## Datagram size

`TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` is the **local** bound on the UDP payload
of every datagram this process sends, and the `max_udp_payload_size` transport
parameter it advertises to peers. It defaults to **1200** — the size RFC 9000
§14 requires every QUIC path to carry — and is clamped into `[1200, 2048]`.

It is only one of the inputs to the size actually emitted. The transport
resolves one *effective* cap per connection as the smallest of:

1. this local configured maximum;
2. the peer's advertised `max_udp_payload_size`, once its transport parameters
   are authenticated;
3. the validated path size.

Consequences worth knowing before tuning it:

- **The cap sits at 1200 for the whole handshake.** A raised local value only
  takes effect once the peer has authenticated and committed to accepting
  larger datagrams. Datagrams carrying Initial packets are always padded to
  1200 regardless.
- **A peer always wins when it asks for less.** Raising this value can never
  push a datagram past what the peer advertised.
- **Raising it is an assertion about the path**, not a measurement. Tardigrade
  does not yet run DPLPMTUD (RFC 8899), so a value above 1200 says "I know this
  path carries this much". If it does not, those datagrams are dropped and the
  connection stalls until the peer's PTO retransmits. Raise it only for paths
  whose MTU you control end to end (a dedicated link, a loopback or same-rack
  benchmark host, a known-jumbo-frame fabric). Leave it at the default on the
  open internet.
- The 2048 ceiling is the transport's work-buffer size, not a path property.

Nothing about this setting relaxes congestion control, flow control, or the
server's anti-amplification budget. In particular, an ordinary packet's
in-flight content is bounded by the *remaining congestion window*, not by this
cap, so raising the cap cannot widen how far in-flight bytes cross the window.
Pure ACKs (not in flight) and PTO probes keep their RFC 9002 exemptions.

## Reload

Advertisement-only knobs can hot reload:

- `TARDIGRADE_HTTP3_ALT_SVC`
- `TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS`

Listener-owned HTTP/3 knobs require a process restart because the current
runtime does not atomically replace a live UDP socket and QUIC connection table:

- `TARDIGRADE_HTTP3_ENABLED`
- `TARDIGRADE_QUIC_PORT`
- `TARDIGRADE_HTTP3_CONNECTION_MIGRATION`
- `TARDIGRADE_HTTP3_RETRY_POLICY`
- `TARDIGRADE_HTTP3_ENABLE_0RTT`
- `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE`

A reload that changes one of those fields is rejected before publication. The
old config, old runtime, and old effective advertisement remain active.

## Drain and rollback

Graceful rollback order is:

1. Withdraw advertisement (`Alt-Svc: clear`).
2. Begin H3 drain; the runtime sends HTTP/3 GOAWAY and refuses new work.
3. Let admitted streams finish until `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS`.
4. Close remaining QUIC connections, remove CID routes, then stop or restart
   the listener.

`TARDIGRADE_HTTP3_RETRY_POLICY=address_validation` enables stateless QUIC Retry
before connection allocation. `off` is the default. `TARDIGRADE_HTTP3_CONNECTION_MIGRATION=false`
allows the hardened NAT-rebinding behavior; enabling migration broadens that
policy and is restart-required.
