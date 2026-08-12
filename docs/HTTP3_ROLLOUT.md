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

Two different quantities share the name "max UDP payload size" in QUIC, and
Tardigrade keeps them separate.

**Receive capacity** is what this endpoint tells peers it is willing to receive,
via the `max_udp_payload_size` transport parameter. It is a property of the
receive buffers the implementation allocates — **2048 bytes** — not something an
operator tunes, and it never changes for the life of a connection. The config
layer refuses to advertise more than the transport can actually deprotect.

**Send size** is what this process puts on the wire. It is *measured*, not
configured: every path starts at **1200** — the size RFC 9000 §14 requires every
QUIC path to carry — and only rises as far as DPLPMTUD has proven the path
carries (see below). The transport resolves the size actually emitted as the
smallest of:

1. the current path size, as discovered by DPLPMTUD;
2. this endpoint's send ceiling — `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE`, clamped
   into `[1200, 2048]` and defaulting to 2048;
3. the peer's advertised receive capacity, once its transport parameters are
   authenticated.

`TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` is therefore a **ceiling on what discovery
may find**, not a size taken on trust. Consequences worth knowing:

- **The send size sits at 1200 for the whole handshake**, and stays there until
  a probe of something larger is acknowledged. Datagrams carrying Initial
  packets are always padded to 1200 regardless.
- **A peer always wins when it asks for less.** Nothing here can push a
  datagram past what the peer advertised.
- **Lowering the ceiling is the only reason to touch it.** Raising it can never
  make Tardigrade send a size the path has not been shown to carry, so the
  default needs no defensive tuning. Lower it when you know a downstream link
  is smaller than discovery would otherwise find, or to switch discovery off
  entirely by pinning it to 1200.

## Path MTU discovery

Tardigrade runs DPLPMTUD (RFC 8899, RFC 9000 §14.3/§14.4) per network path,
starting once the handshake is confirmed — the peer's receive capacity is
authenticated by then, and a completed handshake is itself proof the path
carries 1200 bytes, since every Initial-bearing datagram was padded to it.

- **Probes are standalone datagrams** carrying only PING and PADDING, sized to
  exactly the size being validated. Nothing rides on one, so a probe dropped by
  a path too small for it costs no application progress.
- **The first probe reaches straight for the ceiling** (RFC 8899's optimistic
  search), so a path that really carries the configured maximum is discovered in
  one round trip. After that the search bisects, converging to within 16 bytes.
- **A converged search is re-run every 10 minutes** if it stopped because larger
  sizes failed (RFC 8899's `PMTU_RAISE_TIMER`). A path can *gain* MTU on the
  same address tuple — a tunnel goes away, a route changes — and the previous
  failure bound describes a path condition that no longer exists, so it is
  discarded and the sizes it ruled out become reachable again. A search that
  converged at the ceiling has nothing above it to find and does not re-run.
- **A probe's loss is not a congestion signal** (RFC 9000 §14.4) — being too big
  is what a probe is for — but a probe is still congestion controlled and
  anti-amplification limited like any other datagram, with none of the RFC 9002
  PTO exemptions. It waits for window rather than overshooting.
- **A size is only ruled out after three consecutive probe losses**, so ordinary
  congestion cannot narrow the search.

### Black holes

A path that used to carry the discovered size can stop carrying it — a tunnel
appears, a route changes, an operator lowers an MTU. Tardigrade watches for two
signatures and pulls the send size back to 1200 when either fires three times:

- datagrams **at or above the current send size** being lost while **smaller**
  ones are still delivered. Both halves are measured against the size actually
  in question, not against the 1200-byte floor: with a discovered size of 1452,
  a delivered 1300-byte datagram *corroborates* the black hole rather than
  disproving it, while a delivered 1452-byte datagram clears the evidence
  outright. A loss below the current size is not evidence at all — falling back
  would not have saved it.
- consecutive PTO expirations with nothing acknowledged in between, which is
  what the same failure looks like when *every* datagram in flight is already
  oversized and there is no smaller delivery to compare against.

A false positive costs throughput until the raise timer re-tests. Not falling
back costs the connection: Tardigrade's own retransmissions would keep
re-sending the same oversized datagram until the idle timeout.

Discovery is **per path, never inherited.** Migrating to a new path — or
re-validating a tuple that has been away — restarts from 1200 rather than
carrying over a size only the old path was shown to carry.

### Requirements and diagnostics

Discovering anything above 1200 requires the listener socket to establish a
**no-IP-fragmentation contract** — `IP_PMTUDISC_PROBE` on Linux (DF set, and the
kernel's cached path MTU ignored, per RFC 8899 §4.5), `IP_DONTFRAG` on
macOS/BSD. Without it a large probe may be fragmented, and its acknowledgement
would prove the peer *reassembled* it rather than that the path carries it. On a
platform or kernel that refuses the option the listener logs a warning and holds
the send size at 1200 whatever `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` says — the
conservative policy, not a silently unsound measurement.

Diagnostics are currently **connection-level, not yet operator-facing**:
`pmtu_probes_sent` and `pmtu_black_holes` on `quic.connection.Metrics`, plus a
`pmtu_updated` event carrying the path, the new effective size, and whether it
rose or fell back. The HTTP/3 runtime's metrics/event bridge does not surface
them yet; #255's observability work is where they become operator-visible.

Nothing about this setting relaxes congestion control, flow control, or the
server's anti-amplification budget:

- An in-flight packet's content is bounded by the *remaining congestion
  window*, not by the datagram size, so raising the size cannot widen how far
  in-flight bytes cross the window. The budget covers the packet's **final**
  size, including the padding RFC 9000 mandates for Initial-bearing and
  path-validation datagrams.
- Path validation is delayed when the window cannot cover its padded datagram
  (RFC 9000 §8.2 permits this) rather than being sent uncharged.
- Recovery's packet tracker is bounded; when it is full the transport
  backpressures instead of emitting in-flight packets it cannot track.
- Pure ACKs (never in flight) and PTO probes keep their RFC 9002 exemptions.
  A packet carrying PADDING is in flight even when nothing in it is
  ack-eliciting, and is charged accordingly.

RFC 9002's NewReno windows are defined in terms of the sender's current maximum
datagram size, so the initial window, minimum window, and congestion-avoidance
growth all scale with the value above rather than with a fixed 1200.

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
