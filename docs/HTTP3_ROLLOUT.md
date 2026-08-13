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
- **It has no effect at all without the socket contract below.** On a platform
  where no-IP-fragmentation cannot be established, the send size stays at 1200
  however this is set.

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

Discovery is **per path incarnation, never inherited.** Migrating to a new path
restarts from 1200 rather than carrying over a size only the old path was shown
to carry — and so does re-probing a tuple whose previous validation ended,
whether it was promoted away or expired unanswered. Outcomes still owed by an
earlier incarnation (a delayed acknowledgement, a late loss) are dropped rather
than applied to the state that replaced it.

### Requirements and diagnostics

Discovering anything above 1200 requires the listener socket to establish a
**no-IP-fragmentation contract**. Without it a large probe may be fragmented,
and its acknowledgement would prove the peer *reassembled* it rather than that
the path carries it. Supported platforms:

| Platform | Mechanism | Notes |
| --- | --- | --- |
| Linux | `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE` | Sets DF *and* ignores the kernel's cached path MTU, so DPLPMTUD is in control (RFC 8899 §4.5). |
| macOS, iOS, tvOS, watchOS | `IP_DONTFRAG` (28) / `IPV6_DONTFRAG` (62) | DF only — no probe mode, so a kernel-cached PMTU can still bound a probe. Costs discovery reach, not soundness. |
| FreeBSD | `IP_DONTFRAG` (67) / `IPV6_DONTFRAG` (62) | As above. Note the IPv4 constant differs from Darwin's. |
| NetBSD, OpenBSD, DragonFly, others | — | No verified API; discovery stays at 1200. |

These constants are deliberately **not** shared across the BSDs: Darwin's IPv4
`IP_DONTFRAG` is 28 while FreeBSD's is 67, and OpenBSD uses option 28 for
something else entirely. A wrong constant that a kernel happens to *accept*
would report success without ever setting DF — the exact false positive this
gate exists to prevent — so an unverified platform reports failure instead of
guessing.

Where the contract cannot be established the listener logs a warning and holds
the send size at 1200 whatever `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` says — the
conservative policy, not a silently unsound measurement.

The QUIC transport's own `max_send_udp_payload_size` defaults to 1200 for the
same reason: `src/quic/` owns no socket and cannot know whether a probe would be
fragmented, so **discovery is opt-in by the composition root that created the
socket**. An embedder using `quic.connection` directly gets the conservative
policy until it establishes the contract itself and raises the ceiling.

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

## Socket buffers

The UDP receive buffer is where datagrams wait between the kernel taking them
off the wire and the listener thread reading them. When it fills, the kernel
drops datagrams — silently, as far as QUIC is concerned. To the connection that
looks exactly like network loss: congestion control backs off, packets are
retransmitted, and throughput falls for a reason nothing on the path caused.
A host whose default buffer is small relative to the bandwidth-delay product
will do this under bursts even when the link is idle.

`TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES` and
`TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES` request `SO_RCVBUF` / `SO_SNDBUF` on
the listener socket. Both default to `0`, meaning **leave the kernel's own
sizing alone** — the right setting unless you have measured drops. Requests are
clamped into `[2048, 1073741823]` before reaching the kernel: the `setsockopt`
ABI takes a signed 32-bit size and a typo must not wrap it. The upper bound is
`INT_MAX / 2` rather than a round 1 GiB because Linux stores twice what it is
given and caps a request at that same figure first — asking for 1 GiB exactly
would be reduced by a byte and then reported as clamped forever, blaming a
sysctl that was never the cause.

Everything here is advisory. A kernel that refuses the request, or grants less
than was asked for, still gets a listener that serves HTTP/3 correctly — buffer
sizing is a performance setting, and turning it into a startup failure would
take a service down over a tuning knob. What it must not do is fail silently,
so the size is **read back with `getsockopt`** and reported:

| Log | Meaning |
| --- | --- |
| `udp receive buffer at kernel default effective_bytes=N` | Nothing requested. `N` is what the socket has. |
| `udp receive buffer applied requested_bytes=N granted_bytes=N effective_bytes=M` | Granted. |
| `udp receive buffer clamped by the kernel …` | The request was accepted and cut down by a host-wide ceiling. Only the host operator can raise it. |
| `udp receive buffer … accepted but could not be read back` | The size is unknown; nothing was measured. |
| `udp receive buffer request rejected by the kernel …` | The default buffer stands. |

The readback matters because the request and the grant are routinely different
numbers, and `setsockopt` reports success either way:

- **Linux** caps `SO_RCVBUF` at `net.core.rmem_max` (and `SO_SNDBUF` at
  `net.core.wmem_max`) — commonly 208 KiB on a stock kernel — so a listener
  asking for 16 MiB gets a fraction of it and no indication from the syscall.
  Raise the ceiling on the host (`sysctl -w net.core.rmem_max=8388608`,
  persisted in `/etc/sysctl.d/`) before raising the request.

  Linux also stores and reports **twice** what was set: the other half is
  per-datagram bookkeeping overhead, not payload capacity. Grant-versus-clamp
  is therefore decided on the reading *restated in request units* — the half
  that corresponds to what was asked for — and not on the raw number, which
  would report a success whenever the kernel granted more than half the
  request. A 256 KiB request on a host capped at 208 KiB reads back as
  416 KiB: larger than the request, and still a clamp. Both figures are
  logged, as `granted_bytes` and `effective_bytes`; the second is what the
  kernel will tell anyone who inspects the socket directly.
- **macOS and the BSDs** bound the total per-socket buffer with
  `kern.ipc.maxsockbuf` rather than per direction, and return the size set
  rather than a doubled one.
- **Other platforms** are not assumed to expose either knob; a refusal is
  reported and the default stands.

The effective values are published on the runtime's status snapshot
(`udp_buffers`), which is what benchmark runs should record — the requested
value and the host sysctls describe intent, not what the socket got.

Both variables are restart-required: buffer sizes are socket state applied to
the live descriptor at bind time, so changing one means a new socket.

## Explicit Congestion Notification

ECN (RFC 3168, RFC 9000 §13.4) lets a congested router *mark* a packet instead
of dropping it. When it works, congestion control reacts a round trip earlier
and without a retransmission; when it does not, nothing is lost. That asymmetry
is why Tardigrade runs it by default and treats every failure as a fallback
rather than an error.

Tardigrade marks outbound datagrams **ECT(0)**, counts the codepoints on
received packets, reports them to the peer in ACK_ECN, and validates the
counters the peer sends back. ECT(1) is never sent: it belongs to L4S
(RFC 9331), whose congestion response is not the RFC 9002 one implemented here.

### Per path, and only after the handshake

Marking starts once the handshake is **confirmed**, and each network path
validates independently — the same scoping as DPLPMTUD, for the same reason.
Whether ECN survives end to end is a property of the route, so a migration
re-validates rather than inheriting an answer measured somewhere else. A path
that failed validation stays unmarked for the life of that path incarnation.

Validation is not a formality. The peer's counters are an *input to congestion
control*, reachable by anything on the path and by the peer itself, so they are
checked against what this endpoint actually sent before they are believed:

| Check | Failure |
| --- | --- |
| Acknowledged marked packets, no ECN counts in the ACK | `missing_counts` — the marks were stripped, or the peer does not report |
| A counter went backwards | `counts_regressed` |
| ECT(1) reported | `unsent_codepoint` — something is rewriting the field |
| More marked arrivals reported than were ever marked | `counts_exceed_sent` |
| Marked packets acknowledged without matching counter growth | `insufficient_increase` |
| No usable feedback within the testing window (3×PTO) | `testing_timeout` |

Any of these turns marking off for that path and the connection continues
normally. **CE reports are acted on only on a validated path**, so an
unvalidated or forged report cannot shrink the congestion window on demand. The
counters this endpoint reports back come only from packets that passed AEAD
authentication, so an off-path spoofer cannot inflate what the peer is told.

`ecn_paths_disabled` being non-zero on the open internet is expected and is not
an error condition.

### Platform support

The transport decides *whether* to mark; the kernel is what actually sets and
reads the IP header field, via `sendmsg`/`recvmsg` ancillary data. A socket-wide
`IP_TOS` would not do — ECN is validated per path, and there would be no way to
stop marking on the one path whose validation failed.

| Platform | Receive | Send | Notes |
| --- | --- | --- | --- |
| Linux | `IP_RECVTOS` (13) / `IPV6_RECVTCLASS` (66) | `IP_TOS` (1) / `IPV6_TCLASS` (67) | Received IPv4 codepoints arrive under `IP_TOS`, not under the option that enabled them. |
| macOS, iOS, tvOS, watchOS | `IP_RECVTOS` (27) / `IPV6_RECVTCLASS` (35) | `IP_TOS` (3) / `IPV6_TCLASS` (36) | Control messages align to 4 bytes (`__DARWIN_ALIGN32`), not the platform word. |
| FreeBSD | `IP_RECVTOS` (68) / `IPV6_RECVTCLASS` (57) | `IP_TOS` (3) / `IPV6_TCLASS` (61) | Constants differ from Darwin's; not interchangeable. |
| Other platforms | — | — | No verified API; the listener runs without ECN. |

As with the no-fragmentation table, these are **not** shared across the BSDs and
an unverified platform runs without ECN rather than guessing. The *receive* side
gates everything: without received codepoints there is nothing to put in
ACK_ECN, so the peer's own validation would fail and this endpoint would be
marking into a feedback loop it cannot close. If the kernel later refuses the
send-side control message, the listener logs it, stops asking, and each
connection's validation discovers the marks are not arriving.

There is nothing to tune on the host — no sysctl gates any of this. Whether ECN
does anything useful depends on the routers between the endpoints, not on local
configuration.

### Operating

`TARDIGRADE_HTTP3_ECN` (default `true`) turns marking off outright. The escape
hatch exists for the one failure mode per-path validation cannot detect: a
middlebox that *drops* ECT-marked traffic rather than clearing the marks, which
looks like ordinary loss. Symptom: loss and PTO counts that fall when ECN is
disabled on an otherwise unchanged path.

The runtime status snapshot publishes `ecn_enabled` — whether marking is
actually running, not merely requested — along with `ecn_marked_sent`,
`ecn_paths_validated`, `ecn_paths_disabled`, and `ecn_ce_received`. Benchmark
runs should record all five: a CE count is only meaningful next to the number
of paths that validated.

`TARDIGRADE_HTTP3_ECN` is restart-required, like every other listener-owned knob
— the receive option is socket state applied at bind time.

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
- `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES`
- `TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES`
- `TARDIGRADE_HTTP3_ECN`

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
