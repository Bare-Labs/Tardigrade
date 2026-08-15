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

Diagnostics originate **connection-level**: `pmtu_probes_sent` and
`pmtu_black_holes` on `quic.connection.Metrics`, plus a `pmtu_updated` event
carrying the path, the new effective size, and whether it rose or fell back.
#256-G added the smallest possible bridge from that per-connection state to a
benchmark/status-facing snapshot — `tardigrade_quic_pmtu_probes_total`,
`tardigrade_quic_pmtu_black_holes_total`, and
`tardigrade_quic_effective_plpmtu_bytes_last` and
`tardigrade_quic_effective_plpmtu_bytes_lifetime_{min,max}` on
`/status/metrics` — so a benchmark run can explain a throughput number
without a debugger. That bridge is deliberately bounded (aggregate counts
only, no per-connection or per-path detail); #255 remains the canonical
owner of general QUIC/H3 observability, and a richer per-connection view
belongs there, not here.

The `lifetime_min`/`lifetime_max` pair is named deliberately: it never
resets and is not scoped to any single benchmark scenario or pass — a
listener that has served more than one connection will show
`lifetime_min` stuck at the DPLPMTUD base size (1200) forever after the
first connection's startup fold, regardless of what every later path
converged to. Read it as "has this listener ever seen a path stuck below
the maximum over its whole running time," not as evidence that paths in
any particular benchmark run did or did not converge. `_last` — the
active-path PLPMTU of whichever connection was most recently folded — is
the closer (if still imperfect) proxy for "what one benchmark pass saw."

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
value and the host sysctls describe intent, not what the socket got. #256-G
mirrors that snapshot onto `/status/metrics` as
`tardigrade_quic_udp_buffer_{requested,effective,granted}_bytes{direction=...}`
and `tardigrade_quic_udp_buffer_status{direction=...,status=...}`, so a
benchmark script can scrape requested-vs-effective over HTTP instead of
parsing startup logs. See [benchmarks/competitive/README.md](../benchmarks/competitive/README.md#http3quic-benchmarking-256-g)
for the benchmark rows that record it.

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

Three details make that per-path story hold, because the peer's counters are
*not* per path — they are cumulative per packet number space and span every
path it has been reached on:

- **The baseline is snapshotted when a path starts marking**, before its first
  marked packet goes out (RFC 9000 Appendix A.4), so every mark it places is
  accounted for. Adopting the first report that happens to arrive would write
  off whatever was already in flight, and the next honest report covering
  those packets would look like an over-claim.

  The counters that baseline is taken from advance only on reports that
  *survived* validation. A rejected report is not a synchronisation point: a
  count that regressed to 8 would otherwise become the baseline a later path is
  measured from, and the real cumulative 10 arriving afterwards would credit
  that path with growth it never earned. Counters that regress or over-claim
  fail ECN closed for the connection; a stripped or rewritten codepoint
  condemns only the route, and leaves the counters usable for the next path.
- **A migration waits for the previous path's marks to drain** before the new
  one starts testing. Otherwise the old path's intact marks would validate a
  new path that is stripping every codepoint, and the old path's CE reports
  would halve the new path's window for congestion that is no longer on the
  route. Promotion additionally requires an acknowledgement of a packet the
  new path itself marked.

  Only an *acknowledgement* drains that wait. A loss declaration does not:
  QUIC loss is an inference, and the packet may well have arrived and been
  counted while the ACK reporting it was itself lost. Since a packet that is
  never acknowledged is never settled, the wait is bounded — and running out
  turns ECN off for the connection rather than releasing on an assumption.

  Acknowledgement alone is not quite enough either. If the ACK that
  acknowledged a mark carried no counts, or carried stale ones, the peer may
  already have counted that mark where this endpoint cannot see it — so the
  trusted baseline is behind by an unknown amount, and a new path started from
  it would be handed the old path's growth as its own evidence. The wait
  therefore also covers that obligation, discharged by the next current
  ACK_ECN: generated after the acknowledgement, its counters necessarily
  include whatever the acknowledged packet contributed.
- **An ACK that does not advance the largest acknowledged packet number is
  ignored for ECN counter validation** (RFC 9000 §13.4.2.1). Its cumulative
  counters can legitimately be stale on a reordered ACK, so they cannot fail
  the path. It can still newly acknowledge a previously missing packet,
  though: that packet's local metadata is retired immediately, while any
  marked contribution remains owed until a later advancing ACK_ECN
  resynchronises the cumulative baseline.

The testing window is armed by the first marked packet rather than by
enabling, so an idle connection cannot time out a path that was never given a
chance to carry one. Only packets that are *in flight* are marked at all —
never a pure ACK, which RFC 9000 §13.2 notes can go unacknowledged for a long
time and so would arm that window on feedback that may never come.

Two of these end in ECN being off for the whole connection rather than for one
path: `evidence_lost` (the bounded per-connection ECN metadata overflowed, or a
migration's wait ran out) and `platform_unsupported`. Both are conservative by
design — the peer's counters drive congestion response, so when attribution
stops being provable the answer is to stop using them, not to keep going on
evidence that can no longer be checked. A long-lived connection over a lossy
path can reach `evidence_lost`; that is a deliberate trade, not a defect.

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
| Metadata needed to attribute the counters was dropped | `evidence_lost` |
| The socket turned out to be unable to set the codepoint | `platform_unsupported` |

Path-local validation failures turn marking off for that path and the
connection continues normally. `evidence_lost` and `platform_unsupported`
instead turn ECN off for the whole connection, as described above. **CE
reports are acted on only on a validated path**, so an unvalidated or forged
report cannot shrink the congestion window on demand. The counters this
endpoint reports back come only from packets that passed AEAD authentication,
so an off-path spoofer cannot inflate what the peer is told.

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
send-side control message, the listener logs it, withdraws send-side ECN for
future connections, and disables ECN on every live connection so transport
state and published counters do not continue claiming marks the socket cannot
place on the wire.

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
of paths that validated. #256-G exposes the same five on `/status/metrics`
(`tardigrade_quic_ecn_enabled` and the four `tardigrade_quic_ecn_*_total`
counters) for exactly that purpose.

`TARDIGRADE_HTTP3_ECN` is restart-required, like every other listener-owned knob
— the receive option is socket state applied at bind time.

## Packet pacing

A congestion window is a bound on how much data may be *outstanding*, not on
how fast it may leave. A sender that holds a 64 kB window and simply writes
until the window is full hands that whole window to the first router in the
path as one burst — which is how a connection with plenty of nominal capacity
still sees queue-overflow loss. RFC 9002 §7.7 requires a sender to either pace
or bound such bursts. Tardigrade does both.

Pacing is a **leaky bucket**, not a bandwidth model: credit accrues at
RFC 9002 §7.7's rate `N × congestion_window / smoothed_rtt` and is spent by
packets as they leave. BBR and any other rate estimator are out of scope.

Tardigrade uses `N = 2` in slow start and `N = 1.25` in congestion avoidance.
That split is a **local policy, not an RFC requirement**: RFC 9002 fixes the
shape of the rate and asks only that `N` be a small value above 1, offering
1.25 as an example. The explicit per-phase split comes from the earlier QUIC
recovery drafts, and is kept for the reason those drafts gave — slow start
doubles the window every round trip, so pacing it at 1.25× would hold the
sender below growth the window is already granting.

Two properties follow, and they are what the setting is for:

- **Spacing.** Once the bucket is empty, datagrams leave one interval apart —
  a full window's worth of data reaches the path spread over a round trip
  rather than as a single flight.
- **A burst ceiling.** The bucket holds at most a NewReno **initial window**
  for the current datagram size. That bounds the opening flight, and it bounds
  the *restart* flight: a connection idle for a second has notionally earned
  megabytes of credit, and gets one initial window.

  The ceiling is the smaller of ten datagrams and `initialWindow(datagram
  size)`, which matters once DPLPMTUD raises the path size past 1472 bytes.
  RFC 9002 §7.2 caps the initial window at 14720 bytes, so at a 2048-byte
  datagram the bucket holds 14720 bytes (seven packets), not ten packets'
  20480 bytes.

### What is paced, and what is not

Only application-space data waits on the bucket: stream data, application
control frames, post-handshake CRYPTO (session tickets), and a PATH_RESPONSE
riding on the active path. RFC 9000 §8.2 explicitly permits path validation to
be delayed by congestion control, which is why the last of those is in the
list rather than exempt.

Everything else is exempt from *waiting*, but the two categories differ in
whether the bytes are **charged** to the bucket:

| Traffic | Delayed by pacing? | Charged to the bucket? |
|---|---|---|
| Application data, app control frames, post-handshake CRYPTO, active-path PATH_RESPONSE | yes | yes |
| PTO probes | no | yes |
| Initial and Handshake flights | no | yes |
| DPLPMTUD probes | no | yes |
| Candidate-path PATH_CHALLENGE / PATH_RESPONSE | no | yes |
| Pure ACK packets | no | **no** |

The reasoning behind each exemption:

- **Acknowledgements** are not congestion-controlled traffic at all — an
  ACK-only packet is not in flight, so it is neither delayed by the bucket nor
  charged to it. Metering acknowledgements would add latency to the *peer's*
  loss recovery for no capacity reason.
- **PTO probes** are already exempt from the congestion window by RFC 9002 §7;
  making loss recovery wait on a token is how a stalled connection stays
  stalled.
- **Initial and Handshake flights** are already bounded by the initial window
  and, for a server, by anti-amplification. Pacing them at a rate derived from
  an RTT nobody has measured yet would slow every connection setup to buy
  nothing.
- **DPLPMTUD and path-validation probes** each build their own datagram, and at
  most one is outstanding per path at a time, so they cannot burst.

Everything in the "charged but not delayed" rows still puts bytes on the wire,
and the bucket accounts for them. A pacer that ignored a handshake flight would
let application data follow it at a rate the path was never shown to support.

**Exempt means "may send now", not "outside the schedule."** Those packets
routinely leave when the bucket cannot cover them, so the balance is signed and
goes negative — the overdraft is carried as debt, and refill pays it off before
producing credit again. Discarding it instead would let an exempt packet
consume path capacity for free: one interval later, ordinary application data
would be released as though the probe had never been sent. A connection that
emits a PTO probe on an empty bucket therefore waits two intervals for its next
application datagram, not one.

Congestion control and anti-amplification remain the hard gates. Pacing can
only ever *delay* a datagram — it never authorises one the window or the
amplification budget would refuse, and a connection blocked by either of those
reports no pacing deadline at all.

### How it reaches the wire

Pacing is a schedule, not a sleep. `Connection.pollTransmitOnPath` never
blocks: while the bucket is short it simply declines to build paced data, and
`Connection.nextSendTimeUs` reports the instant the schedule next releases
something. The listener folds that deadline into the same sleep it already
computes from timers, so a paced connection neither spins nor sleeps past its
own release. Packet construction and scheduling stay separable — the same seam
a batching or GSO send path would need later.

### Timer resolution

Pacing intervals are routinely **sub-millisecond**. A 480 kB window over a
10 ms RTT is one datagram every ~20 µs, which is an ordinary datacentre or
loopback figure and exactly the case #256 exists for.

That rules out `poll(2)` as the listener's only wait: its timeout is an integer
number of milliseconds, so every one of those releases would round up to 1 ms.
Against a ten-datagram burst ceiling that would cap the listener near 12 MB/s
no matter how much window and RTT allowed — a 50× loss on the path above. The
listener therefore waits with a nanosecond-resolution primitive where the
platform has one:

| Platform | Wait primitive |
|---|---|
| Linux | `ppoll` |
| macOS, FreeBSD, NetBSD, OpenBSD, DragonFly | `kqueue` timeout |
| Anything else | `poll`, rounded up to the next millisecond |

The fallback is safe, not broken: a platform that lands there sends at a
coarser cadence, never an incorrect one — the pacer still decides *whether* a
datagram may leave. The same reasoning is why the pacing release is not floored
at the recovery timer granularity (1 ms): that constant is loss-detection
resolution, and imposing it on the pacer would reintroduce the cap the
fine-grained wait exists to remove.

There is no operator knob. Pacing follows congestion control, and a rate an
operator could raise independently of the window would be a way to defeat
congestion control rather than to tune it. A path whose measured capacity
grows paces faster on its own.

## Batching, GSO, and GRO

This is a design note, not an implementation (#256-F). The issue scopes
batching/GSO/GRO as future design work, and the latest #256 reconciliation
says implementation should be split into a focused follow-up only if
benchmark evidence justifies it — this note exists so that follow-up has a
contract to build against rather than a blank page.

### Where the runtime stands today

Every datagram crosses the syscall boundary alone, and not through
`quic.udp.Endpoint`: the production H3 listener bypasses that contract
entirely and calls its own `receiveDatagram`/`sendDatagramTo` helpers in
`src/http/http3_runtime.zig` directly, using `recvmsg`/`sendmsg` for the
ancillary ECN metadata (#256-E). `Endpoint` itself is scalar today —
`recvFn`/`sendFn` each move exactly one datagram — and nothing in the
production path currently calls it. `drainConnectionTransmits` calls
`sendDatagram` — one `sendmsg`/`sendto` — for each datagram
`pollTransmitOnPath` releases, and the receive loop calls `receiveDatagram` —
one `recvmsg` — repeatedly until the socket reports `EAGAIN`. At the packet
sizes DPLPMTUD settles on (1200–2048 bytes) and the rates pacing now permits,
a saturated loopback or datacenter link spends a growing share of its time
crossing that boundary rather than building or parsing the datagrams that
cross it. `sendmmsg`/`recvmmsg` (batched syscalls) and UDP GSO/GRO (kernel-side
segmentation and coalescing via `UDP_SEGMENT` and `UDP_GRO`) are the standard
answers to that cost, and neither is implemented.

### Where it would plug in

Unlike the scalar `SendDatagram`/`ReceivedDatagram` values in
`src/quic/udp.zig`, the runtime's own transmit path is not batch-ready as it
stands, so a future implementation has to pick one of two shapes rather than
assume the seam is free:

- **Runtime-local batching** (the smaller change): keep `quic.udp.Endpoint`
  scalar — nothing outside the H3 listener needs batch semantics today — and
  do the batching entirely inside `http3_runtime.zig`. This is the shape the
  rest of this section assumes.
- **A batch-capable `Endpoint` contract**: add explicit `sendBatch`/
  `receiveBatch` methods with their own lifetime rules, for callers other
  than the H3 listener that might want batching later. Nothing in the current
  tree needs this; it is only worth doing if a second caller shows up.

Either way, `drainConnectionTransmits`'s `while` loop is not literally the
only code that would change, because of how it currently produces datagrams:
it has one `out: [quic.datagram.max_size]u8` scratch buffer and repeatedly
calls `pollTransmitOnPath(&out, now)`, and the returned `Transmit.bytes`
slice points *into that same caller-owned buffer*. A batch cannot be
collected by polling repeatedly and holding on to each `Transmit` — the next
poll overwrites the storage the previous one pointed at. A batching send path
needs its own shape:

1. Poll only datagrams the pacer has released (`pollTransmitOnPath` already
   declines to produce more).
2. Copy each result into stable, batch-owned backing storage together with
   its path and ECN metadata, before the next poll reuses the scratch buffer.
3. Submit the vector (`sendmmsg`) or GSO super-buffer.
4. Handle **partial sends** explicitly: `sendmmsg` can send only a prefix of
   the vector, and by that point the transport has already produced the
   remaining datagrams with real packet numbers and recovery accounting.
   Those exact bytes have to be retained and retried — not discarded in favor
   of re-polling, which would fabricate new packets for data already counted
   as sent. The same applies if a GSO attempt is rejected: fall back to
   per-datagram sends of the already-produced bytes rather than losing them.

Packet *construction* itself would not change — pacing already keeps
`pollTransmitOnPath` from blocking (see above) — but "produced" and "sent"
are no longer the same instant once a batch sits between them, and the design
has to own that gap explicitly.

On the receive side the seam is closer to free: the `while (true) {
receiveDatagram(...) }` loop in `serve` already drains everything waiting
before sleeping again; `recvmmsg` would replace repeated `recvmsg` calls with
one call returning several datagrams, and `UDP_GRO` would let the kernel
coalesce datagrams from one peer before the syscall even happens. `ingest`
already takes one datagram, one peer address, and one ECN mark per call, so a
batched receive path would still call it once per datagram inside the batch —
no change to DCID routing or connection lookup.

### What batching must not break

A batch is a kernel-level optimization; it must stay invisible to the
transport guarantees layered above it.

- **Pacing** decides *whether* a datagram may leave, not how it is
  transmitted once released. A batch could only ever hold datagrams the pacer
  has already released — never a way to front-run the schedule by assembling
  a bigger batch than the burst ceiling allows. That existing ceiling (the
  smaller of ten datagrams and one initial window) is also a reasonable first
  cap on batch size: a batch larger than a paced burst would have to sit
  somewhere between release and syscall, reintroducing the same burst the
  leaky bucket exists to prevent.
- **`sendmmsg` batching and GSO restrict different things.** `sendmmsg` takes
  an array of `mmsghdr`, and every element carries its own destination and
  ancillary data — so a `sendmmsg` vector may freely contain independent
  datagrams for independent paths and independent ECN marks. A single GSO
  `UDP_SEGMENT` buffer is the stricter case: all segments in that one
  super-buffer share one destination, one segment size, and one
  `IP_TOS`/`IPV6_TCLASS` control message. The same-path/same-ECN constraint
  therefore belongs to a GSO super-buffer specifically, not to batching in
  general — split the batch into separate GSO buffers whenever path or ECN
  mark differs, but a `sendmmsg` vector needs no such split.
- **PMTU probes** target a datagram size deliberately above the path's
  currently validated PLPMTU, but a probe is identified by its **packet
  number** (`pmtu.Controller.outstanding_pn`), not by its size, precisely
  because the same target size can be retried and a stale ACK or loss report
  for an earlier attempt must not resolve the current probe
  (`recovery.SentPacket.pmtu_probe` marks these packets so recovery treats
  them apart from ordinary congestion traffic). That identity has to survive
  batching: a GSO buffer uses one segment size for the whole buffer, and
  ordinary traffic is bounded by the validated PLPMTU rather than the probe's
  target size, so the simplest correct implementation keeps an outstanding
  PMTU probe out of an ordinary GSO super-buffer and sends it individually. A
  `sendmmsg` vector has no such restriction — a probe can ride in the same
  vector as ordinary datagrams, since each element is independent — but its
  identity is still carried by packet number, not by which slot it occupied
  in the vector.
- **Receive-side ECN is not implied by the peer tuple alone.** Two UDP
  datagrams from the same source address and port can legitimately carry
  different ECN codepoints, so a batched receive path may not assume a shared
  mark just because the datagrams share a peer. What actually makes Linux's
  `UDP_GRO` safe here is a **platform guarantee**, not an inference from the
  tuple: GRO's IP-layer aggregation checks refuse to coalesce packets whose
  IPv4 TOS or IPv6 Traffic Class differ — and those fields carry the ECN
  bits — so a GRO aggregate's one reported TOS/TCLASS cmsg is guaranteed to
  apply to every segment the kernel coalesced into it. A batched receive path
  may expand that single cmsg into per-datagram ECN metadata only because of
  that kernel-enforced compatibility check, and enabling GRO on another
  platform would require verifying the equivalent guarantee there first, not
  assuming it. Getting this wrong would feed a datagram the wrong ECN mark
  into ACK_ECN counting and validation, which #256-E deliberately keeps
  scoped per path and per datagram.
- Splitting a batch back into individual datagrams — on receive, into
  `ReceivedDatagram`s before `ingest` sees them — is required regardless of
  the guarantee above, since DCID routing and AEAD are per-packet regardless
  of how many packets arrived in one syscall.

### Evidence bar before implementing

Reuse the existing competitive benchmark framework (#149, `benchmarks/competitive/`)
rather than building a second one. The case for batching/GSO/GRO is a
syscall-count argument, so the evidence needs to show the syscall boundary is
actually the bottleneck before paying the complexity:

- CPU/request or syscalls/request at a fixed throughput, with a profile
  showing `sendmsg`/`recvmsg` dominating at realistic throughput — not merely
  a benchmark run existing.
- The high-bandwidth loopback/dedicated-host scenario #256 already asks for is
  the right one to profile first: it is the case most likely to be
  syscall-bound rather than network-bound.
- A regression budget: batching adds code on the hot send/receive path, so it
  only earns its keep if it moves throughput or CPU/request outside the noise
  of existing runs, not merely in the same direction as one.

Absent that evidence, the per-datagram path stays.

### Platform support

`UDP_SEGMENT` (Linux 4.18) and `UDP_GRO` (Linux 5.0) are Linux-only kernel
socket options with no macOS or BSD equivalent. `sendmmsg`/`recvmmsg` batch
the syscall without kernel-side segmentation and are more broadly available,
but still not on every platform this runtime already treats as unverified for
ECN and no-fragmentation. Any future implementation would gate on the same
per-platform tables those features already use, and fall back to today's
per-datagram path exactly the way ECN falls back to `.unavailable` — a
batching failure must never become a transport failure.

## Benchmark and operator evidence

#256-G extended the existing benchmark framework (#149) with H3/QUIC rows
rather than building a second one. Full instructions, scenario definitions,
and result-schema details live in
[benchmarks/competitive/README.md](../benchmarks/competitive/README.md#http3quic-benchmarking-256-g);
this section only points at where to look, not at duplicate content.

- **Small/large/proxy H3 rows**: `benchmarks/competitive/run.sh` (also see
  `benchmarks/run.sh --scenarios static-http3,proxy-http3`).
- **Requested vs. effective UDP buffers, PLPMTU, ECN state**: covered above
  under [Socket buffers](#socket-buffers) and
  [Explicit Congestion Notification](#explicit-congestion-notification) —
  every H3 benchmark row carries this as a `quic` sub-object.
- **Controlled loss/reordering**: `benchmarks/competitive/netem-impair.sh`
  (Linux-only, manual, requires root/`CAP_NET_ADMIN`; never runs in ordinary
  PR CI).
- **High-bandwidth loopback/dedicated-host runs**: the same harness with a
  higher `--connections`/`--duration`, run by hand on an idle dedicated host
  — see the competitive README's "High-bandwidth / dedicated-host runs"
  section for the exact command and the metadata (CPU model, kernel, h2load
  version/QUIC support, UDP sysctls, Tardigrade transport settings) every
  result records alongside the numbers.

A required H3-capable `h2load` build (nghttp2 built against ngtcp2 +
nghttp3) is not installed in default CI; on any host without one, H3 rows are
recorded as `supported: false` with a reason rather than silently skipped.
`h2load --h3 --help` succeeding is not sufficient to verify this locally —
the stock `apt`/`brew` build recognizes the flag but has no QUIC library
linked, and silently degrades to plain TCP instead of erroring; see the
competitive README's "Requirements" section for the actual check (flag
recognition plus `otool -L`/`ldd` linkage verification).

Performance claims from any of this must stay scoped to the recorded
hardware and configuration — see the competitive README's repeated warning
about laptop-local and shared-runner results.

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
- `TARDIGRADE_HTTP3_QLOG_DIR`
- `TARDIGRADE_HTTP3_KEYLOG_PATH`

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
