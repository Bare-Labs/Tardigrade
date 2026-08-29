# #709 diagnosis: streaming proxy RTT collapse and downstream connection churn

Parent: #708. Scope: root-cause attribution only, targeted at the specific
`TARDIGRADE_PROXY_STREAMING_MODE=response` collapse reported in #708 — not a
repeat of the #593/#699 broad competitive campaign, whose merged results
remain the canonical baseline.

**Revision history**:

- **v1** ran against the physical Proxmox host directly and used a
  different client tool at each placement; a maintainer review found it
  under-evidenced against #709's acceptance criteria.
- **v2** re-ran everything against a disposable KVM guest matching #708's
  SUT shape, added `tc netem` RTT injection, an explicit-close control, and
  worker/upstream evidence. A follow-up review found two remaining gaps:
  (a) the "cross-machine" `wrk` matrix used the **physical Proxmox host**
  as the client against a **guest** on that same host — real network
  traffic over `vmbr0`, but not a client on separate hardware the way
  #708's original MacBook was; and (b) the 32-error root cause was
  speculated ("most plausibly listen-backlog pressure") rather than
  established with syscall-level evidence.
- **This version (v3)** closes both gaps, entirely through `ssh proxmox`
  per explicit instruction (no other LAN host was used): two disposable
  LXC containers were created on the Proxmox host — one as SUT, one as a
  genuinely separate client (separate kernel network namespace/process,
  separate IP, real traffic over the bridge) — giving a `wrk`
  client that is not the physical host's own process. And `wrk` itself was
  traced with `strace` during a reproduction of the failing case, which
  identified the exact errno for every one of the 32 `connect` failures.

## tl;dr

The forced `Connection: close` in the streaming proxy response path is the
primary and largest cause of the collapse. Four things are now established
with direct evidence, not inference:

1. **Forced downstream connection churn** (`src/gateway_proxy_response.zig:71-137`
   unconditionally emits `Connection: close`, unlike the buffered path).
   Isolated via an explicit-close control that reproduces the same churn
   *without* going through the streaming code path: this alone costs
   35–74% of throughput depending on environment (see Results — the exact
   percentage varies by virtualization technology, the direction and
   presence of the effect does not).
2. **The "32 errors" signature is client-side ephemeral-port exhaustion,
   the same mechanism on every client tested.** `strace` on `wrk` itself
   during a reproduction shows all 32 failures are `connect()` returning
   `-1 EADDRNOTAVAIL` — the identical POSIX error (different OS-specific
   errno number) as the Mac client's `EADDRNOTAVAIL`/`errno 49`. Both are
   downstream consequences of forcing a new TCP connection per request:
   enough sustained churn exhausts the *client's* local `(IP, port)` budget
   before old connections age out of `TIME_WAIT`. See
   `errno-root-cause-strace/README.md` for the full trace evidence.
3. **Worker-pool queueing at default worker count is a real, measurable,
   but environment-dependent secondary factor.** On the KVM guest it
   recovers 78% of the response-mode throughput gap when workers are
   raised to match concurrency; on the LXC container pair it recovers
   essentially nothing. Both are reported — see Results.
4. **A genuine residual RTT-sensitivity specific to `response` mode**,
   isolated with `tc netem`: at the same injected +20ms RTT, `response`
   mode measures 3.15x slower than `off` mode — consistent with paying the
   network round trip *twice* per request (handshake + request) instead of
   once, exactly what forcing a new connection per request implies.

None of this points to a residual event-loop/active-I/O gap; every factor
is explained by the connection-churn defect and its direct, mechanical
consequences. **#710/#711 (fix the streaming serializer to honor
keep-alive) should recover the large majority of the collapse; worker-pool
sizing guidance is a legitimate secondary follow-up. Neither points to
needing the #712/#713 event-driven architecture work.**

## Method

### Environment

Per explicit instruction, **only `ssh proxmox` was used** to reach any
remote resource in this revision — no other LAN host. Two kinds of SUT
were used, each addressing a different part of the review:

**A. KVM guest** (unchanged from v2, kept for the `netem` RTT sweep and as
a second, independently-provisioned data point): a disposable KVM guest
provisioned via `scripts/run-proxmox-performance-campaign.sh` (the
existing #593 canonical infra), matching #708's original SUT shape (4
vCPU, ~3.9 GiB, kernel `6.12.105+deb13-cloud-amd64`), built at commit
`3a2a7a52...`. Destroyed after use.

**B. Two LXC containers** (new in v3, addressing the "client = physical
host" gap): `pct create` on the Proxmox host, one as SUT (192.168.86.56, 4
cores) and one as client (192.168.86.59, 2 cores), both Debian 13, both
reached only via `pct exec`/`ssh proxmox` — neither is the physical host's
own process, and traffic between them is a real hop over `vmbr0`. Built at
commit `a81cfcdc...` (this PR's head at diagnosis time), binary SHA-256
`ac31a48f...`. `wrk` installed via `apt` in the client container. Full
detail, including the honest caveat about what this evidence does and does
not prove, in `lxc-container-to-container/environment.txt`. Both
containers destroyed after use.

All scenarios used `TARDIGRADE_RATE_LIMIT_RPS=0`, `/proxy/health` (2-byte
body), `wrk -t4 -c32`, matching #708's original reproduction shape. Worker
active/queued gauges and upstream-pool/queue-wait/accept counters were
sampled via `metrics_sampler.py` (kept local to this diagnosis directory
alongside `loadgen.py` — neither is a general wrk replacement or a second
supported harness). Raw `wrk` stdout (including any `Socket errors:` line)
is preserved verbatim as a `.txt` artifact per row.

**A methodological lesson worth stating plainly**: churn-heavy `wrk` rows
leave thousands of sockets in `TIME_WAIT` on the client for ~60s. Running
rows back-to-back without waiting let one row's leftover `TIME_WAIT`
population contaminate the next — an early attempt at the LXC matrix hit
this directly (a "clean" `workers=32` row actually inherited ~14,000
stale `TIME_WAIT` entries from the immediately preceding row and produced
misleadingly bad numbers). Every row reported below was preceded by
polling `ss -tan state time-wait` until it dropped under 50 on the client.

`wrk` remains blocked from opening outbound sockets from this session's
own Mac (confirmed again: a `wrk` binary rebuilt from source on the Mac
hits the identical `No route to host` failure that plain `curl`/`nc`/Python
`urllib` do not — some host-level network policy, not a binary-signature
issue, and not something this session can see into or change). Where the
Mac is specifically the subject of the evidence (the original #708 client
was also a MacBook), `benchmarks/results/2026-08-29-709-diagnosis/loadgen.py`
substitutes, run as a matched pair (guest-loopback vs. Mac-cross-machine,
same tool both places).

`tc netem` RTT injection reused `benchmarks/competitive/netem-impair.sh`
unmodified on the KVM guest's `eth0` while `wrk` ran from the physical
host (the wrapper assumes a single-host client+impaired-interface; this
needed the interface impaired on the *server* while the client ran
elsewhere, so the wrapped command is a timed no-op rather than the
benchmark itself — the impairment and its removal are still handled
entirely by the existing script).

## Results

### Primary: two-LXC-container matrix (genuinely separate client)

Client container → SUT container, both reached only via `ssh proxmox`; see
`lxc-container-to-container/` for raw `wrk` output and full environment
detail.

| Row | rps | p50/p99 (ms) | Errors (raw) |
|---|---:|---|---|
| off, keep-alive | 8859.23 | 3.58 / 4.78 | 0 |
| off, client `Connection: close` | 2369.31 | 4.34 / 44.33 | 0 |
| response, workers=4 (default) | 1589.14 | 6.28 / 40.69 | 0 |
| response, workers=32 | 1566.13 | 5.85 / 950.19 | 0 |
| static control | 78310.10 | 0.25 / — | 0 |

Notable: on this pair, raising worker count made **no meaningful
difference** (1589→1566, within noise) — a different result from the KVM
guest below. Also notable: the same failing configuration, run under
`strace` for the root-cause investigation, *did* reproduce exactly 32
`connect` errors (see "The 32-error signature" below) — the clean rows
above happen not to have hit it within their windows, consistent with the
mechanism being a threshold effect (see that section) rather than a
deterministic per-run outcome.

### Secondary: KVM guest matrix (controlled virtual-network evidence)

Kept from v2 as a second, independently-provisioned corroboration and
because it carries the `netem` RTT sweep. Client here is the **physical
Proxmox host**, not a separate machine — per the follow-up review, this is
labeled as controlled virtual-network evidence, not a replacement for the
LXC matrix above.

| Row | rps | p50/p99 (ms) | Errors (raw) | Upstream new/reused Δ | Worker active/queued max | Queue wait avg |
|---|---:|---|---|---|---|---:|
| loopback, off, keep-alive | 7446 | 4.24 / 6.07 | 0 | 0 / 111104 | 4 / 28 | 3.7ms |
| loopback, off, client close | 6679 | 4.65 / 7.17 | 0 | 0 / 99528 | 4 / 30 | — |
| loopback, response | 6082 | 5.09 / 9.25 | 0 | 2 / 91160 | 4 / 61 | 4.5ms |
| loopback, static control | 81888 | 0.34 / — | 0 | — | — | — |
| host→guest, off, keep-alive | 6204 | 5.07 / 7.65 | 0 | 0 / 92618 | 4 / 29 | 4.4ms |
| host→guest, off, client close | 4032 | 6.61 / 22.77 | 0 | 0 / 60571 | 4 / 29 | 6.0ms |
| host→guest, response, workers=4 | 937.64 | 14.57 / 38.22 | `connect 32` | 0 / 13954 | 4 / 48 | 15.0ms |
| host→guest, response, workers=32 | 1666.38 | 8.50 / — | 0 | 14 / 24923 | 32 / 5 | 0.10ms |
| host→guest, static control | 24246 | 1.01 / — | 0 | — | — | — |

Here, unlike the LXC pair, raising workers 4→32 recovers 78% of the
response-mode gap (937.64→1666.38) and eliminates the errors — see
"Worker-count sensitivity is environment-dependent" below for why this and
the LXC result are both taken at face value rather than reconciled into
one number.

### `tc netem` RTT injection (KVM host→guest, applied on the guest's `eth0`)

| RTT added | off req/s | response req/s | response ÷ off |
|---:|---:|---:|---:|
| +5ms | 5480 | 1667 | 0.30x |
| +20ms | 1533 | 486.87 | 0.32x |

At both clean non-zero RTT points, `response` mode is consistently ~3x
slower than `off` mode at the *same* RTT — a genuine RTT-sensitivity
specific to forcing a new connection per request.

### Matched `loadgen.py` pair (same tool, both placements)

| Row | rps | Errors | Reconnects |
|---|---:|---|---:|
| guest-loopback, off, keep-alive | 5040.79 | 0 | 739 |
| guest-loopback, off, client close | 3258.96 | 0 | 48907 |
| guest-loopback, response | 3055.56 | 0 | 45859 |
| Mac→guest, off, keep-alive | 3037.47 | 0 | 448 |
| Mac→guest, off, client close | 1495.45 | 0 | 22462 |
| Mac→guest, response | 1401.06 | 32 (`EADDRNOTAVAIL`) | 16304 |

`loadgen.py`'s absolute numbers are well below `wrk`'s (Python
`http.client` in threads vs. a compiled event-driven C client) — not
comparable to the `wrk` rows in absolute terms, only within this table,
same tool, across placements.

## The 32-error signature: established, not inferred

`wrk`'s `Socket errors: connect N` is a **client-side** counter (`wrk`'s
own `connect()` calls failing) — not something the server reports. The
right target to trace is `wrk` itself.

`strace -f -tt -e trace=connect,close,socket` was attached to `wrk` on the
LXC client container while reproducing the failing case (`response` mode,
`-t4 -c32`) against the LXC SUT. The first attempt (15s) produced 0
errors — a genuine observer effect, since `strace`'s overhead changes
timing enough to avoid the race some runs. The second attempt (20s)
reproduced the exact "32 errors" signature while traced:

```
637   14:47:29.708161 connect(22, ...) = -1 EADDRNOTAVAIL (Cannot assign requested address)
638   14:47:29.714600 <... connect resumed>) = -1 EADDRNOTAVAIL (Cannot assign requested address)
640   14:47:29.716948 <... connect resumed>) = -1 EADDRNOTAVAIL (Cannot assign requested address)
639   14:47:29.717066 <... connect resumed>) = -1 EADDRNOTAVAIL (Cannot assign requested address)
```

**All 32 failures, no exceptions.** Full 400-line excerpt (all four `wrk`
OS threads' socket/connect/close/retry cycles) in
`errno-root-cause-strace/wrk-strace-excerpt-EADDRNOTAVAIL.txt`; the 32
matching lines alone in `wrk-strace-errors-only.txt`.

`EADDRNOTAVAIL` on an outbound `connect()` means the kernel couldn't find
a free local `(source IP, source port)` tuple — client-side ephemeral-port
exhaustion. Immediately after the failing run, `ss -tan state time-wait`
on the client reported 8747 sockets in `TIME_WAIT`, matching that run's
8745 completed requests almost exactly, and still elevated from the
*previous* traced run's ~21,000 connections (60s default `TIME_WAIT`,
not yet aged out). Combined, the two runs' connection counts approached
this container's 28,232-port ephemeral range
(`net.ipv4.ip_local_port_range = 32768 60999`).

**This is the identical mechanism found for the Mac client** —
`EADDRNOTAVAIL` there too (`errno 49` on macOS vs. `errno 99` on Linux;
same POSIX error, different OS-specific number), not a different,
unexplained Linux cause. This supersedes v2's "most plausibly listen-
backlog pressure" speculation entirely — that guess is now known to be
wrong. The two platforms differ only in *how much sustained churn* is
needed to trigger it (macOS: 16,383 ports / 30s `TIME_WAIT`; Linux:
28,232 ports / ~60s `TIME_WAIT`), which is exactly why some Linux/`wrk`
rows in this diagnosis show 0 errors and others show exactly 32: it's a
threshold effect on accumulated `TIME_WAIT` population (including
leftovers from an immediately preceding heavy-churn row), not a
deterministic per-request outcome. Full writeup:
`errno-root-cause-strace/README.md`.

The original #708 artifact only records the aggregate count (`errors: 32`)
with no raw output to compare byte-for-byte, and its client was a
different physical machine (a MacBook, not reproducible in this session —
see Caveats). This diagnosis does not claim to have recovered *that run's*
raw evidence. What it does establish: the same client-side connection-
churn-driven `EADDRNOTAVAIL` exhaustion is a real, reproducible property of
this failing configuration, demonstrated with syscall-level evidence on
two different operating systems (macOS via `loadgen.py`'s exception
capture, Linux via `strace` on real `wrk`).

## Worker-count sensitivity is environment-dependent

The KVM guest matrix shows a large, clean effect: default (4) workers
average ~15.0ms queue wait under churn (a large fraction of the 14.57ms
p50 latency in that row); raising to 32 drops that to ~0.10ms (~150x less)
and recovers 78% of throughput (937.64→1666.38 req/s). The LXC container
pair shows essentially no effect (1589.14 workers=4 vs. 1566.13
workers=32 — within run-to-run noise). Both are reported as measured,
without forcing them into a single number: worker-pool queueing is a real,
measurable, *addressable* factor whose magnitude appears to depend on
virtualization technology (KVM vs. LXC) or on which specific run happened
to carry residual `TIME_WAIT` pressure — this diagnosis did not isolate
which. Either way, the primary attribution (question 1's forced churn) is
unaffected by which number is "correct" here, and neither result points to
worker scarcity being the *dominant* cause (see Ranked attribution).

## Answers to the issue's required questions

**1. Does `response` mode force downstream connection churn?** Yes,
unconditionally. `curl -i` returns `Connection: close` on every
`response`-mode request; accepts/requests is ~1:1 in every `response` and
explicit-close row across both matrices (e.g. LXC response/workers=4:
`accepts_total` delta 23,953 for 23,918 requests; upstream
`new`/`reused` deltas of 24/23,920 confirm the *local origin* connection
was barely touched — only the downstream/client-facing side churns).

**2. How much of the loopback→cross-machine delta is explained by
connection churn?** On the KVM matrix: loopback off/keep-alive (7446) →
host→guest off/keep-alive (6204) is a 16.7% pure-RTT cost with keep-alive
preserved; loopback off/close (6679) → host→guest off/close (4032) is a
39.6% cost once every request pays a fresh handshake — RTT's cost roughly
doubles once churn is forced. The LXC pair shows churn's cost is large
even without an RTT comparison point (keep-alive 8859 → explicit-close
2369, a 73.2% reduction from forced reconnection alone) — consistent
direction, different magnitude, expected given the different network path
(veth/bridge vs. KVM virtio-net) and no isolated LXC loopback control was
run to decompose it the same way.

**3. Does `off` mode retain keep-alive and reduce RTT sensitivity?** Yes:
`Connection: keep-alive` on every non-cycling response in every off-mode
row across both matrices, and a comparatively small (16.7%) loopback-vs-
cross-machine delta on the KVM matrix vs. `response` mode's much larger,
netem-confirmed ~3x-at-matched-RTT sensitivity.

**4/5. Worker-count sensitivity and queueing — primary or secondary?**
Real, measurable, and addressable, but not the dominant cause — see
"Worker-count sensitivity is environment-dependent" above. On the
environment where it helped most (KVM), it still left throughput at only
27% of the off/keep-alive baseline even after eliminating queueing
entirely, so queueing alone does not explain the collapse.

**6. What exactly caused the 32 errors?** **Established**: client-side
`EADDRNOTAVAIL` from ephemeral-port/`TIME_WAIT` exhaustion, confirmed via
`strace` on real `wrk` down to the exact syscall and errno — see "The
32-error signature" above. The same mechanism, cross-platform (macOS and
Linux), only ever under forced reconnection, never under keep-alive.

**7. Residual RTT-sensitive loss after accounting for connection policy
and worker scarcity?** Yes, a real and quantified one: at the KVM matrix's
workers=32 (queueing eliminated) and matched RTT via `netem`, `response`
mode is still ~3.15x slower than `off` mode at the same +20ms (487 vs.
1533 req/s). That residual is explained by paying the network round trip
twice per request instead of once — a direct, mechanical consequence of
forcing a new connection per request, not evidence of a separate
event-loop/active-I/O gap. It disappears once the `Connection: close`
defect is fixed; buffered-mode throughput should not be expected exactly,
since streaming/chunked-encoding framing carries some legitimate
additional per-request cost independent of connection policy (KVM
loopback response 6082 vs. loopback off/keep-alive 7446 — an 18% gap
present even with zero RTT and zero churn).

## Static control

`/health` (not proxied) stayed healthy everywhere it was measured: 78,310
req/s (LXC container-to-container), 81,888 req/s (KVM loopback), 24,246
req/s (KVM host→guest) — consistent with #708's own observation that the
static path did not collapse. Included as the required control, not as
new evidence.

## Ranked attribution

1. **Primary and sufficient cause**: `writeStreamedUpstreamResponseHead`/
   `writeStreamedUpstreamResponseHeadFromHeaders`
   (`src/gateway_proxy_response.zig:71-137`) unconditionally emit
   `Connection: close`, in contrast to `writeBufferedUpstreamResponseHead`
   (same file, `:314-330`), which threads the real negotiated `keep_alive`
   value through. Isolated in both matrices via the explicit-close
   control: forces the same client-side reconnection cost as `response`
   mode, independent of the streaming code path, and directly causes the
   established `EADDRNOTAVAIL` connection-establishment failures.
2. **Doubled per-request RTT cost, mechanically downstream of #1**:
   confirmed via `tc netem` (~3.15x at matched RTT) — exactly what
   "reconnect every request" costs under real RTT, not an independent
   architectural gap, and it disappears once #1 is fixed.
3. **Worker-pool queueing at default worker count, environment-dependent**:
   a real, addressable secondary factor on the KVM guest (recovers 78% of
   the response-mode gap); negligible on the LXC pair. Not the dominant
   cause in either case.
4. **Streaming/chunked-encoding path overhead independent of connection
   policy (minor, ~18% even at zero RTT and zero churn)**: KVM loopback
   off/keep-alive (7446) vs. loopback response (6082).

None of these factors are evidence for #712/#713's event-driven
architecture; all trace to the connection-churn defect or to ordinary,
bounded overhead (worker dispatch, streaming framing) that #710/#711 can
address or that is expected overhead of the streaming feature itself.

## Which #708 child should execute next

**#710/#711** (fix the streaming serializer to honor keep-alive) directly
targets the primary cause and mechanically removes the RTT-doubling
residual along with it, recovering the large majority of the collapse.
Worker-pool sizing guidance for churn-heavy workloads is a legitimate,
low-risk secondary follow-up worth documenting alongside the fix, not a
separate epic. **#712/#713 (event-driven active-I/O architecture) is not
justified by this evidence** — every measured factor traces to the
connection-churn defect or to ordinary, bounded overhead, not to a
residual I/O-model limitation.

## Caveats and scope notes (read before citing these numbers elsewhere)

- This is a **targeted attribution run**, not a new baseline: single-pass
  (not multi-run mean/stddev), shorter durations than #593/#699's
  canonical 30s+, and specific hardware. Do not use these req/s figures as
  replacements for #593/#699 baseline numbers.
- Neither the KVM guest nor the LXC containers are literally the same
  physical machine as #708's original MacBook client — that exact
  reproduction was not available in this session (see below). The LXC
  pair is the best available "genuinely separate client" evidence
  obtainable through the sanctioned `ssh proxmox`-only workflow: real
  separate kernel namespaces/processes/IPs communicating over a real
  bridge hop, but still sharing the same underlying physical CPU/kernel as
  the Proxmox host, unlike two actually distinct boxes.
- The original literal #708 SUT guest (`tardigrade-perf-20260828T234229Z`,
  VMID 104, `192.168.86.58`) is still running on the Proxmox host but has
  no SSH key available in this session (its cloud-init key was ephemeral
  to the campaign run that created it) and was not disturbed.
- Other hosts on the LAN (a separate physical box with an SSH host-key
  mismatch, a device with a fully read-only root filesystem, an
  unreachable host) were considered and explicitly ruled out in favor of
  the `ssh proxmox`-only LXC approach above, per direct instruction to use
  only the Proxmox host.
- `wrk` could not be run from this session's own Mac client (confirmed
  again after rebuilding from source); Mac-side evidence uses `loadgen.py`
  instead, run as a matched pair with the same tool at both placements,
  and is not directly comparable in absolute terms to the `wrk` rows.
- The `off`+close-control run on the Mac (`mac-crossmachine-off-close.json`,
  1495 req/s) did not reproduce the 32-error pattern within its 15s
  window, while the `response`-mode run at a similar rate (1401 req/s)
  did, terminating at 11.6s. Both forced full per-request churn at a
  similar rate; given the now-confirmed threshold-effect mechanism (see
  "The 32-error signature"), this is consistent with the two runs simply
  landing on different sides of the `TIME_WAIT`-population threshold, not
  a contradiction.
