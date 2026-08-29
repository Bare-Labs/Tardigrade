# #709 diagnosis: streaming proxy RTT collapse and downstream connection churn

Parent: #708. Scope: root-cause attribution only, targeted at the specific
`TARDIGRADE_PROXY_STREAMING_MODE=response` collapse reported in #708 — not a
repeat of the #593/#699 broad competitive campaign, whose merged results
remain the canonical baseline.

## tl;dr

The collapse is fully explained by one code defect, with no residual RTT
sensitivity once it's accounted for:

**`writeStreamedUpstreamResponseHead`/`writeStreamedUpstreamResponseHeadFromHeaders`
in [`src/gateway_proxy_response.zig:71-137`](../../../src/gateway_proxy_response.zig#L71-L137)
unconditionally emit `Connection: close` on every streamed proxy response,
ignoring the negotiated `keep_alive` value that the buffered path honors
correctly.** This forces a brand-new TCP connection (and, when TLS is in
play, a new handshake) for every single proxied request whenever
`TARDIGRADE_PROXY_STREAMING_MODE=response`/`full` is set. Over a real
network path, opening a fresh connection per request at multi-thousand
requests/second exhausts the client's local ephemeral-port/TIME_WAIT budget
in about two seconds — which is what produced both the ~8x throughput
collapse and the exact "32 errors at concurrency 32" reported in #708's
original cross-machine run. Worker-pool queueing and RTT itself are real but
minor/non-contributing factors, not the primary cause. **#710/#711
(fixing the streaming serializer to honor keep-alive) should be sufficient;
the evidence here does not justify the #712/#713 event-driven architecture
work.**

## Method

wrk (the tool #593/#699 standardized on) turned out to be blocked from
opening outbound sockets in the sandboxed session this diagnosis ran in —
confirmed by testing plain `curl`/`nc`/Python `urllib` from the same host,
which all connected fine; only `wrk`'s connection pattern was refused. Rather
than lose the targeted evidence to a tooling accident,
[`benchmarks/loadgen.py`](../../loadgen.py) was written as a minimal
keep-alive-aware HTTP/1.1 load driver: N persistent worker threads reusing
`http.client.HTTPConnection`, with an explicit counter for every time a
worker had to open a *new* TCP connection because the previous one ended
(server-forced close or a transport error). That's direct
connection-churn evidence, not an inference from a throughput delta, and one
useful side effect of the accident: it decisively confirmed the failure is a
client TCP/OS-level effect (reproduced independently through a completely
different HTTP client implementation and language runtime than wrk), not
something specific to wrk's own connection handling.

Two real machines were used, matching #708's original client/server split:

- **Server**: the `proxmox` host on this LAN (Debian 13 trixie, Intel N150,
  4 cores, 15.4 GiB RAM) — a real physical/networked machine, not this
  session's own sandbox. Tardigrade was cross-compiled
  (`zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu`) and copied
  over; the origin was `benchmarks/fixtures/upstream_server.py` on
  `127.0.0.1:18080`, kept local to the server exactly as #708 specifies, so
  only the client-facing hop carries real network latency.
- **Client**: this Mac, reached over a dedicated point-to-point link
  (`10.250.250.1` ↔ `10.250.250.2`, `en8`) directly to the proxmox host —
  a real network hop, RTT ≈ single-digit ms (`route get` reports ~9ms; the
  general-LAN/WiFi path to the same host measured 4–9ms by `ping`).

Exact commit: this worktree's `HEAD` at the time of the run (branch
`claude/issue-709-implementation-af313a`). All scenarios used
`TARDIGRADE_RATE_LIMIT_RPS=0`, `/proxy/health` (2-byte body), 32
connections/threads to match #708's original `wrk -t4 -c32` reproduction.
Raw JSON for every run is alongside this file.

## Results

| Placement | Mode | Workers | rps | p50/p99 (ms) | Errors | Downstream `Connection` header |
|---|---|---:|---:|---|---:|---|
| loopback (proxmox, wrk) | off | 4 | 9135 | 3.47 / 4.65 | 0 | keep-alive |
| loopback (proxmox, wrk) | response | 4 | 6519 | 4.78 / 7.90 | 0 | close (always) |
| cross-machine (mac→proxmox) | off | 4 | 9091 | 3.48 / 4.76 | 0 | keep-alive (except every 100th, by `max_requests_per_connection`) |
| cross-machine (mac→proxmox) | response | 4 | 7619* | 3.73 / 6.45 | **32** | close (always) |
| cross-machine (mac→proxmox) | response | 32 | 6589* | 2.34 / 11.15 | **32** | close (always) |
| cross-machine (mac→proxmox), static control | n/a | 4 | 16755 | 1.50 / 6.48 | 0 | keep-alive (except every 100th) |

\* The two `response`-mode cross-machine rows did not run for the requested
15s — every one of the 32 client worker threads failed with the same OS
error at ~2.1–2.5s (see below) and the run ended there. The rps column is
the achieved rate over that shortened window, not a 15s average — it is
**not** directly comparable to the other rows' rps, and reading it as "only
~7.6k in response mode" understates how close it is to the loopback
`response` number (6519) while it was actually running.

## Answers to the issue's required questions

**1. Does `response` mode force downstream connection churn in the failing
workload?** Yes, unconditionally and completely. Direct evidence: `curl -i`
against `/proxy/health` under `response` mode returns `Connection: close` on
every response (verified byte-for-byte); under `off` mode the same request
returns `Connection: keep-alive`. The load-driver's own header tally
confirms it at scale — 16301/16301 responses carried `close` in `response`
mode vs. 1344/136394 (the normal `max_requests_per_connection=100` cycle) in
`off` mode. Server-side `tardigrade_accepts_total` moved in exact lockstep
with client requests in `response` mode (+16302 accepts for 16301 requests),
confirming the server really did open a fresh accepted connection for
essentially every single proxied request.

**2. How much of the loopback→cross-machine delta is explained by
connection churn?** In `off` mode (connections reused), essentially all of
it disappears: 9135 rps loopback vs. 9091 rps cross-machine, under 0.5%
apart, with a real ~single-digit-ms client-facing RTT in the cross-machine
case. RTT is being amortized across ~100 requests per connection and barely
registers. In `response` mode the comparison is confounded by the client-side
failure below, but the achieved instantaneous rate before failure (7619 rps)
is in the same range as the loopback `response` number (6519 rps) — i.e.
even the forced-churn case doesn't show a large *additional* RTT penalty on
top of the churn cost itself; the RTT's contribution is dwarfed by the
churn's.

**3. Does `off` retain keep-alive and materially reduce RTT sensitivity?**
Yes on both counts — see #1 (header evidence) and #2 (<0.5% loopback vs.
cross-machine delta).

**4/5. Worker-count sensitivity and queueing.** At the default worker count
(4, matching this 4-core host), the `response`-mode burst showed real,
measurable worker-pool queueing: `tardigrade_worker_queue_wait_us` moved by
+100,184,725 µs over +32,604 dispatches (≈3.07 ms average wait per
dispatch) during the burst. Raising `TARDIGRADE_WORKER_THREADS` to 32
(concurrency-matched) nearly eliminated that queueing (+534,382 µs over
+32,592 dispatches ≈ 16.4 µs average — about 187x less) but did **not**
improve throughput (7619→6589 rps) or clear the 32 errors, and tail latency
got measurably worse (p99 6.45ms→11.15ms, plausibly from 32 OS threads
contending on a 4-core host instead of 4). Worker queueing is real at the
default worker count but is a minor, non-dominant contributor — fixing it
alone does not touch the actual failure mode.

**6. What caused the 32 errors?** Client-side ephemeral-port exhaustion.
Reproduced deterministically, independent of wrk: rapidly opening and
closing 500 short-lived connections to the server on this Mac fails ~469 of
them with `OSError(49, "Can't assign requested address")` — macOS
`EADDRNOTAVAIL`, the exact signature of running out of local ephemeral
ports before their `TIME_WAIT` entries expire. This machine's own
`sysctl net.inet.ip.portrange.{first,last}` is 49152–65535 (16,383 ports)
and `net.inet.tcp.msl` is 15000 ms (30s `TIME_WAIT`). At the ~7600–7900
new-connections/sec that `response` mode's forced-close forces here,
16,383 ÷ ~7700/s ≈ 2.1s — matching the observed 2.14s and 2.47s failure
times almost exactly. Both `response`-mode runs failed with **exactly 32**
errors — one per concurrent worker thread, each hitting the same
port-exhaustion wall within milliseconds of each other — which is the same
signature #708's original wrk run reported ("32 errors at concurrency 32").
This is consistent with the original MacBook client in #708 hitting the
identical OS-level ceiling, not a Tardigrade-side defect, a network
partition, or a protocol bug.

**7. Residual RTT-sensitive loss after accounting for connection policy and
worker scarcity?** No large residual shown by this evidence. `off` mode is
RTT-insensitive at this scale (<0.5% loopback-vs-cross-machine delta,
question 2). `response` mode's collapse is explained by connection churn
interacting with OS-level connection-establishment limits (question 6);
worker-count changes don't fix it (questions 4/5). Nothing in this evidence
points to a residual event-loop/active-I/O gap once the forced-close defect
is fixed.

## Static control

`/health` (not proxied, so unaffected by streaming mode) stayed healthy
cross-machine: 16,755 rps, 0 errors, p99 6.48ms — consistent with #708's own
observation that the static path did not collapse. Included as the required
control, not as new evidence.

## Ranked attribution

1. **Primary and sufficient cause**: `writeStreamedUpstreamResponseHead`/
   `writeStreamedUpstreamResponseHeadFromHeaders` (`src/gateway_proxy_response.zig:71-137`)
   unconditionally emit `Connection: close`, in contrast to
   `writeBufferedUpstreamResponseHead` (`src/gateway_proxy_response.zig:314-330`),
   which threads the real negotiated `keep_alive` value through. This is a
   plain scope gap in the streaming serializer, not an architectural
   limitation of the blocking-worker-pool model.
2. **Secondary, non-dominant**: worker-pool queue wait is real at default
   worker counts under this specific churn load (~3ms/dispatch) but fixing
   it via worker count alone does not resolve the failure and can make tail
   latency worse.
3. **Not shown to contribute**: raw network RTT itself, independent of
   connection-churn interaction (question 2/7).

## Which #708 child should execute next

**#710/#711** (fix the streaming serializer to honor keep-alive, the same
way the buffered path already does) directly targets the primary cause and
should be attempted first, with a follow-up cross-machine re-run against the
fixed serializer to confirm the collapse and the 32-error signature both
disappear. **#712/#713** (event-driven active-I/O architecture) is not
justified by this evidence — nothing here shows a residual bottleneck that a
correctly-behaving keep-alive streaming path wouldn't already resolve.

## Caveats and scope notes (read before citing these numbers elsewhere)

- This is a **targeted attribution run**, not a new baseline: fewer
  scenarios, shorter durations, single-pass (not multi-run mean/stddev),
  and one specific hardware pair. Do not use these req/s figures as
  replacements for the #593/#699 baseline numbers.
- `wrk` did not run in this session (see Method); results came from
  `benchmarks/loadgen.py` instead. That tool is a real HTTP/1.1 client
  (Python's `http.client`) exercising the real network path and the real
  server, not a simulation — but it is single-language/single-process and
  has not been cross-validated against wrk request-for-request. The loopback
  scenarios *did* run through the standard `benchmarks/run.sh`/wrk path
  (wrk was available directly on the proxmox host), so those two rows are
  directly comparable to prior wrk-based results; the three cross-machine
  rows are not.
- The two `response`-mode cross-machine rows terminated early by design of
  the failure being investigated (see the rps caveat above) — that's the
  finding, not a broken test.
- No explicit `tc netem` RTT injection was used. The dedicated point-to-point
  link's natural RTT (~single-digit ms, confirmed by `route get`/`ping`) was
  treated as the one real non-loopback RTT point, since the `off`-mode
  result already showed RTT sensitivity to be negligible at this RTT scale
  and the `response`-mode result is dominated by an RTT-independent OS
  effect. If #710/#711's fix is later benchmarked and still shows RTT
  sensitivity, `benchmarks/competitive/netem-impair.sh` (Linux-only, so it
  would need to run on the proxmox side) is the right tool to add
  controlled multi-point RTT evidence at that time.
- The proxmox host was running one unrelated idle-ish background VM guest
  (~15% of one core) during these runs; both compared conditions on that
  host (loopback off/response) shared that background load equally.
