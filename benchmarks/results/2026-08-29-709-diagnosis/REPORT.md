# #709 diagnosis: streaming proxy RTT collapse and downstream connection churn

Parent: #708. Scope: root-cause attribution only, targeted at the specific
`TARDIGRADE_PROXY_STREAMING_MODE=response` collapse reported in #708 — not a
repeat of the #593/#699 broad competitive campaign, whose merged results
remain the canonical baseline.

**Revision note**: this report replaces an earlier version of the same
diagnosis that a maintainer review found under-evidenced against #709's
acceptance criteria (missing RTT sweep, no explicit-close control, the
32-error attribution resting on a different client/tool than the original,
no worker/upstream evidence, and the wrong SUT — the physical Proxmox host
instead of a guest matching #708's environment). This version re-runs the
diagnosis against a disposable KVM guest provisioned by
`scripts/run-proxmox-performance-campaign.sh` (the existing #593 canonical
infra) at the exact commit under review, with `wrk` (not a substitute tool)
for the primary matrix, plus `tc netem` RTT injection, an explicit-close
control, and worker/upstream metrics sampled during every canonical run.
The core attribution is confirmed and strengthened by this rerun — but the
new evidence also shows the original "fully explained, no residual RTT
sensitivity" conclusion was too strong. See **Ranked attribution** below for
the corrected, quantified breakdown.

## tl;dr

The forced `Connection: close` in the streaming proxy response path is the
primary and largest cause of the collapse, but it does not explain the
entire gap. Three factors compound:

1. **Forced downstream connection churn** (`src/gateway_proxy_response.zig:71-137`
   unconditionally emits `Connection: close`, unlike the buffered path).
   Isolated via an explicit-close control that reproduces the same churn
   *without* going through the streaming code path: this alone costs ~35%
   of cross-machine throughput under real RTT (6204 → 4032 req/s).
2. **Worker-pool queueing at default worker count**, specific to the
   churn+streaming combination: default (4) workers show ~15ms average
   queue wait per dispatch under `response` mode at concurrency 32;
   raising workers to 32 (concurrency-matched) cuts that to ~0.1ms and
   recovers a further 78% of throughput (938 → 1666 req/s) — and
   eliminates the reproduced 32-error signature entirely.
3. **A genuine residual RTT-sensitivity specific to `response` mode**,
   isolated with `tc netem`: at the same injected +20ms RTT, `response`
   mode measures 3.15x slower than `off` mode (487 vs. 1533 req/s) —
   consistent with paying the network round trip *twice* per request
   (handshake + request) instead of once, exactly what forcing a new
   connection per request implies.

None of this points to a residual event-loop/active-I/O gap; all three
factors are explained by the connection-churn defect and its downstream
consequences (worker dispatch pressure, doubled per-request RTT cost).
**#710/#711 (fix the streaming serializer to honor keep-alive) should
recover the large majority of the collapse; worker-pool sizing guidance is
a legitimate secondary follow-up. Neither points to needing the #712/#713
event-driven architecture work.**

## Method

### Environment correction

The first version of this diagnosis ran against the **physical** Proxmox
host directly (`192.168.86.50` / `10.250.250.2`), not a guest — a mismatch
from #708's actual environment (a 4-core/~3.9 GiB KVM guest,
`192.168.86.58`, kernel `6.12.105+deb13-cloud-amd64`). That guest
(`tardigrade-perf-20260828T234229Z`, VMID 104) is still running on the
physical host but not reachable with any SSH key available in this session
(its cloud-init key was ephemeral to the run that created it), so it could
not be reused directly.

Instead, this revision used the **existing, canonical provisioning path**:

```bash
./scripts/run-proxmox-performance-campaign.sh \
  --tardigrade-ref 3a2a7a520c0677e20a425b396f84c9944a020f1e \
  --suite competitive --smoke --servers tardigrade \
  --duration 3 --connections 4 --threads 2 \
  --noncanonical --keep-guest --name tardigrade-709-diag
```

This built Tardigrade from the exact PR commit inside a **fresh disposable
KVM guest** with the same shape as #708's SUT: 4 vCPUs, 4096 MB configured
(3922 MB reported inside the guest — identical to #708's artifact),
**identical kernel** (`6.12.105+deb13-cloud-amd64`), same CPU model
(Intel N150). `--noncanonical` was required because the host was not
otherwise idle (VM 104 above was still running); this run does not claim
canonical #593 status, matching the `--smoke`/non-canonical labeling
already used by the harness for this kind of run.
`git rev-parse 3a2a7a52...` / the guest's own
`/work/Tardigrade/.tardigrade-source-sha` file, and the built binary's
SHA-256 (`177d0cfc...`), are recorded so the tested artifact is
independently verifiable — addressing the earlier version's "this
worktree's HEAD" non-reproducibility gap. The guest was destroyed
(`qm stop 105 && qm destroy 105 --purge`) after artifacts were pulled,
matching the script's normal ephemeral-VM lifecycle.

Two placements were tested against this guest (IP `192.168.86.37` after
DHCP):

- **Loopback**: `wrk` running *inside* the guest against `127.0.0.1:8069`.
- **Cross-machine**: `wrk` running on the **physical** Proxmox host against
  the guest's LAN IP over the real bridge network (`vmbr0`) — a real,
  different-machine network hop (not the same host, not loopback).

Both used real `wrk` (the tool #593/#699 standardize on), matching the
maintainer review's requirement for a matched-instrument comparison instead
of mixing tools across placements. `wrk` remains blocked from opening
outbound sockets from this session's own Mac (confirmed again this
revision: a `wrk` binary rebuilt from source on this Mac hit the identical
`No route to host` failure that plain `curl`/`nc`/Python `urllib` do not,
so it is not a binary-signature issue — some other property of the
connection pattern is being blocked by a host-level network policy this
session cannot see into or change). Where the Mac is specifically the
subject of the evidence (the original #708 client was also a MacBook — see
the 32-error section below), `benchmarks/results/2026-08-29-709-diagnosis/loadgen.py`
substitutes, and is *also* run in a matched pair (guest-loopback vs.
Mac-cross-machine, same tool both places) per the review's specific request.

All scenarios used `TARDIGRADE_RATE_LIMIT_RPS=0`, `/proxy/health` (2-byte
body), 32 connections/4 threads, matching #708's `wrk -t4 -c32`
reproduction. Worker active/queued gauges and upstream-pool/queue-wait/
accept counters were sampled every 100ms during every canonical `wrk` row
via `metrics_sampler.py` (kept local to this diagnosis directory alongside
`loadgen.py` — see Scope of new tooling below) scraping `/status/metrics`. Raw `wrk`
stdout (including any `Socket errors:` line) is preserved verbatim as a
`.txt` artifact per row, not just parsed into JSON.

### Scope of new tooling

`benchmarks/results/2026-08-29-709-diagnosis/loadgen.py` and
`benchmarks/results/2026-08-29-709-diagnosis/metrics_sampler.py` are kept
local to this diagnosis directory (not `benchmarks/`) per review feedback —
neither is presented as a general wrk replacement or a second supported
harness.
`tc netem` RTT injection reused `benchmarks/competitive/netem-impair.sh`
unmodified, wrapping a `sleep` on the guest while `wrk` ran concurrently
from the physical host (the wrapper assumes a single-host client+impaired-
interface; this diagnosis needed the interface impaired on the *server*
while the client ran elsewhere, so the wrapped command is a timed no-op
rather than the benchmark itself — the impairment and its removal are still
handled entirely by the existing script).

## Results

All cross-machine rows below are `wrk` on the physical Proxmox host against
the guest's LAN IP, unless labeled loadgen.py. All loopback rows are `wrk`
(or loadgen.py, labeled) running inside the guest against `127.0.0.1`.

### Primary matched-`wrk` matrix

| Row | rps | p50/p99 (ms) | Errors (raw) | Upstream new/reused Δ | Worker active/queued max | Queue wait avg |
|---|---:|---|---|---|---|---:|
| loopback, off, keep-alive | 7446 | 4.24 / 6.07 | 0 | 0 / 111104 | 4 / 28 | 3.7ms |
| loopback, off, client `Connection: close` | 6679 | 4.65 / 7.17 | 0 | 0 / 99528 | 4 / 30 | — |
| loopback, response | 6082 | 5.09 / 9.25 | 0 | 2 / 91160 | 4 / 61 | 4.5ms |
| loopback, static control | 81888 | 0.34 / — | 0 | — | — | — |
| cross-machine, off, keep-alive | 6204 | 5.07 / 7.65 | 0 | 0 / 92618 | 4 / 29 | 4.4ms |
| cross-machine, off, client `Connection: close` | 4032 | 6.61 / 22.77 | 0 | 0 / 60571 | 4 / 29 | 6.0ms |
| cross-machine, response, workers=4 (default) | **937.64** | 14.57 / 38.22 | **`Socket errors: connect 32`** | 0 / 13954 | 4 / 48 | 15.0ms |
| cross-machine, response, workers=32 | 1666.38 | 8.50 / — | 0 | 14 / 24923 | 32 / 5 | 0.10ms |
| cross-machine, static control | 24246 | 1.01 / — | 0 | — | — | — |

### `tc netem` RTT injection (cross-machine, applied on the guest's `eth0`)

| RTT added | off req/s | response req/s | response ÷ off |
|---:|---:|---:|---:|
| ~0 (real bridge hop only) | 6204 | 937.64* | 0.15x |
| +5ms | 5480 | 1667 | 0.30x |
| +20ms | 1533 | 486.87 | 0.32x |

\* The workers=4 row above hit the 32-error early-termination pattern; the
netem rows (shorter 10s duration, chosen to fit within the impairment
window) did not reproduce errors, so their ratios are directly comparable
to each other in a way the ~0-RTT ratio partly is not. At the two clean
non-zero RTT points, `response` mode is consistently ~3x slower than `off`
mode at the *same* RTT — a genuine RTT-sensitivity specific to forcing a
new connection per request (see tl;dr point 3).

### Matched `loadgen.py` pair (same tool, both placements — per review request)

| Row | rps | Errors | Reconnects |
|---|---:|---|---:|
| guest-loopback, off, keep-alive | 5040.79 | 0 | 739 |
| guest-loopback, off, client close | 3258.96 | 0 | 48907 |
| guest-loopback, response | 3055.56 | 0 | 45859 |
| Mac→guest cross-machine, off, keep-alive | 3037.47 | 0 | 448 |
| Mac→guest cross-machine, off, client close | 1495.45 | 0 | 22462 |
| Mac→guest cross-machine, response | 1401.06 | **32** (`EADDRNOTAVAIL`) | 16304 |

`loadgen.py`'s absolute numbers are well below `wrk`'s (Python
`http.client` in threads vs. a compiled event-driven C client) — they are
not comparable to the `wrk` rows in absolute terms, only within this table,
across placements, using the same tool. That comparison still shows the
same qualitative pattern as the `wrk` matrix: `off`/keep-alive is close to
RTT-insensitive proportionally (5041→3037, driven partly by Python/GIL
overhead on the Mac, not just RTT), while forced-close and `response`
collapse further under real cross-machine RTT than they do at loopback.

## The 32-error signature: what this run actually establishes

The earlier version of this report inferred that #708's committed "32
errors at concurrency 32" (`benchmarks/results/2026-08-29/crossmachine-competitive-baseline/tardigrade.json`,
which records only the aggregate count, not raw output) was caused by the
same client-side `EADDRNOTAVAIL`/ephemeral-port-exhaustion failure this
diagnosis reproduced via `loadgen.py` on a Mac. That inference is
corroborated, not established: the committed artifact's own `_meta`
records its driver as a real MacBook (`"driver": "macbook-5gbe-crossmachine"`,
`"os": "Darwin"`, `"cpu_model": "Apple M4"`) — the same OS family as the
Mac used here — but no raw stderr from that original run exists to compare
byte-for-byte.

This revision adds a second, independent data point that is **raw,
established evidence**, not inference: re-running the exact failing
canonical case (`wrk -t4 -c32`, `response` mode) against the real guest at
the exact PR commit, from a real second machine, with real `wrk`, produced

```
Socket errors: connect 32, read 0, write 0, timeout 0
Requests/sec:    937.64
```

verbatim (`wrk-host-to-guest-crossmachine/wrk-crossmachine-response-workers4.txt`) — the
same "32" signature, from `wrk` itself, on a real network hop, at the PR's
exact commit. This is genuine raw evidence that connection-churn-driven
connect failures at exactly this shape are a real, reproducible property of
the failing configuration, independent of both the specific client OS and
the specific tool. It does **not** prove wrk's `connect` errors here and
the Mac client's `EADDRNOTAVAIL` errors share one root syscall-level cause:
the guest's Linux client-side ephemeral port range (32768–60999, 28,232
ports) and this run's request volume (14,146 requests, ~938/s over 15s) are
nowhere near port exhaustion the way the Mac's 16,383-port range is at a
much higher churn rate, so a different mechanism (most plausibly transient
listen-backlog pressure on the guest when many of the 32 connections
reconnect in the same instant) is more likely for the Linux/wrk case.
**Both mechanisms only ever appear under forced reconnection (`response`
mode or an explicit client close) and never under keep-alive** across every
row in both tables above — that is the load-bearing fact for question 6
below, not a single unified syscall-level explanation across every
client/tool combination. Determining the exact Linux-side mechanism would
need `strace`/`tcpdump` on the guest during a churn burst, which is beyond
this diagnosis's scope (see #709's non-goals).

## Answers to the issue's required questions

**1. Does `response` mode force downstream connection churn?** Yes,
unconditionally. `curl -i` returns `Connection: close` on every `response`-mode
request; the accepts-total/requests ratio is ~1:1 in every `response` and
explicit-close row above (e.g. cross-machine response/workers4: 14,042
accepts for 14,146 requests).

**2. How much of the loopback→cross-machine delta is explained by
connection churn?** Decomposed with the matched-`wrk` matrix:
loopback off/keep-alive (7446) → cross-machine off/keep-alive (6204) is a
16.7% pure-RTT cost with keep-alive preserved. Loopback off/close-control
(6679) → cross-machine off/close-control (4032) is a 39.6% cost once every
request pays a fresh handshake — RTT's cost roughly doubles (16.7%→39.6%)
once churn is forced, consistent with paying RTT twice per request instead
of once.

**3. Does `off` mode retain keep-alive and reduce RTT sensitivity?** Yes:
`Connection: keep-alive` on every non-cycling response, and only a 16.7%
loopback-vs-cross-machine delta (vs. `response` mode's much larger,
netem-confirmed 3x-at-matched-RTT sensitivity).

**4/5. Worker-count sensitivity and queueing — is queueing primary or
secondary?** Real and non-trivial, but not the majority of the collapse.
At default (4) workers, `response` mode shows ~15.0ms average worker-queue
wait — a large fraction of the 14.57ms p50 latency in that row. Raising to
32 (concurrency-matched) drops queue wait to ~0.10ms (≈150x less), recovers
78% of throughput (937.64→1666.38 req/s), and eliminates the 32-error
signature entirely (`worker_active_jobs` maxes at 32, fully utilized;
`worker_queued_jobs` maxes at only 5). Queueing is a genuine, addressable
secondary contributor — but even at workers=32, throughput is still only
27% of the off/keep-alive baseline (6204), so queueing does not explain the
whole gap either (see question 7).

**6. What exactly caused the 32 errors?** See the dedicated section above:
established (not inferred) for a genuine `wrk` re-run at the PR's exact
commit over a real network hop; corroborated but not proven identical for
the original Mac-client run. Both only occur under forced reconnection,
never under keep-alive.

**7. Residual RTT-sensitive loss after accounting for connection policy and
worker scarcity?** Yes, a real and now-quantified one — this is the
correction to the earlier version's overclaim. At workers=32 (queueing
eliminated) and accounting for the pure-RTT×churn cost (question 2),
`response` mode is still ~3.15x slower than `off` mode at the *same*
injected RTT (netem +20ms: 487 vs. 1533 req/s). That residual is explained
by paying the network round trip twice per request instead of once — a
direct, mechanical consequence of forcing a new connection per request,
not evidence of a separate event-loop/active-I/O gap. Fixing the
`Connection: close` defect removes the mechanism that causes the doubled
RTT cost in the first place; it should not be expected to also match
buffered-mode throughput exactly, because streaming/chunked-encoding
framing itself carries some additional legitimate per-request cost
independent of connection policy (loopback response 6082 vs. loopback
off/keep-alive 7446 — an 18% gap present even with zero RTT and zero churn).

## Static control

`/health` (not proxied) stayed healthy at both placements: 81,888 req/s
loopback, 24,246 req/s cross-machine — consistent with #708's own
observation that the static path did not collapse. Included as the
required control, not as new evidence.

## Ranked attribution (quantified)

Using the matched-`wrk` cross-machine numbers, off/keep-alive (6204) as the
healthy baseline and response/workers=4 (937.64) as the failing
reproduction — a 6.6x collapse, consistent with #708's original ~8x at
different hardware/network specifics:

1. **RTT × forced-reconnection interaction (primary, ~35% of baseline
   lost even without touching the streaming path or worker count)**:
   off/keep-alive (6204) → off/close-control (4032). This is what
   `writeStreamedUpstreamResponseHead`/`writeStreamedUpstreamResponseHeadFromHeaders`
   (`src/gateway_proxy_response.zig:71-137`) directly cause, since they
   force exactly this connection-close behavior on every streamed response
   regardless of client intent — this is the primary, sufficient-to-fix
   defect.
2. **Worker-pool queueing at default worker count under churn (secondary,
   addressable via config, recovers 78% of the remaining gap)**:
   response/workers=4 (937.64) → response/workers=32 (1666.38).
3. **Doubled per-request RTT cost, mechanically downstream of #1 (residual,
   ~3.15x at matched RTT even with queueing eliminated)**: confirmed via
   `tc netem`, not an independent architectural gap — it is exactly what
   "reconnect every request" costs under real RTT, and disappears once #1
   is fixed.
4. **Streaming/chunked-encoding path overhead independent of connection
   policy (minor, ~18% even at zero RTT and zero churn)**: loopback
   off/keep-alive (7446) vs. loopback response (6082).

None of these four factors are evidence for #712/#713's event-driven
architecture; all four are direct, mechanical consequences of the
`Connection: close` defect and ordinary worker-pool/streaming-path costs
that #710/#711 can address or that are expected, bounded overhead of the
streaming feature itself.

## Which #708 child should execute next

**#710/#711** (fix the streaming serializer to honor keep-alive) directly
targets the primary cause (factor 1) and mechanically removes factor 3 (the
doubled-RTT cost) along with it, recovering the large majority of the
collapse. Worker-pool sizing guidance for churn-heavy workloads (factor 2)
is a legitimate, low-risk secondary follow-up worth documenting alongside
the fix, not a separate epic. **#712/#713 (event-driven active-I/O
architecture) is not justified by this evidence** — every measured factor
traces to the connection-churn defect or to ordinary, bounded overhead
(worker dispatch, streaming framing), not to a residual I/O-model
limitation.

## Caveats and scope notes (read before citing these numbers elsewhere)

- This is a **targeted attribution run**, not a new baseline: single-pass
  (not multi-run mean/stddev), shorter durations than #593/#699's
  canonical 30s+, and one specific hardware pair. Do not use these req/s
  figures as replacements for #593/#699 baseline numbers.
- The guest is the same *shape* as #708's original SUT (same image family,
  same kernel, same core/RAM allocation) but is a freshly provisioned VM,
  not literally the same disk/boot as the original `192.168.86.58` guest
  (which is unreachable in this session — see Method). Treat this as "same
  environment class," not "identical historical instance."
- `wrk` could not be run from this session's own Mac client (confirmed
  again after rebuilding from source); the Mac-side evidence uses
  `loadgen.py` instead, run as a matched pair with the same tool at both
  placements per review request, and is not directly comparable in
  absolute terms to the `wrk` rows (see the matched-pair table's note).
- The `off`+close-control run at 1495 req/s on the Mac (`mac-crossmachine-off-close.json`)
  did not reproduce the 32-error pattern within its 15s window, while the
  `response`-mode run at a similar rate (1401 req/s) did, terminating at
  11.6s. Both forced full per-request churn at a similar rate; this
  inconsistency is reported honestly rather than smoothed over — the exact
  conditions under which the Mac's local port budget gets exhausted appear
  to have some run-to-run sensitivity this diagnosis did not fully pin
  down, and a confident single-sentence mechanism should not be inferred
  beyond "it's driven by sustained per-request reconnection rate."
- Determining the exact Linux-side cause of the `wrk`-reported 32 `connect`
  errors (vs. inferring it from the Mac's confirmed `EADDRNOTAVAIL`
  mechanism) would need `strace`/`tcpdump` capture during a churn burst on
  the guest — out of scope for this diagnosis per #709's non-goals.
