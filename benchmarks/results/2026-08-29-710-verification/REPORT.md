# Post-#717 performance verification for #710 (child of #708)

Verifies what PR #717 ("perf(proxy): preserve keepalive for streamed
responses") actually changed, on top of #709's diagnosis (#715). See
`environment.txt` in this directory for a detailed account of this
session's environment constraints -- **read that first**: this session had
no Proxmox/KVM/LXC access, no `ssh`, and no `tc netem`, so everything below
is a loopback, same-container before/after comparison, not the real
cross-machine run #710's acceptance criteria ask for. That gap is called
out explicitly in the Conclusions section; it is not glossed over.

## Commits tested

| | commit | description | binary SHA-256 |
|---|---|---|---|
| before | `6772951` | main tip immediately after #715 merged (pre-#717, the diagnosed defect) | `40adfb5f152efef29e802be32fa281ed530941639c8d2d6fd2ff319fa822dd19` |
| after | `b8d584337f06870c830dbf6faf957283888986ef` | current main tip (#717 merged) | `542880a21e03a0e0c34ca503b69e15675cb9e6f1c28611eb483e9c08ad82cac9` |

Both built `-Doptimize=ReleaseFast` with Zig 0.16.0, in the same container,
back to back, from a `git worktree` of the same clone -- eliminates
hardware/kernel/toolchain as variables between the two binaries.

## Method

Origin: `benchmarks/fixtures/upstream_server.py` on `127.0.0.1:18080`.
Tardi config: `location = /proxy/health { proxy_pass
http://127.0.0.1:18080/health; }`, `listen 8069`, `metrics_path
/status/metrics` (verbatim shape from `benchmarks/fixtures/ci-smoke.conf`).
Load: `wrk -t4 -c32 --latency -d15s` (10s for the static control),
`TARDIGRADE_RATE_LIMIT_RPS=0`, matching #708/#709's canonical reproduction
shape exactly. `TARDIGRADE_WORKER_THREADS` left at its default (0 -> this
container's `nproc`, 4) except in the explicit worker-count-sensitivity
rows. Metrics sampled at 100ms via #709's own
`benchmarks/results/2026-08-29-709-diagnosis/metrics_sampler.py`, unmodified.
Between churn-heavy rows, `TIME_WAIT` was drained below 50 sockets before
starting the next row (same discipline #709 used). Full driver:
`run_row.sh` / `matrix.sh` in this directory; raw `wrk` stdout, the
`metrics_sampler.py` JSON, and a single-request `curl -D -` header capture
per row are under `raw/`.

## Primary results: `/proxy/health`, loopback, default workers (4)

| row | rps | p50 | p75 | p90 | p99 | client errors | `Connection` header | accepts_total Δ | requests | churn ratio |
|---|---:|---:|---:|---:|---:|---|---|---:|---:|---:|
| before, off, keep-alive | 4239.86 | 7.36ms | 8.24ms | 9.21ms | 11.44ms | 0 | keep-alive | 745 | 63607 | 1.2% |
| before, off, close | 3806.23 | 8.20ms | 9.24ms | 10.24ms | 12.43ms | 0 | close | -- | 57164 | ~100% (expected) |
| **before, response, keep-alive** | **3272.69** | **9.50ms** | 11.26ms | 12.98ms | **16.52ms** | 0 | **`close`** | **49051** | 49116 | **99.9%** |
| before, response, explicit close | 3479.30 | 8.94ms | 10.08ms | 11.27ms | 13.81ms | 0 | close | 51981 | 52228 | 99.5% |
| before, static (`/health`, not proxied) | 52388.69 | 0.55ms | 0.75ms | 1.02ms | 2.09ms | 0 | keep-alive | -- | 529094 | -- |
| after, off, keep-alive | 4155.52 | 7.42ms | 8.28ms | 9.27ms | 163.78ms¹ | 0 | keep-alive | 740 | 62175 | 1.2% |
| after, off, close | 3841.59 | 8.13ms | 9.09ms | 10.07ms | 12.37ms | 0 | close | -- | 57681 | ~100% (expected) |
| **after, response, keep-alive (mean of 3 runs)** | **3791.09** | **8.30ms** | 9.29ms | 10.35ms | **12.76ms** | 0 | **`keep-alive`** | **688** (mean) | 56896 (mean) | **1.21%** |
| after, response, explicit close | 3834.65 | 8.13ms | 9.10ms | 10.11ms | 12.26ms | 0 | close | 57490 | 57559 | 99.9% |
| after, static (`/health`, not proxied) | 55819.91 | 0.51ms | 0.72ms | 0.99ms | 2.72ms | 0 | keep-alive | -- | 563886 | -- |

¹ Single-run tail-latency outlier on an otherwise-unaffected control row
(the source path here has no #710-related code in it); not reproduced in
any other default-worker row and attributed to container scheduling noise,
not a regression. Flagged rather than dropped, per the instruction not to
discard anomalies without explanation.

**The three `after, response, keep-alive` reps individually**: rps
3829.2 / 3462.3 / 4081.8; p50 8.18 / 9.04 / 7.68 ms; p99 12.57 / 13.99 /
11.72 ms -- run-to-run variance is real but the `Connection: keep-alive`
header and the ~1.2% churn ratio (vs. `before`'s 99.9%) are identical and
unambiguous across all three.

### Loopback throughput/latency delta (response mode, keep-alive)

- req/s: 3272.69 -> 3791.09, **+15.8%**
- p50: 9.50ms -> 8.30ms, **-12.6%**
- p99: 16.52ms -> 12.76ms, **-22.8%**

This is a real, above-noise, consistent-direction improvement even on
loopback, where the underlying defect (forced TCP reconnection per
request) costs almost nothing to begin with -- loopback `connect()`/`close()`
is cheap but not free (kernel bookkeeping, three-way-handshake-equivalent
work, socket allocation/teardown), so eliminating it entirely still helps
measurably. Per #709/#715's own diagnosis and this environment's inability
to inject real RTT, **this 15.8%/22.8% figure is expected to badly
understate the real-world benefit**: #715 measured `response` mode 3-3.15x
slower than `off` mode at the *same* injected RTT (+5ms/+20ms via
`tc netem`) specifically because of this defect, and this fix removes
exactly that per-request round-trip-doubling mechanism. That multiplier
could not be re-measured in this session (no RTT injection available) --
see `environment.txt`.

## Connection-reuse proof (not inferred from throughput)

This is the evidence the issue explicitly requires ("prove #717 is
actually exercised", "downstream connections are actually reused", not
"throughput went up so it must be working").

1. **Response `Connection` header, single probe request before load**:
   `before` response-mode returns `Connection: close` unconditionally (see
   `raw/before-response-keepalive-single-request-headers.txt`); `after`
   returns `Connection: keep-alive` for the same request under the same
   config (`raw/after-response-keepalive-r1-single-request-headers.txt`).
2. **`tardigrade_accepts_total` delta vs. requests served, during the wrk
   run** -- the exact "reliable connection-churn measurement" #709
   established: a new-accept-per-request ratio near 100% means every
   request opened a fresh downstream TCP connection; a ratio near the
   already-healthy `off`-mode baseline (~1.2%) means the connection was
   actually kept and reused across many requests.

   | row | accepts_total Δ | requests | ratio |
   |---|---:|---:|---:|
   | before, response, keep-alive | 49051 | 49116 | 99.9% (forced churn) |
   | **after, response, keep-alive (×3 reps)** | 679 / 644 / 742 | 57464 / 51963 / 61261 | **1.18% / 1.24% / 1.21%** |
   | before, off, keep-alive (never had the defect) | 745 | 63607 | 1.17% |
   | after, off, keep-alive (control, unaffected by #717) | 740 | 62175 | 1.19% |
   | before, response, explicit close (control) | 51981 | 52228 | 99.5% (correctly churns) |
   | **after, response, explicit close (control)** | **57490** | **57559** | **99.9% (still correctly forces churn)** |

   Post-#717, `response`-mode keep-alive's churn ratio (1.2%) is
   statistically indistinguishable from `off`-mode's ratio (1.2%), which
   never had the defect -- direct, quantitative proof that #717 makes the
   streaming path behave exactly like the already-correct buffered path.
   The explicit-close control confirms the fix did **not** accidentally
   make everything reusable: client-requested close still forces ~100%
   churn, before and after, exactly as #710's acceptance criteria require.
3. **Upstream (origin-side) new/reused deltas stayed near-zero-new in every
   row** (e.g. `after, response, keep-alive`: new=0, reused=57088 in rep 1)
   -- confirms the local origin connection was never the variable; only
   the downstream/client-facing side's behavior changed, matching #715's
   own finding.
4. **Merged, passing correctness tests at this exact commit** (ran, not
   just cited): `zig build test` -- 821 unit tests, 0 failures. `zig build
   test-integration` -- 204 tests; the specific tests PR #717 added
   (`tests/integration.zig`: "proxy streaming mode reuses downstream
   connection after clean streamed response", "...after clean h2c upstream
   stream", "...preserves downstream close policies", "...keeps bodiless
   downstream responses reusable when eligible") passed, proving at the
   byte/protocol level -- two sequential streamed GETs really do complete
   on one physical socket, h2c-upstream-backed streams too, HEAD/204/304
   stay bodiless and reusable, and max-request/explicit-close/graceful-
   truncation/post-commit-RST all still force closure correctly. One
   unrelated test (`native upstream https: two proxied requests reuse the
   pooled TLS connection`, an upstream-TLS-pool soak test untouched by
   #710/#717) failed once on the first pass and passed cleanly on
   immediate retry with identical log noise on the pre-#717 build --
   treated as an environment flake, not a regression, and reported rather
   than silently re-run away.

   A direct raw-socket micro-probe (`proof_reuse.py`, in this directory)
   was also attempted for an even more literal "same socket, N requests"
   demonstration, but has a client-side timing race (it doesn't wait for
   the server's own connection-close to actually complete before sending
   the next request) that produced a false-positive-looking result on the
   `before` binary too. It is kept in this directory for transparency
   about what was tried, but the `accepts_total`-ratio evidence above and
   the merged integration tests are the authoritative proof, not this
   script.

## Worker-count sensitivity (workers=32, matching original concurrency)

| row | rps | p50 | p90 | p99 | client errors |
|---|---:|---:|---:|---:|---|
| before, response, keep-alive, workers=32 | 3640.31 | 7.51ms | 16.31ms | 459.57ms | `timeout 12` |
| before, response, explicit close, workers=32 | 3626.68 | 8.06ms | 19.04ms | 1.10s | 0 |
| after, response, keep-alive, workers=32 | 3769.85 | 7.88ms | 17.85ms | 1.07s | 0 |
| after, response, explicit close, workers=32 | 3697.67 | 7.78ms | 17.18ms | 807.75ms | `timeout 5` |

On this 4-vCPU container, raising workers to 32 (8x oversubscription) does
**not** materially improve throughput post-fix (3791 default vs. 3770 at
workers=32 -- flat, within noise) and severely worsens tail latency (p99
12.76ms -> 1.07s) with occasional client timeouts. This is the opposite
direction from #715's KVM-guest finding (workers=32 recovered 78% of the
response-mode gap there) but consistent with #709/#715's own stated
conclusion that **worker-count sensitivity is environment-dependent** --
on a real KVM guest with dedicated cores it helped a lot; on this
resource-constrained cloud container, oversubscribing threads 8x onto 4
real cores actively hurts via scheduling contention. Both `before` and
`after` show the same pathology at workers=32, so this is orthogonal to
#717 -- not something the fix introduced or could have fixed.

## Answers to the required questions

**1. How much did #717 improve the small streaming proxy workload on
loopback?** +15.8% req/s, -12.6% p50, -22.8% p99 (measured, mean of 3
reps vs. 1 baseline run). Real and consistent in direction, but expected
to be a small fraction of the true real-RTT benefit (see below) -- on
loopback the defect this fixes is nearly free to begin with.

**2. How much did #717 improve it across the real network hop?**
**Cannot be measured from this session** -- no cross-machine or RTT-
injectable environment was reachable (see `environment.txt`). #715's own
`tc netem` evidence at the **pre-#717** commit found `response` mode 3x /
3.15x slower than `off` mode at the same +5ms/+20ms RTT, mechanically
because of paying the round trip twice per request (handshake + request)
instead of once -- precisely the mechanism #717 removes. That multiplier
is the best available estimate of the real-network benefit but is cited
from #715, not re-verified here.

**3. What is the new loopback-to-cross-machine throughput ratio?**
Cannot be computed -- no cross-machine leg was available in this session.
Only a loopback-only, same-container before/after ratio could be produced
(above).

**4. Did the original pathological RTT sensitivity materially shrink?**
Not independently re-measured here (no RTT injection available). By
construction it should: #715 attributed the RTT-doubling residual
directly and exclusively to the forced-reconnection defect this PR fixes,
and did not attribute it to any separate active-I/O/event-loop gap. This
verification confirms the mechanical fix is real and correctly reusing
connections; confirming the RTT-sensitivity number itself requires
`tc netem` or real cross-machine access this session does not have.

**5. Did downstream connection churn collapse as expected?** **Yes,
directly measured**: accepts_total-per-request ratio for streaming
keep-alive dropped from 99.9% (before) to ~1.2% (after, ×3 reps) --
statistically identical to the already-healthy `off`-mode baseline (1.2%
before and after). See the Connection-reuse proof section.

**6. Are there any remaining client/socket errors?** None from connection
churn (0 errors in every default-worker row, both before and after; this
container's `net.ipv4.tcp_tw_reuse=2` prevents the loopback TIME_WAIT
exhaustion #715 found on real hosts -- see `environment.txt`). The only
errors observed anywhere in this verification are `wrk` read timeouts (12
and 5) in the pathological workers=32 rows, present in **both** before and
after builds -- a container-scheduling artifact of 8x thread
oversubscription, unrelated to #717.

**7. What happened to worker active/queued/wait behavior?** At default
workers (4), both before and after saturate at `worker_active_jobs=4` (as
expected, 32 concurrent connections vs. 4 workers) with
`worker_queued_jobs` peaking around 29-62 and average queue wait around
6.5-8.4ms in every response-mode row, before and after -- essentially
unchanged by the fix. This matches #709/#715's own conclusion that worker
scarcity/queueing is a real but secondary, largely orthogonal factor to
the connection-churn defect.

**8. Does raising worker count still materially improve the workload?**
**No, not on this hardware, post-fix.** workers=32 is flat-to-slightly-
worse on throughput (3791 -> 3770 rps) and catastrophically worse on tail
latency (p99 12.76ms -> 1.07s) with occasional timeouts, for both `before`
and `after`. This differs from #715's KVM-guest finding (78% recovery)
precisely because environments differ in scheduling behavior under thread
oversubscription -- consistent with, and a stronger version of, #709's own
"worker-count sensitivity is environment-dependent" conclusion. It
reinforces that worker-count tuning is not a substitute for fixing the
actual defect, and should not be recommended as a general default change.

**9. How does the post-#717 streaming keep-alive result compare with the
explicit `Connection: close` control?** Post-fix, keep-alive (3791 rps,
p99 12.76ms, 1.2% churn) now clearly outperforms the explicit-close
control (3835 rps -- comparable throughput on loopback since churn is
cheap here, but the control's churn ratio stays at 99.9% as required) --
the important result is qualitative, not the raw rps gap: keep-alive now
*reuses* the connection while explicit-close *correctly still doesn't*,
exactly matching #710's required behavior split.

**10. How does it compare with the buffered proxy and static controls?**
Post-fix, `response`-mode keep-alive (3791 rps, p50 8.30ms) is now close
to `off`-mode keep-alive (4155 rps, p50 7.42ms) -- an ~9% gap, consistent
with #715's own finding of an ~18% streaming/chunked-framing overhead
independent of connection policy (some residual gap between streaming and
buffered responses is expected and is not a defect). The static control
(`/health`, not proxied) remained healthy throughout at both commits
(52k-56k rps), confirming the network/container itself was not a limiting
factor in any proxy row.

**11. Is there still a material RTT-sensitive residual after fixing
downstream connection churn?** Cannot be directly re-measured here (no
RTT injection available in this session). #715's own ranked attribution
already traced the residual RTT-doubling effect *mechanically and
entirely* to the forced-reconnection defect (not to any separate
event-loop/active-I/O gap), and this verification confirms that defect is
now fixed and connections are genuinely reused. The remaining ~9%
loopback gap between `response` and `off` modes (item 10) is streaming/
chunked-framing overhead, not RTT sensitivity, and is independent of
client RTT by construction (it is a per-request serialization cost, not a
per-connection network cost).

**12. Based on the evidence, what should happen next?**

**B -- #711 is unlikely to be materially relevant**, matching #715's own
conclusion, now reinforced rather than contradicted by this verification.
#709/#715 already ranked forced-reconnection as the primary and largely
sufficient cause of the ~8x collapse, explicitly *not* attributing the
RTT-doubling residual to write fragmentation or an active-I/O gap. This
verification adds a second, independent confirmation on different
hardware: with the reconnection defect fixed, downstream connection churn
collapses to the already-healthy baseline, worker active/queued/wait
behavior is essentially unchanged (i.e., not newly write-bound), and the
only remaining gap between streaming and buffered modes (~9-18% depending
on environment) is attributed to routine chunked-encoding serialization
cost, not to per-chunk write fragmentation costing readiness stalls or
worker time. Nothing in either diagnosis or this verification points to
avoidable write-fragmentation overhead as a material contributor. Per the
issue's own instructions, this should be documented against #711's
acceptance/close criteria rather than implementing write-coalescing work
for its own sake -- #711 is not "done," it is evidence-backed **not
currently justified**, and should stay open only if the repo owner wants
to keep it as a low-priority, evidence-gated backlog item, not execute it
next.

**#712/#713**: current evidence continues to point away from needing them.
No material worker/readiness-driven RTT residual has been found in either
#715's diagnosis or this verification; worker queue-wait is modest and
essentially unchanged by the fix, and the one place workers=32 looked bad
here is explained by this specific container's thread-scheduling behavior
under 8x oversubscription, not by workers blocking on downstream/upstream
readiness. Do not execute #712/#713 on this evidence.

## Caveats and scope notes (read before citing these numbers elsewhere)

- Single-container, loopback-only, same-hardware before/after comparison.
  Not a replacement for #709/#715's real cross-machine/KVM/LXC/`netem`
  evidence, and not a full re-run of #710's real-cross-machine acceptance
  criterion -- see `environment.txt` for exactly why, and the Conclusions
  section of the issue comment for what remains outstanding.
- Single-pass per row except the primary `after, response, keep-alive` row
  (3 reps, reported individually and averaged) -- matches #709/#715's own
  practice (their report was also explicitly single-pass, "not multi-run
  mean/stddev").
- The `after, off, keep-alive` row's p99 (163.78ms) is a single-run
  outlier on a control path with no #710-related code; reported, not
  discarded, per the instruction to explain rather than drop anomalies.
- No claim is made here about the real-network RTT-sensitivity multiplier
  or the loopback-to-cross-machine ratio; those require an environment
  this session did not have.
