# Competitive Benchmark Report — 2026-08-25 (beelink)

Real-hardware execution of the #589 competitive suite (Tardigrade vs NGINX,
HAProxy, and Caddy) for #593. This covers **only** the four-server
competitive-suite lane of #593 — the accept-batching/fairness suite (#146 /
#601), the epoll-vs-io_uring backend comparison (#148 / #602), and the
HTTP/3/QUIC evidence lane were **not executed** in this session and remain
open follow-up work under #593.

## Test environment

This was run on a live homelab host, not a dedicated idle benchmark
machine — treat every number here as representative/comparative on this
specific host and configuration, not a canonical baseline. See
[Non-idle host caveat](#non-idle-host-caveat) below for what else was
running concurrently.

| | |
| --- | --- |
| Host | beelink (Beelink mini PC, Proxmox-hosted Debian container) |
| CPU | Intel(R) N150, 4 cores / 4 threads, no hyperthreading |
| Memory | 10 GiB |
| OS / kernel | Debian GNU/Linux 13 (trixie), Linux 6.17.13-2-pve |
| `ulimit -n` | 1024 (default, not raised for this run) |
| `net.core.somaxconn` | 4096 |
| `net.core.rmem_max` / `wmem_max` | 212992 / 212992 (default) |
| `net.ipv4.tcp_fin_timeout` | 60 |
| `net.ipv4.ip_local_port_range` | 32768–60999 |
| Loopback | `lo`, MTU 65536 |
| Zig | 0.16.0 (installed fresh for this run; host default was 0.14.1, which does not meet the repo's `minimum_zig_version = 0.16.0`) |
| Tardigrade build | `zig build -Doptimize=ReleaseFast`, default `-Dtls-profile=general` |
| Tardigrade commit benchmarked | `efe0876` (`v0.6.2-8-gefe0876`) — the pre-rebase commit this binary was actually built from and benchmarked at. This branch was later rebased onto current `main` (dropping an unrelated commit per PR review), so `efe0876` itself is no longer reachable from this branch's history; its tree content is unchanged and now lives as this branch's `3de7fd7f` (k6 fix) on top of `e8e3f54f`/`ead6807e` (the harness-audit and HAProxy fixes) — same fixes, same benchmarked behavior, different commit hash. |
| wrk | debian/4.1.0-4+b1 [epoll] |
| k6 | v2.2.0 (commit 00a9a1b7f5) |
| nginx | 1.26.3 (Debian package) |
| HAProxy | 3.0.11-1+deb13u3 (Debian package) |
| Caddy | v2.11.4 (official apt repo) |
| h2load | nghttp2/1.64.0 — **not** QUIC-capable (`ldd` shows no libngtcp2/libnghttp3); H3 rows correctly reported `unsupported`, never fabricated |

### Native-implementation guardrail

Per the 2026-08-20 issue comment, the Tardigrade binary benchmarked here must
be the native shipping implementation, not a transitional OpenSSL-backed
build. Confirmed: `build.zig`'s `tls-profile` option comment states both
`general` (default, used here) and `appliance` profiles are pure-Zig native
as of #634/#649 — there is no more OpenSSL-backed `general` profile to avoid.
Verified independently with `ldd zig-out/bin/tardi`: only `libc.so.6` and the
dynamic linker, no `libssl`/`libcrypto`.

### Non-idle-host caveat

beelink is a live homelab host, not a dedicated idle benchmark machine.
During this run it was concurrently running:

- 8 `ffmpeg` RTSP camera transcoding streams (continuous, low-but-nonzero
  CPU each)
- `dockerd` / `containerd`
- a Cloudflare tunnel (`cloudflared`)
- assorted other homelab Python services (all independent of Tardigrade
  and the benchmark harness)

The host's own production Tardigrade instance (a separate deployment
fronting other homelab services, listening on ports 80/8443) was stopped
for the duration of the benchmark run (with the owner's explicit go-ahead)
so it would not collide with the competitive suite's edge-server ports, and
was left stopped between runs; it auto-restarted on its own after an
unrelated mid-session power interruption (see below) because its systemd
unit is enabled.

Partway through this work, the host lost power (a physically knocked-loose
power cable, unrelated to anything in this benchmark run or Tardigrade
itself) and rebooted. All in-flight benchmark state from that attempt was
discarded and the full suite was re-run from a clean process state
afterward; the results in this directory are from that clean re-run. All
other homelab services (cameras, Docker, tunnel, production Tardigrade)
came back up on their own via systemd and were otherwise undisturbed by
this work, both before and after the reboot.

Given the concurrent load and the shared 4-core CPU, absolute throughput
numbers should not be read as an upper bound on any server's real capacity.
Relative comparisons between servers in the *same* run, on the *same* host,
under the *same* load, remain meaningful.

## Benchmark configuration

Default competitive-suite parameters (`benchmarks/competitive/run.sh` with
no overrides beyond `--binary`):

```
duration = 15s
connections = 32
threads = 4
tool = wrk (k6 for idle-keepalive-active-traffic)
servers = tardigrade, nginx, haproxy, caddy
```

Reproduce with:

```bash
zig build -Doptimize=ReleaseFast   # Zig >= 0.16.0
./benchmarks/competitive/run.sh --binary zig-out/bin/tardi \
  --out-dir benchmarks/competitive/results/<date>
```

Committed alongside this report: the combined `competitive-results.json`
(the canonical artifact — every scenario, every server, in one file),
`competitive-results.csv`, `competitive-summary.md`, and
`upstream-pool-matrix.json`. The ~50 intermediate per-server/per-pass raw
`wrk`/`k6` JSON files the harness also writes are not committed — they're
subsumed by the combined JSON above and are large, run-specific debug
artifacts rather than durable evidence; regenerate them with the exact
command above if needed.

## Results by scenario

See `competitive-summary.md` for the full table. Headline numbers (req/s,
0 errors unless noted):

| Scenario | tardigrade | nginx | haproxy | caddy |
| --- | ---: | ---: | ---: | ---: |
| static-tiny-http1 | 40840 (6114 errors — see [#682](#682-max_requests_per_connection-keep-alive-bug)) | 74596 | 137374 | 37840 |
| static-tiny-keepalive | 40977 (6143 errors) | 74540 | 139175 | 38062 |
| static-large-http1 (1 MiB) | 7290 (1088 errors) | 8145 | unsupported* | 6990 |
| proxy-small-http1 | 5712 | 9629 | 9430 | 6413 |
| proxy-large-http1 (1 MiB) | 1384 | 1309 | 1948 | 1777 |
| connection-churn-http1 | 22987 | 29292 | 34475 | 16500 |
| idle-keepalive-active-traffic (k6) | 13550 | 18588 | 22975 | 13526 |
| proxy-slow-client-download | ~0.06 req/s (16 s to download a 1 MiB/s-rate-limited 16 MiB file) — same shape for all four, by scenario design | ~0.06 req/s, 4 errors\*\* | ~0.06 req/s | ~0.06 req/s |
| upstream-pool-matrix (Tardigrade only) | see below | — | — | — |

\* HAProxy intentionally reports `static-large-http1` as unsupported: its
representative `http-request return file` config path is bounded by
HAProxy's response buffer size and cannot serve the 1 MiB fixture without a
misleading config change. This is a pre-existing, documented harness
limitation (`benchmarks/competitive/README.md`), not something introduced
or changed by this run.

\*\* nginx's `proxy-slow-client-download` pass logged 4 client/socket
errors — a low-volume, rate-limited scenario (a handful of requests over
15s) where a small absolute error count moves the percentage a lot. Not
investigated further in this session; worth a closer look if this lane is
rerun, but not attributed to a specific cause here.

### Observations

- **Tardigrade vs NGINX/HAProxy/Caddy, static file serving**: NGINX and
  HAProxy substantially outperform Tardigrade on raw tiny-static req/s on
  this host (74.6k and 137k vs Tardigrade's 40.8k); Caddy is roughly on par
  with Tardigrade (37.8k). On the 1 MiB static file, Tardigrade (7290 req/s,
  ≈7.3 GB/s over loopback) is close to NGINX (8145) and ahead of Caddy
  (6990).
- **Reverse proxy**: Tardigrade's small-payload proxy throughput (5712
  req/s) trails NGINX (9629) and HAProxy (9430), and is close to Caddy
  (6413). On the large (1 MiB) proxied payload, Tardigrade (1384 req/s) is
  in the same range as the other three (1309–1948), i.e. proxy throughput
  differences shrink as payload size grows and the workload becomes more
  I/O- than per-request-overhead-bound.
- **Connection churn** (`Connection: close`, one request per TCP
  connection): HAProxy leads (34475 req/s), then NGINX (29292), Tardigrade
  (22987), then Caddy (16500).
- **Idle-keepalive + active traffic** (k6, 20 idle holders + 10 active-burst
  VUs): HAProxy leads (22975 req/s), then NGINX (18588), then Tardigrade and
  Caddy essentially tied (13550 / 13526).
- **CPU usage**: Tardigrade's reported `cpu_pct_avg` on the tiny-static pass
  (232.80%, i.e. ~2.3 cores of the host's 4) is comparable to NGINX
  (214.58%) and lower than Caddy (269.71%). HAProxy used less CPU than all
  three (201.00%) while serving ~3.4x Tardigrade's and ~1.8x NGINX's
  req/s on this scenario — HAProxy is the clear CPU-efficiency leader on
  this workload on this host.
- **RSS**: Tardigrade's RSS stayed under 7 MiB across every core
  competitive-suite scenario (static/proxy/churn/idle-keepalive) — still
  dramatically lower than NGINX (~28 MiB), HAProxy (~28–30 MiB), and Caddy
  (~55–58 MiB). One upstream-pool-matrix row (`upstream-tls-handshake-reuse`,
  8.89 MiB — TLS identity/session material) exceeds 7 MiB, so "under 7 MiB
  across every scenario" is not literally true across the full matrix; the
  qualified "core competitive-suite scenarios" claim above is. Even the
  highest observed Tardigrade RSS (8.89 MiB) remains far below any
  competitor's lowest observed RSS in this run.
- **Static-file error rate — real Tardigrade defect, not noise**:
  Tardigrade's `static-tiny-http1`/`static-tiny-keepalive`/
  `static-large-http1` scenarios reproducibly show roughly a 1% wrk `read`
  socket-error rate that NGINX, HAProxy, and Caddy do not show at the same
  or higher throughput, on the same host, same harness, same run. This was
  isolated to a real, independently-reproducible protocol bug — see below.

### Upstream pool matrix (Tardigrade only)

From `upstream-pool-matrix.json` / the table in `competitive-summary.md`:

- **Uneven route distribution — not concurrent-fairness evidence.**
  route-a-hot (8244 req/s), route-b-warm (8078 req/s), route-c-cold (6885
  req/s), each with reuse ratio ≥ 0.9998. **Important caveat found in PR
  review:** `benchmarks/competitive/upstream-pool-matrix.sh` runs these
  three routes as three separate, sequential `wrk` passes (route A
  finishes entirely, then route B starts, then route C) with different
  durations/concurrency per route, not as concurrent mixed traffic. The
  routes never compete for the same worker pool at the same time, so this
  does **not** exercise or validate uneven-route fairness/starvation the
  way #149/#593 require — it only confirms each route works and reuses
  connections well in isolation. Treat the per-route numbers above as
  informational, not as fairness evidence, until the harness is changed to
  drive all three routes concurrently. That harness gap is real,
  independent of this run, and needs a dedicated fix — filed as
  [#683](https://github.com/Bare-Systems/Tardigrade/issues/683), not
  something to patch inline in a benchmark-execution PR.
- **Many low-volume origins** (16 origins): even distribution, ~7.5 req/s
  per origin as configured, reuse ratio 1.0, 0 errors.
- **Hot origin, many workers**: 8244 req/s, p99 7.16 ms, reuse ratio
  0.99998, CPU 63.18% — no contention signal at this concurrency on this
  4-core host.
- **Upstream TLS handshake/reuse**: 97.27 req/s, p99 330.8 ms (dominated by
  TLS handshake cost, as expected for a scenario specifically measuring
  that), reuse ratio 0.9973.
- **Local vs. cross-worker reuse ratio** (`#593` explicitly asks for this):
  of the connections Tardigrade reused rather than opening fresh, the
  share served by a *different* worker than originally opened it
  (`cross_worker_reuse_ratio`) was:

  | Scenario | local_reuse | cross_worker_reuse | cross-worker share |
  | --- | ---: | ---: | ---: |
  | route-a-hot | 48,623 | 75,881 | 60.9% |
  | route-b-warm | 6,577 | 9,583 | 59.3% |
  | route-c-cold | 2,895 | 4,676 | 61.8% |
  | many-origins-low-volume | 50 | 30 | 37.5% |
  | hot-origin-many-workers | 48,623 | 75,881 | 60.9% |
  | upstream-tls-handshake-reuse | 1,440 | 48 | 3.2% |

  Across the higher-volume scenarios, roughly 59–62% of reused connections
  crossed worker boundaries — the shared upstream pool is actively serving
  most reuse across workers, not just within the worker that happened to
  open the connection. The TLS-handshake scenario is the outlier (3.2%
  cross-worker) — plausible given its far lower request volume (97 req/s)
  giving each of the 4 workers fewer opportunities to hit another worker's
  parked connection before its own becomes available, but not confirmed
  further in this session.
- **Pool-lock contention sweep** (1/2/4 workers): req/s scales
  6694 → 8064 → 8578 as worker count increases, and CPU-ms/request stays
  essentially flat (0.059 → 0.071 → 0.074 ms/req) rather than climbing —
  **no evidence of pool-lock contention becoming a bottleneck at up to 4
  workers on this host.** Lock-wait ns/request does increase with worker
  count (108 → 179 → 257 ns/req) but stays a negligible fraction (< 0.4%)
  of total per-request CPU time even at 4 workers.
- **Conclusion**: on this hardware and worker-count range, the data does
  not support opening a sharding/cross-process-sharing follow-up for the
  upstream pool. This conclusion is scoped to ≤4 workers on a 4-core host;
  it says nothing about behavior at the higher core/worker counts #593
  specifically asks about for the "high-core upstream-pool contention
  sweep" — that sweep needs a host with meaningfully more cores than this
  one to be evidentiary, which beelink cannot provide.

## Harness defects found and fixed during this run

Bugs in the benchmark harness itself were found and fixed while executing
this suite and responding to PR review — all in `benchmarks/`, not in
Tardigrade:

1. **HAProxy reverse-proxy routes always 404'd**
   (`benchmarks/competitive/configs/haproxy.cfg.in`). HAProxy evaluates all
   `http-request` rules before any `use_backend` rule regardless of their
   textual order in the config file (it warns about this at parse time).
   The template's unconditional 404 fallback sat textually after
   `use_backend`, so it ran first and returned 404 for every `/proxy/*`
   request before routing ever got a turn. This has silently broken every
   HAProxy reverse-proxy scenario in this suite since it was introduced by
   #589 — any prior HAProxy proxy numbers from this harness (if any exist)
   should be treated as invalid. Fixed by scoping the fallback to
   `unless { path_beg /proxy/ }`.
2. **`idle-keepalive-active-traffic` silently reported 0 req/s for every
   server** (`benchmarks/scenarios/keepalive-starvation.js`,
   `benchmarks/run.sh`). k6 treats an env var literally named
   `K6_DURATION` (or `K6_VUS`) as a global override that replaces the
   script's `scenarios` block entirely — documented k6 behavior for the
   classic single-`default`-function test style.
   `keepalive-starvation.js` is the only scenario script in this repo using
   named `scenarios` with per-VU-group `exec` functions and no `default`
   export, so passing `-e K6_DURATION=...` made k6 discard the scenarios
   block and fail immediately looking for a nonexistent `default` function.
   That failure was invisible because `run_k6_scenario` redirected k6's
   stderr to `/dev/null` and swallowed its exit code with `|| true`, so
   every idle-keepalive-active-traffic row silently reported "0 req/s, 0
   errors" — indistinguishable from a genuinely idle server. Fixed by
   renaming the script's env var to `SCENARIO_DURATION` and making
   `run_k6_scenario` surface k6's stderr and fail loudly on nonzero exit
   instead of fabricating a zero-valued result.
3. **`remote-run.sh` could silently report `0 req/s, 0 errors` for a
   failed remote run** (found in PR review, not exercised by this session's
   loopback-only run). `run_wrk_remote` swallowed a nonzero SSH exit with
   `|| true` and only counted `Non-2xx` HTTP errors, never wrk's `Socket
   errors:` line — so a dropped SSH connection or a remote `wrk` crash
   could produce a result indistinguishable from a real, clean, zero-load
   pass. Fixed to fail loudly (print the raw output, exit nonzero) on a
   failed SSH/wrk execution or unparseable output, and to count Non-2xx +
   Socket errors together like `benchmarks/run.sh`'s own `wrk_error_count`
   already does. Also fixed two smaller bugs found alongside it: the
   documented `--remote SSH_HOST` flag had no parser arm at all (any use of
   it exited as "Unknown option"), and `--help` used the GNU-only `head -n
   -1` (crashes on macOS/BSD `head`).
4. **`covered`/`supported: false` silently rendered as `true` in the
   retained JSON/CSV/Markdown** (`benchmarks/competitive/run.sh`, found
   fixing item 2 of this round's review). Every `X // Y // true`-style jq
   fallback used to render these fields treats jq's `//` operator as
   "use the right side if the left side is `null` *or* `false`" — so any
   scenario explicitly marked `covered: false` or `supported: false`
   rendered as `true` anyway. This silently affected every previously
   "unsupported" row in this suite too (HAProxy's `static-large-http1`, the
   H3 rows) in the CSV export specifically — the Markdown table happened to
   use a direct `== false` check for those and rendered correctly, but the
   CSV did not. Fixed every occurrence to distinguish `false` from `null`
   explicitly, and added a "Reason" column to the Upstream Pool Matrix
   Markdown table so a `false`/uncovered row's explanation is visible
   inline, not just in the machine-readable JSON.

All fixes above are included in this branch/PR and were verified (manually,
and via `test-report.sh`/`test-h3-benchmark.sh`, plus new regression tests
added in review response) before/alongside this canonical run.

## Harness gap found, not fixed — deferred to #683

The upstream-pool matrix's `uneven-route-distribution` scenario runs its
three routes as sequential, non-competing `wrk` passes rather than
concurrent mixed traffic, so it doesn't actually test the concurrent
route-fairness question #149/#593 ask about. This is a real harness
design gap (needs concurrent-process orchestration in
`upstream-pool-matrix.sh`, not a one-line fix), found in PR review of this
PR. Filed as [#683](https://github.com/Bare-Systems/Tardigrade/issues/683)
rather than attempted inline here. See the "Uneven route distribution" bullet
under [Upstream pool matrix](#upstream-pool-matrix-tardigrade-only) below
for how this affects reading that scenario's numbers in this report.

## Real Tardigrade defect found during this run

### #682: `max_requests_per_connection` keep-alive bug

Isolated the reproducible ~1% static-file error rate to a real,
independently-confirmed protocol bug, unrelated to host load: hitting
`max_requests_per_connection` (default 100) closes the connection
server-side without ever sending `Connection: close` on the response that
hits the limit. A client that reuses the connection per the header it just
received (standard, compliant keep-alive behavior) gets no response at all
on its next request.

Confirmed independently of `wrk`/the benchmark harness with a raw
`http.client` trace against an isolated Tardigrade instance:

```
request 97:  200  connection: keep-alive
request 98:  200  connection: keep-alive
request 99:  200  connection: keep-alive
request 100: 200  connection: keep-alive
request 101: RemoteDisconnected: Remote end closed connection without response
```

This explains the observed error math almost exactly:
`static-tiny-http1` served 40840 req/s × 15s ≈ 612,600 requests over 32
connections ≈ 19,144 requests/connection ≈ 191 hits of the 100-request
limit/connection × 32 connections ≈ 6,112 — matching the observed 6114
errors to within noise.

Filed as [Bare-Systems/Tardigrade#682](https://github.com/Bare-Systems/Tardigrade/issues/682)
with root cause (`src/edge_gateway.zig:1271-1285` decides `keep_alive`
before knowing the request-count cutoff will be hit) and a suggested fix
direction. **Not fixed in this PR** — this is a real product bug found
while executing the benchmark suite, filed as a dedicated follow-up per
#593's acceptance criteria, and out of scope for a benchmark-execution
change.

This bug is a plausible full or partial explanation for why NGINX/HAProxy
show meaningfully higher `static-tiny-http1` throughput than Tardigrade on
this host: NGINX/HAProxy/Caddy's equivalent connection-limit settings don't
exhibit this failure mode (0 errors on the same scenario at the same or
higher throughput), so at minimum some of Tardigrade's client-visible
"lower" static-file numbers here include ~1% outright request failures that
the other three servers don't pay.

## What was not covered by this session

Per the issue's dependency semantics, the following #593 lanes are
independent of this competitive-suite lane and were **not** attempted in
this session:

- Accept-batching / fairness suite (#146 / #601,
  `benchmarks/listener-sharding.sh`)
- `epoll` vs `io_uring` event-loop backend comparison (#148 / #602)
- HTTP/3 / QUIC real-hardware evidence lane (issue comments referencing
  #256 / #623 / #247 / #628) — this host's `h2load` is not QUIC-capable, so
  even if attempted, it could not have produced valid H3 evidence here
  without first installing a QUIC-enabled `h2load` build.

These remain open under #593.

## Repetition / run-to-run variance — explicitly not covered

**This report represents one clean canonical pass per server, not the
repeated/variance-checked evidence #593 asks for.** The issue's stated bar
is "run enough repetitions across all suites to identify obviously noisy or
unstable measurements" — that was not done here. Two runs were attempted in
this session (the first aborted mid-run when the host lost power), but the
first attempt used a different harness state (pre-HAProxy-fix, pre-k6-fix)
and was discarded entirely rather than treated as a second data point for
the same configuration, so there is no valid same-configuration repetition
to report variance from.

This means: do not read any single number in this report as free of
run-to-run noise. The observed differences between servers on this host
(e.g., HAProxy's throughput lead, Tardigrade's RSS advantage) are large
enough relative to typical wrk run-to-run variance that they're unlikely to
be pure noise, but that is a judgment call, not a measured variance bound.
Treat this PR as completing the "prove the suite runs end-to-end against
all four servers and produces valid, non-fabricated results" portion of
#593's competitive-suite lane, not the "reproducible baseline with
documented variance" portion — the latter remains open work under #593 and
needs multiple same-configuration runs (ideally with `benchmarks/run.sh`'s
`--runs > 1` support, which this session's harness fixes correctly
aggregate) before any number here should be cited as a stable baseline.

## Reproducibility

Exact commands used for the canonical run:

```bash
zig build -Doptimize=ReleaseFast   # Zig 0.16.0
./benchmarks/competitive/run.sh \
  --binary zig-out/bin/tardi \
  --out-dir benchmarks/competitive/results/2026-08-25-beelink-competitive
```

Tardigrade commit benchmarked: `efe0876` — a **pre-rebase** SHA no longer
reachable from this branch's history (see the "Tardigrade commit
benchmarked" row in [Test environment](#test-environment) above for the
post-rebase provenance mapping). The branch has since gained further
review-response commits on top of that fix set, including a
`competitive/run.sh` fix to how `covered`/`supported` booleans render in
the retained JSON/CSV/Markdown (this file). That fix changes how existing
data is *displayed* — it does not touch how `wrk`/`k6` are invoked against
the servers under test, so it does not affect any recorded throughput,
latency, CPU, RSS, or error number in this report.
