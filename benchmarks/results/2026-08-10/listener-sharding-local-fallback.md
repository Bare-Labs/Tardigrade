# Listener Sharding Local Fallback Benchmark

PR #596 / issue #137 listener-sharding evidence, captured on 2026-08-10 with the repo benchmark harness.

This is fallback data from a local Mac, not the dedicated benchmark target recommended by `benchmarks/README.md`. Use it to verify the benchmark procedure, metric shape, and obvious regressions; do not treat it as the canonical performance claim. The follow-up review fix for PR #596 now treats macOS as unsupported for listener sharding because this run showed duplicate-bind behavior without load-balanced accept distribution.

## Environment

- Binary: `zig build -Doptimize=ReleaseFast install`
- Git tag metadata from harness: `v0.5.0-181-g8adb3fef`
- Provenance note: captured from the local working tree that was committed as `947222028c8481970cc65d6f44e3c876323db253`; the harness tag output does not encode dirty-tree state.
- Host: `127.0.0.1`, Darwin `25.3.0`, Apple M4, 10 CPU threads, 16 GiB RAM
- Load tool: `wrk`
- Tardigrade workers: 4
- Profiles compared on the same generated config and upstream fixture:
  - single listener: `TARDIGRADE_LISTENER_SHARDS=0`
  - sharded listener: `TARDIGRADE_LISTENER_SHARDS=4`
- Common load settings: 4 seconds, 20 connections, 4 wrk threads
- Rate limiting disabled for the run: `TARDIGRADE_RATE_LIMIT_RPS=0`

## Harness Results

| Scenario | single req/s | 4-shard req/s | Delta | single p99 ms | 4-shard p99 ms | single CPU % | 4-shard CPU % | single errors | 4-shard errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `static-http1` | 28,589 | 27,219 | -4.8% | 1.300 | 1.403 | 394.9 | 391.4 | 1,160 | 1,102 |
| `proxy-http1` | 27,407 | 26,103 | -4.8% | 1.270 | 1.986 | 53.5 | 52.7 | 1,119 | 1,060 |
| `keepalive` | 27,889 | 26,269 | -5.8% | 1.418 | 1.519 | 392.4 | 389.9 | 1,136 | 1,066 |

Raw JSON:

- `benchmarks/results/2026-08-10/listener-sharding-single-local-fallback.json`
- `benchmarks/results/2026-08-10/listener-sharding-4shards-local-fallback.json`

The standard harness reported socket-level errors under this short laptop-local `wrk` run. Both profiles showed the same class of errors, and the sharded profile did not increase them.

## Connection-Churn Probe

Direct `wrk` run with `Connection: close` against the same static fixture:

| Profile | req/s | p50 ms | p95 ms | p99 ms | p999 ms | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| single listener | 17,168 | 0.599 | 0.873 | 17.616 | 81.100 | 0 |
| 4 shards | 15,773 | 0.647 | 1.060 | 9.888 | 77.962 | 0 |

Raw wrk output:

- `benchmarks/results/2026-08-10/listener-sharding-single-connection-close.wrk.txt`
- `benchmarks/results/2026-08-10/listener-sharding-4shards-connection-close.wrk.txt`

## Accept And Worker Metrics

Single listener scrape after the run:

```text
tardigrade_listener_shards 1
tardigrade_accepts_total{shard="0"} 73973
tardigrade_accept_errors_total{shard="0",reason="poll"} 0
tardigrade_accept_errors_total{shard="0",reason="accept"} 0
tardigrade_worker_queued_jobs 0
tardigrade_worker_queue_wait_us_count 414503
tardigrade_worker_queue_wait_us_sum 132918319
```

4-shard scrape after the run:

```text
tardigrade_listener_shards 4
tardigrade_accepts_total{shard="0"} 0
tardigrade_accepts_total{shard="1"} 0
tardigrade_accepts_total{shard="2"} 0
tardigrade_accepts_total{shard="3"} 68025
tardigrade_accept_errors_total{shard="0",reason="poll"} 0
tardigrade_accept_errors_total{shard="0",reason="accept"} 0
tardigrade_accept_errors_total{shard="1",reason="poll"} 0
tardigrade_accept_errors_total{shard="1",reason="accept"} 0
tardigrade_accept_errors_total{shard="2",reason="poll"} 0
tardigrade_accept_errors_total{shard="2",reason="accept"} 0
tardigrade_accept_errors_total{shard="3",reason="poll"} 0
tardigrade_accept_errors_total{shard="3",reason="accept"} 0
tardigrade_worker_queued_jobs 1
tardigrade_worker_queue_wait_us_count 391158
tardigrade_worker_queue_wait_us_sum 134056492
```

Raw metric scrapes:

- `benchmarks/results/2026-08-10/listener-sharding-single-metrics.prom`
- `benchmarks/results/2026-08-10/listener-sharding-4shards-metrics.prom`

## Reusable Suite

The reusable #137 benchmark path is now `benchmarks/listener-sharding.sh`. It
starts the same foreground gateway command with `TARDIGRADE_LISTENER_SHARDS=1`
and `=N`, delegates the standard static/proxy/keepalive scenarios to
`benchmarks/run.sh`, adds explicit `Connection: close` churn and mixed
static/proxy workloads, scrapes `/status/metrics`, and saves per-profile raw
outputs plus a combined `summary.json`.

## Interpretation

- The sharded startup path ran and exported the required `listener_shards`, per-shard accepts, and `{shard,reason}` accept-error labels.
- Accept errors stayed at zero in both profiles.
- On this macOS loopback run, all accepted connections landed on one reuse-port shard, so this local result does not demonstrate shard-distribution fairness. A canonical Linux/BSD benchmark target is still needed for publishable fairness numbers.
- The local 4-shard profile was slightly slower than single-listener in these short runs; this is not enough evidence to enable listener sharding by default.
- The canonical Linux/BSD performance run remains intentionally absent from this artifact. `benchmarks/remote-run.sh` expects the dedicated SSH target (`remote-runner`) and a reachable gateway target; those runner credentials were not available in the local workspace used for this follow-up.
