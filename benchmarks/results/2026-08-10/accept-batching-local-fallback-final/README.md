# Accept batching local fallback benchmark

Run: 2026-08-10T22:04:40Z from `v0.5.0-186-ga30f6e06`

Host: macOS 26.3 arm64 (`Darwin 25.3.0`)

Command shape:

```sh
./benchmarks/listener-sharding.sh \
  --start-command "TARDIGRADE_ACCESS_LOG_MIN_STATUS=600 ./zig-out/bin/tardi run -c <generated-ci-smoke.conf> > <tmp>/tardi.log 2>&1" \
  --host 127.0.0.1 \
  --port 19169 \
  --shards 4 \
  --duration 10 \
  --connections 30 \
  --burst-connections 120 \
  --threads 4 \
  --static-path /health \
  --proxy-path /proxy/health \
  --keepalive-path /health \
  --save-dir benchmarks/results/2026-08-10/accept-batching-local-fallback-final
```

`summary.json` is the authoritative machine-readable artifact. The raw wrk
outputs and Prometheus snapshots are retained in this directory.

## Results

| profile | requested shards | effective shards | batch | fairness every | churn req/s | churn p99/p999 ms | burst req/s | burst p99/p999 ms | mixed keepalive req/s | mixed keepalive p99/p999 ms | mixed churn req/s | mixed churn p99/p999 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| batch-1 | 1 | 1 | 1 | 0 | 24214.97 | 47.097 / 98.385 | 1.10 | 8.073 / 8.073 | 9.90 | 4.145 / 4.145 | 0.00 | 0.000 / 0.000 |
| batch-64 | 1 | 1 | 64 | 0 | 11384.73 | 7.486 / 167.021 | 0.00 | 0.000 / 0.000 | 6462.40 | 0.095 / 0.444 | 0.10 | 0.144 / 0.144 |
| batch-64-fair-8 | 1 | 1 | 64 | 8 | 7915.05 | 1.013 / 16.513 | 0.90 | 4.983 / 4.983 | 9.90 | 3.274 / 3.274 | 0.00 | 0.000 / 0.000 |
| sharded-batch-64 | 4 | 1 | 64 | 0 | 21081.51 | 38.368 / 95.167 | 114.12 | 0.895 / 5.350 | 4116.23 | 0.108 / 0.478 | 0.10 | 0.097 / 0.097 |

| profile | gateway accept/poll errors | fairness yields | worker queue wait count | worker queue wait sum us | accept distribution |
| --- | ---: | ---: | ---: | ---: | --- |
| batch-1 | 0 | 0 | 3475382 | 170696746 | shard 0=277018 |
| batch-64 | 0 | 0 | 6937067 | 339871164 | shard 0=425372 |
| batch-64-fair-8 | 0 | 0 | 10338398 | 510080207 | shard 0=538424 |
| sharded-batch-64 | 0 | 0 | 13734374 | 682164200 | shard 0=783689 |

## Notes

- macOS does not enable the listener sharding path because
  `isReusePortSupported()` is true only on Linux and FreeBSD. The requested
  four-shard profile therefore recorded an effective shard count of one and is
  included as a local diagnostic, not as a valid sharded throughput result.
- The gateway reported zero accept/poll errors in every profile. The wrk burst
  and mixed close-connection workloads reported client-side connect errors; see
  the corresponding `*.wrk.txt` files for the raw socket error lines.
- The `batch-64` local fallback profile improved mixed keepalive tail latency
  relative to `batch-1`, but this macOS fallback run should not be treated as a
  substitute for the Linux same-host sharded acceptance run.
