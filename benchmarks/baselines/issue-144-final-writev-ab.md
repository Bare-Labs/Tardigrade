# Issue #144 Final Writev A/B Notes

Date: 2026-08-17

This records the local same-host A/B data captured for issue #144 before handing
the work to a fresh session. It is intentionally preserved with the unresolved
`wrk` status-error caveat rather than polished into closeout evidence.

## Compared commits

- Base: `d39353267f51116e0d30bdccec3614b3019a12db`
- Final writev head: `e302ca96046ad724d541be026c17e904d4d6e90d`

Both binaries were built with:

```bash
zig build -Doptimize=ReleaseFast
```

## Host and command

- Host: local loopback fallback, not the dedicated benchmark target
- OS: macOS 26.3 / Darwin 25.3.0
- CPU: Apple M4, 10 threads
- Zig: 0.16.0
- Driver: `wrk`
- Duration: 10s per run
- Repetitions: 3
- Threads/connections: 2 / 10
- Tardigrade workers: 4
- Config: plaintext reverse proxy to `benchmarks/fixtures/upstream_server.py`
- Env: `TARDIGRADE_PROXY_STREAMING_MODE=off`, `TARDIGRADE_RATE_LIMIT_RPS=0`

Benchmark command shape:

```bash
benchmarks/run.sh \
  --host 127.0.0.1 \
  --port 18081 \
  --host-header localhost \
  --driver loopback-local-fallback \
  --worker-count 4 \
  --config-label "issue-144 proxy buffered fixture" \
  --duration 10 \
  --connections 10 \
  --threads 2 \
  --runs 3 \
  --tool wrk \
  --scenarios proxy-http1

benchmarks/run.sh \
  --host 127.0.0.1 \
  --port 18081 \
  --host-header localhost \
  --driver loopback-local-fallback \
  --worker-count 4 \
  --config-label "issue-144 proxy buffered fixture" \
  --duration 10 \
  --connections 10 \
  --threads 2 \
  --runs 3 \
  --tool wrk \
  --scenarios proxy-payload-64k
```

## Results

| Case | Commit | req/s mean | req/s stddev | p99 mean | p99 stddev | wrk errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| small proxy `/health` | base | 24138.653 | 987.259 | 2.177 ms | 0.926 ms | 7298 |
| small proxy `/health` | final | 25770.587 | 1048.985 | 2.450 ms | 2.377 ms | 7793 |
| 64 KiB proxy `/payload-64k.bin` | base | 21447.237 | 602.818 | 1.334 ms | 0.218 ms | 6485 |
| 64 KiB proxy `/payload-64k.bin` | final | 20242.483 | 288.457 | 1.838 ms | 0.395 ms | 6120 |

Access-log status counts for the same low-concurrency run:

```text
731429 base small responses: status=200
649871 base 64 KiB responses: status=200
780976 final small responses: status=200
613398 final 64 KiB responses: status=200
```

## Final-head response-write mode evidence

Small proxy `/health` after-run metrics:

```text
tardigrade_response_write_mode_total{mode="writev"} 1
tardigrade_response_write_mode_total{mode="single_write"} 780974
tardigrade_response_writev_iovecs_total 2
tardigrade_response_write_errors_total{mode="writev"} 0
tardigrade_response_write_errors_total{mode="single_write"} 0
```

The single `writev` and two iovecs are from metrics/readiness traffic before the
benchmark load; the benchmarked small proxy traffic used `single_write`.

Large proxy `/payload-64k.bin` after-run metrics:

```text
tardigrade_response_write_mode_total{mode="writev"} 613396
tardigrade_response_write_mode_total{mode="single_write"} 1
tardigrade_response_writev_iovecs_total 1226792
tardigrade_response_write_errors_total{mode="writev"} 0
tardigrade_response_write_errors_total{mode="single_write"} 0
```

This confirms the >8 KiB response path exercised gathered writes with two iovecs
per response.

## Caveat

The `wrk` summary reported nonzero status errors even though Tardigrade access
logs for the captured runs recorded only HTTP 200 responses and response-write
metrics recorded zero write errors. This note should not be treated as final
closeout evidence until the `wrk` status-error source is explained or a clean
zero-error run is captured.

Linux syscall/request and allocation/request data were not captured in this
local macOS fallback run.
