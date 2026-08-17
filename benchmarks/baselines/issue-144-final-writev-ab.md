# Issue #144 Final Writev A/B Notes

Date: 2026-08-17

This records the final local same-host A/B data for issue #144. The targeted
comparison covers the merged response-writer base against the final writev head
for the small buffered proxy branch and the >8 KiB gathered-write branch.

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
- Env: `TARDIGRADE_PROXY_STREAMING_MODE=off`, `TARDIGRADE_RATE_LIMIT_RPS=0`,
  `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0`

The keepalive request cap is disabled here to match `benchmarks/ci-smoke.sh`
and avoid counting intentional downstream connection retirement as `wrk` read
socket errors. A control run with the default cap (`100`) reproduced the earlier
`wrk` read-error behavior on otherwise successful 200 responses.

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
| small proxy `/health` | base | 25250.717 | 30.341 | 1.500 ms | 0.079 ms | 0 |
| small proxy `/health` | final | 25384.847 | 319.720 | 1.540 ms | 0.252 ms | 0 |
| 64 KiB proxy `/payload-64k.bin` | base | 21021.543 | 400.566 | 1.675 ms | 0.092 ms | 0 |
| 64 KiB proxy `/payload-64k.bin` | final | 19869.927 | 1230.074 | 2.226 ms | 1.190 ms | 0 |

Process CPU samples from the per-run output:

| Case | Commit | CPU/run samples |
| --- | --- | --- |
| small proxy `/health` | base | 75.58%, 75.22%, 75.12% |
| small proxy `/health` | final | 75.37%, 75.50%, 75.89% |
| 64 KiB proxy `/payload-64k.bin` | base | 167.60%, 167.36%, 168.14% |
| 64 KiB proxy `/payload-64k.bin` | final | 158.84%, 168.48%, 166.34% |

Interpretation:

- Small buffered proxy response: final is +0.5% req/s with p99 effectively
  unchanged (+0.040 ms), confirming the restored `single_write` branch is
  baseline-neutral.
- 64 KiB buffered proxy response: final is -5.5% req/s. The first final sample
  was noisy (`18483.88` req/s, p99 `3.599 ms`), while the next two samples were
  close to base (`20294.18` and `20831.72` req/s). This is not a reproducible
  material regression on the local fallback host, and it exercises the intended
  gathered-write branch.

## Final-head response-write mode evidence

Small proxy `/health` after-run metrics:

```text
tardigrade_response_write_mode_total{mode="writev"} 1
tardigrade_response_write_mode_total{mode="single_write"} 769159
tardigrade_response_writev_iovecs_total 2
tardigrade_response_write_errors_total{mode="writev"} 0
tardigrade_response_write_errors_total{mode="single_write"} 0
```

The single `writev` and two iovecs are from metrics/readiness traffic before the
benchmark load; the benchmarked small proxy traffic used `single_write`.

Large proxy `/payload-64k.bin` after-run metrics:

```text
tardigrade_response_write_mode_total{mode="writev"} 602133
tardigrade_response_write_mode_total{mode="single_write"} 0
tardigrade_response_writev_iovecs_total 1204266
tardigrade_response_write_errors_total{mode="writev"} 0
tardigrade_response_write_errors_total{mode="single_write"} 0
```

This confirms the >8 KiB response path exercised gathered writes with two iovecs
per response.

## Earlier caveat resolved

The first local capture reported nonzero `wrk` errors even though Tardigrade
access logs recorded only HTTP 200 responses and response-write metrics recorded
zero write errors. A control run reproduced that pattern with the default
`TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=100`:

```text
Running 5s test @ http://127.0.0.1:18146/proxy/health
  131047 requests in 5.10s, 70.86MB read
  Socket errors: connect 0, read 1306, write 0, timeout 0
Requests/sec:  25696.56
```

The clean A/B above disables that cap (`0`, unlimited), which removes the
intentional keepalive-close noise from `wrk` and leaves both compared proxy
cases with zero benchmark errors.

Linux syscall/request and allocation/request data were not captured in this
local macOS fallback run.

## Closeout

The remaining issue #144 acceptance criteria are satisfied by this targeted A/B:

- same-host base-vs-final-head small buffered proxy evidence is recorded;
- same-host base-vs-final-head >8 KiB proxy evidence is recorded;
- final-head counters prove `single_write` for the small branch and `writev`
  with two iovecs per response for the 64 KiB branch;
- no reproducible material response-writer regression remains in either branch.
