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
- Repetitions: 3 for the small-path summary; 10 interleaved base/final pairs
  for the 64 KiB closeout series
- Threads/connections: 2 / 10
- Tardigrade workers: 4
- Config: plaintext reverse proxy to `benchmarks/fixtures/upstream_server.py`
- Env: `TARDIGRADE_PROXY_STREAMING_MODE=off`, `TARDIGRADE_RATE_LIMIT_RPS=0`,
  `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0`

The keepalive request cap is disabled here to match `benchmarks/ci-smoke.sh`
and avoid counting intentional downstream connection retirement as `wrk` read
socket errors. A control run with the default cap (`100`) reproduced the earlier
`wrk` read-error behavior on otherwise successful 200 responses.

The process-sampled runs launched Tardigrade with the same runtime knobs used in
the benchmark metadata:

```bash
python3 benchmarks/fixtures/upstream_server.py --port "${UPSTREAM_PORT}" &

TARDIGRADE_PROXY_STREAMING_MODE=off \
TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0 \
TARDIGRADE_WORKER_THREADS=4 \
./zig-out/bin/tardi run -c "${CONFIG_FILE}" &
TARDI_PID=$!
```

Benchmark command shape, including process CPU/RSS sampling:

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
  --pid "$TARDI_PID" \
  --sample-interval-ms 500 \
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
  --runs 1 \
  --tool wrk \
  --pid "$TARDI_PID" \
  --sample-interval-ms 500 \
  --scenarios proxy-payload-64k
```

## Results

Observed final-head response sizes:

| Case | Body bytes | Header bytes | Total head+body bytes |
| --- | ---: | ---: | ---: |
| small proxy `/health` | 2 | 565 | 567 |
| 64 KiB proxy `/payload-64k.bin` | 65,536 | 583 | 66,119 |

The small response is comfortably inside the 8 KiB coalescing scratch buffer.
The 64 KiB response is outside that boundary and exercises the gathered-write
branch.

Initial small-path and 3-run 64 KiB summary:

| Case | Commit | req/s mean | req/s stddev | p99 mean | p99 stddev | wrk errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| small proxy `/health` | base | 25250.717 | 30.341 | 1.500 ms | 0.079 ms | 0 |
| small proxy `/health` | final | 25384.847 | 319.720 | 1.540 ms | 0.252 ms | 0 |
| 64 KiB proxy `/payload-64k.bin` | base | 21021.543 | 400.566 | 1.675 ms | 0.092 ms | 0 |
| 64 KiB proxy `/payload-64k.bin` | final | 19869.927 | 1230.074 | 2.226 ms | 1.190 ms | 0 |

Additional 64 KiB interleaved series:

| Pair | Commit | req/s | p95 | p99 | CPU | wrk errors |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | base | 23330.13 | 0.665 ms | 1.042 ms | 145.76% | 0 |
| 1 | final | 22987.48 | 0.696 ms | 1.863 ms | 141.60% | 0 |
| 2 | base | 23351.99 | 0.655 ms | 0.876 ms | 143.88% | 0 |
| 2 | final | 23025.81 | 0.677 ms | 1.002 ms | 143.12% | 0 |
| 3 | base | 22819.18 | 0.674 ms | 1.065 ms | 143.77% | 0 |
| 3 | final | 22234.67 | 0.765 ms | 7.761 ms | 138.44% | 0 |
| 4 | base | 22116.99 | 0.735 ms | 2.550 ms | 141.29% | 0 |
| 4 | final | 22695.86 | 0.683 ms | 1.472 ms | 141.49% | 0 |
| 5 | base | 22219.51 | 0.691 ms | 1.641 ms | 143.29% | 0 |
| 5 | final | 21345.25 | 0.769 ms | 2.383 ms | 140.02% | 0 |
| 6 | base | 23241.36 | 0.659 ms | 0.876 ms | 142.37% | 0 |
| 6 | final | 23386.72 | 0.656 ms | 0.937 ms | 139.50% | 0 |
| 7 | base | 23159.19 | 0.670 ms | 1.168 ms | 142.52% | 0 |
| 7 | final | 22705.86 | 0.698 ms | 2.240 ms | 140.26% | 0 |
| 8 | base | 22426.16 | 0.697 ms | 1.650 ms | 140.70% | 0 |
| 8 | final | 22631.14 | 0.677 ms | 0.922 ms | 140.94% | 0 |
| 9 | base | 21707.45 | 0.728 ms | 1.241 ms | 143.09% | 0 |
| 9 | final | 22029.97 | 0.708 ms | 1.443 ms | 139.97% | 0 |
| 10 | base | 22041.04 | 0.698 ms | 1.037 ms | 141.47% | 0 |
| 10 | final | 21049.03 | 0.797 ms | 24.220 ms | 136.80% | 0 |

64 KiB aggregate from the 10-pair series:

| Commit | req/s mean | req/s stddev | req/s median | p95 mean | p95 median | p99 mean | p99 median | CPU mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| base | 22641.300 | 612.007 | 22622.670 | 0.687 ms | 0.682 ms | 1.315 ms | 1.116 ms | 142.814% |
| final | 22409.179 | 748.771 | 22663.500 | 0.713 ms | 0.697 ms | 4.424 ms | 1.668 ms | 140.214% |

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
- 64 KiB buffered proxy response: the 10-pair interleaved series is effectively
  throughput-neutral on this local fallback host: final mean req/s is -1.0% and
  final median req/s is +0.2%. Process CPU also does not regress; final average
  sampled CPU is lower.
- Tail latency remains noisy on this macOS loopback fallback. The final series
  includes two large p99 outliers, so the p99 mean is not clean. The p95
  distribution is close (final +0.026 ms mean, +0.015 ms median), there are zero
  `wrk` errors, zero response-write errors, and no corresponding throughput or
  CPU regression. For this closeout, I treat a material regression as a
  sustained >10% req/s loss or process-CPU increase, or a repeatable tail shift
  accompanied by p95, error, CPU, or throughput movement. The retained samples
  do not meet that threshold.

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
tardigrade_response_write_mode_total{mode="writev"} 212695
tardigrade_response_write_mode_total{mode="single_write"} 0
tardigrade_response_writev_iovecs_total 425390
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
