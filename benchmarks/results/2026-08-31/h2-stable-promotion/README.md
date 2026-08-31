# HTTP/2 Stable-Promotion Baseline for #389

Purpose: final native HTTP/2 performance-baseline evidence for Bare-Systems/Tardigrade issue #389. This run covers only the two required protocol rows: `static-http2` and `proxy-http2`.

This evidence does not reopen #593, does not benchmark competitors, and does not cover the final installed-release #677 sweep.

## Artifact Identity

- Tardigrade Git SHA: `7afc1b4920c83f48ce404bfbf9309796fa8f4583`
- Git describe: `v0.6.4-18-g7afc1b4`
- PR #699 merge commit `5ce1426216f84324fa0148fb56b305e341527b1e` is an ancestor of the tested SHA.
- Binary SHA-256: `076a096bed56868bd489d259b9a5e80c2d3b2ab84bef1bd6a2d37abd8ee7161f`
- `tardi version`: `dev (tls-profile=general, tls-backend=native)`
- Build command: `/opt/zig-versions/0.16.0/zig-x86_64-linux-0.16.0/zig build -Doptimize=ReleaseFast --summary all`
- Zig version: `0.16.0`
- TLS profile/backend: `general` / `native`

## Environment

- Target: Proxmox LXC `102` (`tardigrade-perf`) on `beelink/proxmox`
- OS/kernel: Debian GNU/Linux 13.1 (`trixie`), Linux `6.17.13-2-pve`
- Architecture: `x86_64`
- CPU: Intel(R) N150, 2 online benchmark-container threads
- Memory: 4096 MiB assigned to the container
- h2load: `h2load nghttp2/1.69.0`
- h2load binary: `/tmp/nghttp2-1.69.0/build/src/h2load`
- Benchmark host/port: `127.0.0.1:18443`
- Connections: `50`
- Threads: `2`
- Duration: `30s`
- Runs: `3`
- PID sampling: enabled via `/tmp/tardigrade-issue389-h2-run/tardi.pid`, 500 ms interval

Before the accepted run, stale `nginx`, `haproxy`, and old `/opt/tardigrade-src` services were stopped. The clean pre-run process inventory showed only the intended Tardigrade process and its two-worker upstream fixture as benchmark services.

## Tardigrade Runtime

Start command:

```bash
TARDIGRADE_WORKER_THREADS=2 \
TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_PROXY_STREAMING_MODE=off \
./zig-out/bin/tardi run -c /tmp/tardigrade-issue389-h2-run/tardigrade-h2.conf
```

Upstream fixture:

```bash
python3 benchmarks/fixtures/upstream_server.py --port 18080 --workers 2
```

Config:

```nginx
pid /tmp/tardigrade-issue389-h2-run/tardi.pid;
listen 18443 ssl;
server_name localhost;
tls_cert_path /tmp/tardigrade-issue389-h2-run/server.crt;
tls_key_path /tmp/tardigrade-issue389-h2-run/server.key;
root /tmp/tardigrade-issue389-h2-run/public;

location = /health {
    return 200 ok;
}

location /proxy/ {
    proxy_pass http://127.0.0.1:18080/;
}
```

Endpoint validation before benchmarking:

- `https://127.0.0.1:18443/tiny.txt`: 200, 30-byte static file body.
- `https://127.0.0.1:18443/proxy/health`: 200, body `ok`.
- Retained `static-probe.txt` and `proxy-probe.txt` both show `Application protocol: h2` and `1 succeeded, 0 failed, 0 errored, 0 timeout`.

## Benchmark Command

```bash
PATH=/tmp/nghttp2-1.69.0/build/src:/opt/zig-versions/0.16.0/zig-x86_64-linux-0.16.0:$PATH \
  ./benchmarks/run.sh \
    --tool h2load \
    --tls \
    --insecure \
    --host 127.0.0.1 \
    --port 18443 \
    --static-path /tiny.txt \
    --h2-path /tiny.txt \
    --proxy-path /proxy/health \
    --pid-file /tmp/tardigrade-issue389-h2-run/tardi.pid \
    --driver "loopback (dedicated benchmark target)" \
    --worker-count 2 \
    --config-label "issue-389 native H2 baseline config" \
    --duration 30 \
    --runs 3 \
    --connections 50 \
    --threads 2 \
    --idle-check \
    --scenarios static-http2,proxy-http2 \
    --meta-file /tmp/tardigrade-issue389-h2-run/h2-baseline-meta.json \
    --save benchmarks/results/2026-08-31/h2-stable-promotion/h2-baseline.json
```

## Results

| Scenario | req/s mean | req/s stddev | req/s variance | p50 ms | p95 ms | p99 ms mean | p99 ms stddev | p99 ms variance | CPU avg | Peak RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `static-http2` | 14628.667 | 702.069 | 492901.333 | 0.129 | 0.165 | 0.175 | 0.024 | 0.000561 | 108.317% | 24.750 MiB | 0 |
| `proxy-http2` | 6139.333 | 114.212 | 13044.333 | 0.304 | 0.352 | 0.416 | 0.022 | 0.000496 | 58.297% | 32.920 MiB | 0 |

Observed repetitions:

| Scenario | Run | req/s | p50 ms | p95 ms | p99 ms | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `static-http2` | 1 | 15038 | 0.130 | 0.152 | 0.160 | 0 |
| `static-http2` | 2 | 15030 | 0.129 | 0.152 | 0.162 | 0 |
| `static-http2` | 3 | 13818 | 0.128 | 0.190 | 0.202 | 0 |
| `proxy-http2` | 1 | 6067 | 0.302 | 0.343 | 0.402 | 0 |
| `proxy-http2` | 2 | 6080 | 0.302 | 0.344 | 0.405 | 0 |
| `proxy-http2` | 3 | 6271 | 0.308 | 0.370 | 0.442 | 0 |

Unavailable metrics:

- `p999_ms` is `null`; the existing h2load JSON parser records median/p95/p99 from h2load 1.69.0 and does not provide p999.

## Conclusion

On this recorded Beelink LXC target and configuration, both required native HTTP/2 rows executed over TLS with ALPN `h2`, completed three repetitions, and reported zero benchmark/request errors. This satisfies the missing H2 performance-baseline evidence requirement for #389 on this hardware/configuration only.
