# Competitive Benchmark Summary

Generated: 2026-08-25T20:46:17Z

| Server | Scenario | Supported | req/s | p50 ms | p95 ms | p99 ms | p999 ms | p99 TTFB ms | MB/s | CPU % | RSS MiB | Open FDs | Errors |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `tardigrade` | `static-large-http1` | yes | 7290 | 2.996 | 7.178 | 10.170 | 16.302 | - | 7295.67 | 132.17 | 6.45 | 40 | 1088 |
| `tardigrade` | `static-tiny-http1` | yes | 40840 | 0.650 | 2.265 | 5.219 | 353.445 | - | 26.13 | 232.80 | 5.80 | 41 | 6114 |
| `tardigrade` | `proxy-small-http1` | yes | 5712 | 5.309 | 8.546 | 10.842 | 16.667 | - | 3.17 | 156.33 | 6.40 | 74 | 0 |
| `tardigrade` | `static-tiny-keepalive` | yes | 40977 | 0.650 | 2.133 | 3.889 | 103.713 | - | 26.22 | 233.98 | 6.45 | 39 | 6143 |
| `tardigrade` | `proxy-large-http1` | yes | 1384 | 21.698 | 36.111 | 46.632 | 68.141 | - | 1385.66 | 171.57 | 6.54 | 73 | 0 |
| `tardigrade` | `proxy-slow-client-download` | yes | 0 | 15909.936 | 15921.053 | 15921.053 | 15921.053 | - | 4.00 | 0.31 | 6.54 | 13 | 0 |
| `tardigrade` | `idle-keepalive-active-traffic` | yes | 13550 | 0.3575935 | 1.28740425 | 2.7920672500000037 | 5.694037105000088 | - | 8.67 | 89.81 | 6.59 | 40 | 0 |
| `tardigrade` | `connection-churn-http1` | yes | 22987 | 1.044 | 2.689 | 4.128 | 6.852 | - | 14.60 | 180.36 | 6.57 | 39 | 0 |
| `tardigrade` | `static-small-http3` | unsupported: h2load on this host does not support HTTP/3 (no QUIC-enabled build). | - | - | - | - | - | - | - | - | - | - | - |
| `tardigrade` | `static-large-http3` | unsupported: h2load on this host does not support HTTP/3 (no QUIC-enabled build). | - | - | - | - | - | - | - | - | - | - | - |
| `tardigrade` | `proxy-large-http3` | unsupported: h2load on this host does not support HTTP/3 (no QUIC-enabled build). | - | - | - | - | - | - | - | - | - | - | - |
| `nginx` | `static-large-http1` | yes | 8145 | 2.495 | 6.659 | 13.571 | 62.239 | - | 8147.13 | 121.64 | 28.75 | 141 | 0 |
| `nginx` | `static-tiny-http1` | yes | 74596 | 0.305 | 2.225 | 4.985 | 30.373 | - | 16.93 | 214.58 | 27.80 | 95 | 0 |
| `nginx` | `proxy-small-http1` | yes | 9629 | 3.004 | 184.443 | 1172.602 | 1766.344 | - | 1.37 | 54.37 | 28.74 | 135 | 0 |
| `nginx` | `static-tiny-keepalive` | yes | 74540 | 0.308 | 2.222 | 5.673 | 117.664 | - | 16.92 | 215.01 | 28.75 | 142 | 0 |
| `nginx` | `proxy-large-http1` | yes | 1309 | 23.941 | 48.101 | 63.920 | 98.314 | - | 1310.04 | 205.51 | 29.05 | 138 | 0 |
| `nginx` | `proxy-slow-client-download` | yes | 0 | - | - | - | - | - | - | 0.38 | 29.34 | 90 | 4 |
| `nginx` | `idle-keepalive-active-traffic` | yes | 18588 | 0.207293 | 1.0716767499999975 | 2.4524473799999997 | 4.769364142000018 | - | 4.22 | 65.60 | 29.34 | 112 | 0 |
| `nginx` | `connection-churn-http1` | yes | 29292 | 0.600 | 2.514 | 4.702 | 12.102 | - | 6.51 | 153.27 | 29.34 | 114 | 0 |
| `haproxy` | `static-large-http1` | unsupported: HAProxy http-request return file responses must fit a response buffer; the 1 MiB static-file scenario is intentionally unsupported for this representative config. | - | - | - | - | - | - | - | - | - | - | - |
| `haproxy` | `static-tiny-http1` | yes | 137374 | 0.180 | 1.141 | 3.227 | 19.136 | - | 8.78 | 201.00 | 27.94 | 59 | 0 |
| `haproxy` | `proxy-small-http1` | yes | 9430 | 3.090 | 9.756 | 863.300 | 1266.797 | - | 1.25 | 70.11 | 28.10 | 90 | 0 |
| `haproxy` | `static-tiny-keepalive` | yes | 139175 | 0.163 | 1.391 | 14.117 | 147.189 | - | 8.89 | 202.53 | 28.10 | 90 | 0 |
| `haproxy` | `proxy-large-http1` | yes | 1948 | 15.360 | 30.491 | 210.850 | 961.748 | - | 1948.94 | 158.43 | 29.04 | 90 | 0 |
| `haproxy` | `proxy-slow-client-download` | yes | 0 | 15921.114 | 15975.415 | 15975.415 | 15975.415 | - | 4.00 | 0.19 | 29.04 | 62 | 0 |
| `haproxy` | `idle-keepalive-active-traffic` | yes | 22975 | 0.166166 | 0.8091523999999987 | 2.1206919599999976 | 4.2011841680000925 | - | 1.47 | 54.75 | 29.68 | 59 | 0 |
| `haproxy` | `connection-churn-http1` | yes | 34475 | 0.479 | 2.181 | 5.120 | 67.609 | - | 2.83 | 149.11 | 29.75 | 71 | 0 |
| `caddy` | `static-large-http1` | yes | 6990 | 3.180 | 8.470 | 12.577 | 20.016 | - | 6991.86 | 150.04 | 56.12 | 74 | 0 |
| `caddy` | `static-tiny-http1` | yes | 37840 | 0.673 | 7.097 | 12.554 | 21.313 | - | 8.95 | 269.71 | 55.05 | 43 | 0 |
| `caddy` | `proxy-small-http1` | yes | 6413 | 4.620 | 11.323 | 17.635 | 264.901 | - | 0.95 | 124.61 | 57.89 | 121 | 0 |
| `caddy` | `static-tiny-keepalive` | yes | 38062 | 0.665 | 7.217 | 12.590 | 21.249 | - | 9.00 | 269.73 | 55.61 | 73 | 0 |
| `caddy` | `proxy-large-http1` | yes | 1777 | 16.381 | 34.613 | 45.478 | 59.353 | - | 1778.24 | 167.64 | 55.96 | 71 | 0 |
| `caddy` | `proxy-slow-client-download` | yes | 0 | 15950.122 | 15950.563 | 15950.563 | 15950.563 | - | 4.00 | 0.31 | 55.15 | 42 | 0 |
| `caddy` | `idle-keepalive-active-traffic` | yes | 13526 | 0.358833 | 1.3515221999999993 | 2.835526879999991 | 5.3965691000001605 | - | 3.20 | 110.54 | 54.32 | 70 | 0 |
| `caddy` | `connection-churn-http1` | yes | 16500 | 1.543 | 4.746 | 7.509 | 13.213 | - | 4.20 | 208.65 | 55.45 | 71 | 0 |

## Upstream Pool Matrix

| Scenario | Covered | req/s | p99 ms | p99 TTFB ms | CPU % | CPU ms/req | RSS MiB | New conn/s | Reuse ratio | Lock wait ns/req | Sharding | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `uneven-route-distribution` | true | - | - | - | - | - | - | - | - | - | - | 0 |
| `many-origins-low-volume` | true | 120.120 | - | - | 4.33 | 0.3604728604728604 | 6.12 | 0 | 1 | - | - | 0 |
| `hot-origin-many-workers` | true | 8243.63 | 7.160 | 9.185759179999998 | 63.18 | 0.07664099431925014 | 6.04 | 0.19841269841269843 | 0.9999759049691985 | - | - | 0 |
| `upstream-tls-handshake-reuse` | true | 97.27 | 330.826 | 330.92033190999996 | 1.73 | 0.1778554538912306 | 8.89 | 0.2661698163428267 | 0.9973190348525469 | - | - | 0 |
| `pool-contention` | true | - | - | - | - | - | - | - | - | - | - | - |

### Upstream Pool Detail Rows

| Detail | req/s | p99 ms | p99 TTFB ms | CPU % | CPU ms/req | RSS MiB | Open FDs | New conn/s | Reuse ratio | Lock wait ns/req | Lock wait ns/acq | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `uneven/route-a-hot` | 8243.63 | 7.160 | 9.185759179999998 | 63.18 | 0.07664099431925014 | 6.04 | 56 | 0.19841269841269843 | 0.9999759049691985 | - | - | 0 |
| `uneven/route-b-warm` | 8078.22 | 1.558 | - | 66.49 | 0.08230773611018267 | 6.10 | 31 | 1.4858841010401187 | 0.9998143908927798 | - | - | 0 |
| `uneven/route-c-cold` | 6885.24 | 0.913 | - | 60.97 | 0.08855174256816031 | 6.12 | 30 | 0.8936550491510277 | 0.9998679344955098 | - | - | 0 |
| `origin/origin-0` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-1` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-2` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-3` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-4` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-5` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-6` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-7` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-8` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-9` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-10` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-11` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-12` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-13` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-14` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `origin/origin-15` | 7.5075075075075075 | - | - | - | - | - | - | - | - | - | - | 0 |
| `contention/1w` | 6693.87 | 8.133 | 10.657570999999999 | 39.65 | 0.05923329852536723 | 5.14 | 38 | 0.47192071731949026 | 0.9999289823165969 | 108.47828539199098 | 36.41530778879606 | 0 |
| `contention/2w` | 8064.30 | 6.250 | 10.436302090000002 | 57.35 | 0.07111590590627828 | 5.41 | 39 | 0.9442870632672333 | 0.9998820546087162 | 178.81768149882905 | 60.024094491283925 | 0 |
| `contention/4w` | 8578.14 | 6.022 | 9.204261359999999 | 63.48 | 0.07400205638984675 | 6.01 | 41 | 1.8885741265344667 | 0.9997782582183048 | 257.3907754967252 | 86.38968836015 | 0 |

> Use these numbers only for same-host relative comparisons. Dedicated idle hosts are required for canonical claims.
