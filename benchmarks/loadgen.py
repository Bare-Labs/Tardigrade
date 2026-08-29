#!/usr/bin/env python3
"""Minimal HTTP/1.1 keep-alive-aware load generator, written for #709.

A dependency-free fallback for environments where wrk (or another native
load-testing binary) isn't available or is blocked from opening outbound
sockets by a host network policy -- only curl/python-level HTTP clients are
guaranteed to work in that case. It also does one thing wrk doesn't: each
worker keeps a persistent http.client.HTTPConnection and explicitly counts
how many times it had to open a *new* TCP connection because the server (or
a transport error) ended the previous one -- direct downstream-connection-
churn evidence, not an inference from throughput deltas.

Usage: loadgen.py --host H --port P --path /proxy/health --duration 15
                   --connections 32 [--close] [--json]
"""
import argparse
import http.client
import json
import threading
import time


def worker(host, port, path, duration, close_header, stats, lock, stop_at):
    conn = None
    requests_done = 0
    reconnects = 0
    errors = {}
    latencies = []
    connection_header_seen = {}

    def open_conn():
        nonlocal conn
        c = http.client.HTTPConnection(host, port, timeout=5)
        c.connect()
        conn = c

    try:
        open_conn()
    except Exception as e:
        with lock:
            errors[f"connect:{type(e).__name__}"] = errors.get(f"connect:{type(e).__name__}", 0) + 1
        stats.append((requests_done, reconnects, errors, latencies, connection_header_seen))
        return

    while time.monotonic() < stop_at:
        t0 = time.monotonic()
        try:
            headers = {"Connection": "close"} if close_header else {}
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            t1 = time.monotonic()
            latencies.append((t1 - t0) * 1000.0)
            requests_done += 1
            ch = (resp.getheader("Connection") or "").lower()
            connection_header_seen[ch] = connection_header_seen.get(ch, 0) + 1
            if resp.status >= 400:
                errors[f"http:{resp.status}"] = errors.get(f"http:{resp.status}", 0) + 1
            if ch == "close" or close_header:
                conn.close()
                reconnects += 1
                try:
                    open_conn()
                except Exception as e:
                    errors[f"reconnect:{type(e).__name__}"] = errors.get(f"reconnect:{type(e).__name__}", 0) + 1
                    break
        except Exception as e:
            errors[f"request:{type(e).__name__}"] = errors.get(f"request:{type(e).__name__}", 0) + 1
            try:
                conn.close()
            except Exception:
                pass
            reconnects += 1
            try:
                open_conn()
            except Exception as e2:
                errors[f"reconnect:{type(e2).__name__}"] = errors.get(f"reconnect:{type(e2).__name__}", 0) + 1
                break

    stats.append((requests_done, reconnects, errors, latencies, connection_header_seen))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/proxy/health")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--connections", type=int, default=32)
    ap.add_argument("--close", action="store_true", help="client sends Connection: close on every request")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    stats = []
    lock = threading.Lock()
    stop_at = time.monotonic() + args.duration
    threads = []
    start = time.monotonic()
    for _ in range(args.connections):
        th = threading.Thread(target=worker, args=(args.host, args.port, args.path, args.duration, args.close, stats, lock, stop_at))
        th.start()
        threads.append(th)
    for th in threads:
        th.join()
    elapsed = time.monotonic() - start

    total_requests = sum(s[0] for s in stats)
    total_reconnects = sum(s[1] for s in stats)
    all_latencies = []
    for s in stats:
        all_latencies.extend(s[3])
    all_errors = {}
    for s in stats:
        for k, v in s[2].items():
            all_errors[k] = all_errors.get(k, 0) + v
    conn_headers = {}
    for s in stats:
        for k, v in s[4].items():
            conn_headers[k] = conn_headers.get(k, 0) + v

    all_latencies.sort()

    def pct(p):
        if not all_latencies:
            return None
        idx = min(len(all_latencies) - 1, int(len(all_latencies) * p / 100.0))
        return round(all_latencies[idx], 3)

    result = {
        "requests": total_requests,
        "rps": round(total_requests / elapsed, 2) if elapsed > 0 else 0,
        "elapsed_s": round(elapsed, 3),
        "reconnects": total_reconnects,
        "reconnects_per_sec": round(total_reconnects / elapsed, 2) if elapsed > 0 else 0,
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
        "errors_total": sum(all_errors.values()),
        "errors_by_class": all_errors,
        "response_connection_header_counts": conn_headers,
        "connections": args.connections,
        "duration_requested_s": args.duration,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
