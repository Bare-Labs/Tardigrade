#!/usr/bin/env python3
"""Minimal HTTP/1.1 keep-alive-aware load generator, written for the #709
diagnosis (benchmarks/results/*-709-diagnosis/). Local to that diagnosis --
not a general wrk replacement or a second supported benchmark harness.

wrk was unavailable on the Mac client used for that diagnosis (blocked from
opening outbound sockets by a host network policy; plain curl/python HTTP
clients worked fine on the same host). This script filled the same narrow
role for a matched-instrument comparison, with one deliberate addition over
wrk: each worker keeps a persistent http.client.HTTPConnection and
explicitly counts how many times it had to open a *new* TCP connection
because the server (or a transport error) ended the previous one -- direct
downstream-connection-churn evidence, not an inference from throughput
deltas -- and keeps a bounded sample of the raw {stage, type, errno,
message} for every error, not just an aggregate class count.

Usage: loadgen.py --host H --port P --path /proxy/health --duration 15
                   --connections 32 [--close] [--json]
"""
import argparse
import http.client
import json
import threading
import time

MAX_ERROR_SAMPLES = 50


def describe_error(stage, e):
    return {
        "stage": stage,
        "type": type(e).__name__,
        "errno": getattr(e, "errno", None),
        "message": str(e),
    }


def worker(host, port, path, duration, close_header, stats, lock, stop_at):
    conn = None
    requests_done = 0
    reconnects = 0
    errors = {}
    error_samples = []
    latencies = []
    connection_header_seen = {}

    def record_error(stage, e):
        key = f"{stage}:{type(e).__name__}"
        errors[key] = errors.get(key, 0) + 1
        with lock:
            if len(error_samples) < MAX_ERROR_SAMPLES:
                error_samples.append(describe_error(stage, e))

    def open_conn():
        nonlocal conn
        c = http.client.HTTPConnection(host, port, timeout=5)
        c.connect()
        conn = c

    try:
        open_conn()
    except Exception as e:
        record_error("connect", e)
        stats.append((requests_done, reconnects, errors, error_samples, latencies, connection_header_seen))
        return

    while time.monotonic() < stop_at:
        t0 = time.monotonic()
        try:
            headers = {"Connection": "close"} if close_header else {}
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            resp.read()
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
                    record_error("reconnect", e)
                    break
        except Exception as e:
            record_error("request", e)
            try:
                conn.close()
            except Exception:
                pass
            reconnects += 1
            try:
                open_conn()
            except Exception as e2:
                record_error("reconnect", e2)
                break

    stats.append((requests_done, reconnects, errors, error_samples, latencies, connection_header_seen))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/proxy/health")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--connections", type=int, default=32)
    ap.add_argument("--close", action="store_true", help="client sends Connection: close on every request")
    ap.add_argument("--label", default="", help="free-form label recorded in _meta for this artifact")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    stats = []
    lock = threading.Lock()
    stop_at = time.monotonic() + args.duration
    threads = []
    start = time.monotonic()
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
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
        all_latencies.extend(s[4])
    all_errors = {}
    for s in stats:
        for k, v in s[2].items():
            all_errors[k] = all_errors.get(k, 0) + v
    all_error_samples = []
    for s in stats:
        all_error_samples.extend(s[3])
    all_error_samples = all_error_samples[:MAX_ERROR_SAMPLES]
    conn_headers = {}
    for s in stats:
        for k, v in s[5].items():
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
        "error_samples": all_error_samples,
        "response_connection_header_counts": conn_headers,
        "connections": args.connections,
        "duration_requested_s": args.duration,
        "_meta": {
            "tool": "benchmarks/loadgen.py",
            "label": args.label,
            "host": args.host,
            "port": args.port,
            "path": args.path,
            "client_sends_connection_close": args.close,
            "started_at": start_wall,
        },
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
