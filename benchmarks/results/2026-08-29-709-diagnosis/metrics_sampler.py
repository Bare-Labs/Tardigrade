#!/usr/bin/env python3
"""Poll /status/metrics on a Tardigrade instance for the duration of a
benchmark pass and report worker active/queued peaks plus counter deltas
(accepts, upstream new/reused, worker queue-wait sum/count).

Usage: metrics_sampler.py --host H --port P --duration 15 --interval 0.1 [--json]
"""
import argparse
import json
import re
import time
import urllib.request

GAUGES = ["tardigrade_worker_active_jobs", "tardigrade_worker_queued_jobs"]
COUNTERS = [
    "tardigrade_accepts_total",
    "tardigrade_upstream_connections_new_total",
    "tardigrade_upstream_connections_reused_total",
    "tardigrade_worker_queue_wait_us_sum",
    "tardigrade_worker_queue_wait_us_count",
]


def scrape(host, port):
    url = f"http://{host}:{port}/status/metrics"
    with urllib.request.urlopen(url, timeout=3) as r:
        text = r.read().decode("utf-8", "replace")
    values = {}
    for name in GAUGES + COUNTERS:
        total = 0.0
        found = False
        for m in re.finditer(rf"^{re.escape(name)}(\{{[^}}]*\}})? +([0-9.eE+-]+)", text, re.MULTILINE):
            total += float(m.group(2))
            found = True
        values[name] = total if found else None
    return values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--interval", type=float, default=0.1)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    samples = []
    stop_at = time.monotonic() + args.duration
    first = None
    last = None
    max_gauges = {g: None for g in GAUGES}
    while time.monotonic() < stop_at:
        try:
            v = scrape(args.host, args.port)
            if first is None:
                first = v
            last = v
            for g in GAUGES:
                if v[g] is not None:
                    max_gauges[g] = v[g] if max_gauges[g] is None else max(max_gauges[g], v[g])
            samples.append(v)
        except Exception:
            pass
        time.sleep(args.interval)

    result = {
        "samples_collected": len(samples),
        "gauge_max": max_gauges,
        "counter_deltas": {},
    }
    if first and last:
        for c in COUNTERS:
            if first.get(c) is not None and last.get(c) is not None:
                result["counter_deltas"][c] = last[c] - first[c]
            else:
                result["counter_deltas"][c] = None
        result["counter_first"] = {c: first.get(c) for c in COUNTERS}
        result["counter_last"] = {c: last.get(c) for c in COUNTERS}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
