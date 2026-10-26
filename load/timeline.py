"""Per-interval timeline of a k6 run (load/README.md): sign-in attempts by status and their latency, renewals.

python3 load/timeline.py results/run.k6.csv.gz [--bucket 10]
"""

import argparse
import csv
import gzip
import statistics
from collections import defaultdict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--bucket", type=int, default=10)
    args = parser.parse_args()
    rows: dict[int, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    start = None
    with gzip.open(args.path, "rt") as f:
        for r in csv.DictReader(f):
            if r["metric_name"] != "http_req_duration":
                continue
            t = int(r["timestamp"])
            start = t if start is None else min(start, t)
            name, status = r.get("name", ""), r.get("status", "")
            key = {"POST /auth/login": f"login {status}", "POST /auth/session/token": f"renew {status}"}.get(name)
            if key:
                rows[t][key].append(float(r["metric_value"]))
    if start is None:
        print("no requests")
        return
    buckets: dict[int, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for t, series in rows.items():
        for key, values in series.items():
            buckets[(t - start) // args.bucket][key].extend(values)
    keys = sorted({k for b in buckets.values() for k in b})
    print("t(s)  " + "  ".join(f"{k:>22}" for k in keys))
    for b in sorted(buckets):
        cells = []
        for k in keys:
            v = buckets[b].get(k, [])
            cells.append(f"{len(v):>5} x {statistics.median(v):>7.0f}ms med" if v else f"{'':>22}")
        print(f"{b * args.bucket:>4}  " + "  ".join(cells))


if __name__ == "__main__":
    main()
