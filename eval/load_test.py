"""HTTP load test against a RUNNING service (requires `pip install requests`).

    export API_KEY=...            # same key the service uses
    python eval/load_test.py --url http://localhost:8000 --requests 2000 --concurrency 16

Replays texts from eval/dataset.jsonl against /v1/check/prompt and reports
client-side latency percentiles, throughput and error rate.
"""
import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.fakes import expand, make_fakes  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--requests", type=int, default=2000)
    ap.add_argument("--concurrency", type=int, default=16)
    args = ap.parse_args()

    fakes = make_fakes()
    rows = [json.loads(l) for l in (ROOT / "eval" / "dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    texts = [expand(r["text"], fakes) for r in rows]
    headers = {"X-API-Key": os.environ.get("API_KEY", "")}
    session_local = requests.Session()

    def one(i: int):
        t0 = time.perf_counter()
        try:
            r = session_local.post(f"{args.url}/v1/check/prompt", json={"text": texts[i % len(texts)]},
                                   headers=headers, timeout=10)
            return (time.perf_counter() - t0) * 1000, r.status_code
        except requests.RequestException:
            return (time.perf_counter() - t0) * 1000, 0

    for i in range(50):  # warm-up
        one(i)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        out = list(pool.map(one, range(args.requests)))
    wall = time.perf_counter() - t0

    lat = sorted(x[0] for x in out)
    errors = sum(1 for _, code in out if code != 200)
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
    print(f"requests={len(out)} concurrency={args.concurrency} wall={wall:.2f}s")
    print(f"throughput: {len(out) / wall:.0f} req/s | errors: {errors} ({100 * errors / len(out):.2f}%)")
    print(f"latency ms: mean {statistics.fmean(lat):.2f} | p50 {q(.5):.2f} | p95 {q(.95):.2f} | p99 {q(.99):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
