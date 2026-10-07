"""Evaluate the guardrails engine on the labeled dataset and benchmark latency.

Positive class = "block" (text that SHOULD be stopped).

    python eval/evaluate.py                       # report dev + test + all
    python eval/evaluate.py --split test --latency
    python eval/evaluate.py --split test --min-f1 0.85 --max-fpr 0.10   # CI quality gate

Writes eval/results.json. Uses only the standard library.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.guardrails import GuardrailsEngine  # noqa: E402
from tests.fakes import expand, make_fakes  # noqa: E402

DATASET = ROOT / "eval" / "dataset.jsonl"
RESULTS = ROOT / "eval" / "results.json"


def load(split: str) -> list[dict]:
    fakes = make_fakes()
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        r["text"] = expand(r["text"], fakes)
    return rows if split == "all" else [r for r in rows if r["split"] == split]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def evaluate(rows: list[dict], engine: GuardrailsEngine) -> dict:
    tp = fp = tn = fn = 0
    per_cat = defaultdict(lambda: {"n": 0, "caught": 0})
    misses, false_alarms = [], []
    for r in rows:
        pred = engine.check(r["text"]).decision
        gold = r["label"]
        if gold == "block":
            per_cat[r["category"]]["n"] += 1
            if pred == "block":
                tp += 1
                per_cat[r["category"]]["caught"] += 1
            else:
                fn += 1
                misses.append(r)
        else:
            if pred == "block":
                fp += 1
                false_alarms.append(r)
            else:
                tn += 1
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / n if n else 0.0,
        "false_positive_rate": fpr,
        "recall_ci95": wilson(tp, tp + fn),
        "fpr_ci95": wilson(fp, fp + tn),
        "per_category_recall": {c: {"caught": v["caught"], "n": v["n"],
                                    "recall": v["caught"] / v["n"] if v["n"] else 0.0}
                                for c, v in sorted(per_cat.items())},
        "misses": [{"category": m["category"], "text": m["text"][:90]} for m in misses],
        "false_alarms": [{"text": m["text"][:90]} for m in false_alarms],
    }


def benchmark(rows: list[dict], engine: GuardrailsEngine, passes: int = 50) -> dict:
    for r in rows:  # warm-up (regex caches, imports)
        engine.check(r["text"])
    samples = []
    t_start = time.perf_counter()
    for _ in range(passes):
        for r in rows:
            t0 = time.perf_counter_ns()
            engine.check(r["text"])
            samples.append((time.perf_counter_ns() - t0) / 1e6)
    wall = time.perf_counter() - t_start
    samples.sort()

    def q(p: float) -> float:
        return samples[min(len(samples) - 1, int(p * len(samples)))]

    return {
        "calls": len(samples),
        "mean_ms": statistics.fmean(samples),
        "p50_ms": q(0.50), "p95_ms": q(0.95), "p99_ms": q(0.99), "max_ms": samples[-1],
        "single_thread_checks_per_sec": len(samples) / wall,
        "avg_chars": statistics.fmean(len(r["text"]) for r in rows),
    }


def print_report(name: str, m: dict) -> None:
    lo, hi = m["recall_ci95"]
    flo, fhi = m["fpr_ci95"]
    print(f"\n=== {name} (n={m['n']}: {m['tp'] + m['fn']} should-block, {m['tn'] + m['fp']} should-allow) ===")
    print(f"TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print(f"Precision {pct(m['precision'])} | Recall {pct(m['recall'])} (95% CI {pct(lo)}-{pct(hi)}) | F1 {pct(m['f1'])}")
    print(f"Accuracy {pct(m['accuracy'])} | False-positive rate {pct(m['false_positive_rate'])} (95% CI {pct(flo)}-{pct(fhi)})")
    print("Recall by category: " + ", ".join(
        f"{c} {v['caught']}/{v['n']}" for c, v in m["per_category_recall"].items()))
    if m["misses"]:
        print("Missed (false negatives):")
        for x in m["misses"]:
            print(f"  - [{x['category']}] {x['text']!r}")
    if m["false_alarms"]:
        print("Wrongly blocked (false positives):")
        for x in m["false_alarms"]:
            print(f"  - {x['text']!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test", "all"], default=None,
                    help="evaluate one split (default: report dev, test and all)")
    ap.add_argument("--latency", action="store_true", help="also benchmark engine latency")
    ap.add_argument("--min-f1", type=float, default=None, help="exit 1 if F1 is below this (CI gate)")
    ap.add_argument("--max-fpr", type=float, default=None, help="exit 1 if false-positive rate is above this")
    args = ap.parse_args()

    engine = GuardrailsEngine()
    splits = [args.split] if args.split else ["dev", "test", "all"]
    results = {}
    for s in splits:
        results[s] = evaluate(load(s), engine)
        print_report(s, results[s])

    if args.latency:
        b = benchmark(load("all"), engine)
        results["latency"] = b
        print(f"\n=== Engine latency ({b['calls']} calls, avg {b['avg_chars']:.0f} chars/text, no HTTP) ===")
        print(f"mean {b['mean_ms']:.3f} ms | p50 {b['p50_ms']:.3f} | p95 {b['p95_ms']:.3f} | "
              f"p99 {b['p99_ms']:.3f} | max {b['max_ms']:.3f} ms")
        print(f"single-thread throughput: {b['single_thread_checks_per_sec']:.0f} checks/sec")

    RESULTS.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {RESULTS.relative_to(ROOT)}")

    gate_split = args.split or "test"
    rc = 0
    if args.min_f1 is not None and results[gate_split]["f1"] < args.min_f1:
        print(f"FAIL: F1 {results[gate_split]['f1']:.3f} < {args.min_f1}")
        rc = 1
    if args.max_fpr is not None and results[gate_split]["false_positive_rate"] > args.max_fpr:
        print(f"FAIL: FPR {results[gate_split]['false_positive_rate']:.3f} > {args.max_fpr}")
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
