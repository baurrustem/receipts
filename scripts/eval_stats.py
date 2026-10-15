#!/usr/bin/env python3
"""Summarise with-skill vs without-skill eval runs.

Input: JSONL, one run per line (extra keys are ignored):
  {"case": "basic-001", "arm": "with", "success": true}
  {"case": "basic-001", "arm": "without", "success": false}

Output: runs and successes per arm, success rates, delta (with - without) and a 95% confidence
interval for the delta. The interval is Newcombe's hybrid score interval (method 10 in
Newcombe 1998), built from the Wilson score interval of each arm. `exploratory` is true when
either arm has fewer than --min-n runs (default 20): such numbers stay out of public claims.

Usage:
  python3 scripts/eval_stats.py evals/<skill>/runs/results.jsonl [more.jsonl ...] [--json]
  cat results.jsonl | python3 scripts/eval_stats.py - --json

Exit codes: 0 = summary printed, 2 = bad input. Stdlib only (Python 3.9+).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from statistics import NormalDist
from typing import Any, Iterable

ARMS = ("with", "without")
CONFIDENCE = 0.95
Z95 = NormalDist().inv_cdf(1 - (1 - CONFIDENCE) / 2)  # 1.959963984540054
MIN_N_PER_ARM = 20
METHOD = "Newcombe hybrid score interval (method 10) from Wilson score intervals"


class InputError(ValueError):
    pass


def wilson_interval(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a single proportion."""
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= successes <= n:
        raise ValueError("successes must be between 0 and n")
    p = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, center - half), min(1.0, center + half)


def newcombe_interval(x1: int, n1: int, x2: int, n2: int, z: float = Z95) -> tuple[float, float]:
    """CI for p1 - p2 (Newcombe 1998, method 10: hybrid score, no continuity correction)."""
    p1, p2 = x1 / n1, x2 / n2
    l1, u1 = wilson_interval(x1, n1, z)
    l2, u2 = wilson_interval(x2, n2, z)
    d = p1 - p2
    lower = d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    upper = d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return max(-1.0, lower), min(1.0, upper)


def parse_runs(lines: Iterable[str], source: str = "<input>") -> list[dict[str, Any]]:
    runs = []
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        where = f"{source}:{lineno}"
        try:
            rec = json.loads(line)
        except ValueError as e:
            raise InputError(f"{where}: invalid JSON ({e})") from None
        if not isinstance(rec, dict):
            raise InputError(f"{where}: each line must be a JSON object")
        arm = rec.get("arm")
        if arm not in ARMS:
            raise InputError(f"{where}: 'arm' must be \"with\" or \"without\", got {arm!r}")
        success = rec.get("success")
        if isinstance(success, bool):
            pass
        elif isinstance(success, int) and success in (0, 1):
            success = bool(success)
        else:
            raise InputError(f"{where}: 'success' must be true or false, got {success!r}")
        case = rec.get("case")
        if case is None or (isinstance(case, str) and not case.strip()) or not isinstance(case, (str, int)):
            raise InputError(f"{where}: 'case' must be a non-empty string")
        runs.append({"case": str(case), "arm": arm, "success": success})
    return runs


def load_runs(paths: list[str]) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for p in paths:
        if p == "-":
            runs += parse_runs(sys.stdin, "<stdin>")
        else:
            with open(p, encoding="utf-8") as fh:
                runs += parse_runs(fh, str(Path(p)))
    return runs


def summarize(runs: list[dict[str, Any]], min_n: int = MIN_N_PER_ARM) -> dict[str, Any]:
    n = {a: 0 for a in ARMS}
    x = {a: 0 for a in ARMS}
    cases: dict[str, set[str]] = {a: set() for a in ARMS}
    for r in runs:
        n[r["arm"]] += 1
        x[r["arm"]] += 1 if r["success"] else 0
        cases[r["arm"]].add(r["case"])
    for a in ARMS:
        if n[a] == 0:
            raise InputError(f"no runs for arm '{a}'")
    p = {a: x[a] / n[a] for a in ARMS}
    lo, hi = newcombe_interval(x["with"], n["with"], x["without"], n["without"])
    n_per_arm = min(n.values())
    warnings = []
    only_with = sorted(cases["with"] - cases["without"])
    only_without = sorted(cases["without"] - cases["with"])
    if only_with:
        warnings.append(f"cases only in the 'with' arm: {', '.join(only_with)}")
    if only_without:
        warnings.append(f"cases only in the 'without' arm: {', '.join(only_without)}")
    exploratory = n_per_arm < min_n
    if exploratory:
        warnings.append(f"exploratory: fewer than {min_n} runs per arm; keep these numbers out of public claims")
    return {
        "n": dict(n),
        "successes": dict(x),
        "cases": {a: len(cases[a]) for a in ARMS},
        "n_per_arm": n_per_arm,
        "with": round(p["with"], 4),
        "without": round(p["without"], 4),
        "delta": round(p["with"] - p["without"], 4),
        "ci95": [round(lo, 4), round(hi, 4)],
        "wilson95": {a: [round(v, 4) for v in wilson_interval(x[a], n[a])] for a in ARMS},
        "method": METHOD,
        "min_n_per_arm": min_n,
        "exploratory": exploratory,
        "warnings": warnings,
    }


def format_text(s: dict[str, Any]) -> str:
    rows = [f"{'arm':<8} {'runs':>5} {'pass':>5} {'rate':>7}   Wilson 95% CI"]
    for a in ARMS:
        lo, hi = s["wilson95"][a]
        rows.append(f"{a:<8} {s['n'][a]:>5} {s['successes'][a]:>5} {s[a]:>7.3f}   [{lo:.3f}, {hi:.3f}]")
    lo, hi = s["ci95"]
    rows.append(f"delta (with - without) = {s['delta']:+.3f}   95% CI [{lo:+.3f}, {hi:+.3f}]")
    rows.append(f"method: {s['method']}")
    rows.append(f"n per arm: {s['n_per_arm']}   exploratory: {'yes' if s['exploratory'] else 'no'}")
    rows.extend(f"warning: {w}" for w in s["warnings"])
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="With-skill vs without-skill eval statistics.")
    ap.add_argument("files", nargs="+", help="JSONL files of runs ('-' for stdin)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--min-n", type=int, default=MIN_N_PER_ARM, help="runs per arm below which results are exploratory")
    args = ap.parse_args(argv)
    try:
        summary = summarize(load_runs(args.files), min_n=args.min_n)
    except (InputError, OSError) as e:
        print(f"eval_stats: {e}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2) if args.json else format_text(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
