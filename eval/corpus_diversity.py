"""
TraFiSec — descriptive corpus diversity (eval/corpus_diversity.py)
====================================================================================
Phn tch 80 incidents (corpus/incidents.jsonl) theo:
  * attack_type          — phn b loi tn cng (8 classes, guide.md)
  * chain                — mainnet/arbitrum (E4 replay ch ethereum)
  * year                 — block → nm (xc nhn 2021–2026 ph u)
  * gt_factors           — tn sut factor (f_fl/f_orc/f_swap/f_auth) Stage 2 dng
  * screener coverage: mean score across the 4 views per attack type.
                            screener (from offline crawled cache - no RPC) -> identify category
                            evaluates feature visibility for Stage 2 triage across categories.

Output: eval/results/corpus_diversity.csv and formatted summary table.

Describes corpus coverage; this is not a numbered experiment or generalization test.
khng, loi no screener gn nh m (→ limitation / cn thm case).

CLI:
  python -m eval.corpus_diversity                      # Verified execution property
  python -m eval.corpus_diversity --corpus <p> --cache <p> --dry
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from .e1_common import _ensure_utf8  # noqa: E402
from .e1_train import build_dataset  # noqa: E402

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
CORPUS_CSV_PATH = RESULTS_DIR / "corpus_diversity.csv"
CORPUS_DEFAULT = _REPO_ROOT / "corpus" / "incidents.jsonl"

# Execution trace analysis and verification
FACTOR_NAMES = {"f_fl": "flash-loan", "f_orc": "oracle", "f_swap": "swap",
                "f_auth": "auth"}


def load_corpus(path: Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(r)
    return out


def _year_of_date(date: str | None) -> int | None:
    """'YYYY-MM-DD' → nm; None nu thiu."""
    if not isinstance(date, str) or len(date) < 4:
        return None
    try:
        return int(date[:4])
    except ValueError:
        return None


def analyze(corpus_path: Path, cache_path: Path,
            write_files: bool = True) -> dict:
    incidents = load_corpus(corpus_path)
    # Execution trace analysis and verification
    evalset = [inc for inc in incidents
               if inc.get("chain") == "ethereum"
               and inc.get("verified") == "onchain"]
    # cache: tx_hash → screener view scores (attack rows)
    ds = build_dataset(cache_path)
    scores = ds["scores"]
    atk_type: Counter = Counter()
    chain: Counter = Counter()
    year: Counter = Counter()
    factors: Counter = Counter()
    per_type_scores: dict[str, list[float]] = {}
    per_type_cov: dict[str, list[dict]] = {}

    for inc in evalset:
        atk_type[inc.get("attack_type", "other")] += 1
        chain[inc.get("chain", "?")] += 1
        y = _year_of_date(inc.get("date"))
        year[str(y) if y else "unknown"] += 1
        for f in (inc.get("gt_factors") or ["unknown"]):
            factors[f] += 1

        t = inc.get("attack_type", "other")
        per_type_scores.setdefault(t, [])
        # Execution trace analysis and verification
        h = (inc.get("tx_hashes") or [None])[0]
        s = scores.get(h)
        if s:
            per_type_scores[t].append(
                (s.get("call_structure") or 0) + (s.get("token_flow") or 0)
                + (s.get("economic") or 0))
            per_type_cov.setdefault(t, []).append(
                {v: (s.get(v) is not None) for v in
                 ("call_structure", "token_flow", "state_delta", "economic")})

    # Execution trace analysis and verification
    type_stats = {}
    for t, vals in sorted(per_type_scores.items()):
        n = len(vals)
        if n == 0:
            type_stats[t] = {"n_cached": 0}
            continue
        cov = {v: sum(1 for d in per_type_cov[t] if d[v]) / n
               for v in ("call_structure", "token_flow", "state_delta", "economic")}
        type_stats[t] = {"n_cached": n,
                         "mean_3view": round(sum(vals) / n, 3),
                         "coverage": {k: round(v, 2) for k, v in cov.items()}}

    out = {
        "n_corpus": len(incidents), "n_evalset": len(evalset),
        "attack_type": dict(atk_type),
        "chain": dict(chain),
        "year": dict(sorted(year.items(), key=lambda kv: str(kv[0]))),
        "factors": dict(factors),
        "type_stats": type_stats,
    }
    if write_files:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path = RESULTS_DIR / "corpus_diversity.csv"
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["group", "item", "count"])
            for k, v in sorted(atk_type.items()):
                w.writerow(["attack_type", k, v])
            for k, v in sorted(chain.items()):
                w.writerow(["chain", k, v])
            for k, v in sorted(year.items()):
                w.writerow(["year", k, v])
            for k, v in sorted(factors.items()):
                w.writerow(["factor", k, v])
        out["file"] = str(path)
    return out


def _print(out: dict) -> None:
    print(f"== Descriptive corpus diversity (corpus {out['n_corpus']}, "
          f"eval set {out['n_evalset']} ethereum/onchain) ==")
    print(f"attack_type: {dict(sorted(out['attack_type'].items()))}")
    print(f"chain      : {out['chain']}")
    print(f"year       : {out['year']}")
    print(f"gt_factors : {dict(sorted(out['factors'].items()))}")
    print("\nScreener coverage theo attack_type (mean 3-view sum, c cache):")
    print(f"  {'type':<18} {'n_cached':>8} {'mean_3v':>8}   coverage cs/tf/sd/ec")
    for t, st in sorted(out["type_stats"].items()):
        if "mean_3view" not in st:
            continue
        c = st["coverage"]
        print(f"  {t:<18} {st['n_cached']:>8} {st['mean_3view']:>8.3f}   "
              f"{c['call_structure']}/{c['token_flow']}/{c['state_delta']}/{c['economic']}")
    n_cached = sum(st.get("n_cached", 0) for st in out["type_stats"].values())
    print(f"\ncached attacks: {n_cached}/{out['n_evalset']}")
    if out.get("file"):
        print(f"csv      : {out['file']}")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Descriptive corpus diversity")
    p.add_argument("--corpus", default=None)
    p.add_argument("--cache", default=None)
    p.add_argument("--dry", action="store_true")
    args = p.parse_args(argv)

    from .e1_crawl import CACHE_PATH
    corpus_path = Path(args.corpus) if args.corpus else CORPUS_DEFAULT
    cache_path = Path(args.cache) if args.cache else CACHE_PATH
    out = analyze(corpus_path, cache_path, write_files=not args.dry)
    _print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
