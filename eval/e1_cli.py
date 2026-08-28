"""
TraFiSec — E1 CLI orchestrator (eval/e1_cli.py)
=======================================================
Orchestrates full E1 screening pipeline (C1: screener vs baseline precision/recall):

  crawl    → e1_crawl (attack set t corpus onchain)
  benign   → e1_benign (benign set deterministic seed 42)
  train    → e1_train (split 80/20 stratify, fit fusion, metrics)
  baselines→ e1_baselines (rule/invariant/static trn cng test set)
  report   → in summary p (so snh screener vs baselines @FP-budget)

Default pipeline steps: crawl, benign, train, baselines.
Each module can also be executed independently via its respective CLI.

CLI:
  python -m eval.e1_cli --scale A3 --steps benign train baselines   # nhanh
  python -m eval.e1_cli --scale A2 --resume                         # full
  python -m eval.e1_cli --scale A1                                  # Verified execution property

Security: RPC key loaded strictly from .env; read-only - never sends mainnet transactions.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.env import load_dotenv  # noqa: E402

from .e1_common import _ensure_utf8  # noqa: E402
from .e1_crawl import SCALES, main as crawl_main  # noqa: E402
from .e1_benign import main as benign_main  # noqa: E402
from .e1_train import main as train_main  # noqa: E402
from .e1_baselines import main as baselines_main  # noqa: E402

ALL_STEPS = ("crawl", "benign", "train", "baselines", "report")

# Execution trace analysis and verification
_STEPS_NO_RPC = ("train", "baselines", "report")


def _print_report() -> None:
    """So snh screener vs baselines @FP-budget t cc file E1 (C1 evidence)."""
    _ensure_utf8()
    import csv
    from collections import defaultdict

    print("\n== E1 report (C1: screener vs baselines, FP-budget) ==")
    main_csv = _REPO_ROOT / "eval" / "results" / "e1_main.csv"
    base_csv = _REPO_ROOT / "eval" / "results" / "e1_baselines.csv"
    if not main_csv.exists():
        print("  e1_main.csv not found - execute `--steps train` first.")
        return

    rows: dict[str, list[dict]] = defaultdict(list)
    for path in (main_csv, base_csv):
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r.get("fp_budget"):
                    rows[r["fp_budget"]].append({
                        "name": r.get("baseline") or "screener",
                        "precision": float(r.get("precision") or 0),
                        "recall": float(r.get("recall") or 0),
                        "f1": float(r.get("f1") or 0),
                        "auc_pr": float(r.get("auc_pr") or 0),
                        "n_test": r.get("n_test", ""),
                        "scale": r.get("scale", ""),
                    })
    if not rows:
        print("  cha c d liu metrics.")
        return
    for b in sorted(rows, key=float):
        print(f"  FP-budget {float(b):.1%}:")
        for r in sorted(rows[b], key=lambda x: -x["precision"]):
            tag = r["name"]
            note = f" (n_test={r['n_test']}, scale={r['scale']})" if tag == "screener" else ""
            print(f"    {tag:<22} P={r['precision']:.4f} R={r['recall']:.4f} "
                  f"F1={r['f1']:.4f}  AUC-PR={r['auc_pr']:.4f}{note}")
    print("  NOTE: DeFiScope/TraceLLM (LLM-based) baseline DEFERRED — LLM API cost.")
    print("  (paper s nu FP-budget + benign set + raw counts, khng phng i.)")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    load_dotenv()
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(
        description="E1 orchestrator: crawl attack → benign → train → baselines → report")
    p.add_argument("--scale", choices=sorted(SCALES), default="A2",
                   help="scale E1 — A1 150K / A2 15K / A3 5K tx budget")
    p.add_argument("--steps", nargs="+", default=["crawl", "benign", "train",
                                                   "baselines"],
                   help="cc step chy: crawl benign train baselines report "
                        "(mc nh: crawl benign train baselines)")
    p.add_argument("--resume", action="store_true",
                   help="b qua tx  cache thnh cng (crawl/benign)")
    p.add_argument("--workers", type=int, default=4, help="thread crawl")
    p.add_argument("--rpc", default=None, help="archive RPC (mc nh .env)")
    p.add_argument("--dry", action="store_true", help="Print execution plan without running steps")
    args = p.parse_args(argv)

    steps = [s for s in args.steps if s in ALL_STEPS]
    if not steps:
        print("ERROR: --steps contains no valid steps.", file=sys.stderr)
        return 1
    if any(s not in _STEPS_NO_RPC for s in steps):
        # Execution trace analysis and verification
        print("NOTE: step crawl/benign cn ARCHIVE_RPC trong .env (hoc --rpc).")

    print(f"== E1 orchestrator: scale {args.scale} ({SCALES[args.scale]:,} tx budget) "
          f"| steps: {' → '.join(steps)} | resume={args.resume} ==")
    if args.dry:
        print("DRY run - no steps executed.")
        return 0

    rc = 0
    for step in steps:
        print(f"\n### STEP {step} ###")
        if step == "crawl":
            rc = crawl_main(["--scale", args.scale, "--workers", str(args.workers)] +
                            (["--resume"] if args.resume else []) +
                            (["--rpc", args.rpc] if args.rpc else []))
        elif step == "benign":
            rc = benign_main(["--scale", args.scale, "--workers", str(args.workers)] +
                             (["--resume"] if args.resume else []) +
                             (["--rpc", args.rpc] if args.rpc else []))
        elif step == "train":
            rc = train_main(["--budgets", "0.001,0.01",
                             "--scale", args.scale])
        elif step == "baselines":
            rc = baselines_main(["--budgets", "0.001,0.01",
                                 "--scale", args.scale])
        elif step == "report":
            _print_report()
            rc = 0
        if rc != 0:
            print(f"ERROR: step {step} exited with code {rc} - stopping orchestrator.", file=sys.stderr)
            return rc

    print("\n== E1 done. Files ==")
    for f in ("e1_trace_cache.jsonl", "e1_crawl_progress.csv",
              "e1_model.json", "e1_main.csv", "e1_baselines.csv"):
        path = _REPO_ROOT / "eval" / "results" / f
        print(f"  {f:<28} {'OK' if path.exists() else '—'} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
