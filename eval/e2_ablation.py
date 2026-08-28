"""
TraFiSec -- E2 Feature View Ablation Study (eval/e2_ablation.py)
================================================================
Evaluates leave-one-out feature view contributions across screener sub-vectors:
fits models on subsets (full and drop-1 view) on the same train/test split (seed 42)
and measures AUC-PR drops to quantify per-view importance.
"""
from __future__ import annotations

# Script entry points add the repository root before importing project modules.
# ruff: noqa: E402

import argparse
import csv
import sys
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402

from core.fusion import (LogisticFusion, calibrate_temperature,
                             fit_logistic_fusion)  # noqa: E402

from .e1_common import (_ensure_utf8, canonical_floats, metrics_at_thresholds,
                        select_fpr_thresholds)  # noqa: E402
from .e1_train import (SEED, build_dataset, fit_calibration_split,
                       train_test_split)  # noqa: E402

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
ABLATION_CSV_PATH = RESULTS_DIR / "e2_ablation.csv"

FULL_VIEWS = LogisticFusion.DEFAULT_VIEWS  # Verified execution property


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _view_matrix(ds: dict, hashes: list[str], views: tuple[str, ...]) -> np.ndarray:
    """(n, len(views)) matrix scores — view missing (None) → 0.0."""
    X = []
    for h in hashes:
        s = ds["scores"][h]
        X.append([float(s.get(v) or 0.0) for v in views])
    return np.array(X, dtype=float)


# ---------------------------------------------------------------------------
# Ablation: full + leave-one-out
# ---------------------------------------------------------------------------
def run_ablation(cache_path: Path, out_dir: Path = RESULTS_DIR,
                 budgets: tuple[float, ...] = (0.001, 0.01),
                 seed: int = SEED, write_files: bool = True) -> dict:
    """Fit model cho full + 4 leave-one-out configs → metrics + CSV.

    Identical train/test split across all configurations for fair ablation comparison.
    Tr dict {config: {metrics, n_test_attack, n_test_benign}} + full view_names.
    """
    ds = build_dataset(cache_path)
    split = train_test_split(ds, seed=seed)
    tr, te = split["train"], split["test"]

    # Execution trace analysis and verification
    configs: list[tuple[str, tuple[str, ...]]] = [("full", FULL_VIEWS)]
    for v in FULL_VIEWS:
        configs.append((f"no_{v}", tuple(x for x in FULL_VIEWS if x != v)))

    results: dict = {}
    csv_rows = []
    for name, views in configs:
        train_part = {"hashes": tr["hashes"],
                      "X": _view_matrix(ds, tr["hashes"], views),
                      "y": tr["y"]}
        fit, cal = fit_calibration_split(train_part, seed=seed)
        Xte = _view_matrix(ds, te["hashes"], views)
        model = fit_logistic_fusion(fit["X"], fit["y"], view_names=views, seed=seed)
        model = calibrate_temperature(model, cal["X"], cal["y"])
        thresholds = select_fpr_thresholds(
            cal["y"], model.predict(cal["X"]), budgets
        )
        scores_test = model.predict(Xte)
        m = metrics_at_thresholds(te["y"], scores_test, thresholds, budgets=budgets)
        results[name] = {
            "views": list(views),
            "auc_pr": m.get("auc_pr", 0.0),
            "accuracy": m.get("accuracy", 0.0),
            "metrics": m,
            "weights": {v: round(float(model.weights.get(v, 0.0)), 4)
                        for v in views},
            "offset": round(float(model.offset), 4),
            "thresholds": thresholds,
            "n_fit": len(fit["y"]),
            "n_calibration": len(cal["y"]),
        }
        for b in budgets:
            r = m.get(b) or {}
            csv_rows.append([name, "+".join(views),
                             int((te["y"] == 1).sum()), int((te["y"] == 0).sum()),
                             b, r.get("precision", ""), r.get("recall", ""),
                             r.get("f1", ""), m.get("auc_pr", ""),
                             r.get("threshold", ""), r.get("realized_fpr", ""),
                             r.get("fp", ""), r.get("tp", ""),
                             r.get("budget_satisfied_on_test", "")])

    # Execution trace analysis and verification
    full_ap = results["full"]["auc_pr"]
    for name in results:
        results[name]["delta_auc_pr"] = round(
            results[name]["auc_pr"] - full_ap, 6)

    out = {
        "seed": seed,
        "views": list(FULL_VIEWS),
        "n_train_attack": int((tr["y"] == 1).sum()),
        "n_train_benign": int((tr["y"] == 0).sum()),
        "n_test_attack": int((te["y"] == 1).sum()),
        "n_test_benign": int((te["y"] == 0).sum()),
        "n_hard": len(ds["hard_rows"]),
        "configs": results,
    }
    if write_files:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "e2_ablation.csv"
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["config", "views", "n_test_attack", "n_test_benign",
                        "fp_budget", "precision", "recall", "f1", "auc_pr",
                        "threshold", "realized_fpr", "fp", "tp",
                        "budget_satisfied_on_test"])
            w.writerows(canonical_floats(csv_rows))
        out["file"] = str(path)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_ablation(out: dict) -> None:
    print(f"== E2 ablation (seed {out['seed']}, views {out['views']}) ==")
    print(f"train: {out['n_train_attack']} attack + {out['n_train_benign']} benign"
          f"   |   test: {out['n_test_attack']} + {out['n_test_benign']}"
          f"   |   hard: {out['n_hard']}")
    full_ap = out["configs"]["full"]["auc_pr"]
    print(f"full AUC-PR = {full_ap:.4f}")
    print(f"{'config':<24} {'AUC-PR':>8} {'ΔAUC':>8}   weights")
    for name, c in out["configs"].items():
        w = " ".join(f"{v}:{c['weights'].get(v, 0):.2f}" for v in c["views"])
        print(f"{name:<24} {c['auc_pr']:>8.4f} {c['delta_auc_pr']:>+8.4f}   {w}")
    print("\nAblation ranking (AUC-PR drop when omitting view -- larger drop indicates higher importance):")
    ranked = sorted(out["configs"].items(), key=lambda kv: kv[1]["delta_auc_pr"])
    for name, c in ranked:
        if name == "full":
            continue
        print(f"  drop {name[3:]:<18} ΔAUC-PR={c['delta_auc_pr']:+.4f}")
    if out.get("file"):
        print(f"csv      : {out['file']}")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(
        description="E2: Ablation study of feature view contributions")
    p.add_argument("--cache", default=None,
                   help="Path to trace cache JSONL file")
    p.add_argument("--out-dir", default=None)
    p.add_argument("--budgets", default="0.001,0.01")
    p.add_argument("--seed", type=int, default=SEED, help="Deterministic random seed (default: 42)")
    p.add_argument("--dry", action="store_true", help="Dry run without writing output files")
    args = p.parse_args(argv)

    from .e1_crawl import CACHE_PATH
    cache_path = Path(args.cache) if args.cache else CACHE_PATH
    budgets = tuple(float(x) for x in args.budgets.split(",") if x.strip())
    out_dir = Path(args.out_dir) if args.out_dir else RESULTS_DIR
    out = run_ablation(cache_path, out_dir=out_dir, budgets=budgets,
                       seed=args.seed, write_files=not args.dry)
    _print_ablation(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
