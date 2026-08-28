"""
TraFiSec — E1 training + metrics (eval/e1_train.py)
===========================================================
Train/test split (stratify theo attack_type, 80/20, seed 42) trn cache
(eval/results/e1_trace_cache.jsonl), fit logistic fusion trn 4-view scores
(src/core/fusion.py fit_logistic_fusion), calibrate temperature (ECE), lu
model eval/results/e1_model.json, ghi eval/results/e1_main.csv (1 dng/FP-budget).

Metrics (guide.md E1): Precision@FP-budget (0.1%, 1%), Recall@budget, F1@budget,
AUC-PR, accuracy — o trn TEST set (khng fit trn test).

nh ngha test set: (a) 20% attack tx stratified theo attack_type,
(b) 20% benign tx (seed 42) — benign ly t cache (label 'benign', status ok).
Hard-negatives are NOT included in training (used exclusively in holdout evaluation E3).
reported separately under hard-negative stress testing).

CLI:
  python -m eval.e1_train                       # Verified execution property
  python -m eval.e1_train --cache <path> --out-dir <dir> --budgets 0.001,0.01
  python -m eval.e1_train --dry                  # Verified execution property

Deterministic: seed 42 fixed; all outputs reproducible from cache.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402

from core.fusion import (  # noqa: E402
    LogisticFusion,
    calibrate_temperature,
    expected_calibration_error,
    fit_logistic_fusion,
)
from core.views import evaluate_all  # noqa: E402

from .e1_common import (  # noqa: E402
    _ensure_utf8,
    _sha256_id,
    canonical_floats,
    load_cache_rows,
    metrics_at_thresholds,
    select_fpr_thresholds,
    trace_from_cache,
)
from .run_manifest import utc_run_id, write_manifest  # noqa: E402

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
MODEL_PATH = RESULTS_DIR / "e1_model.json"
MAIN_CSV_PATH = RESULTS_DIR / "e1_main.csv"
SEED = 42
TEST_FRAC = 0.20
VIEWS = LogisticFusion.DEFAULT_VIEWS  # Verified execution property


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def build_dataset(cache_path: Path) -> dict:
    """Cache → dataset: {rows, scores dict, y, labels, attack_type per row}.

    Mi row: trace_from_cache (input  trim — view_economic ch cn word[1])
    + empty delta (state_delta view evaluated over available inputs without unfair penalty).
    Processes attack and benign samples with valid receipt status; skips
    trace retrieval errors and isolates hard negatives to holdout set.
    """
    cache = load_cache_rows(cache_path)
    rows = []
    for h, r in cache.items():
        if r.get("error"):
            continue
        if r.get("status") is False:
            continue
        label = r.get("label")
        if label not in ("attack", "benign"):
            continue  # Verified execution property
        rows.append({"tx_hash": h, "label": label, "block": r.get("block"),
                     "attack_type": r.get("attack_type") or "other",
                     "protocol": r.get("protocol"), "row": r})
    return {
        "rows": rows,
        "scores": {r["tx_hash"]: _row_scores(r["row"]) for r in rows},
        "y": np.array([1.0 if r["label"] == "attack" else 0.0 for r in rows]),
        "labels": [r["label"] for r in rows],
        "attack_type": [r["attack_type"] for r in rows],
        "hard_rows": [r for h, r in cache.items()
                      if r.get("label") == "hard" and not r.get("error")],
    }


def _row_scores(row: dict) -> dict:
    """Extract feature view scores from trace cache."""
    trace = trace_from_cache(row.get("trace") or {})
    res = evaluate_all(trace, {})
    return {v: (res[v]["score"] if res[v]["coverage"] else None) for v in VIEWS}


def _view_matrix(ds: dict, hashes: list[str]) -> np.ndarray:
    """(n, 4) matrix scores — view missing (None) → 0.0 (fusion b qua)."""
    X = []
    for h in hashes:
        s = ds["scores"][h]
        X.append([float(s.get(v) or 0.0) for v in VIEWS])
    return np.array(X, dtype=float)


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------
def train_test_split(ds: dict, test_frac: float = TEST_FRAC,
                     seed: int = SEED) -> dict:
    """Stratified 80/20: attack chia theo attack_type, benign theo t l chung.

    Deterministic: _sha256_id(tx_hash, salt=seed) sp xp li theo attack_type
    and slice 20% test set - deterministic and fully reproducible across processes.
    """
    if not ds["rows"]:
        raise ValueError("Trace cache is empty - run e1_crawl/e1_benign first")
    train_h: list[str] = []
    test_h: list[str] = []

    # attack: stratify theo attack_type
    groups: dict[str, list[str]] = {}
    for r in ds["rows"]:
        if r["label"] == "attack":
            groups.setdefault(r["attack_type"], []).append(r["tx_hash"])
    for g, hs in groups.items():
        hs = sorted(hs, key=lambda h: _sha256_id(h, f"{seed}:{g}"))
        n_test = max(1, math.ceil(test_frac * len(hs))) if len(hs) > 1 else (1 if len(hs) == 1 else 0)
        n_test = min(n_test, len(hs))
        test_h.extend(hs[-n_test:])
        train_h.extend(hs[:-n_test] if n_test else hs)

    # Execution trace analysis and verification
    benign_h = sorted([r["tx_hash"] for r in ds["rows"] if r["label"] == "benign"],
                      key=lambda h: _sha256_id(h, f"{seed}:benign"))
    n_test_b = max(1, math.ceil(test_frac * len(benign_h))) if len(benign_h) > 1 \
        else (1 if len(benign_h) == 1 else 0)
    n_test_b = min(n_test_b, len(benign_h))
    test_h.extend(benign_h[-n_test_b:])
    train_h.extend(benign_h[:-n_test_b] if n_test_b else benign_h)

    # Execution trace analysis and verification
    # Execution trace analysis and verification
    # Execution trace analysis and verification
    # Execution trace analysis and verification
    rng = random.Random(seed * 7919 + 13)
    rng.shuffle(test_h)

    h2y = {h: float(y) for h, y in zip([r["tx_hash"] for r in ds["rows"]], ds["y"])}
    return {
        "train": {"hashes": train_h, "X": _view_matrix(ds, train_h),
                  "y": np.array([h2y[h] for h in train_h])},
        "test": {"hashes": test_h, "X": _view_matrix(ds, test_h),
                 "y": np.array([h2y[h] for h in test_h])},
    }


def fit_calibration_split(train_part: dict, frac: float = 0.20,
                          seed: int = SEED) -> tuple[dict, dict]:
    """Deterministic stratified fit/calibration split inside training data.

    Calibration and threshold selection must not reuse the examples that fit
    logistic weights.  The outer test set remains untouched.
    """
    hashes = list(train_part["hashes"])
    y = np.asarray(train_part["y"], dtype=float)
    X = np.asarray(train_part["X"], dtype=float)
    fit_idx: list[int] = []
    cal_idx: list[int] = []
    for label in (0.0, 1.0):
        idx = [i for i, value in enumerate(y) if value == label]
        idx.sort(key=lambda i: _sha256_id(hashes[i], f"{seed}:cal:{int(label)}"))
        if len(idx) <= 1:
            fit_idx.extend(idx)
            continue
        n_cal = min(max(1, math.floor(frac * len(idx))), len(idx) - 1)
        fit_idx.extend(idx[:-n_cal])
        cal_idx.extend(idx[-n_cal:])
    # Extremely small synthetic data: calibration cannot be estimated.
    if not cal_idx or len(set(y[cal_idx])) < 2:
        cal_idx = list(fit_idx)
    def part(indices: list[int]) -> dict:
        return {"hashes": [hashes[i] for i in indices], "X": X[indices], "y": y[indices]}
    return part(fit_idx), part(cal_idx)


# ---------------------------------------------------------------------------
# Train + persist
# ---------------------------------------------------------------------------
def train(cache_path: Path, out_dir: Path = RESULTS_DIR,
          budgets: tuple[float, ...] = (0.001, 0.01),
          seed: int = SEED, offset_fixed: float | None = None,
          write_files: bool = True, scale: str = "A?") -> dict:
    """Full pipeline: build dataset → split → fit → calibrate → metrics → files.

    Returns result dictionary containing test scores, model parameters, and metrics.
    """
    ds = build_dataset(cache_path)
    split = train_test_split(ds, seed=seed)

    fit_part, cal_part = fit_calibration_split(split["train"], seed=seed)
    Xfit, yfit = fit_part["X"], fit_part["y"]
    Xcal, ycal = cal_part["X"], cal_part["y"]
    ytr = split["train"]["y"]
    model = fit_logistic_fusion(Xfit, yfit, view_names=VIEWS,
                                offset_fixed=offset_fixed, seed=seed)
    model = calibrate_temperature(model, Xcal, ycal)
    probs_cal = model.predict(Xcal)
    model.train_recall_99_tau = _tau_recall(probs_cal, ycal, target_recall=0.99)
    model.ece = expected_calibration_error(probs_cal, ycal)

    Xte, yte = split["test"]["X"], split["test"]["y"]
    scores_test = model.predict(Xte)
    thresholds = select_fpr_thresholds(ycal, probs_cal, budgets=budgets)
    m = metrics_at_thresholds(yte, scores_test, thresholds, budgets=budgets)

    h2type = {r["tx_hash"]: r["attack_type"] for r in ds["rows"]
              if r["label"] == "attack"}
    out = {
        "seed": seed, "offset_fixed": offset_fixed, "scale": scale,
        "n_fit": len(yfit), "n_calibration": len(ycal),
        "n_train_attack": int((ytr == 1).sum()), "n_train_benign": int((ytr == 0).sum()),
        "n_test_attack": int((yte == 1).sum()), "n_test_benign": int((yte == 0).sum()),
        "n_hard": len(ds["hard_rows"]),
        "model": model.to_dict(),
        "operating_thresholds": thresholds,
        "threshold_selection": "calibration_split",
        "metrics": m,
        "scores_test": {h: round(float(s), 6) for h, s in zip(split["test"]["hashes"], scores_test)},
        "test_hashes": split["test"]["hashes"],
        "train_attack_types": dict(Counter(h2type.get(h, "other") for h in split["train"]["hashes"]
                                           if h2type.get(h))),
    }
    if write_files:
        out_dir.mkdir(parents=True, exist_ok=True)
        run_id = utc_run_id("e1")
        out["run_id"] = run_id
        model_path = out_dir / "e1_model.json"
        model.save(str(model_path))
        csv_path = out_dir / "e1_main.csv"
        write_main_csv(csv_path, out, budgets)
        evaluation_path = out_dir / "e1_evaluation.json"
        evaluation = {
            "seed": seed,
            "scale": scale,
            "threshold_selection": out["threshold_selection"],
            "operating_thresholds": {
                str(k): (v if math.isfinite(v) else None)
                for k, v in thresholds.items()
            },
            "n_fit": out["n_fit"],
            "n_calibration": out["n_calibration"],
            "n_test_attack": out["n_test_attack"],
            "n_test_benign": out["n_test_benign"],
            "metrics": {
                str(k): ({key: (None if isinstance(value, float) and not math.isfinite(value)
                                else value) for key, value in val.items()}
                         if isinstance(val, dict) else val)
                for k, val in m.items()
            },
            "test_hashes": out["test_hashes"],
            "scores_test": out["scores_test"],
        }
        evaluation_path.write_text(
            json.dumps(canonical_floats(evaluation), indent=2,
                       ensure_ascii=False) + "\n",
            encoding="utf-8", newline="\n",
        )
        manifest_path = out_dir / "e1_manifest.json"
        write_manifest(manifest_path, run_id=run_id,
                       experiment="E1-screening-fixed-split",
                       repository=_REPO_ROOT, inputs={"trace_cache": cache_path},
                       parameters={"seed": seed, "budgets": budgets,
                                   "threshold_selection": "calibration_split",
                                   "scale": scale},
                       extra={"outputs": [str(model_path), str(csv_path),
                                          str(evaluation_path)]})
        out["files"] = {"model": str(model_path),
                        "csv": str(csv_path),
                        "evaluation": str(evaluation_path),
                        "manifest": str(manifest_path)}
    return out


def _tau_recall(probs: np.ndarray, y: np.ndarray, target_recall: float = 0.99) -> float:
    """Find minimum threshold tau such that training recall >= target."""
    pos = probs[y == 1]
    if len(pos) == 0:
        return 0.0
    n_keep = max(1, int(math.ceil(target_recall * len(pos))))
    sorted_pos = np.sort(pos)[::-1]
    return float(sorted_pos[min(n_keep - 1, len(sorted_pos) - 1)])


def write_main_csv(path: Path, out: dict, budgets: tuple[float, ...]) -> None:
    """Write e1_main.csv evaluation summary per FPR budget."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["scale", "n_train", "n_test", "fp_budget", "precision",
                    "recall", "f1", "auc_pr", "threshold_source", "threshold",
                    "realized_fpr", "allowed_fp", "fp", "tp",
                    "budget_satisfied_on_test"])
        m = out["metrics"]
        for b in budgets:
            row = m.get(b) or {}
            w.writerow(canonical_floats([out.get("scale", "A?"),
                        out["n_train_attack"] + out["n_train_benign"],
                        out["n_test_attack"] + out["n_test_benign"],
                        b, row.get("precision", ""), row.get("recall", ""),
                        row.get("f1", ""), m.get("auc_pr", ""),
                        row.get("threshold_source", ""), row.get("threshold", ""),
                        row.get("realized_fpr", ""), row.get("allowed_fp", ""),
                        row.get("fp", ""), row.get("tp", ""),
                        row.get("budget_satisfied_on_test", "")]))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_result(out: dict) -> None:
    tr, te = out["n_train_attack"], out["n_train_benign"]
    print(f"== E1 train (seed {out['seed']}, offset_fixed={out['offset_fixed']}) ==")
    print(f"train: {tr} attack + {te} benign   |   test: "
          f"{out['n_test_attack']} attack + {out['n_test_benign']} benign   "
          f"|   hard (n/a train): {out['n_hard']}")
    print(f"model : weights={json.dumps(out['model']['weights'])}  "
          f"offset={out['model']['offset']:.4f}  ECE={out['model'].get('ece')}")
    m = out["metrics"]
    for b in ("0.001", "0.01"):
        r = m.get(float(b))
        if r is None:
            r = m.get(b)
        if r:
            print(f"  FP-budget {float(b):.1%}: precision={r['precision']:.4f}  "
                  f"recall={r['recall']:.4f}  f1={r['f1']:.4f}  "
                  f"(tp={r['tp']}, fp={r['fp']})")
    print(f"AUC-PR={m.get('auc_pr'):.4f}  accuracy={m.get('accuracy'):.4f}")
    for f, p in (out.get("files") or {}).items():
        print(f"{f:>8}: {p}")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(description="E1: train fusion model and compute metrics")
    p.add_argument("--cache", default=None,
                   help="Path to trace cache JSONL file")
    p.add_argument("--out-dir", default=None, help="Directory to save e1_model.json and e1_main.csv")
    p.add_argument("--budgets", default="0.001,0.01",
                   help="Comma-separated FPR budgets (e.g., 0.001,0.01)")
    p.add_argument("--seed", type=int, default=SEED, help="Deterministic random seed (default: 42)")
    p.add_argument("--offset-fixed", type=float, default=None,
                   help="Fixed offset during logistic fit (default: unconstrained fit)")
    p.add_argument("--dry", action="store_true", help="Dry run without writing output files")
    p.add_argument("--scale", default="A?", help="Scale identifier for output CSV")
    args = p.parse_args(argv)
    args = p.parse_args(argv)

    from .e1_crawl import CACHE_PATH
    cache_path = Path(args.cache) if args.cache else CACHE_PATH
    budgets = tuple(float(x) for x in args.budgets.split(",") if x.strip())
    out_dir = Path(args.out_dir) if args.out_dir else RESULTS_DIR

    out = train(cache_path, out_dir=out_dir, budgets=budgets,
                seed=args.seed, offset_fixed=args.offset_fixed,
                write_files=not args.dry, scale=getattr(args, "scale", "A?"))
    _print_result(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
