"""Paper-grade offline robustness evaluations for E1--E3.

The module consumes the immutable trace cache only; it performs no RPC calls.
It reports raw denominators, repeated splits, a chronological split,
leave-one-attack-family-out transfer, and a structurally mined near-negative
holdout.  The latter is intentionally not called a verified hard-negative set.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

from core.fusion import calibrate_temperature, fit_logistic_fusion

from .e1_common import (FLASH_SELECTORS, ORACLE_SELECTORS, SWAP_SELECTORS,
                        _sha256_id, canonical_floats, metrics_at_thresholds,
                        select_fpr_thresholds, selectors_from_trace,
                        trace_from_cache)
from .e1_train import (RESULTS_DIR, SEED, VIEWS, _view_matrix, build_dataset,
                       fit_calibration_split, train_test_split)
from .run_manifest import utc_run_id, write_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DEFAULT = RESULTS_DIR / "e1_trace_cache.jsonl"
CORPUS_DEFAULT = REPO_ROOT / "corpus" / "incidents.jsonl"


def _labels(ds: dict) -> dict[str, float]:
    return {r["tx_hash"]: 1.0 if r["label"] == "attack" else 0.0 for r in ds["rows"]}


def _fit(ds: dict, hashes: list[str], seed: int, budgets: tuple[float, ...]):
    h2y = _labels(ds)
    part = {"hashes": hashes, "X": _view_matrix(ds, hashes),
            "y": np.array([h2y[h] for h in hashes], dtype=float)}
    fit, cal = fit_calibration_split(part, seed=seed)
    if len(set(fit["y"])) < 2:
        raise ValueError("fit split needs both attack and benign examples")
    model = fit_logistic_fusion(fit["X"], fit["y"], view_names=VIEWS, seed=seed)
    if len(cal["y"]):
        model = calibrate_temperature(model, cal["X"], cal["y"])
    thresholds = select_fpr_thresholds(cal["y"], model.predict(cal["X"]), budgets)
    return model, len(fit["y"]), len(cal["y"]), thresholds


def _metric_rows(experiment: str, split_id: str, y: np.ndarray, scores: np.ndarray,
                 budgets: tuple[float, ...], thresholds: dict[float, float],
                 **meta) -> list[dict]:
    metrics = metrics_at_thresholds(y, scores, thresholds, budgets)
    rows: list[dict] = []
    for budget in budgets:
        m = metrics[budget]
        rows.append({"experiment": experiment, "split_id": split_id,
                     "fp_budget": budget, "n_attack": int((y == 1).sum()),
                     "n_benign": int((y == 0).sum()), "auc_pr": metrics["auc_pr"],
                     **m, **meta})
    return rows


def bootstrap_ci(y: np.ndarray, scores: np.ndarray, budgets: tuple[float, ...],
                 thresholds: dict[float, float], groups: np.ndarray | None = None,
                 n_boot: int = 1000, seed: int = 20260812) -> dict:
    """Resample positive incidents and negative sampling blocks separately."""
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    values: dict[str, list[float]] = {"auc_pr": []}
    for b in budgets:
        values[f"recall@{b}"] = []
        values[f"precision@{b}"] = []
    if not len(pos) or not len(neg):
        return {"method": "unavailable", "reason": "both classes required"}
    if groups is None:
        groups = np.array([f"row:{i}" for i in range(len(y))], dtype=object)
    negative_clusters = sorted({str(groups[i]) for i in neg})
    cluster_indices = {
        cluster: neg[np.array([str(groups[i]) == cluster for i in neg])]
        for cluster in negative_clusters
    }
    for _ in range(n_boot):
        sampled_clusters = rng.choice(negative_clusters, len(negative_clusters), replace=True)
        sampled_neg = np.concatenate([cluster_indices[str(cluster)]
                                      for cluster in sampled_clusters])
        idx = np.concatenate([rng.choice(pos, len(pos), replace=True), sampled_neg])
        m = metrics_at_thresholds(y[idx], scores[idx], thresholds, budgets)
        values["auc_pr"].append(float(m["auc_pr"]))
        for b in budgets:
            values[f"recall@{b}"].append(float(m[b]["recall"]))
            values[f"precision@{b}"].append(float(m[b]["precision"]))
    return {"method": "positive-incident / negative-block cluster bootstrap percentile",
            "n_boot": n_boot, "seed": seed, "n_positive_incidents": len(pos),
            "n_negative_clusters": len(negative_clusters),
            "intervals": {k: {"low": float(np.percentile(v, 2.5)),
                               "median": float(np.percentile(v, 50)),
                               "high": float(np.percentile(v, 97.5))}
                          for k, v in values.items()}}


def repeated_splits(ds: dict, seeds: list[int], budgets: tuple[float, ...]) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    reference = None
    for seed in seeds:
        split = train_test_split(ds, seed=seed)
        model, nfit, ncal, thresholds = _fit(ds, split["train"]["hashes"], seed, budgets)
        y = split["test"]["y"]
        scores = model.predict(split["test"]["X"])
        rows += _metric_rows("E1-repeated-stratified", str(seed), y, scores, budgets, thresholds,
                             n_fit=nfit, n_calibration=ncal, cutoff_block="",
                             held_family="", negative_set="random-benign")
        if seed == SEED:
            reference = (y, scores, thresholds, split["test"]["hashes"])
    if reference is None:
        split = train_test_split(ds, seed=seeds[0])
        model, _, _, thresholds = _fit(ds, split["train"]["hashes"], seeds[0], budgets)
        reference = (split["test"]["y"], model.predict(split["test"]["X"]),
                     thresholds, split["test"]["hashes"])
    row_by_hash = {r["tx_hash"]: r for r in ds["rows"]}
    groups = np.array([
        h if row_by_hash[h]["label"] == "attack"
        else f"block:{row_by_hash[h].get('block', h)}"
        for h in reference[3]
    ], dtype=object)
    return rows, bootstrap_ci(reference[0], reference[1], budgets, reference[2], groups)


def temporal_split(ds: dict, budgets: tuple[float, ...], seed: int = SEED) -> list[dict]:
    attacks = sorted(int(r["block"]) for r in ds["rows"]
                     if r["label"] == "attack" and r.get("block") is not None)
    cutoff = attacks[max(0, int(np.floor(0.8 * len(attacks))) - 1)]
    train_h = [r["tx_hash"] for r in ds["rows"] if int(r.get("block") or 0) <= cutoff]
    test_h = [r["tx_hash"] for r in ds["rows"] if int(r.get("block") or 0) > cutoff]
    model, nfit, ncal, thresholds = _fit(ds, train_h, seed, budgets)
    h2y = _labels(ds)
    y = np.array([h2y[h] for h in test_h])
    scores = model.predict(_view_matrix(ds, test_h))
    return _metric_rows("E1-temporal", f"block>{cutoff}", y, scores, budgets, thresholds,
                        n_fit=nfit, n_calibration=ncal, cutoff_block=cutoff,
                        held_family="", negative_set="future-benign")


def held_family(ds: dict, budgets: tuple[float, ...], seed: int = SEED) -> list[dict]:
    rows: list[dict] = []
    families = sorted({r["attack_type"] for r in ds["rows"] if r["label"] == "attack"})
    benign = sorted([r["tx_hash"] for r in ds["rows"] if r["label"] == "benign"],
                    key=lambda h: _sha256_id(h, f"{seed}:held-benign"))
    n_test_b = max(1, int(np.ceil(0.2 * len(benign))))
    train_b, test_b = benign[:-n_test_b], benign[-n_test_b:]
    h2y = _labels(ds)
    for family in families:
        held = [r["tx_hash"] for r in ds["rows"]
                if r["label"] == "attack" and r["attack_type"] == family]
        other = [r["tx_hash"] for r in ds["rows"]
                 if r["label"] == "attack" and r["attack_type"] != family]
        model, nfit, ncal, thresholds = _fit(ds, other + train_b, seed, budgets)
        test_h = held + test_b
        y = np.array([h2y[h] for h in test_h])
        scores = model.predict(_view_matrix(ds, test_h))
        rows += _metric_rows("E2-held-family", family, y, scores, budgets, thresholds,
                             n_fit=nfit, n_calibration=ncal, cutoff_block="",
                             held_family=family, negative_set="fixed-benign",
                             family_primary=len(held) >= 3)
    return rows


def _is_near_negative(row: dict) -> bool:
    trace = trace_from_cache(row.get("trace") or {})
    sels = set(selectors_from_trace(trace))
    structural = bool(sels & (set(FLASH_SELECTORS) | set(SWAP_SELECTORS) |
                              set(ORACLE_SELECTORS)))
    complex_trace = len(trace.get("flat_calls") or []) >= 10 or len(trace.get("logs") or []) >= 5
    return structural or complex_trace


def near_negative_holdout(ds: dict, budgets: tuple[float, ...], seed: int = SEED) -> list[dict]:
    near = [r["tx_hash"] for r in ds["rows"]
            if r["label"] == "benign" and _is_near_negative(r["row"])]
    background = [r["tx_hash"] for r in ds["rows"]
                  if r["label"] == "benign" and r["tx_hash"] not in set(near)]
    attacks = sorted([r["tx_hash"] for r in ds["rows"] if r["label"] == "attack"],
                     key=lambda h: _sha256_id(h, f"{seed}:near-attack"))
    n_test_a = max(1, int(np.ceil(0.2 * len(attacks))))
    train_a, test_a = attacks[:-n_test_a], attacks[-n_test_a:]
    model, nfit, ncal, thresholds = _fit(ds, train_a + background, seed, budgets)
    test_h = test_a + near
    h2y = _labels(ds)
    y = np.array([h2y[h] for h in test_h])
    scores = model.predict(_view_matrix(ds, test_h))
    return _metric_rows("E3-near-negative", "structural-holdout", y, scores, budgets, thresholds,
                        n_fit=nfit, n_calibration=ncal, cutoff_block="",
                        held_family="", negative_set="mined-structural-near-negative",
                        selection="known selectors OR >=10 calls OR >=5 logs")


def token_flow_covered_split(ds: dict, budgets: tuple[float, ...],
                             seed: int = SEED) -> list[dict]:
    """Sensitivity split conditioned on token-flow coverage for both labels.

    This removes the label-correlated missingness gap from the sampled data. It
    is a diagnostic sensitivity analysis, not an estimate of chain prevalence,
    because coverage itself is a post-selection condition.
    """
    covered = [r for r in ds["rows"]
               if ds["scores"][r["tx_hash"]].get("token_flow") is not None]
    filtered = {
        "rows": covered,
        "scores": {r["tx_hash"]: ds["scores"][r["tx_hash"]] for r in covered},
        "y": np.array([1.0 if r["label"] == "attack" else 0.0 for r in covered]),
        "hard_rows": [],
    }
    split = train_test_split(filtered, seed=seed)
    model, nfit, ncal, thresholds = _fit(
        filtered, split["train"]["hashes"], seed, budgets
    )
    y = split["test"]["y"]
    scores = model.predict(split["test"]["X"])
    return _metric_rows(
        "E3-token-flow-covered", "coverage-conditioned", y, scores, budgets,
        thresholds, n_fit=nfit, n_calibration=ncal, cutoff_block="",
        held_family="", negative_set="token-flow-covered-background",
        selection="token_flow coverage required for both labels",
        diagnostic_only=True,
    )


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = sorted({key for row in rows for key in row})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(canonical_floats(rows))


def run(cache: Path = CACHE_DEFAULT, out_dir: Path = RESULTS_DIR,
        budgets: tuple[float, ...] = (0.001, 0.01), n_seeds: int = 30,
        n_boot: int = 1000) -> dict:
    ds = build_dataset(cache)
    seeds = list(range(SEED, SEED + n_seeds))
    repeated, ci = repeated_splits(ds, seeds, budgets)
    # Recompute only if caller requests a non-default bootstrap count.
    if n_boot != 1000:
        split = train_test_split(ds, seed=SEED)
        model, _, _, thresholds = _fit(ds, split["train"]["hashes"], SEED, budgets)
        row_by_hash = {r["tx_hash"]: r for r in ds["rows"]}
        groups = np.array([
            h if row_by_hash[h]["label"] == "attack"
            else f"block:{row_by_hash[h].get('block', h)}"
            for h in split["test"]["hashes"]
        ], dtype=object)
        ci = bootstrap_ci(split["test"]["y"], model.predict(split["test"]["X"]),
                          budgets, thresholds, groups, n_boot=n_boot)
    rows = repeated + temporal_split(ds, budgets) + held_family(ds, budgets) + \
        near_negative_holdout(ds, budgets) + token_flow_covered_split(ds, budgets)
    run_id = utc_run_id("e1e3")
    csv_path = out_dir / "e1_e3_robustness.csv"
    _write_csv(csv_path, rows)
    summary = {
        "cache_rows": len(ds["rows"]),
        "class_counts": dict(Counter(r["label"] for r in ds["rows"])),
        "n_repeated_seeds": n_seeds, "bootstrap_ci_reference_seed": SEED,
        "bootstrap": ci,
        "experiments": dict(Counter(r["experiment"] for r in rows)),
        "caveats": [
            "0.1% FPR is empirically unresolved when a split has fewer than 1000 benign examples; allowed_fp is then zero.",
            "Near negatives are structurally mined benign transactions, not manually verified protocol-matched hard negatives.",
            "Held families with fewer than three incidents are diagnostic only (family_primary=false).",
            "The current cache has no state-delta view coverage; results characterize the available three-view signal.",
            "The token-flow-covered split conditions on view coverage and is diagnostic, not a deployment-prevalence estimate.",
            "FPR thresholds are selected on calibration data and frozen before test evaluation; test-set budget violations are reported, not optimized away.",
        ],
    }
    summary_path = out_dir / "e1_e3_robustness.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8", newline="\n")
    write_manifest(out_dir / "e1_e3_manifest.json", run_id=run_id,
                   experiment="E1-E3-robustness", repository=REPO_ROOT,
                   inputs={"trace_cache": cache, "corpus": CORPUS_DEFAULT},
                   parameters={"budgets": budgets, "seeds": seeds, "n_boot": n_boot},
                   command=sys.argv, extra={"outputs": [str(csv_path), str(summary_path)]})
    return {"rows": rows, "summary": summary, "csv": csv_path, "json": summary_path}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline E1-E3 robustness suite")
    parser.add_argument("--cache", type=Path, default=CACHE_DEFAULT)
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--budgets", default="0.001,0.01")
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--bootstrap", type=int, default=1000)
    args = parser.parse_args(argv)
    budgets = tuple(float(x) for x in args.budgets.split(","))
    out = run(args.cache, args.out_dir, budgets, args.seeds, args.bootstrap)
    print(json.dumps(out["summary"], indent=2, ensure_ascii=False))
    print(f"csv: {out['csv']}\njson: {out['json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
