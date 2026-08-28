"""E1 Random Forest comparison using the frozen logistic protocol.

Only classifier changes here. Dataset construction, feature views, missing-value
encoding, outer split, calibration split, threshold selection, and metrics are
reused from :mod:`eval.e1_train` and :mod:`eval.e1_common`.

This runner prints one primary evaluation to stdout and does not write result
artifacts. Hyperparameters are constants below; no tuning is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402
from scipy.optimize import minimize_scalar  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402

from .e1_common import (  # noqa: E402
    _ensure_utf8,
    metrics_at_thresholds,
    select_fpr_thresholds,
)
from .e1_train import (  # noqa: E402
    RESULTS_DIR,
    SEED,
    VIEWS,
    build_dataset,
    fit_calibration_split,
    train_test_split,
)
from core.fusion import expected_calibration_error  # noqa: E402

RF_CONFIG = {
    "n_estimators": 200,
    "max_depth": 6,
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": SEED,
    "n_jobs": 1,
}
BUDGETS = (0.001, 0.01)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _apply_temperature(raw_probabilities: np.ndarray, temperature: float) -> np.ndarray:
    probabilities = np.clip(np.asarray(raw_probabilities, dtype=float), 1e-9, 1 - 1e-9)
    logits = np.log(probabilities / (1.0 - probabilities))
    return 1.0 / (1.0 + np.exp(-np.clip(logits / max(temperature, 1e-3), -40, 40)))


def _fit_temperature(raw_probabilities: np.ndarray,
                     y_calibration: np.ndarray) -> float:
    """Fit same ECE-minimizing temperature procedure as logistic E1."""
    probabilities = np.clip(np.asarray(raw_probabilities, dtype=float), 1e-9, 1 - 1e-9)
    logits = np.log(probabilities / (1.0 - probabilities))

    def calibrated(temperature: float) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(logits / max(temperature, 1e-3), -40, 40)))

    result = minimize_scalar(
        lambda temperature: expected_calibration_error(
            calibrated(temperature), y_calibration
        ),
        bounds=(0.1, 10.0),
        method="bounded",
    )
    return max(float(result.x), 0.1)


def evaluate(cache_path: Path, seed: int = SEED,
             budgets: tuple[float, ...] = BUDGETS) -> dict:
    """Run one frozen RF evaluation without writing artifacts."""
    dataset = build_dataset(cache_path)
    split = train_test_split(dataset, seed=seed)
    fit_part, calibration_part = fit_calibration_split(split["train"], seed=seed)

    classifier = RandomForestClassifier(**{**RF_CONFIG, "random_state": seed})
    classifier.fit(fit_part["X"], fit_part["y"])

    calibration_raw = classifier.predict_proba(calibration_part["X"])[:, 1]
    temperature = _fit_temperature(calibration_raw, calibration_part["y"])
    calibration_probabilities = _apply_temperature(calibration_raw, temperature)
    thresholds = select_fpr_thresholds(
        calibration_part["y"], calibration_probabilities, budgets=budgets
    )

    test_raw = classifier.predict_proba(split["test"]["X"])[:, 1]
    test_probabilities = _apply_temperature(test_raw, temperature)
    metrics = metrics_at_thresholds(
        split["test"]["y"], test_probabilities, thresholds, budgets=budgets
    )

    return {
        "schema_version": 1,
        "experiment": "E1-random-forest-protocol-comparison",
        "classifier": "RandomForestClassifier",
        "protocol": {
            "feature_set": list(VIEWS),
            "missing_value_handling": "same e1_train _view_matrix: missing view -> 0.0",
            "outer_split": "same train_test_split as E1",
            "calibration_split": "same fit_calibration_split as E1",
            "calibration": "same E1 ECE-minimizing temperature scaling",
            "threshold_source": "calibration_split_only",
            "primary_metric": "AUPRC",
            "operating_point": "1% FPR budget",
            "secondary_metrics": ["precision", "recall", "realized_fpr"],
        },
        "rf_config": {**RF_CONFIG, "random_state": seed},
        "seed": seed,
        "inputs": {
            "cache_path": str(cache_path),
            "cache_sha256": _sha256(cache_path),
        },
        "split": {
            "n_fit": len(fit_part["y"]),
            "n_calibration": len(calibration_part["y"]),
            "n_test": len(split["test"]["y"]),
            "test_hashes": split["test"]["hashes"],
        },
        "calibration_temperature": temperature,
        "thresholds": {str(key): value for key, value in thresholds.items()},
        "metrics": {str(key): value for key, value in metrics.items()},
    }


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    parser = argparse.ArgumentParser(description="Run one frozen E1 RF comparison")
    parser.add_argument(
        "--cache",
        default=str(RESULTS_DIR / "e1_trace_cache.jsonl"),
        help="audited E1 cache path",
    )
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)
    result = evaluate(Path(args.cache), seed=args.seed)
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
