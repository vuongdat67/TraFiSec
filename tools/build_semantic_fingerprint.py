"""Build the cross-platform semantic fingerprint of published evidence."""
from __future__ import annotations

import csv
import json
from pathlib import Path

if __package__ in (None, ""):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.e1_common import canonical_floats  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "eval" / "results"
OUTPUT = ROOT / "eval" / "artifacts" / "semantic_fingerprint.json"


def read_json(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def read_csv(name: str, excluded: set[str] = frozenset()) -> list[dict[str, str]]:
    with (RESULTS / name).open(encoding="utf-8", newline="") as handle:
        return [
            {key: value for key, value in row.items() if key not in excluded}
            for row in csv.DictReader(handle)
        ]


def without_keys(value, excluded: set[str]):
    if isinstance(value, dict):
        return {
            key: without_keys(item, excluded)
            for key, item in value.items()
            if key not in excluded
        }
    if isinstance(value, list):
        return [without_keys(item, excluded) for item in value]
    return value


def build() -> dict:
    evaluation = read_json("e1_evaluation.json")
    fixed = {
        "seed": evaluation["seed"],
        "scale": evaluation["scale"],
        "threshold_selection": evaluation["threshold_selection"],
        "n_fit": evaluation["n_fit"],
        "n_calibration": evaluation["n_calibration"],
        "n_test_attack": evaluation["n_test_attack"],
        "n_test_benign": evaluation["n_test_benign"],
        "test_hashes": evaluation["test_hashes"],
        "metrics": without_keys(evaluation["metrics"], {"threshold"}),
    }
    return {
        "schema_version": 1,
        "contract": (
            "Cross-platform scientific semantics; excludes optimizer threshold "
            "floats, provenance timestamps, and renderer bytes."
        ),
        "dataset": read_json("dataset_audit.json"),
        "e1_fixed": fixed,
        "e1_e3_rows": read_csv("e1_e3_robustness.csv", {"threshold"}),
        "e2_ablation_rows": read_csv("e2_ablation.csv", {"threshold"}),
        "ground_truth": read_json("ground_truth_audit.json"),
        "e4_queue": read_json("e4_preregistration_queue.json"),
        "e4_fixed_set": json.loads(
            (ROOT / "eval" / "e4_fixed_set_v2.json").read_text(encoding="utf-8")
        ),
        "hard_negative_queue": read_json("hard_negative_review_queue.json"),
        "hard_negative_audit": read_json("hard_negative_audit.json"),
        "hard_negative_evaluation": read_json("hard_negative_evaluation.json"),
        "review_workflow_audit": read_json("review_workflow_audit.json"),
        "local_validity_controls": read_json("validity_controls.json"),
        "claim_audit_status": read_json("claim_audit.json")["status"],
        "citation_audit_status": read_json("citation_audit.json")["status"],
    }


def main() -> int:
    data = build()
    # Everything in the fingerprint, not just the CSV rows that already went
    # through canonical_floats, must be byte-stable across BLAS/libm/libxmlm
    # variants. Raw JSON floats (e.g. wilson 95% intervals in
    # hard_negative_evaluation) can differ in the last bits between Windows
    # and Linux; collapse them to 9 decimals here too.
    data = canonical_floats(data, digits=9)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"Semantic fingerprint written: {OUTPUT} ({len(data['e1_e3_rows'])} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
