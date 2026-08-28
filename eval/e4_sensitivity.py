"""Pre-registered E4 harm-oracle sensitivity analysis.

This module never repairs or drops rows.  It reclassifies only already
observed, execution-preserving, behavior-changing interventions with numeric
baseline and mutated loss values.  All other rows remain inconclusive.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .necessity import criterion, mutation_factor

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "eval" / "results" / "e4_necessity.csv"
DEFAULT_OUTPUT = ROOT / "eval" / "results" / "e4_sensitivity.json"

SCENARIOS = {
    "lower_valuation_20pct": {"valuation_multiplier": 0.8, "threshold_multiplier": 1.0},
    "primary": {"valuation_multiplier": 1.0, "threshold_multiplier": 1.0},
    "higher_valuation_20pct": {"valuation_multiplier": 1.2, "threshold_multiplier": 1.0},
    "half_harm_threshold": {"valuation_multiplier": 1.0, "threshold_multiplier": 0.5},
    "double_harm_threshold": {"valuation_multiplier": 1.0, "threshold_multiplier": 2.0},
}


def _yes(value: object) -> bool:
    return str(value).lower() == "true"


def _number(value: object) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def analyze(rows: list[dict]) -> dict:
    mutation_rows = [
        row for row in rows
        if row.get("mutation") not in {
            "fidelity", "no_mutation", "error", "ineligible", "control_sham"
        }
        and _yes(row.get("paper_eligible"))
    ]
    result: dict[str, object] = {
        "schema_version": 1,
        "policy": "fixed scenarios; no row selection or replacement",
        "scenarios": {},
        "input_interventions": len(mutation_rows),
    }
    for name, params in SCENARIOS.items():
        counts: Counter[str] = Counter()
        by_factor: dict[str, Counter[str]] = {}
        changed = 0
        analyzable = 0
        for row in mutation_rows:
            loss_s = _number(row.get("positive_candidate_delta_usd", row.get("loss_S")))
            loss_sm = _number(row.get("positive_candidate_delta_usd_mutated", row.get("loss_Sm")))
            lmin = _number(row.get("lmin_usd"))
            if not (_yes(row.get("observed")) and
                    _yes(row.get("execution_preserving")) and
                    _yes(row.get("behavior_changed")) and
                    loss_s is not None and loss_sm is not None and lmin is not None):
                verdict = "INCONCLUSIVE-not-analyzable"
            else:
                analyzable += 1
                threshold = lmin * params["threshold_multiplier"]
                value_scale = params["valuation_multiplier"]
                baseline_harm = "HARM" if loss_s * value_scale > threshold else "NO_HARM"
                mutated_harm = "HARM" if loss_sm * value_scale > threshold else "NO_HARM"
                verdict = criterion(
                    str(row.get("outcome") or "EXECUTED_UNKNOWN"),
                    baseline_harm=baseline_harm,
                    mutated_harm=mutated_harm,
                    observed=True,
                    execution_preserving=True,
                    behavior_changed=True,
                )
                if verdict != row.get("verdict"):
                    changed += 1
            counts[verdict] += 1
            joint_factors = str(row.get("joint_factors") or "").strip()
            factor = (f"joint:{joint_factors}" if joint_factors else
                      mutation_factor(str(row.get("mutation") or "unknown")))
            by_factor.setdefault(factor, Counter())[verdict] += 1
        result["scenarios"][name] = {
            **params,
            "analyzable": analyzable,
            "changed_from_recorded_primary": changed,
            "verdict_counts": dict(counts),
            "by_factor": {factor: dict(values) for factor, values in sorted(by_factor.items())},
        }
    return result


def run(input_path: Path = DEFAULT_INPUT, output_path: Path = DEFAULT_OUTPUT) -> dict:
    rows: list[dict] = []
    if input_path.is_file():
        with input_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    report = analyze(rows)
    try:
        report["input"] = input_path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        report["input"] = f"<external>/{input_path.name}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8", newline="\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E4 harm-oracle sensitivity analysis")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.input, args.out), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
