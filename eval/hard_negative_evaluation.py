"""Evaluate only reviewer-verified matched hard negatives at frozen E1 thresholds."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT))
else:
    ROOT = Path(__file__).resolve().parent.parent

from corpus.scripts.audit_hard_negatives import audit  # noqa: E402
from eval.e1_common import load_cache_rows  # noqa: E402
from eval.e1_train import _row_scores  # noqa: E402
from eval.statistics import wilson_interval  # noqa: E402
from core.fusion import LogisticFusion  # noqa: E402

RESULTS = ROOT / "eval" / "results"


def analyze(scored: list[tuple[str, float]], thresholds: dict[str, float],
            *, eligible: int, cache_available: int) -> dict:
    operating_points = {}
    for budget, threshold in sorted(thresholds.items(), key=lambda item: float(item[0])):
        alerts = sum(score >= float(threshold) for _, score in scored)
        operating_points[str(budget)] = {
            "frozen_threshold": float(threshold),
            "alerts": alerts,
            "verified_benign_scored": len(scored),
            "matched_negative_fpr": alerts / len(scored) if scored else None,
            "wilson_95": wilson_interval(alerts, len(scored)),
        }
    return {
        "schema_version": 1,
        "label_contract": "schema-v2 reviewer-verified benign only",
        "denominators": {
            "paper_eligible_annotations": eligible,
            "cache_available": cache_available,
            "scored": len(scored),
            "missing_cache": max(eligible - cache_available, 0),
        },
        "operating_points": operating_points,
        "scores": [{"candidate_tx_hash": tx_hash, "score": round(score, 9)}
                   for tx_hash, score in scored],
        "claim_eligible": bool(eligible and cache_available == eligible),
    }


def run(queue: Path, annotations: Path, cache: Path, model_path: Path,
        evaluation_path: Path, output: Path) -> dict:
    audit_rows, _ = audit(queue, annotations)
    eligible_hashes = [row["candidate_tx_hash"] for row in audit_rows
                       if row["paper_eligible_hard_negative"]]
    cache_rows = load_cache_rows(cache)
    available = [tx_hash for tx_hash in eligible_hashes if tx_hash in cache_rows]
    model = LogisticFusion.load(str(model_path))
    scored = [(tx_hash, model.score(_row_scores(cache_rows[tx_hash])))
              for tx_hash in available]
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    report = analyze(scored, evaluation["operating_thresholds"],
                     eligible=len(eligible_hashes), cache_available=len(available))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8", newline="\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path,
                        default=RESULTS / "hard_negative_review_queue.csv")
    parser.add_argument("--annotations", type=Path,
                        default=ROOT / "corpus" / "annotations" /
                        "hard_negative_annotations.jsonl")
    parser.add_argument("--cache", type=Path,
                        default=RESULTS / "e1_trace_cache.jsonl")
    parser.add_argument("--model", type=Path, default=RESULTS / "e1_model.json")
    parser.add_argument("--evaluation", type=Path,
                        default=RESULTS / "e1_evaluation.json")
    parser.add_argument("--out", type=Path,
                        default=RESULTS / "hard_negative_evaluation.json")
    args = parser.parse_args(argv)
    print(json.dumps(run(args.queue, args.annotations, args.cache, args.model,
                         args.evaluation, args.out), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
