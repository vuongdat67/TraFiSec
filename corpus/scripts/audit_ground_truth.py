"""Audit causal-label provenance without upgrading legacy labels.

The validator is deliberately dependency-free and enforces the paper eligibility
contract in addition to the JSON Schema. Presence of a sidecar row alone is not
enough to enter the E4 causal-accuracy denominator.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.reviewer_agreement import e4_agreement  # noqa: E402

TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
FACTORS = {"f_fl", "f_orc", "f_swap", "f_auth", "f_re", "f_other", "unknown"}


def validate_review_record(annotation: dict, inventory: dict | None = None) -> list[str]:
    """Validate independent review completion, including ineligible cases."""
    required = {
        "schema_version", "case_id", "tx_hash", "eligibility",
        "security_objective", "root_cause_gt", "enabling_primitives",
        "intervention_candidates", "harm_spec", "causal_calls",
        "label_confidence", "reviewer_votes", "adjudication", "evidence",
    }
    missing = sorted(required - set(annotation))
    if missing:
        return ["missing:" + ",".join(missing)]
    errors: list[str] = []
    if annotation.get("schema_version") != 2:
        errors.append("schema_version_must_be_2")
    if not TX_HASH.fullmatch(str(annotation.get("tx_hash") or "")):
        errors.append("tx_hash_invalid")
    eligibility = annotation.get("eligibility") or {}
    if eligibility.get("status") not in ("eligible", "ineligible"):
        errors.append("eligibility_status_invalid")
    if not eligibility.get("reason"):
        errors.append("eligibility_reason_missing")
    votes = annotation.get("reviewer_votes") or []
    reviewers = [vote.get("reviewer") for vote in votes if vote.get("reviewer")]
    if len(set(reviewers)) < 2:
        errors.append("two_distinct_reviewers_required")
    if any(not vote.get("note") for vote in votes):
        errors.append("reviewer_vote_note_missing")
    if any(vote.get("eligibility") not in ("eligible", "ineligible") for vote in votes):
        errors.append("reviewer_eligibility_invalid")
    if any(not set(vote.get("root_cause") or []).issubset(FACTORS) for vote in votes):
        errors.append("reviewer_root_cause_invalid")
    adjudication = annotation.get("adjudication") or {}
    if adjudication.get("status") != "adjudicated" or not adjudication.get("adjudicator"):
        errors.append("adjudication_incomplete")
    if not str(adjudication.get("note") or "").strip():
        errors.append("adjudication_note_missing")
    if not annotation.get("evidence"):
        errors.append("evidence_missing")
    elif any(not item.get("reference") for item in annotation.get("evidence") or []):
        errors.append("evidence_reference_missing")
    if inventory is not None:
        expected_hashes = {str(value).lower() for value in inventory.get("tx_hashes") or []}
        if str(annotation.get("tx_hash") or "").lower() not in expected_hashes:
            errors.append("tx_hash_not_in_inventory_case")
    return errors


def validate_annotation(annotation: dict, inventory: dict | None = None) -> list[str]:
    errors = validate_review_record(annotation, inventory)
    if any(error.startswith("missing:") for error in errors):
        return errors
    if (annotation.get("eligibility") or {}).get("status") != "eligible":
        errors.append("not_marked_eligible")
    if not (annotation.get("eligibility") or {}).get("reason"):
        errors.append("eligibility_reason_missing")
    objective = annotation.get("security_objective") or {}
    if not objective.get("statement") or not objective.get("reference"):
        errors.append("security_objective_incomplete")
    causes = annotation.get("root_cause_gt") or []
    if not causes or "unknown" in causes:
        errors.append("adjudicated_root_cause_missing")
    if not set(causes).issubset(FACTORS):
        errors.append("adjudicated_root_cause_invalid")
    candidates = annotation.get("intervention_candidates") or []
    if not any(candidate.get("applicability") == "supported" for candidate in candidates):
        errors.append("no_supported_intervention")
    harm = annotation.get("harm_spec") or {}
    if not harm.get("victims") or not harm.get("token_prices"):
        errors.append("harm_spec_missing_victims_or_prices")
    if not harm.get("valuation_source"):
        errors.append("valuation_source_missing")
    try:
        if float(harm.get("lmin_usd")) < 0:
            errors.append("lmin_usd_invalid")
    except (TypeError, ValueError):
        errors.append("lmin_usd_invalid")
    for token, price in (harm.get("token_prices") or {}).items():
        try:
            if (not token or float(price.get("usd_per_token")) < 0 or
                    not 0 <= int(price.get("decimals")) <= 36):
                errors.append("token_price_invalid")
                break
        except (AttributeError, TypeError, ValueError):
            errors.append("token_price_invalid")
            break
    if not annotation.get("causal_calls"):
        errors.append("causal_calls_missing")
    return errors


def _load_annotations(path: Path | None) -> tuple[dict[str, dict], dict[str, list[str]], list[str]]:
    annotations: dict[str, dict] = {}
    parse_errors: dict[str, list[str]] = {}
    duplicates: list[str] = []
    if not path or not path.exists():
        return annotations, parse_errors, duplicates
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            parse_errors[f"line:{line_number}"] = [f"invalid_json:{exc.msg}"]
            continue
        case_id = str(row.get("case_id") or f"line:{line_number}")
        if case_id in annotations:
            duplicates.append(case_id)
            continue
        annotations[case_id] = row
    return annotations, parse_errors, duplicates


def audit(corpus: Path, annotation_file: Path | None = None) -> tuple[list[dict], dict]:
    inventory = [json.loads(line) for line in corpus.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
    inventory_by_id = {item.get("id"): item for item in inventory}
    annotations, parse_errors, duplicates = _load_annotations(annotation_file)
    validation = {
        case_id: validate_annotation(annotation, inventory_by_id.get(case_id))
        for case_id, annotation in annotations.items()
    }
    review_validation = {
        case_id: validate_review_record(annotation, inventory_by_id.get(case_id))
        for case_id, annotation in annotations.items()
    }
    rows = []
    for item in inventory:
        if item.get("verified") != "onchain":
            continue
        factors = item.get("gt_factors") or ["unknown"]
        note = item.get("notes") or ""
        if factors == ["unknown"] or "unknown" in factors:
            tier = "unknown"
        elif "[auto-label:" in note:
            tier = "legacy_auto_heuristic"
        else:
            tier = "legacy_source_only"
        case_id = item.get("id")
        present = case_id in annotations
        errors = validation.get(case_id, [])
        review_errors = review_validation.get(case_id, [])
        eligible = present and not errors and case_id not in duplicates
        rows.append({
            "case_id": case_id,
            "tx_hash": (item.get("tx_hashes") or [""])[0],
            "attack_type": item.get("attack_type"),
            "legacy_gt_factors": "+".join(factors),
            "legacy_evidence_tier": tier,
            "causal_sidecar_present": present,
            "causal_sidecar_valid": present and not errors,
            "independent_review_complete": present and not review_errors,
            "paper_e4_eligible": eligible,
            "review_validation_errors": ";".join(review_errors),
            "validation_errors": ";".join(errors),
        })
    counts = Counter(row["legacy_evidence_tier"] for row in rows)
    orphan_ids = sorted(set(annotations) - set(inventory_by_id))
    summary = {
        "onchain_records": len(rows),
        "legacy_label_tiers": dict(counts),
        "causal_sidecar_records": sum(row["causal_sidecar_present"] for row in rows),
        "valid_causal_sidecars": sum(row["causal_sidecar_valid"] for row in rows),
        "independent_reviews_complete": sum(
            row["independent_review_complete"] for row in rows
        ),
        "paper_e4_eligible": sum(row["paper_e4_eligible"] for row in rows),
        "duplicate_case_ids": duplicates,
        "orphan_case_ids": orphan_ids,
        "parse_errors": parse_errors,
        "validation_error_counts": dict(Counter(
            error for errors in validation.values() for error in errors
        )),
        "reviewer_agreement": e4_agreement(annotations.values()),
        "eligibility_contract": "schema v2 + two distinct reviewers + adjudication + security objective + supported intervention + victim valuation + causal calls + evidence",
        "conclusion": "Legacy gt_factors are not adjudicated causal ground truth and cannot support E4 accuracy claims.",
    }
    return rows, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=ROOT / "corpus" / "incidents.jsonl")
    parser.add_argument("--annotations", type=Path,
                        default=ROOT / "corpus" / "annotations" / "e4_annotations.jsonl")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "eval" / "results")
    args = parser.parse_args()
    rows, summary = audit(args.corpus, args.annotations)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "ground_truth_audit.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [],
                                lineterminator="\n")
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    (args.out_dir / "ground_truth_audit.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        newline="\n"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
