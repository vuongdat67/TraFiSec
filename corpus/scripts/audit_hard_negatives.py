"""Validate two-reviewer matched hard negatives without upgrading uncertainty."""
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

from eval.reviewer_agreement import cohen_kappa, first_two_votes  # noqa: E402

TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
MECHANISMS = {
    "arbitrage", "liquidation", "migration", "governance_execution",
    "router_aggregation", "flash_liquidity", "other", "unknown",
}


def validate_review_record(annotation: dict, queue_row: dict | None = None) -> list[str]:
    """Validate completed review provenance, including excluded/non-benign rows."""
    errors: list[str] = []
    required = {
        "schema_version", "candidate_tx_hash", "matched_incident_id",
        "protocol_relation", "time_relation", "economic_mechanism", "final_label",
        "reviewer_votes", "adjudication", "evidence",
    }
    missing = sorted(required - set(annotation))
    if missing:
        return ["missing:" + ",".join(missing)]
    if annotation.get("schema_version") != 2:
        errors.append("schema_version_must_be_2")
    if not TX_HASH.fullmatch(str(annotation.get("candidate_tx_hash") or "")):
        errors.append("candidate_tx_hash_invalid")
    if not str(annotation.get("matched_incident_id") or "").strip():
        errors.append("matched_incident_id_missing")
    if annotation.get("protocol_relation") not in {
            "same_protocol", "same_contract_family", "unmatched", "unknown"}:
        errors.append("protocol_relation_invalid")
    relation = annotation.get("time_relation") or {}
    for field in ("candidate_block", "incident_block", "block_distance",
                  "window_blocks", "within_window", "rationale"):
        if relation.get(field) in (None, ""):
            errors.append(f"time_relation_{field}_missing")
    try:
        expected_distance = abs(int(relation["candidate_block"])
                                - int(relation["incident_block"]))
        if int(relation["block_distance"]) != expected_distance:
            errors.append("block_distance_inconsistent")
        within = expected_distance <= int(relation["window_blocks"])
        if bool(relation["within_window"]) != within:
            errors.append("within_window_inconsistent")
        if int(relation["window_blocks"]) <= 0:
            errors.append("window_blocks_invalid")
    except (KeyError, TypeError, ValueError):
        errors.append("time_relation_not_numeric")
    if annotation.get("economic_mechanism") in (None, ""):
        errors.append("economic_mechanism_missing")
    elif annotation.get("economic_mechanism") not in MECHANISMS:
        errors.append("economic_mechanism_invalid")
    if annotation.get("final_label") not in {
            "verified_benign", "exclude_uncertain", "security_incident"}:
        errors.append("final_label_pending_or_invalid")
    votes = annotation.get("reviewer_votes") or []
    reviewers = [str(vote.get("reviewer") or "") for vote in votes]
    if len({value for value in reviewers if value}) < 2:
        errors.append("two_distinct_reviewers_required")
    if any(vote.get("label") not in {
            "verified_benign", "exclude_uncertain", "security_incident"
    } for vote in votes):
        errors.append("invalid_reviewer_label")
    if any(not vote.get("note") for vote in votes):
        errors.append("reviewer_vote_note_missing")
    adjudication = annotation.get("adjudication") or {}
    if adjudication.get("status") != "adjudicated" or not adjudication.get("adjudicator"):
        errors.append("adjudication_incomplete")
    if not adjudication.get("note"):
        errors.append("adjudication_note_missing")
    if not annotation.get("evidence"):
        errors.append("evidence_missing")
    elif any(not item.get("reference") for item in annotation.get("evidence") or []):
        errors.append("evidence_reference_missing")
    if queue_row is not None:
        if str(annotation.get("candidate_tx_hash") or "").lower() != str(
                queue_row.get("candidate_tx_hash") or "").lower():
            errors.append("candidate_hash_not_in_queue")
        if annotation.get("matched_incident_id") != queue_row.get("attack_case_id"):
            errors.append("matched_incident_mismatch")
        for annotation_field, queue_field in (
            ("candidate_block", "candidate_block"),
            ("incident_block", "attack_block"),
            ("block_distance", "block_distance"),
            ("window_blocks", "window_blocks"),
        ):
            try:
                if int(relation.get(annotation_field)) != int(queue_row.get(queue_field)):
                    errors.append(f"{annotation_field}_queue_mismatch")
            except (TypeError, ValueError):
                errors.append(f"{annotation_field}_queue_invalid")
        queue_within = str(queue_row.get("within_window") or "").lower() == "true"
        if relation.get("within_window") is not queue_within:
            errors.append("within_window_queue_mismatch")
    return errors


def validate_annotation(annotation: dict, queue_row: dict | None = None) -> list[str]:
    """Validate the stricter paper-eligible verified-benign contract."""
    errors = validate_review_record(annotation, queue_row)
    if any(error.startswith("missing:") for error in errors):
        return errors
    if annotation.get("protocol_relation") != "same_protocol":
        errors.append("not_same_protocol")
    relation = annotation.get("time_relation") or {}
    if relation.get("within_window") is not True:
        errors.append("outside_preregistered_time_window")
    if annotation.get("economic_mechanism") in (None, "", "unknown"):
        errors.append("economic_mechanism_unresolved")
    if annotation.get("final_label") != "verified_benign":
        errors.append("not_adjudicated_verified_benign")
    return errors


def _load_jsonl(path: Path) -> tuple[dict[str, dict], dict[str, list[str]], list[str]]:
    rows: dict[str, dict] = {}
    parse_errors: dict[str, list[str]] = {}
    duplicates: list[str] = []
    if not path.is_file():
        return rows, parse_errors, duplicates
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            parse_errors[f"line:{line_number}"] = [f"invalid_json:{exc.msg}"]
            continue
        key = str(row.get("candidate_tx_hash") or f"line:{line_number}").lower()
        if key in rows:
            duplicates.append(key)
        else:
            rows[key] = row
    return rows, parse_errors, duplicates


def audit(queue_path: Path, annotation_path: Path) -> tuple[list[dict], dict]:
    with queue_path.open(encoding="utf-8", newline="") as handle:
        queue = list(csv.DictReader(handle))
    queue_by_hash = {str(row.get("candidate_tx_hash") or "").lower(): row for row in queue}
    annotations, parse_errors, duplicates = _load_jsonl(annotation_path)
    validation = {
        key: validate_annotation(annotation, queue_by_hash.get(key))
        for key, annotation in annotations.items()
    }
    review_validation = {
        key: validate_review_record(annotation, queue_by_hash.get(key))
        for key, annotation in annotations.items()
    }
    rows: list[dict] = []
    for key, queued in queue_by_hash.items():
        present = key in annotations
        errors = validation.get(key, [])
        review_errors = review_validation.get(key, [])
        rows.append({
            "candidate_tx_hash": key,
            "matched_incident_id": queued.get("attack_case_id"),
            "annotation_present": present,
            "annotation_valid": present and not errors,
            "review_complete": present and not review_errors,
            "paper_eligible_hard_negative": present and not errors and key not in duplicates,
            "validation_errors": ";".join(errors),
            "review_validation_errors": ";".join(review_errors),
        })
    eligible = sum(row["paper_eligible_hard_negative"] for row in rows)
    agreement_pairs = first_two_votes(annotations.values(), "label")
    summary = {
        "queue_rows": len(queue),
        "annotation_records": len(annotations),
        "completed_review_records": sum(row["review_complete"] for row in rows),
        "paper_eligible_hard_negatives": eligible,
        "duplicate_candidate_hashes": duplicates,
        "orphan_candidate_hashes": sorted(set(annotations) - set(queue_by_hash)),
        "parse_errors": parse_errors,
        "validation_error_counts": dict(Counter(
            error for errors in validation.values() for error in errors
        )),
        "reviewer_label_agreement": cohen_kappa(agreement_pairs),
        "eligibility_contract": (
            "schema v2 + same protocol + preregistered time window + resolved benign "
            "mechanism + two distinct reviewers + adjudication + evidence"
        ),
    }
    return rows, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path,
                        default=ROOT / "eval" / "results" / "hard_negative_review_queue.csv")
    parser.add_argument("--annotations", type=Path,
                        default=ROOT / "corpus" / "annotations" /
                        "hard_negative_annotations.jsonl")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "eval" / "results")
    args = parser.parse_args(argv)
    rows, summary = audit(args.queue, args.annotations)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "hard_negative_audit.csv").open(
            "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [],
                                lineterminator="\n")
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    (args.out_dir / "hard_negative_audit.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
