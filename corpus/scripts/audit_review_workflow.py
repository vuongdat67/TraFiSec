"""Fail-closed audit from independent worksheets to adjudicated sidecars.

This script never creates or changes a human label.  It checks exact frozen-set
coverage, reviewer independence/completeness, disagreement fields, and—when a
final sidecar exists—that the preserved votes exactly match the two worksheets.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from corpus.scripts.audit_ground_truth import validate_review_record  # noqa: E402
from corpus.scripts.audit_hard_negatives import validate_review_record as validate_hard_review  # noqa: E402
from eval.reviewer_agreement import cohen_kappa  # noqa: E402
from eval.run_manifest import sha256_file  # noqa: E402

SUBMISSIONS = ROOT / "corpus" / "annotations" / "review_submissions"
E4_FIXED = ROOT / "eval" / "e4_fixed_set_v2.json"
HARD_QUEUE = ROOT / "eval" / "results" / "hard_negative_review_queue.csv"
OUTPUT = ROOT / "eval" / "results" / "review_workflow_audit.json"

E4_COMPARE_FIELDS = (
    "eligibility", "eligibility_reason", "security_objective_kind",
    "security_objective_statement", "security_objective_reference", "victims",
    "token_prices", "lmin_usd", "valuation_source", "root_cause",
    "enabling_primitives", "causal_calls", "intervention_candidates",
    "label_confidence",
)
HARD_COMPARE_FIELDS = (
    "preregistered_window_blocks", "same_protocol", "within_window",
    "legitimate_mechanism", "label", "rationale",
)


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _normal(value):
    if isinstance(value, dict):
        return {key: _normal(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((_normal(item) for item in value), key=lambda item: json.dumps(
            item, sort_keys=True, ensure_ascii=False))
    return value


def _e4_errors(row: dict) -> list[str]:
    errors = []
    if row.get("eligibility") not in ("eligible", "ineligible"):
        errors.append("eligibility_pending")
    if not str(row.get("eligibility_reason") or "").strip():
        errors.append("eligibility_reason_missing")
    if not str(row.get("reviewer_note") or "").strip():
        errors.append("reviewer_note_missing")
    if not row.get("evidence"):
        errors.append("evidence_missing")
    if row.get("eligibility") == "eligible":
        required = (
            "security_objective_kind", "security_objective_statement",
            "security_objective_reference", "victims", "token_prices",
            "valuation_source", "root_cause", "causal_calls",
            "intervention_candidates",
        )
        errors.extend(f"{field}_missing" for field in required if not row.get(field))
        if row.get("lmin_usd") is None:
            errors.append("lmin_usd_missing")
        if not any(item.get("applicability") == "supported"
                   for item in row.get("intervention_candidates") or []):
            errors.append("supported_intervention_missing")
    return errors


def _hard_errors(row: dict) -> list[str]:
    errors = []
    if row.get("same_protocol") not in (True, False):
        errors.append("same_protocol_pending")
    if row.get("within_window") not in (True, False):
        errors.append("within_window_pending")
    window = row.get("preregistered_window_blocks")
    if isinstance(window, bool) or not isinstance(window, int) or window < 0:
        errors.append("window_missing_or_invalid")
    if not str(row.get("legitimate_mechanism") or "").strip():
        errors.append("mechanism_missing")
    if row.get("label") not in (
            "verified_benign", "exclude_uncertain", "security_incident"):
        errors.append("label_pending")
    for field in ("rationale", "reviewer_note"):
        if not str(row.get(field) or "").strip():
            errors.append(f"{field}_missing")
    if not row.get("evidence"):
        errors.append("evidence_missing")
    return errors


def _packet_pair(first: list[dict], second: list[dict], *, key_fields: tuple[str, ...],
                 expected_keys: set[tuple], error_fn, compare_fields: tuple[str, ...],
                 label_field: str) -> dict:
    errors: list[str] = []
    maps = []
    reviewer_ids = []
    for label, rows in (("a", first), ("b", second)):
        mapping = {}
        reviewers = {str(row.get("reviewer") or "") for row in rows}
        if rows and (len(reviewers) != 1 or "" in reviewers):
            errors.append(f"reviewer_{label}_identity_not_constant")
        reviewer_ids.append(next(iter(reviewers), ""))
        for row in rows:
            key = tuple(str(row.get(field) or "").lower() for field in key_fields)
            if key in mapping:
                errors.append(f"reviewer_{label}_duplicate:{'|'.join(key)}")
            mapping[key] = row
        if rows and set(mapping) != expected_keys:
            errors.append(f"reviewer_{label}_frozen_set_mismatch")
        maps.append(mapping)
    if reviewer_ids[0] and reviewer_ids[0] == reviewer_ids[1]:
        errors.append("reviewers_not_distinct")
    validation: dict[str, dict[str, list[str]]] = {}
    disagreements: dict[str, list[str]] = {}
    agreement_pairs = []
    complete = 0
    for key in sorted(expected_keys):
        a = maps[0].get(key, {})
        b = maps[1].get(key, {})
        a_errors = error_fn(a) if a else ["submission_missing"]
        b_errors = error_fn(b) if b else ["submission_missing"]
        key_text = "|".join(key)
        validation[key_text] = {"reviewer_a": a_errors, "reviewer_b": b_errors}
        if not a_errors and not b_errors:
            complete += 1
            differing = [field for field in compare_fields
                         if _normal(a.get(field)) != _normal(b.get(field))]
            if differing:
                disagreements[key_text] = differing
            agreement_pairs.append((str(a.get(label_field)), str(b.get(label_field))))
    return {
        "expected": len(expected_keys), "reviewed_complete": complete,
        "reviewer_ids": reviewer_ids, "errors": errors,
        "validation_error_counts": dict(Counter(
            error for pair in validation.values() for values in pair.values()
            for error in values
        )),
        "disagreement_cases": len(disagreements),
        "disagreements": disagreements,
        "primary_label_agreement": cohen_kappa(agreement_pairs),
        "ready_for_adjudication": not errors and complete == len(expected_keys),
    }


def audit_e4(first: list[dict], second: list[dict], fixed: dict,
             final_rows: list[dict] | None = None) -> dict:
    expected = {(str(row["case_id"]).lower(), str(row["tx_hash"]).lower())
                for row in fixed.get("cases") or []}
    result = _packet_pair(first, second, key_fields=("case_id", "tx_hash"),
                          expected_keys=expected, error_fn=_e4_errors,
                          compare_fields=E4_COMPARE_FIELDS,
                          label_field="eligibility")
    result["final_sidecar"] = _audit_final_e4(first, second, expected, final_rows)
    return result


def audit_e4_files(first_path: Path, second_path: Path, fixed_path: Path,
                   final_path: Path) -> dict:
    """Paper-run gate over the exact two packets, frozen set, and final sidecar."""
    return audit_e4(
        _load_jsonl(first_path), _load_jsonl(second_path),
        json.loads(fixed_path.read_text(encoding="utf-8")),
        _load_jsonl(final_path),
    )


def _audit_final_e4(first: list[dict], second: list[dict], expected: set[tuple],
                    final_rows: list[dict] | None) -> dict:
    if final_rows is None:
        return {"present": False, "valid": False, "errors": ["not_supplied"]}
    final_map = {(str(row.get("case_id") or "").lower(),
                  str(row.get("tx_hash") or "").lower()): row for row in final_rows}
    errors = []
    if set(final_map) != expected or len(final_map) != len(final_rows):
        errors.append("final_exact_set_mismatch_or_duplicate")
    packet_maps = [{(str(row.get("case_id") or "").lower(),
                     str(row.get("tx_hash") or "").lower()): row for row in rows}
                   for rows in (first, second)]
    for key in sorted(expected & set(final_map)):
        row = final_map[key]
        errors.extend(f"{key[0]}:{error}" for error in validate_review_record(row))
        expected_votes = [{
            "reviewer": source.get("reviewer"),
            "eligibility": source.get("eligibility"),
            "root_cause": source.get("root_cause") or [],
            "note": source.get("reviewer_note"),
        } for source in (packet_maps[0].get(key, {}), packet_maps[1].get(key, {}))]
        if row.get("reviewer_votes") != expected_votes:
            errors.append(f"{key[0]}:reviewer_votes_not_packet_exact")
    return {"present": True, "valid": not errors, "errors": errors}


def audit_hard(first: list[dict], second: list[dict], queue: list[dict],
               final_rows: list[dict] | None = None) -> dict:
    expected = {(str(row["attack_case_id"]).lower(),
                 str(row["candidate_tx_hash"]).lower()) for row in queue}
    result = _packet_pair(first, second,
                          key_fields=("incident_case_id", "candidate_tx_hash"),
                          expected_keys=expected, error_fn=_hard_errors,
                          compare_fields=HARD_COMPARE_FIELDS,
                          label_field="label")
    result["final_sidecar"] = _audit_final_hard(first, second, queue, final_rows)
    return result


def _audit_final_hard(first: list[dict], second: list[dict], queue: list[dict],
                      final_rows: list[dict] | None) -> dict:
    if final_rows is None:
        return {"present": False, "valid": False, "errors": ["not_supplied"]}
    queue_map = {(str(row["attack_case_id"]).lower(),
                  str(row["candidate_tx_hash"]).lower()): row for row in queue}
    final_map = {(str(row.get("matched_incident_id") or "").lower(),
                  str(row.get("candidate_tx_hash") or "").lower()): row
                 for row in final_rows}
    errors = []
    if set(final_map) != set(queue_map) or len(final_map) != len(final_rows):
        errors.append("final_exact_queue_mismatch_or_duplicate")
    packet_maps = [{(str(row.get("incident_case_id") or "").lower(),
                     str(row.get("candidate_tx_hash") or "").lower()): row
                    for row in rows} for rows in (first, second)]
    for key in sorted(set(queue_map) & set(final_map)):
        row = final_map[key]
        errors.extend(f"{key[0]}|{key[1]}:{error}"
                      for error in validate_hard_review(row, queue_map[key]))
        expected_votes = [{
            "reviewer": source.get("reviewer"), "label": source.get("label"),
            "note": source.get("reviewer_note"),
        } for source in (packet_maps[0].get(key, {}), packet_maps[1].get(key, {}))]
        if row.get("reviewer_votes") != expected_votes:
            errors.append(f"{key[0]}|{key[1]}:reviewer_votes_not_packet_exact")
    return {"present": True, "valid": not errors, "errors": errors}


def run(e4_final: Path | None = None, hard_final: Path | None = None,
        output: Path = OUTPUT) -> dict:
    fixed = json.loads(E4_FIXED.read_text(encoding="utf-8"))
    with HARD_QUEUE.open(newline="", encoding="utf-8") as handle:
        queue = list(csv.DictReader(handle))
    e4_a = _load_jsonl(SUBMISSIONS / "e4_reviewer_a.jsonl")
    e4_b = _load_jsonl(SUBMISSIONS / "e4_reviewer_b.jsonl")
    hard_a = _load_jsonl(SUBMISSIONS / "hard_negatives_reviewer_a.jsonl")
    hard_b = _load_jsonl(SUBMISSIONS / "hard_negatives_reviewer_b.jsonl")
    report = {
        "schema_version": 1,
        "policy": "human labels are audited, never inferred or auto-adjudicated",
        "input_sha256": {
            "e4_reviewer_a": sha256_file(SUBMISSIONS / "e4_reviewer_a.jsonl"),
            "e4_reviewer_b": sha256_file(SUBMISSIONS / "e4_reviewer_b.jsonl"),
            "hard_reviewer_a": sha256_file(
                SUBMISSIONS / "hard_negatives_reviewer_a.jsonl"),
            "hard_reviewer_b": sha256_file(
                SUBMISSIONS / "hard_negatives_reviewer_b.jsonl"),
            "e4_final": sha256_file(e4_final) if e4_final else None,
            "hard_final": sha256_file(hard_final) if hard_final else None,
        },
        "e4": audit_e4(e4_a, e4_b, fixed,
                       _load_jsonl(e4_final) if e4_final else None),
        "hard_negatives": audit_hard(
            hard_a, hard_b, queue, _load_jsonl(hard_final) if hard_final else None),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8", newline="\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--e4-final", type=Path)
    parser.add_argument("--hard-final", type=Path)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    report = run(args.e4_final, args.hard_final, args.out)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
