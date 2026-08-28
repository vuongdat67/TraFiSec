"""Build separate label-blind packets for independent E4/hard-negative review."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
E4_SET = ROOT / "eval" / "e4_fixed_set_v2.json"
HARD_QUEUE = ROOT / "eval" / "results" / "hard_negative_review_queue.csv"
OUT_DIR = ROOT / "corpus" / "annotations" / "review_packets"
FORBIDDEN_E4_KEYS = {
    "gt_factors", "root_cause_gt", "attack_type", "blind_candidate_factors",
    "supported_from_cache", "trace_evidence",
}


def e4_packet(fixed_set: dict, reviewer: str) -> list[dict]:
    rows = []
    for item in fixed_set.get("cases") or []:
        row = {
            "packet_schema_version": 1,
            "reviewer": reviewer,
            "case_id": item["case_id"],
            "tx_hash": item["tx_hash"],
            "block": item.get("block"),
            "eligibility": "pending",
            "eligibility_reason": "",
            "security_objective_kind": "",
            "security_objective_statement": "",
            "security_objective_reference": "",
            "victims": [],
            "token_prices": {},
            "lmin_usd": None,
            "valuation_source": "",
            "root_cause": [],
            "enabling_primitives": [],
            "causal_calls": [],
            "intervention_candidates": [],
            "label_confidence": "unknown",
            "evidence": [],
            "reviewer_note": "",
        }
        if FORBIDDEN_E4_KEYS & set(row):
            raise AssertionError("review packet leaked forbidden label fields")
        rows.append(row)
    if len(rows) != 20 or len({row["case_id"] for row in rows}) != 20:
        raise ValueError("E4 review packet requires exactly 20 unique frozen cases")
    return rows


def hard_negative_packet(queue_rows: list[dict], reviewer: str) -> list[dict]:
    rows = []
    for item in queue_rows:
        rows.append({
            "packet_schema_version": 1,
            "reviewer": reviewer,
            "incident_case_id": item["attack_case_id"],
            "incident_tx_hash": item["attack_tx_hash"],
            "incident_block": int(item["attack_block"]),
            "candidate_tx_hash": item["candidate_tx_hash"],
            "candidate_block": int(item["candidate_block"]),
            "preregistered_window_blocks": int(item["window_blocks"]),
            "same_protocol": "pending",
            "within_window": str(item["within_window"]).lower() == "true",
            "legitimate_mechanism": "",
            "label": "pending",
            "rationale": "",
            "evidence": [],
            "reviewer_note": "",
        })
    if len(rows) != len(queue_rows):
        raise AssertionError("hard-negative packet lost queue rows")
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                    encoding="utf-8", newline="\n")


def run(fixed_path: Path = E4_SET, hard_queue_path: Path = HARD_QUEUE,
        out_dir: Path = OUT_DIR) -> dict:
    fixed = json.loads(fixed_path.read_text(encoding="utf-8"))
    with hard_queue_path.open(newline="", encoding="utf-8") as handle:
        hard_rows = list(csv.DictReader(handle))
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for reviewer in ("reviewer_a", "reviewer_b"):
        e4_rows = e4_packet(fixed, reviewer)
        hard_packet = hard_negative_packet(hard_rows, reviewer)
        e4_path = out_dir / f"e4_{reviewer}.jsonl"
        hard_path = out_dir / f"hard_negatives_{reviewer}.jsonl"
        _write_jsonl(e4_path, e4_rows)
        _write_jsonl(hard_path, hard_packet)
        outputs.extend((e4_path, hard_path))
    return {
        "e4_rows_per_reviewer": len(fixed.get("cases") or []),
        "hard_negative_rows_per_reviewer": len(hard_rows),
        "packets": [path.relative_to(ROOT).as_posix() for path in outputs],
        "independence_rule": "reviewers exchange no votes before both files are frozen",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-set", type=Path, default=E4_SET)
    parser.add_argument("--hard-queue", type=Path, default=HARD_QUEUE)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.fixed_set, args.hard_queue, args.out_dir),
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
