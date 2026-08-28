"""Deterministic Stage-2 systematic-subset selector.

Selection is based only on the frozen E4 fixed-20 queue and technical metadata.
It never reads ground-truth factors, harm, replay outcomes, or reviewer votes.
Runtime/provider failures remain execution results, not selection signals.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_QUEUE = ROOT / "eval" / "e4_fixed_set_v2.json"
CASE_COUNT = 5
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _supported_factors(row: dict) -> list[str]:
    return [item for item in str(row.get("supported_from_cache") or "").split("+") if item]


def is_technically_selectable(row: dict) -> tuple[bool, list[str]]:
    """Check pre-replay technical requirements, without interpreting outcomes."""
    reasons: list[str] = []
    if not TX_HASH_RE.fullmatch(str(row.get("tx_hash") or "")):
        reasons.append("invalid_tx_hash")
    if not isinstance(row.get("block"), int) or row["block"] <= 0:
        reasons.append("invalid_block")
    supported = _supported_factors(row)
    if not supported:
        reasons.append("no_supported_mutation_in_cache")
    if any("?" in factor for factor in supported):
        reasons.append("uncertain_supported_mutation")
    if not str(row.get("trace_evidence") or "").strip():
        reasons.append("missing_trace_evidence")
    return not reasons, reasons


def load_fixed_queue(path: Path = FIXED_QUEUE) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("name") != "TraceGuard E4 blind fixed-20 attempted set":
        raise ValueError("unexpected fixed queue identity")
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise ValueError("fixed queue must contain exactly 20 cases")
    return payload


def select_subset(path: Path = FIXED_QUEUE, count: int = CASE_COUNT) -> tuple[list[dict], list[dict]]:
    """Return first ``count`` selectable rows and deterministic exclusions."""
    if count <= 0:
        raise ValueError("subset count must be positive")
    queue = load_fixed_queue(path)
    selected: list[dict] = []
    exclusions: list[dict] = []
    for queue_index, row in enumerate(queue["cases"]):
        selectable, reasons = is_technically_selectable(row)
        if selectable and len(selected) < count:
            selected.append({
                "subset_index": len(selected),
                "queue_index": queue_index,
                "case_id": row["case_id"],
                "tx_hash": row["tx_hash"],
                "block": row["block"],
                "supported_from_cache": row["supported_from_cache"],
            })
        elif not selectable:
            exclusions.append({
                "queue_index": queue_index,
                "case_id": row.get("case_id"),
                "reasons": reasons,
            })
    if len(selected) < count:
        raise ValueError(f"fixed queue has only {len(selected)} technically selectable cases")
    return selected, exclusions


def build_manifest(path: Path = FIXED_QUEUE, count: int = CASE_COUNT) -> dict:
    selected, exclusions = select_subset(path, count)
    return {
        "schema_version": 1,
        "experiment": "E4-stage2-systematic-subset",
        "status": "protocol-frozen-before-execution",
        "source_queue": str(path.relative_to(ROOT)),
        "source_queue_sha256": sha256_file(path),
        "selection_rule": "first N technically selectable cases in fixed-20 queue order",
        "subset_size": count,
        "technical_selectability": [
            "valid 32-byte transaction hash",
            "positive historical block number",
            "at least one supported mutation in frozen cache metadata",
            "no uncertain mutation marker",
            "non-empty trace evidence",
        ],
        "replacement_policy": (
            "Before execution only: skip rows failing technical selectability and "
            "continue queue order. After runtime starts, provider/transport/EVM "
            "failure never selects a replacement; record INCONCLUSIVE."
        ),
        "outcome_taxonomy": ["CAUSE", "NO_EFFECT", "REVERT", "INCONCLUSIVE"],
        "stop_conditions": [
            "missing prepared context or proof input",
            "baseline fidelity/proof gate failure",
            "mutation applicability or validity cannot be established",
            "harm oracle unavailable or valuation evidence missing",
            "provider/process timeout; record UNOBSERVED/INCONCLUSIVE, never causal",
        ],
        "review_protocol": {
            "reviewers": ["reviewer_a", "reviewer_b"],
            "independent_raw_vote_files": True,
            "adjudication_file_separate": True,
            "votes_append_only": True,
            "reviewers_read_same_frozen_packet": True,
        },
        "selected_cases": selected,
        "technical_exclusions_before_execution": exclusions,
    }


if __name__ == "__main__":
    print(json.dumps(build_manifest(), indent=2, ensure_ascii=False))
