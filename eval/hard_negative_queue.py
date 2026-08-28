"""Build a deterministic review queue for matched hard-negative annotation.

The output contains *candidates*, never verified benign labels. Matching uses
block proximity and generic trace structure only; protocol identity and benign
intent require manual review under the accompanying schema.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np

from .e1_common import (FLASH_SELECTORS, ORACLE_SELECTORS, SWAP_SELECTORS,
                        selectors_from_trace, trace_from_cache)
from .e1_robustness import _is_near_negative
from .e1_train import RESULTS_DIR, build_dataset
from .run_manifest import utc_run_id, write_manifest

ROOT = Path(__file__).resolve().parent.parent
CACHE_DEFAULT = RESULTS_DIR / "e1_trace_cache.jsonl"
# Approximately 30 days at 12-second Ethereum blocks. Frozen before review;
# reviewers cannot widen it after seeing candidate intent or labels.
MATCH_WINDOW_BLOCKS = 216_000


def _features(row: dict) -> tuple[np.ndarray, dict]:
    trace = trace_from_cache(row.get("trace") or {})
    selectors = set(selectors_from_trace(trace))
    meta = {
        "n_calls": len(trace.get("flat_calls") or []),
        "n_logs": len(trace.get("logs") or []),
        "has_flash": bool(selectors & set(FLASH_SELECTORS)),
        "has_swap": bool(selectors & set(SWAP_SELECTORS)),
        "has_oracle": bool(selectors & set(ORACLE_SELECTORS)),
    }
    vector = np.array([
        math.log1p(meta["n_calls"]), math.log1p(meta["n_logs"]),
        float(meta["has_flash"]), float(meta["has_swap"]),
        float(meta["has_oracle"]),
    ])
    return vector, meta


def _cluster_key(row: dict) -> str:
    """Coarse transaction-family key: same caller + same contract + same
    top-level selector path.

    Two transactions from the same bot hitting the same router with the same
    call-selector sequence are the same *family* even when their calldata
    differs (different token/position IDs, as in the block-25114801 case).
    This key deliberately ignores calldata params so it clusters repeated-bot
    activity without needing full protocol/ABI decoding.
    """
    trace = trace_from_cache(row.get("trace") or {})
    frm = (trace.get("from") or "").lower()
    to = (trace.get("to") or "").lower()
    path = "|".join(selectors_from_trace(trace))
    return f"{frm}:{to}:{path}"


def build_queue(cache: Path, per_incident: int = 2,
                max_per_cluster: int = 2) -> tuple[list[dict], dict]:
    ds = build_dataset(cache)
    attacks = sorted((row for row in ds["rows"] if row["label"] == "attack"),
                     key=lambda row: (int(row.get("block") or 0), row["tx_hash"]))
    candidates = [row for row in ds["rows"]
                  if row["label"] == "benign" and _is_near_negative(row["row"])]
    candidate_data = []
    for row in candidates:
        vector, meta = _features(row["row"])
        cluster = _cluster_key(row["row"])
        candidate_data.append((row, vector, meta, cluster))
    if not candidate_data:
        return [], {"reason": "no structural candidates"}
    matrix = np.stack([item[1] for item in candidate_data])
    scale = matrix.std(axis=0)
    scale[scale < 1e-9] = 1.0
    used: set[str] = set()
    cluster_used: Counter[str] = Counter()
    cluster_incidents: dict[str, set[str]] = {}
    output: list[dict] = []
    for attack in attacks:
        attack_vector, attack_meta = _features(attack["row"])
        attack_block = int(attack.get("block") or 0)
        attack_case_id = attack["row"].get("attack_id") or attack["tx_hash"]
        ranked = []
        for candidate, vector, meta, cluster in candidate_data:
            if candidate["tx_hash"] in used:
                continue
            if cluster_used[cluster] >= max_per_cluster:
                continue
            structure_distance = float(np.linalg.norm((vector - attack_vector) / scale))
            block_distance = abs(int(candidate.get("block") or 0) - attack_block)
            time_penalty = min(block_distance / 1_000_000, 5.0) * 0.25
            ranked.append((structure_distance + time_penalty, block_distance,
                           candidate["tx_hash"], candidate, meta, cluster))
        for rank, item in enumerate(sorted(ranked)[:per_incident], 1):
            score, block_distance, _, candidate, meta, cluster = item
            used.add(candidate["tx_hash"])
            cluster_used[cluster] += 1
            cluster_incidents.setdefault(cluster, set()).add(attack_case_id)
            output.append({
                "attack_case_id": attack_case_id,
                "attack_tx_hash": attack["tx_hash"],
                "attack_type": attack["attack_type"],
                "attack_block": attack_block,
                "candidate_tx_hash": candidate["tx_hash"],
                "candidate_block": candidate.get("block"),
                "rank": rank,
                "match_distance": round(score, 6),
                "block_distance": block_distance,
                "window_blocks": MATCH_WINDOW_BLOCKS,
                "within_window": block_distance <= MATCH_WINDOW_BLOCKS,
                "candidate_calls": meta["n_calls"],
                "candidate_logs": meta["n_logs"],
                "candidate_has_flash": meta["has_flash"],
                "candidate_has_swap": meta["has_swap"],
                "candidate_has_oracle": meta["has_oracle"],
                "cluster_id": cluster,
                "same_transaction_family": False,
                "protocol_match": "unknown",
                "review_status": "pending",
                "verified_benign": "unknown",
                "review_note": "",
            })
    summary = {
        "incidents": len(attacks),
        "structural_candidate_pool": len(candidates),
        "queue_rows": len(output),
        "per_incident_requested": per_incident,
        "max_per_cluster": max_per_cluster,
        "unique_candidate_hashes": len({row["candidate_tx_hash"] for row in output}),
        "distinct_clusters": len(cluster_used),
        "clusters_spanning_multiple_incidents": sum(
            1 for incidents in cluster_incidents.values() if len(incidents) > 1),
        "candidate_signal_counts": dict(Counter(
            "flash" if row["candidate_has_flash"] else
            "oracle" if row["candidate_has_oracle"] else
            "swap" if row["candidate_has_swap"] else "complexity_only"
            for row in output
        )),
        "paper_eligible_hard_negatives": 0,
        "preregistered_window_blocks": MATCH_WINDOW_BLOCKS,
        "within_preregistered_window": sum(row["within_window"] for row in output),
        "warning": "Rows are an annotation queue, not verified hard negatives. Protocol match and benign intent require two-reviewer adjudication. same_transaction_family=true rows share a (from,to,selector-path) cluster with another incident's candidate(s) and should be reviewed together, not treated as independent evidence.",
    }
    for row in output:
        row["same_transaction_family"] = len(
            cluster_incidents[row["cluster_id"]]) > 1
    return output, summary


def run(cache: Path = CACHE_DEFAULT, out_dir: Path = RESULTS_DIR,
        per_incident: int = 2, max_per_cluster: int = 2) -> dict:
    rows, summary = build_queue(cache, per_incident, max_per_cluster)
    run_id = utc_run_id("hard-negative-queue")
    csv_path = out_dir / "hard_negative_review_queue.csv"
    json_path = out_dir / "hard_negative_review_queue.json"
    out_dir.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [],
                                lineterminator="\n")
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8", newline="\n")
    write_manifest(out_dir / "hard_negative_review_queue_manifest.json",
                   run_id=run_id, experiment="hard-negative-review-queue",
                   repository=ROOT, inputs={"trace_cache": cache},
                   parameters={"per_incident": per_incident,
                               "max_per_cluster": max_per_cluster},
                   extra={"outputs": [str(csv_path), str(json_path)]})
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build an unverified hard-negative review queue")
    parser.add_argument("--cache", type=Path, default=CACHE_DEFAULT)
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--per-incident", type=int, default=2)
    parser.add_argument("--max-per-cluster", type=int, default=2,
                        help="Cap on total queue rows sharing the same "
                             "(from,to,selector-path) transaction family, "
                             "across all incidents.")
    args = parser.parse_args(argv)
    print(json.dumps(run(args.cache, args.out_dir, args.per_incident,
                         args.max_per_cluster),
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
