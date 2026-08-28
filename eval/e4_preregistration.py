"""Build a blind E4 annotation/preregistration queue from trace evidence only."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .e1_common import (FLASH_SELECTORS, ORACLE_SELECTORS, selectors_from_trace,
                        trace_from_cache)
from .e1_train import RESULTS_DIR, build_dataset
from .run_manifest import utc_run_id, write_manifest
from core.mutate import START_SELECTOR

ROOT = Path(__file__).resolve().parent.parent
CACHE_DEFAULT = RESULTS_DIR / "e1_trace_cache.jsonl"
FIXED_SET_DEFAULT = ROOT / "eval" / "e4_fixed_set_v2.json"


def _even_sample(rows: list[dict], n: int) -> list[dict]:
    """Deterministically cover the chronological span of one blind stratum."""
    ordered = sorted(rows, key=lambda row: (int(row.get("block") or 0), row["case_id"]))
    if n >= len(ordered):
        return ordered
    if n <= 0:
        return []
    if n == 1:
        return [ordered[len(ordered) // 2]]
    indices = [round(i * (len(ordered) - 1) / (n - 1)) for i in range(n)]
    return [ordered[index] for index in indices]


def build_fixed_set(rows: list[dict]) -> dict:
    """Freeze 20 attempted cases using trace evidence, never legacy labels."""
    strata: dict[str, list[dict]] = {
        "flash_trace": [], "oracle_delegate": [],
        "oracle_only": [], "delegate_only": [], "other": [],
    }
    for row in rows:
        factors = set(filter(None, str(row["blind_candidate_factors"]).split("+")))
        if "f_fl" in factors:
            stratum = "flash_trace"
        elif "f_orc" in factors and "f_auth?" in factors:
            stratum = "oracle_delegate"
        elif factors == {"f_orc"}:
            stratum = "oracle_only"
        elif factors == {"f_auth?"}:
            stratum = "delegate_only"
        else:
            stratum = "other"
        strata[stratum].append(row)
    quotas = {"flash_trace": 4, "oracle_delegate": 8,
              "oracle_only": 4, "delegate_only": 4, "other": 0}
    selected: list[dict] = []
    used: set[str] = set()
    for stratum, quota in quotas.items():
        for row in _even_sample(strata[stratum], quota):
            selected.append({**row, "selection_stratum": stratum})
            used.add(row["case_id"])
    if len(selected) < 20:
        remaining = [row for row in rows if row["case_id"] not in used]
        for row in _even_sample(remaining, 20 - len(selected)):
            selected.append({**row, "selection_stratum": "deterministic_fill"})
    if len(selected) != 20 or len({row["case_id"] for row in selected}) != 20:
        raise ValueError("blind E4 fixed set must contain 20 unique cases")
    return {
        "schema_version": 1,
        "name": "TraceGuard E4 blind fixed-20 attempted set",
        "selection_source": "trace-only preregistration queue",
        "selection_rule": (
            "all four flash-trace candidates; chronological-span samples of "
            "8 oracle+delegate, 4 oracle-only, and 4 delegate-only candidates"
        ),
        "label_blinding": "legacy gt_factors and attack_type were not inputs",
        "replacement_policy": "no replacement after human eligibility or replay outcomes",
        "cases": [{
            "case_id": row["case_id"], "tx_hash": row["tx_hash"],
            "block": row["block"], "selection_stratum": row["selection_stratum"],
            "blind_candidate_factors": row["blind_candidate_factors"],
            "supported_from_cache": row["supported_from_cache"],
            "trace_evidence": row["trace_evidence"],
        } for row in selected],
    }


def build_queue(cache: Path) -> tuple[list[dict], dict]:
    ds = build_dataset(cache)
    rows: list[dict] = []
    for item in ds["rows"]:
        if item["label"] != "attack":
            continue
        raw = item["row"]
        trace = trace_from_cache(raw.get("trace") or {})
        selectors = set(selectors_from_trace(trace))
        factors: list[str] = []
        evidence: list[str] = []
        if selectors & set(FLASH_SELECTORS):
            factors.append("f_fl")
            evidence.append("known flash entrypoint in trace")
        if selectors & set(ORACLE_SELECTORS):
            factors.append("f_orc")
            evidence.append("known oracle getter in trace")
        top_input = str(trace.get("input") or "")
        if top_input.startswith("0x" + START_SELECTOR) and len(top_input) == 202:
            factors.append("f_swap")
            evidence.append("exact supported start(flash,amount,min) calldata")
        has_delegate = any(str(call.get("type") or "").upper() == "DELEGATECALL"
                           for call in trace.get("flat_calls") or [])
        if has_delegate:
            factors.append("f_auth?")
            evidence.append("delegatecall present; EIP-1967 storage probe required")
        if not factors:
            continue
        supported = [factor for factor in factors if not factor.endswith("?")]
        rows.append({
            # Public trace-cache rows often have no attack_id.  A stable
            # transaction-derived id keeps the blind queue deterministic and
            # prevents unrelated cache rows from collapsing into one case.
            "case_id": raw.get("attack_id") or f"tx-{item['tx_hash'][2:10]}",
            "tx_hash": item["tx_hash"],
            "block": item.get("block"),
            "blind_candidate_factors": "+".join(factors),
            "supported_from_cache": "+".join(supported),
            "trace_evidence": "; ".join(evidence),
            "security_objective_status": "pending_human_review",
            "harm_spec_status": "pending_human_review",
            "reviewer_1": "pending",
            "reviewer_2": "pending",
            "adjudication": "pending",
            "paper_eligible": False,
        })
    rows.sort(key=lambda row: (-len(row["supported_from_cache"].split("+"))
                               if row["supported_from_cache"] else 0,
                               row["case_id"]))
    summary = {
        "attack_rows_scanned": sum(item["label"] == "attack" for item in ds["rows"]),
        "queue_rows": len(rows),
        "with_cache_supported_factor": sum(bool(row["supported_from_cache"]) for row in rows),
        "candidate_factor_counts": dict(Counter(
            factor for row in rows for factor in row["blind_candidate_factors"].split("+") if factor
        )),
        "paper_eligible": 0,
        "label_blinding": "legacy gt_factors and attack_type are intentionally omitted",
        "warning": "Trace candidates are not causal labels. Eligibility requires schema-v2 human adjudication.",
    }
    return rows, summary


def run(cache: Path = CACHE_DEFAULT, out_dir: Path = RESULTS_DIR,
        fixed_set_path: Path = FIXED_SET_DEFAULT) -> dict:
    rows, summary = build_queue(cache)
    fixed_set = build_fixed_set(rows)
    run_id = utc_run_id("e4-preregister")
    csv_path = out_dir / "e4_preregistration_queue.csv"
    json_path = out_dir / "e4_preregistration_queue.json"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [],
                                lineterminator="\n")
        if rows:
            writer.writeheader()
            writer.writerows(rows)
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8", newline="\n")
    fixed_set_path.write_text(json.dumps(fixed_set, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8", newline="\n")
    write_manifest(out_dir / "e4_preregistration_manifest.json", run_id=run_id,
                   experiment="E4-blind-preregistration-queue", repository=ROOT,
                   inputs={"trace_cache": cache}, parameters={},
                   extra={"outputs": [str(csv_path), str(json_path), str(fixed_set_path)],
                          "fixed_set_cases": 20})
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build blind E4 annotation queue")
    parser.add_argument("--cache", type=Path, default=CACHE_DEFAULT)
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--fixed-set", type=Path, default=FIXED_SET_DEFAULT)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.cache, args.out_dir, args.fixed_set),
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
