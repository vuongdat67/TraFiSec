"""Classify frozen f_orc candidates from cached callTracer evidence only.

This is a read-only pre-replay triage.  It never contacts an RPC and never
selects a replacement case.  A trace with neither recognized price-feed nor
AMM-reserve selectors is deliberately classified as ``unknown``.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


EXTERNAL_PRICE_SELECTORS = {
    "50d25bcd": "latestAnswer",
    "feaf968c": "latestRoundData",
    "85bb7d69": "answer",
    "59e02dd7": "peek",
    "4197d7f0": "getUnderlyingPrice",
}
AMM_RESERVE_SELECTORS = {
    "0902f1ac": "getReserves",
    "3850c7bd": "slot0",
}


def _walk(node: Any):
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get("calls") or []:
        yield from _walk(child)


def _trace_tree(row: dict) -> dict | None:
    trace = row.get("trace") or {}
    tree = trace.get("tree") if isinstance(trace, dict) else None
    return tree if isinstance(tree, dict) else None


def classify_trace(row: dict) -> dict[str, Any]:
    tree = _trace_tree(row)
    external: set[str] = set()
    amm: set[str] = set()
    if tree:
        for node in _walk(tree):
            input_data = str(node.get("input") or "")
            selector = input_data[2:10].lower() if input_data.startswith("0x") else ""
            if selector in EXTERNAL_PRICE_SELECTORS:
                external.add(f"0x{selector}={EXTERNAL_PRICE_SELECTORS[selector]}")
            if selector in AMM_RESERVE_SELECTORS:
                amm.add(f"0x{selector}={AMM_RESERVE_SELECTORS[selector]}")
    if external:
        classification = "external-price-feed"
    elif amm:
        classification = "amm-reserve"
    else:
        classification = "unknown"
    return {
        "case_id": row.get("case_id", ""),
        "tx_hash": row.get("tx_hash", ""),
        "classification": classification,
        "external_evidence": "; ".join(sorted(external)),
        "amm_evidence": "; ".join(sorted(amm)),
        "trace_available": bool(tree),
    }


def load_fixed_candidates(fixed_set: Path) -> list[dict]:
    payload = json.loads(fixed_set.read_text(encoding="utf-8"))
    return [
        item for item in payload.get("cases", [])
        if "f_orc" in str(item.get("supported_from_cache", ""))
    ]


def load_cache(cache_path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with cache_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid cache JSON at line {line_number}: {exc}") from exc
            tx_hash = str(row.get("tx_hash") or "").lower()
            if tx_hash:
                rows[tx_hash] = row
    return rows


def triage(fixed_set: Path, cache_path: Path) -> list[dict]:
    cache = load_cache(cache_path)
    results = []
    for item in load_fixed_candidates(fixed_set):
        tx_hash = str(item.get("tx_hash") or "").lower()
        row = cache.get(tx_hash, {"case_id": item.get("case_id"), "tx_hash": tx_hash})
        result = classify_trace({**item, **row})
        result["case_id"] = item.get("case_id", "")
        result["tx_hash"] = item.get("tx_hash", "")
        results.append(result)
    return results


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["case_id", "tx_hash", "classification", "external_evidence",
              "amm_evidence", "trace_available"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-set", type=Path, default=Path("eval/e4_fixed_set_v2.json"))
    parser.add_argument("--cache", type=Path, default=Path("eval/results/e1_trace_cache.jsonl"))
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    rows = triage(args.fixed_set, args.cache)
    for row in rows:
        evidence = row["external_evidence"] or row["amm_evidence"] or "none"
        print(f"{row['case_id']}\t{row['classification']}\t{evidence}\tcache={row['trace_available']}")
    print("summary", dict(Counter(row["classification"] for row in rows)))
    if args.out:
        write_csv(rows, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
