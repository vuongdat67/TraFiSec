"""Read-only AMM storage-layout triage for frozen f_orc candidates.

This tool intentionally reports candidates, not proof.  A ``getReserves``
selector does not establish a storage layout; a layout-specific mutation is
allowed only after authenticated prestate and code/ABI evidence are present.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def _walk(node: Any):
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get("calls") or []:
        yield from _walk(child)


def _load_context(case_id: str, root: Path) -> Path | None:
    slug = case_id.removeprefix("defihacklabs-").split("-")[0]
    candidates = sorted(root.glob(f"b2-context-{slug}*"))
    return candidates[0] if candidates else None


def triage_case(case: dict, trace_row: dict, runs_root: Path) -> dict[str, str]:
    pools: set[str] = set()
    tree = ((trace_row.get("trace") or {}).get("tree") or {})
    for node in _walk(tree):
        data = str(node.get("input") or "")
        if data[2:10].lower() == "0902f1ac" and node.get("to"):
            pools.add(str(node["to"]).lower())
    context = _load_context(str(case.get("case_id", "")), runs_root)
    if not context or not (context / "prestates.json").is_file():
        return {"case_id": case.get("case_id", ""), "pool": ";".join(sorted(pools)),
                "layout_status": "prestate-unavailable", "evidence": ""}
    prestates = json.loads((context / "prestates.json").read_text())
    accounts: dict[str, dict] = {}
    for item in prestates:
        trace = item.get("trace", {})
        accounts.update(json.loads(trace) if isinstance(trace, str) else trace)
    observed = []
    for pool in sorted(pools):
        storage = accounts.get(pool, {}).get("storage", {})
        # This is only a candidate signal: a non-zero slot does not prove ABI.
        slot8 = storage.get("0x" + "0" * 63 + "8")
        if slot8:
            observed.append(f"{pool}:slot8={slot8}")
    status = "packed-slot-candidate" if observed else "storage-layout-unproven"
    return {"case_id": case.get("case_id", ""), "pool": ";".join(sorted(pools)),
            "layout_status": status, "evidence": ";".join(observed)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-set", type=Path, default=Path("eval/e4_fixed_set_v2.json"))
    parser.add_argument("--oracle-triage", type=Path,
                        default=Path("eval/results/e4/triage/e4_oracle_mode_triage_fixed20.csv"))
    parser.add_argument("--trace-cache", type=Path, default=Path("eval/results/e1_trace_cache.jsonl"))
    parser.add_argument("--runs-root", type=Path, default=Path("eval/results/runs"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    amm_ids = set()
    with args.oracle_triage.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("classification") == "amm-reserve":
                amm_ids.add(row["case_id"])
    traces = {}
    with args.trace_cache.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            traces[str(row.get("case_id") or row.get("tx_hash"))] = row
            traces[str(row.get("tx_hash", "")).lower()] = row
    fixed = json.loads(args.fixed_set.read_text())["cases"]
    rows = []
    for case in fixed:
        if case.get("case_id") not in amm_ids:
            continue
        trace = traces.get(str(case.get("tx_hash", "")).lower(), {})
        rows.append(triage_case(case, trace, args.runs_root))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["case_id", "pool", "layout_status", "evidence"]
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(f"{row['case_id']}\t{row['layout_status']}\t{row['pool']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
