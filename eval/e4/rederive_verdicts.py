"""Re-derive stored E4 verdicts after a pure verdict-policy correction.

This deliberately consumes existing CSV evidence only; it never replays B2
or contacts an RPC provider.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval.e4.reporting import build_evidence_graph, load_results, write_csv


ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "eval" / "results" / "runs"
ATTRIBUTION_INCOMPLETE_CASES = {"defihacklabs-veth-2024-11-14"}


def rederive(path: Path) -> int:
    rows = load_results(path)
    changed = 0
    for row in rows:
        # Removal-style NOT_NECESSARY requires measured baseline harm.  Do
        # not reinterpret unrelated legacy rows lacking a verdict.
        if row.get("verdict") == "NOT_NECESSARY" and row.get("harm_S") != "HARM":
            row["verdict"] = "INCONCLUSIVE-baseline-harm"
            row["cause"] = ""
            note = row.get("note", "")
            marker = "verdict re-derived: baseline harm was not HARM"
            if marker not in note:
                row["note"] = f"{note}; {marker}" if note else marker
            changed += 1
        elif (row.get("case") in ATTRIBUTION_INCOMPLETE_CASES
              and row.get("verdict") == "INCONCLUSIVE-baseline-harm"):
            row["verdict"] = "INCONCLUSIVE-attribution-incomplete"
            row["cause"] = ""
            note = row.get("note", "")
            marker = "verdict re-derived: post-target same-block scope unavailable"
            if marker not in note:
                row["note"] = f"{note}; {marker}" if note else marker
            changed += 1
        elif (row.get("verdict") == "INCONCLUSIVE-revert"
              and row.get("observed") == "True"
              and row.get("harm_S") != "HARM"):
            row["verdict"] = (
                "INCONCLUSIVE-harm-unmeasured"
                if row.get("harm_S") == "UNKNOWN"
                else "INCONCLUSIVE-baseline-harm")
            row["cause"] = ""
            note = row.get("note", "")
            marker = "verdict re-derived: baseline-harm precedence"
            if marker not in note:
                row["note"] = f"{note}; {marker}" if note else marker
            changed += 1
    if changed:
        write_csv(rows, path)
        graph = path.with_name("e4_evidence_graph.json")
        graph.write_text(
            json.dumps(build_evidence_graph(rows), indent=2) + "\n",
            encoding="utf-8",
        )
    return changed


def main() -> int:
    total = 0
    for path in sorted(RUNS.glob("e4-*/e4_necessity.csv")):
        changed = rederive(path)
        if changed:
            print(f"{path}: {changed} row(s) re-derived")
            total += changed
    print(f"total changed: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
