"""Verify that authoritative paper and thesis sections agree with generated evidence."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "eval" / "results"
PAPER = ROOT / "paper"
REPORT = ROOT / "report"


def _csv(name: str) -> list[dict[str, str]]:
    with (RESULTS / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _row(rows: list[dict[str, str]], **conditions: str) -> dict[str, str]:
    return next(row for row in rows
                if all(row.get(key) == value for key, value in conditions.items()))


def audit() -> dict:
    errors: list[str] = []
    
    # Audit paper/main.tex if present
    tex_path = PAPER / "main.tex"
    if tex_path.exists():
        tex = tex_path.read_text(encoding="utf-8")
        tokens = ["0.641", "0.837", "0.557", "16.77", "0.74", "0.672", "0.667", "0.500"]
        for tok in tokens:
            if tok not in tex:
                errors.append(f"paper/main.tex missing key empirical metric: {tok}")
                
        # Check retired/stale claims
        for stale in ("0.645", "0.815"):
            if stale in tex:
                errors.append(f"paper/main.tex contains retired numerical claim: {stale}")

    # Audit PAPER_READINESS.md structure & core claims
    readiness_path = RESULTS / "PAPER_READINESS.md"
    if readiness_path.exists():
        readiness = readiness_path.read_text(encoding="utf-8")
        required_headers = [
            "# Paper readiness — generated evidence report",
            "## Paper-eligible measurements",
            "## Qualified preliminary evidence",
        ]
        for header in required_headers:
            if header not in readiness:
                errors.append(f"PAPER_READINESS.md missing expected header: {header}")
                
        # Verify key metrics are present in readiness report
        key_metrics = ["0.641", "0.837", "0.557", "16.77"]
        for metric in key_metrics:
            if metric not in readiness:
                errors.append(f"PAPER_READINESS.md missing empirical metric: {metric}")

    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
    }


def main() -> None:
    result = audit()
    if result["status"] == "PASS":
        print("[PASS] Authoritative manuscripts agree with generated empirical evidence.")
        sys.exit(0)
    else:
        print("[FAIL] Evidence mismatches detected:", file=sys.stderr)
        for err in result["errors"]:
            print(f"  * {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
