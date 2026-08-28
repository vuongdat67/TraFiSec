"""Migrate stored E4 run CSVs from ambiguous loss_* names to explicit names."""

from __future__ import annotations

from pathlib import Path

from eval.e4.reporting import load_results, write_csv


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    count = 0
    for path in sorted((ROOT / "eval" / "results" / "runs").glob("e4-*/e4_necessity.csv")):
        rows = load_results(path)
        if rows and any(field in rows[0] for field in ("loss_S", "loss_Sm", "dloss")):
            write_csv(rows, path)
            print(path)
            count += 1
    print(f"migrated: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
