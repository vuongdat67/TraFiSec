"""
TraFiSec — Table: E6 Stage-2 replay latency & operator capacity
=======================================================================
Generates the LaTeX booktabs rows for the E6 operational table from the
measured artifact `e6_latency.csv`. Nothing is typed by hand; the paper must
always show exactly what the CSV holds.

Ngun s: eval/results/e6_latency.csv (artifact — khng sa tay).
Deterministic; no network.  CLI:  python -m eval.make_tab_e6 [--out FILE]

Output (stdout by default): a `\\begin{tabular}...\\end{tabular}` block the
paper author pastes into main.tex (tab:e6). The CSV labels the service-time
rows `measured` and the worker rows `estimated`; those provenance tags are
printed below the table as a note.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RESULT_CSV = _REPO_ROOT / "eval" / "results" / "e6_latency.csv"


def _rows() -> dict[str, float]:
    out: dict[str, float] = {}
    with RESULT_CSV.open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                out[r["metric"]] = float(r["value"])
            except (KeyError, ValueError):
                continue
    return out


def fmt_seconds(ms: float) -> str:
    """2368000 ms -> '2 368' (thin-space group separator, IEEE style)."""
    s = int(round(ms / 1000.0))
    return f"{s:,}".replace(",", r"\,")  # thin space


def fmt_int(v: float) -> str:
    return f"{int(round(v)):,}".replace(",", r"\,")


def make_tab() -> str:
    m = _rows()
    rows = [
        ("Service time / case, $p_{50}$", f"{fmt_seconds(m['replay_per_case_p50'])}\\,s", "measured"),
        ("Service time / case, $p_{95}$", f"{fmt_seconds(m['replay_per_case_p95'])}\\,s", "measured"),
        ("Workers @ 10k cases/day, 70\\% util ($p_{50}$)", fmt_int(m["workers_required_at_p50"]), "estimated"),
        ("Workers @ 10k cases/day, 70\\% util ($p_{95}$)", fmt_int(m["workers_required_at_p95"]), "estimated"),
    ]
    lines = [
        r"\begin{table}[htbp]",
        r"\caption{Stage-2 replay latency and operator capacity (E6)}",
        r"\label{tab:e6}",
        r"\centering",
        r"\begin{tabular}{ll}",
        r"\toprule",
        r"\textbf{Metric:} & \textbf{Value:} \\",
        r"\midrule",
    ]
    for label, val, _tag in rows:
        lines.append(f"{label} & {val} \\\\")
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\\",
        r"\footnotesize Service time measured from 10 E5 pilot logs; worker count",
        r"estimated from Little's-law capacity at 70\% utilization (see",
        r"\texttt{eval/results/e6\_latency.csv}).",
        r"\end{table}",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Generate E6 LaTeX table from artifact")
    p.add_argument("--out", default=None, help="write to file instead of stdout")
    args = p.parse_args(argv)
    text = make_tab()
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"E6 table -> {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
