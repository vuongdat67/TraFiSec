"""
TraFiSec — Figure 5: E6 Stage-2 latency & operator capacity
===================================================================
Two-panel operational figure (1-column):

  * Panel A: Stage-2 replay service time per case — p50 (515 s) and
    p95 (2368 s) measured from 10 E5 wall-time logs, as CDF-style bars.
  * Panel B: workers required to clear 10k cases/day at 70% utilization —
    86 @ p50 vs 392 @ p95 (little's-law style computation from e6_latency.csv).

Output:
  figures/fig5_e6.png   (300 dpi, paper-ready)
  figures/fig5_e6.svg

Ngun s: eval/results/e6_latency.csv (n=10 E5 logs; worker count = capacity rows).
Deterministic; no network.  CLI:  python -m eval.make_fig5_e6 [--show]
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
FIG_DIR = _REPO_ROOT / "figures"


def make_fig(out_dir: Path = FIG_DIR, show: bool = False) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "traceguard-defi"
    import matplotlib.pyplot as plt

    metric: dict[str, float] = {}
    with RESULT_CSV.open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                metric[r["metric"]] = float(r["value"])
            except (KeyError, ValueError):
                continue

    p50_ms = metric["replay_per_case_p50"]
    p95_ms = metric["replay_per_case_p95"]
    w_p50 = metric["workers_required_at_p50"]
    w_p95 = metric["workers_required_at_p95"]

    fig, (axa, axb) = plt.subplots(
        2, 1, figsize=(3.6, 4.2), dpi=200,
        gridspec_kw={"hspace": 0.55, "top": 0.90, "bottom": 0.08, "left": 0.16, "right": 0.97},
    )

    # --- A: service time per case ---
    labels_a = ["p50", "p95"]
    vals_a = [p50_ms / 1000.0, p95_ms / 1000.0]
    bars = axa.bar(labels_a, vals_a, color=["#0D9488", "#F59E0B"], width=0.5, zorder=3)
    for b, v in zip(bars, vals_a):
        axa.text(b.get_x() + b.get_width() / 2, v * 1.03, f"{v:,.0f} s",
                 ha="center", va="bottom", fontsize=8)
    axa.set_ylabel("service time / case", fontsize=8)
    axa.set_title("E6 — Stage-2 replay latency (n=10 E5 logs)", fontsize=8.5)
    axa.set_ylim(0, 3000)
    axa.tick_params(labelsize=7.5)
    axa.grid(axis="y", alpha=0.3, zorder=0)

    # --- B: workers @ 10k cases/day, 70% util ---
    labels_b = ["@ p50", "@ p95"]
    vals_b = [w_p50, w_p95]
    bars = axb.bar(labels_b, vals_b, color=["#0D9488", "#F59E0B"], width=0.5, zorder=3)
    for b, v in zip(bars, vals_b):
        axb.text(b.get_x() + b.get_width() / 2, v * 1.03, f"{v:,.0f}",
                 ha="center", va="bottom", fontsize=8)
    axb.set_ylabel("workers", fontsize=8)
    axb.set_title("E6 — capacity for 10k cases/day @ 70% util", fontsize=8.5)
    axb.set_ylim(0, 450)
    axb.tick_params(labelsize=7.5)
    axb.grid(axis="y", alpha=0.3, zorder=0)

    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / "fig5_e6.png"
    svg = out_dir / "fig5_e6.svg"
    fig.savefig(png, dpi=300, metadata={"Date": None})
    fig.savefig(svg, metadata={"Date": None})
    svg_text = svg.read_text(encoding="utf-8")
    svg.write_text(
        "\n".join(line.rstrip() for line in svg_text.splitlines()) + "\n",
        encoding="utf-8", newline="\n",
    )
    if show:
        plt.show()
    plt.close(fig)
    print(f"fig5 -> {png}  (+svg)")
    return png


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Figure 5: E6 latency & capacity")
    p.add_argument("--out", default=None)
    p.add_argument("--show", action="store_true")
    args = p.parse_args(argv)
    out_dir = Path(args.out) if args.out else FIG_DIR
    make_fig(out_dir=out_dir, show=args.show)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
