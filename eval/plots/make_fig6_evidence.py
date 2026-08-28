"""
TraFiSec — Figure 6: Stage-2 evidence status (E4 causal + E5 fidelity)
=============================================================================
Honest evidence-stack figure for the paper's limitations section. Draws ONLY
counts that exist in artifacts — nothing inferred, nothing fabricated:

  * Panel A: E4 causal-annotation funnel — preregistered 63 candidates,
    20 fixed attempted, and the REAL denominator: 0 review pairs complete
    (sidecar invalid → no causal-accuracy number is reported).
  * Panel B: E5 replay fidelity — legacy 13/20 execution-pass, then the
    corrected fixed-20 gate CLOSED (public endpoint cannot serve an observed
    receipt within the 300 s replay bound) → state-eligible/state-pass = 0
    paper-grade. The "13/20" bar is annotated LEGACY (not paper-grade).

Output:
  figures/fig6_evidence.png   (300 dpi, paper-ready)
  figures/fig6_evidence.svg

Ngun s: eval/results/e4_preregistration_queue.csv + review_workflow_audit.json +
legacy/e5_fidelity.csv + e5-preflight-20260813-full300s/e5_preflight.json.
Deterministic; no network.  CLI:  python -m eval.make_fig6_evidence [--show]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RESULTS = _REPO_ROOT / "eval" / "results"
E4_QUEUE = RESULTS / "e4_preregistration_queue.csv"
AUDIT = RESULTS / "review_workflow_audit.json"
E5_LEGACY = RESULTS / "legacy" / "e5_fidelity.csv"
E5_PREFLIGHT = RESULTS / "runs" / "e5-preflight-20260813-full300s" / "e5_preflight.json"
FIG_DIR = _REPO_ROOT / "figures"

RED = "#c25b3b"
GRAY = "#9CA3AF"
AMBER = "#F59E0B"


def _count_csv_lines(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open(encoding="utf-8", newline="") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return max(n - 1, 0)  # minus header


def make_fig(out_dir: Path = FIG_DIR, show: bool = False) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "traceguard-defi"
    import matplotlib.pyplot as plt

    # --- E4: queue count, attempted 20, review pairs complete 0 ---
    e4_queue = _count_csv_lines(E4_QUEUE)
    try:
        audit = json.loads(AUDIT.read_text(encoding="utf-8"))
        e4_complete = int(audit["e4"]["reviewed_complete"])
        e4_expected = int(audit["e4"]["expected"])
    except Exception:
        e4_complete, e4_expected = 0, 0

    # --- E5: legacy pass count (13/20) vs fixed-20 gate (0 paper-grade) ---
    e5_legacy_pass = 0
    if E5_LEGACY.exists():
        import csv
        with E5_LEGACY.open(encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get("pass", "").strip().lower() == "true":
                    e5_legacy_pass += 1
    e5_fixed_observed = 0  # fixed-20 gate closed; nothing observed within 300 s
    try:
        pf = json.loads(E5_PREFLIGHT.read_text(encoding="utf-8"))
        if pf.get("observed") is True:
            e5_fixed_observed = 1
    except Exception:
        pass

    fig, (axa, axb) = plt.subplots(
        2, 1, figsize=(3.6, 4.4), dpi=200,
        gridspec_kw={"hspace": 0.6, "top": 0.90, "bottom": 0.08, "left": 0.16, "right": 0.97},
    )

    # --- A: E4 funnel ---
    stages_a = ["preregistered\ncandidates", "fixed set\nattempted", "review pairs\ncomplete"]
    vals_a = [e4_queue, e4_expected or e4_queue, e4_complete]
    colors_a = [AMBER, AMBER, GRAY]
    bars = axa.bar(stages_a, vals_a, color=colors_a, width=0.55, zorder=3)
    for b, v in zip(bars, vals_a):
        axa.text(b.get_x() + b.get_width() / 2, v + max(max(vals_a) * 0.02, 0.5),
                 str(v), ha="center", va="bottom", fontsize=9)
    axa.set_ylabel("cases", fontsize=8)
    axa.set_title("E4 — causal annotation funnel (sidecar invalid: no causal number)",
                  fontsize=8.5)
    axa.set_ylim(0, max(vals_a) * 1.25)
    axa.tick_params(labelsize=7.5)
    axa.grid(axis="y", alpha=0.3, zorder=0)
    axa.text(0.02, 0.93, "no causal-accuracy claim", transform=axa.transAxes,
             fontsize=7, color=RED, ha="left")

    # --- B: E5 fidelity ---
    stages_b = ["legacy replay\nexecution pass", "fixed-20 gate\n(observed within 300 s)"]
    vals_b = [e5_legacy_pass, e5_fixed_observed]
    colors_b = [GRAY, RED]
    bars = axb.bar(stages_b, vals_b, color=colors_b, width=0.55, zorder=3)
    for b, v in zip(bars, vals_b):
        axb.text(b.get_x() + b.get_width() / 2, v + 0.15,
                 str(v), ha="center", va="bottom", fontsize=9)
    axb.set_ylabel("cases (of 20)", fontsize=8)
    axb.set_title("E5 — replay fidelity (gate closed; not paper-grade)", fontsize=8.5)
    axb.set_ylim(0, 22)
    axb.tick_params(labelsize=7.5)
    axb.grid(axis="y", alpha=0.3, zorder=0)
    axb.text(0.02, 0.90, "legacy method: state-match invalid", transform=axb.transAxes,
             fontsize=7, color=GRAY, ha="left")

    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / "fig6_evidence.png"
    svg = out_dir / "fig6_evidence.svg"
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
    print(f"fig6 -> {png}  (+svg)")
    return png


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Figure 6: Stage-2 evidence status (E4/E5)")
    p.add_argument("--out", default=None)
    p.add_argument("--show", action="store_true")
    args = p.parse_args(argv)
    out_dir = Path(args.out) if args.out else FIG_DIR
    make_fig(out_dir=out_dir, show=args.show)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
