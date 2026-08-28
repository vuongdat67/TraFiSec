"""
TraFiSec — Figure 4: E2 held-family + E3 structural near-negatives
==========================================================================
Two-panel robustness figure (1-column):

  * Panel A (top): E2 held-family AUPRC — 6 primary families (n>=3), sorted,
    from `e1_e3_robustness.csv`. Bridge / rug-pull (n<3) are diagnostic-only
    and excluded (their AUPRC is not a family-generalization claim).
  * Panel B (bottom): realized FPR at the FROZEN 1% budget — random-benign
    test (0.74%) vs structural near-negative test (16.77%), annotated with the
    AUPRC drop 0.641 -> 0.557. Log scale (FPR spans ~1.7 decades).

Output:
  figures/fig4_e2_e3.png   (300 dpi, paper-ready)
  figures/fig4_e2_e3.svg

Ngun s: eval/results/e1_e3_robustness.csv (artifact — khng sa tay).
Deterministic; no network.  CLI:  python -m eval.make_fig4_e2_e3 [--show]
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RESULT_CSV = _REPO_ROOT / "eval" / "results" / "e1_e3_robustness.csv"
FIG_DIR = _REPO_ROOT / "figures"

FAMILY_ORDER = ["accounting", "oracle", "governance/access", "flash-loan", "token", "precision"]


def _load_rows() -> list[dict]:
    with RESULT_CSV.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _row(rows: list[dict], experiment: str, fp_budget: float) -> dict | None:
    for r in rows:
        try:
            b = float(r["fp_budget"])
        except (KeyError, ValueError):
            continue
        if r.get("experiment") == experiment and b == fp_budget:
            return r
    return None


def make_fig(out_dir: Path = FIG_DIR, show: bool = False) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "traceguard-defi"
    import matplotlib.pyplot as plt

    rows = _load_rows()

    # --- Panel A: E2 held-family AUPRC (primary families, n>=3) ---
    family = {}
    for r in rows:
        if r.get("experiment") != "E2-held-family":
            continue
        try:
            b = float(r["fp_budget"])
        except (KeyError, ValueError):
            continue
        fam = r.get("family", r.get("held_family", ""))
        if b == 0.01 and r.get("family_primary") == "True" and fam:
            family[fam] = {
                "auc_pr": float(r["auc_pr"]),
                "n": int(r["n_attack"]),
                "recall": float(r["recall"]),
            }
    order = [f for f in FAMILY_ORDER if f in family]
    names = [f"{f} (n={family[f]['n']})" for f in order]
    aucs = [family[f]["auc_pr"] for f in order]
    recalls = [family[f]["recall"] for f in order]

    # --- Panel B: E3 realized FPR @ frozen 1% budget ---
    e1 = _row(rows, "E1-repeated-stratified", 0.01)      # split_id 42 fixed
    e3 = _row(rows, "E3-near-negative", 0.01)
    assert e1 is not None and e3 is not None, "missing E1/E3 rows in robustness CSV"
    fpr_e1 = float(e1["realized_fpr"])
    fpr_e3 = float(e3["realized_fpr"])
    auc_e1 = float(e1["auc_pr"])
    auc_e3 = float(e3["auc_pr"])
    n_bg_e1 = int(e1["n_benign"])
    n_bg_e3 = int(e3["n_benign"])

    fig, (axa, axb) = plt.subplots(
        2, 1, figsize=(3.6, 4.4), dpi=200,
        gridspec_kw={"hspace": 0.55, "top": 0.90, "bottom": 0.08, "left": 0.16, "right": 0.97},
    )

    # --- A: held-family AUPRC bars ---
    colors = ["#4F46E5", "#0D9488", "#64748B", "#F59E0B", "#8a6ab5", "#c25b3b"]
    bars = axa.barh(names, aucs, color=colors, height=0.62, zorder=3)
    for b, auc, rec in zip(bars, aucs, recalls):
        axa.text(b.get_width() + 0.012, b.get_y() + b.get_height() / 2,
                 f"{auc:.3f}", va="center", ha="left", fontsize=8)
    axa.set_xlim(0, 1.0)
    axa.axvline(0.5, color="gray", ls=":", lw=0.8)
    axa.set_xlabel("AUPRC (held-out family)", fontsize=8)
    axa.set_title("E2 — held-family AUPRC (n≥3)", fontsize=9)
    axa.tick_params(axis="y", labelsize=7.5)
    axa.tick_params(axis="x", labelsize=7.5)
    axa.grid(axis="x", alpha=0.3, zorder=0)

    # --- B: realized FPR @ 1% budget, log scale ---
    cats = [f"random benign\n(n={n_bg_e1})", f"structural near-neg\n(n={n_bg_e3})"]
    fprs = [fpr_e1 * 100, fpr_e3 * 100]
    bars = axb.bar(cats, fprs, color=["#1a6fb0", "#c25b3b"], width=0.55, zorder=3)
    for b, f in zip(bars, fprs):
        axb.text(b.get_x() + b.get_width() / 2, f * 1.12, f"{f:.2f}%",
                 ha="center", va="bottom", fontsize=8)
    axb.axhline(1.0, color="gray", ls=":", lw=0.8)
    axb.text(1.02, 1.0, "budget 1%", va="bottom", ha="left", fontsize=6.5, color="gray", rotation=90)
    axb.set_yscale("log")
    axb.set_ylim(0.3, 50)
    axb.set_ylabel("realized FPR (%)", fontsize=8)
    axb.set_title(f"E3 — FPR@1% budget (AUPRC {auc_e1:.3f}→{auc_e3:.3f})", fontsize=9)
    axb.set_xticks(range(len(cats)))
    axb.set_xticklabels(cats, fontsize=7)
    axb.tick_params(axis="y", labelsize=7.5)
    axb.grid(axis="y", which="both", alpha=0.3, zorder=0)

    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / "fig4_e2_e3.png"
    svg = out_dir / "fig4_e2_e3.svg"
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
    print(f"fig4 -> {png}  (+svg)")
    return png


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Figure 4: E2 held-family + E3 near-negatives")
    p.add_argument("--out", default=None)
    p.add_argument("--show", action="store_true")
    args = p.parse_args(argv)
    out_dir = Path(args.out) if args.out else FIG_DIR
    make_fig(out_dir=out_dir, show=args.show)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
