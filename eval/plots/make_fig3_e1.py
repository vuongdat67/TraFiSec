"""
TraFiSec — Figure 3: E1 PR curves (eval/make_fig3_e1.py)
================================================================
Precision-recall curves on the same test split (seed 42) for:
  * Screener (4-view logistic fusion — fit trn train)
  * 3 baselines: rule_flash_oracle / invariant_balance / static_smartaxe

Output:
  figures/fig3_e1_prcurve.png   (300 dpi, paper-ready)
  figures/fig3_e1_prcurve.svg

Ngun s: cache (views recompute offline) + e1_train train_test_split +
fusion fit + e1_baselines.BASELINE_SCORERS. Deterministic (seed 42).

CLI:
  python -m eval.make_fig3_e1 [--cache <p>] [--out <fig_dir>] [--show]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402

from eval.e1_common import _ensure_utf8  # noqa: E402
from eval.e1_baselines import BASELINE_SCORERS, BASELINES  # noqa: E402
from eval.e1_train import SEED, build_dataset, train, train_test_split  # noqa: E402
from core.fusion import LogisticFusion  # noqa: E402

FIG_DIR = _REPO_ROOT / "figures"
VIEWS = LogisticFusion.DEFAULT_VIEWS


def _pr_curve(y_true, scores, n_points: int = 200) -> tuple[np.ndarray, np.ndarray]:
    """Tie-aware PR curve in increasing-recall order."""
    y = np.asarray(y_true, float)
    s = np.asarray(scores, float)
    if len(y) == 0:
        return np.array([]), np.array([])
    thresholds = np.unique(s)[::-1]
    if len(thresholds) > n_points:
        indices = np.unique(np.linspace(0, len(thresholds) - 1, n_points, dtype=int))
        thresholds = thresholds[indices]
    P, R = [1.0], [0.0]
    total_pos = max(float(y.sum()), 1.0)
    for t in thresholds:
        pred = s >= t
        tp = float((pred & (y == 1)).sum())
        fp = float((pred & (y == 0)).sum())
        p = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        r = tp / total_pos
        P.append(p)
        R.append(r)
    return np.asarray(R), np.asarray(P)


def make_fig(cache_path: Path, out_dir: Path = FIG_DIR, show: bool = False) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "traceguard-defi"
    import matplotlib.pyplot as plt

    ds = build_dataset(cache_path)
    split = train_test_split(ds, seed=SEED)
    te = split["test"]
    row_by_hash = {r["tx_hash"]: r["row"] for r in ds["rows"]}
    te_y = te["y"]

    trained = train(cache_path, seed=SEED, write_files=False)
    scr_screener = np.array([trained["scores_test"][h] for h in te["hashes"]])
    scr_baseline = {}
    for name in BASELINES:
        scorer = BASELINE_SCORERS[name]
        scr_baseline[name] = np.array(
            [scorer(row_by_hash[h]) for h in te["hashes"]], dtype=float)

    # --- plot ---
    fig, ax = plt.subplots(figsize=(6.4, 5.2), dpi=200)
    curves = [("TraceGuard (screener)", scr_screener, "#1a6fb0", 2.4, "-"),
              ("Rule flash+oracle", scr_baseline["rule_flash_oracle"], "#c25b3b", 1.8, "--"),
              ("Static-feature proxy", scr_baseline["static_smartaxe"], "#5a7d3a", 1.8, "-."),
              ("Balance-invariant proxy", scr_baseline["invariant_balance"], "#8a6ab5", 1.8, ":")]
    baseline_random = float((te_y == 1).mean())
    for label, s, color, lw, ls in curves:
        R, P = _pr_curve(te_y, s)
        ax.plot(R, P, label=label, color=color, lw=lw, ls=ls)
    ax.axhline(baseline_random, color="gray", lw=1.0, ls=":",
               label=f"random (prev {baseline_random:.3f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.02)
    ax.grid(alpha=0.3)
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    png = out_dir / "fig3_e1_prcurve.png"
    svg = out_dir / "fig3_e1_prcurve.svg"
    fig.savefig(png, dpi=300, metadata={"Date": None})
    fig.savefig(svg, metadata={"Date": None})
    # Matplotlib emits harmless trailing spaces in SVG path data. Normalize the
    # generated artifact so repository cleanliness checks are reproducible.
    svg_text = svg.read_text(encoding="utf-8")
    svg.write_text(
        "\n".join(line.rstrip() for line in svg_text.splitlines()) + "\n",
        encoding="utf-8", newline="\n",
    )
    if show:
        plt.show()
    plt.close(fig)
    print(f"fig3 -> {png}  (+svg)")
    return png


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Figure 3: E1 PR curves")
    p.add_argument("--cache", default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--show", action="store_true")
    args = p.parse_args(argv)

    from eval.e1_crawl import CACHE_PATH
    cache_path = Path(args.cache) if args.cache else CACHE_PATH
    out_dir = Path(args.out) if args.out else FIG_DIR
    make_fig(cache_path, out_dir=out_dir, show=args.show)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
