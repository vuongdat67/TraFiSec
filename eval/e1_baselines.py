"""
TraFiSec — E1 baselines (eval/e1_baselines.py)
=======================================================
Three internal baseline models evaluated on the same test partition as the screener (E1 main).
heuristic proxies and ablations rather than full external systems:
used for controlled baseline benchmarking under identical inputs:

  (a) rule/pattern detector — heuristic flash-loan + oracle (guide.md E1 §baseline):
      score = 1 if trace contains flash-loan selector AND (swap | oracle) - baseline pattern
      hard-negative label rule, quyt nh bng rule n gin t features.
      Score = 0.5 for simple flash loans without subsequent oracle/swap manipulation.
  (b) invariant-only balance proxy: pht hin token
      token balance drops > Lmin ($100K equivalent) without corresponding inflow - computed
      from Transfer logs: if received amount is negligible relative to outflow
      total net outflow > Lmin -> flag as 1.0. Native ETH delta is evaluated via pre/post state.
      balance delta of root sender without corresponding ETH inflow
      into the root from call value transfers).
  (c) callgraph / static proxy: curated list of high-risk selectors (withdrawal,
      ln (withdraw/removeLiquidity/sweep), i quyn (setStorageAt/transferOwnership/
      setOwner/updateOwner), call ngoi ti EOAs (coded-size 0 — heuristic theo
      guide.md: CALL edge ti address c code — c code cost RPC nn ta dng
      heuristic: CALL from contract to unknown entity). Score = 1.0 if matching,
      setStorageAt/transferOwnership/setOwner; 0.5 nu withdraw/removeLiquidity
      vi amount > Lmin (nhiu selector withdraw — dng heuristic t flat_calls);
      0.25 if calling untrusted entity or unrecognized selector.

  DeFiScope/TraceLLM (LLM-based) baseline: DEFERRED — tn API cost (ghi ch ny
  standardized scoring interface across baseline implementations.

All baselines share the identical test_hashes from e1_train (e1_model.json).
split li deterministic). Ghi eval/results/e1_baselines.csv — 1 dng/baseline/FP-budget.

CLI:
  python -m eval.e1_baselines                      # Verified execution property
  python -m eval.e1_baselines --cache <path> --out-dir <dir> --budgets 0.001,0.01
  python -m eval.e1_baselines --dry                # Verified execution property

Deterministic: split deterministic; baseline scores thun lut — khng RNG.
"""
from __future__ import annotations

# Script entry points add the repository root before importing project modules.
# ruff: noqa: E402

import argparse
import csv
import sys
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402

from .e1_common import (  # noqa: E402
    FLASH_SELECTORS,
    LMIN_ETH_WEI,
    ORACLE_SELECTORS,
    SWAP_SELECTORS,
    _ensure_utf8,
    metrics_at_thresholds,
    select_fpr_thresholds,
    selectors_from_trace,
    trace_from_cache,
)
from .e1_train import (SEED, build_dataset, fit_calibration_split,
                       train_test_split)  # noqa: E402

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
BASELINES_CSV_PATH = RESULTS_DIR / "e1_baselines.csv"

# Execution trace analysis and verification
_ADMIN_SELECTORS = {
    "0x3a4f4063": "setStorageAt",       # proxy admin setStorageAt
    "0xf2fde38b": "transferOwnership",  # OpenZeppelin Ownable
    "0x715018a6": "renounceOwnership",  # (admin-lock-style)
    "0x13af4035": "setOwner",
    "0x8f32d59b": "isOwner",
    "0x7d6b68df": "setAuthorized",
    "0x2b0f9d0f": "setAdmin",
}
_WITHDRAW_SELECTORS = {
    "0x441a3e70": "withdraw",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0x51cff8d9": "withdraw(address,uint256)",
    "0xf3fef3a3": "withdraw(address,uint256)",
    "0x853828b6": "withdrawMany",
    "0xba087652": "removeLiquidityETH",
    "0x5c11d795": "swapExactTokensForTokensSupportingFee",
    "0x1ff1b75d": "emergencyWithdraw",
    "0x4c9f534f": "harvest",
}
# Execution trace analysis and verification
# Execution trace analysis and verification
# trong batch crawl — E6 latency constraint).
_KNOWN_CONTRACT_PREFIXES = (
    "0x7a250d",  # UniswapV2Router
    "0xc02aaa",  # WETH
    "0x6b1754",  # DAI
    "0xa0b869",  # USDC
    "0xdac17f",  # USDT
    "0x514910",  # LINK
    "0x2260fa",  # WBTC
    "0xba1222",  # BalancerVault
    "0x111111",  # 1inch
    "0xdef171",  # 1inch v4
    "0x0d500b",  # WMATIC
    "0x31e2cd",  # ? generic
)

BASELINES = ("rule_flash_oracle", "invariant_balance", "static_smartaxe")
BASELINE_SCOPE = "internal_proxy_not_external_reimplementation"


def _transfer_events(trace: dict) -> list[dict]:
    """Transfer events t logs (khp views.token_flow_features)."""
    out = []
    for log in trace.get("logs", []):
        topics = log.get("topics") or []
        if (len(topics) >= 3
                and topics[0].lower()
                == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"):
            d = log.get("data")
            out.append({
                "token": log.get("address"),
                "frm": "0x" + topics[1][-40:].lower(),
                "to": "0x" + topics[2][-40:].lower(),
                "amt": int(d, 16) if (isinstance(d, str) and len(d) >= 3) else 0,
            })
    return out


# ---------------------------------------------------------------------------
# (a) Rule/pattern detector — flash-loan + oracle heuristic
# ---------------------------------------------------------------------------
def rule_flash_oracle_score(trace: dict) -> float:
    """1.0 nu flash-loan + (swap|oracle); 0.5 nu flash-loan n; else 0.0.

    aligned with hard-negative evaluation criteria (e1_common.classify_benign_label)
    tr score lin tc  rank theo FP-budget.
    """
    sels = selectors_from_trace(trace)
    block = trace.get("block")
    flash = any(s in FLASH_SELECTORS for s in sels)
    swap = any(s in SWAP_SELECTORS for s in sels)
    oracle = any(s in ORACLE_SELECTORS for s in sels)
    _ = block  # Verified execution property
    if flash and (swap or oracle):
        return 1.0
    if flash:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# (b) Invariant-only — MonteCrypto-style balance invariant (Transfer logs)
# ---------------------------------------------------------------------------
def invariant_balance_score(trace: dict, pre: dict, post: dict,
                            lmin_wei: int = LMIN_ETH_WEI) -> float:
    """Returns 1.0 if token net outflow exceeds Lmin ($100K equivalent) without corresponding inflow
    for the same (account, token) pair or native ETH balance drop > Lmin
    without ETH inflow. Returns 0.5 if outflow > Lmin has partial inflow
    and 0.0 if balanced.
    """
    logs = _transfer_events(trace)
    # net per (account, token): in − out
    net: dict[tuple, int] = {}
    for t in logs:
        k1 = (t["frm"], t["token"])
        net[k1] = net.get(k1, 0) - t["amt"]
        k2 = (t["to"], t["token"])
        net[k2] = net.get(k2, 0) + t["amt"]
    drain = 0
    suspicious = 0
    for (acc, tok), n in net.items():
        if n < -lmin_wei:  # Verified execution property
            # Execution trace analysis and verification
            inflows = sum(t["amt"] for t in logs if t["to"] == acc and t["token"] == tok)
            if inflows == 0:
                drain += 1
            elif inflows < -n:
                suspicious += 1
    # Execution trace analysis and verification
    root_from = trace.get("from")
    if root_from and root_from.lower() in pre and root_from.lower() in post:
        eth_delta = post.get(root_from.lower(), 0) - pre.get(root_from.lower(), 0)
        eth_inflow = sum(int(c.get("value") or 0) for c in trace.get("flat_calls", [])
                         if c.get("to") == root_from.lower())
        if eth_delta < -lmin_wei and eth_inflow == 0:
            drain += 1
        elif eth_delta < -lmin_wei:
            suspicious += 1
    if drain > 0:
        return 1.0
    if suspicious > 0:
        return 0.5
    return 0.0


# ---------------------------------------------------------------------------
# (c) Static-style — SmartAxe-adapted dangerous selectors
# ---------------------------------------------------------------------------
def static_smartaxe_score(trace: dict) -> float:
    """1.0 nu admin selector (setStorageAt/transferOwnership/setOwner...);
    0.5 nu withdraw/removeLiquidity vi amount > Lmin; 0.25 nu call ti
    EOA-l (heuristic) — else 0.0.
    """
    calls = trace.get("flat_calls", [])
    sels = selectors_from_trace(trace)
    if any(s in _ADMIN_SELECTORS for s in sels):
        return 1.0
    for c in calls:
        if c.get("selector") in _WITHDRAW_SELECTORS:
            if int(c.get("value") or 0) > LMIN_ETH_WEI:
                return 0.5
    for c in calls:
        if c.get("type") == "CALL" and c.get("depth", 0) > 0:
            to = (c.get("to") or "").lower()
            if (len(to) != 42 or not to.startswith("0x")
                    or to == trace.get("from")):
                continue
            if to[:8] not in _KNOWN_CONTRACT_PREFIXES:
                return 0.25
    return 0.0


BASELINE_SCORERS = {
    "rule_flash_oracle": lambda row: rule_flash_oracle_score(
        trace_from_cache(row.get("trace") or {})),
    "invariant_balance": lambda row: invariant_balance_score(
        trace_from_cache(row.get("trace") or {}),
        row.get("pre_balances") or {}, row.get("post_balances") or {}),
    "static_smartaxe": lambda row: static_smartaxe_score(
        trace_from_cache(row.get("trace") or {})),
}


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def run_baselines(cache_path: Path, out_dir: Path = RESULTS_DIR,
                  budgets: tuple[float, ...] = (0.001, 0.01),
                  seed: int = SEED, write_files: bool = True,
                  scale: str = "A?") -> dict:
    """Baseline scores trn test set (cng split vi train) → metrics + CSV."""
    ds = build_dataset(cache_path)
    split = train_test_split(ds, seed=seed)
    test_h = split["test"]["hashes"]
    yte = split["test"]["y"]
    row_by_hash = {r["tx_hash"]: r["row"] for r in ds["rows"]}
    calibration_part = fit_calibration_split({
        "hashes": split["train"]["hashes"],
        "X": np.zeros((len(split["train"]["hashes"]), 1)),
        "y": split["train"]["y"],
    }, seed=seed)[1]

    results: dict = {}
    csv_rows = []
    for name in BASELINES:
        scorer = BASELINE_SCORERS[name]
        calibration_scores = np.array(
            [scorer(row_by_hash[h]) for h in calibration_part["hashes"]], dtype=float
        )
        thresholds = select_fpr_thresholds(
            calibration_part["y"], calibration_scores, budgets
        )
        scores = np.array([scorer(row_by_hash[h]) for h in test_h], dtype=float)
        m = metrics_at_thresholds(yte, scores, thresholds, budgets=budgets)
        results[name] = {"scores": {h: round(float(s), 6) for h, s in zip(test_h, scores)},
                         "metrics": m}
        for b in budgets:
            r = m.get(b) or {}
            csv_rows.append([name, BASELINE_SCOPE, len(test_h), b, r.get("precision", ""),
                             r.get("recall", ""), r.get("f1", ""),
                             r.get("tp", ""), r.get("fp", ""),
                             r.get("allowed_fp", ""), r.get("realized_fpr", ""),
                             r.get("budget_satisfied_on_test", ""),
                             m.get("auc_pr", ""), scale])

    out = {
        "seed": seed,
        "n_test": len(test_h),
        "baselines": results,
        "note": "External baselines are not implemented; these scorers are internal diagnostic proxies only.",
    }
    if write_files:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "e1_baselines.csv"
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["baseline", "scope", "n_test", "fp_budget", "precision",
                        "recall", "f1", "tp", "fp", "allowed_fp", "realized_fpr",
                        "budget_satisfied_on_test", "auc_pr", "scale"])
            w.writerows(csv_rows)
        out["file"] = str(path)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_baselines(out: dict) -> None:
    print(f"== E1 baselines (test n={out['n_test']}, seed {out['seed']}) ==")
    print(out["note"])
    for name, res in out["baselines"].items():
        m = res["metrics"]
        parts = []
        for b in (0.001, 0.01):
            r = m.get(b)
            if r:
                parts.append(f"FP{b:.1%}: P={r['precision']:.3f} R={r['recall']:.3f}")
        print(f"  {name:<22} AUC-PR={m.get('auc_pr', 0):.4f}  " + "  ".join(parts))
    if out.get("file"):
        print(f"csv      : {out['file']}")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(
        description="E1 baselines: rule/invariant/static trn test set (C1)")
    p.add_argument("--cache", default=None,
                   help="cache path (mc nh eval/results/e1_trace_cache.jsonl)")
    p.add_argument("--out-dir", default=None)
    p.add_argument("--budgets", default="0.001,0.01")
    p.add_argument("--seed", type=int, default=SEED)
    p.add_argument("--dry", action="store_true", help="khng ghi file")
    p.add_argument("--scale", default="A?", help="Scale column identifier (default: A?)")
    args = p.parse_args(argv)

    from .e1_crawl import CACHE_PATH
    cache_path = Path(args.cache) if args.cache else CACHE_PATH
    budgets = tuple(float(x) for x in args.budgets.split(",") if x.strip())
    out_dir = Path(args.out_dir) if args.out_dir else RESULTS_DIR
    out = run_baselines(cache_path, out_dir=out_dir, budgets=budgets,
                        seed=args.seed, write_files=not args.dry,
                        scale=getattr(args, "scale", "A?"))
    _print_baselines(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
