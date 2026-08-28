"""
TraFiSec — E1 shared helpers (eval/e1_common.py)
========================================================
Pure helper functions shared across E1 modules (crawl, benign, train, baselines, CLI):

  * metrics      — precision/recall/F1 @ FP-budget (top-k t ngn sch FP),
                    AUC-PR (xp x tch phn, Manning 2008 §8.3), accuracy.
                    Thun numpy, deterministic, test bng d liu gi.
  * Multicall3   — 0xcA11bde05977b3631167028862bE2a173976CA11 `getEthBalance(address)`
                    aggregate: encode calldata + decode returnData; batching
                    eth_getBalance (fallback per-account khi block < deploy
                    14353601 — cc case 2020 him).
  * label rule   — benign set: hard-negative = tx c flash-loan + (swap | oracle)
                    (guide.md E1 §baseline rule heuristic), km epoch-gate:
                    Selectors are evaluated after protocol deployment block to prevent
                    4-byte selector collisions with pre-deployment historical transactions.
  * cache rows   — builders ti cu trc TraceData t cache; input di b trim
                    (gi selector + 4 word u —  cho view economic slippage
                    word[1]) into cached file; views re-execute without requiring RPC.

Deterministic: all functions here are pure; seed passed by caller. No network I/O.
"""
from __future__ import annotations

import json
import math
import gzip
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
# Multicall3 (deploy block 14353601 — 2022-03-21, etherscan verified).
MULTICALL3_ADDR = "0xcA11bde05977b3631167028862bE2a173976CA11"
MULTICALL3_SELECTOR = "0x4d2301cc"  # getEthBalance(address) — 4byte verified
MULTICALL3_DEPLOY_BLOCK = 14353601

# Execution trace analysis and verification
LMIN_USD = 100_000
# Execution trace analysis and verification
LMIN_ETH_WEI = 33 * 10**18

# Execution trace analysis and verification
# Execution trace analysis and verification
MAX_INPUT_HEX = 8 + 64 * 4

# Execution trace analysis and verification
FLASH_SELECTORS = {
    "0x5cffe9de": "AaveV2.flashLoan",
    "0xab9c4b5d": "AaveV3.flashLoan",
    "0x7dc8c37a": "AaveV2.flashLoanSimple",
    "0xf740f328": "BalancerV2.flash",
    "0x78b5c2ce": "BalancerV2.flashSimple",
    "0x641ccd83": "CreamFork.start",
    "0xb1cd2534": "NativePool.flash",
}
ORACLE_SELECTORS = {
    "0xfeaf968c": "Chainlink.latestRoundData",
    "0x50d25bcd": "Chainlink.latestAnswer",
    "0x0902f1ac": "UniswapV2Pair.getReserves",
    "0xfc57d4df": "Compound.getUnderlyingPrice",
    "0x41976e09": "getPrice",
    "0xd61a7847": "getPriceUsdc",
    "0x59e02dd7": "peek",
    "0x57de26a4": "read",
}
SWAP_SELECTORS = {
    "0x38ed1739": "UniswapV2.swapExactTokensForTokens",
    "0x8803dbee": "UniswapV2.swapTokensForExactTokens",
    "0xc04b8d59": "UniswapV3Router.exactInput",
    "0x414bf389": "UniswapV3Router.exactInputSingle",
    "0x095ea7b3": "ERC20.approve",
}

# Execution trace analysis and verification
# Execution trace analysis and verification
_SEL_EPOCH: dict[str, tuple[int, int | None]] = {
    "0x5cffe9de": (11_934_026, None),   # AaveV2 (01-2021)
    "0x7dc8c37a": (11_934_026, None),   # AaveV2 flashLoanSimple
    "0xab9c4b5d": (15_971_871, None),   # AaveV3 (01-2023)
    "0xf740f328": (12_272_146, None),   # BalancerV2 (04-2021)
    "0x78b5c2ce": (12_272_146, None),   # BalancerV2 flashSimple
    "0x641ccd83": (12_081_751, None),   # Cream flash-loan fork (03-2021)
    "0xb1cd2534": (15_971_871, None),   # NativePool flash (2023+)
    "0x38ed1739": (10_000_835, None),   # UniswapV2Router (05-2020)
    "0x8803dbee": (10_000_835, None),   # UniswapV2Router
    "0xc04b8d59": (12_369_621, None),   # UniswapV3Router (05-2021)
    "0x414bf389": (12_369_621, None),   # UniswapV3Router
    "0x095ea7b3": (0, None),            # Verified execution property
    "0x0902f1ac": (10_000_835, None),   # UniswapV2Pair.getReserves
    "0xfeaf968c": (0, None),            # Verified execution property
    "0x50d25bcd": (0, None),
    "0xfc57d4df": (0, None),
    "0x41976e09": (0, None),
    "0xd61a7847": (0, None),
    "0x59e02dd7": (0, None),
    "0x57de26a4": (0, None),
}


def _ensure_utf8() -> None:
    """Console UTF-8 (Windows cp1252 khng hng ting Vit/Δ) — pattern fidelity_cli."""
    import sys
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and "utf" not in sys.stderr.encoding.lower():
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _sha256_id(tx_hash: str, salt: str = "") -> int:
    """Deterministic string hash function across Python processes for stable splitting."""
    import hashlib
    return int(hashlib.sha256(f"{salt}{tx_hash}".encode()).hexdigest()[:16], 16)


def canonical_floats(value, digits: int = 9):
    """Round generated numeric artifacts above published precision.

    BLAS/libm implementations can differ in their last few bits. Keeping nine
    decimal places preserves substantially more precision than the paper uses
    while making tabular/JSON evidence byte-stable across supported hosts.
    """
    if isinstance(value, float):
        return round(value, digits) if math.isfinite(value) else value
    if isinstance(value, dict):
        return {key: canonical_floats(item, digits) for key, item in value.items()}
    if isinstance(value, list):
        return [canonical_floats(item, digits) for item in value]
    if isinstance(value, tuple):
        return tuple(canonical_floats(item, digits) for item in value)
    return value


# ---------------------------------------------------------------------------
# Metrics — precision/recall/F1 @ FP-budget, AUC-PR, accuracy
# ---------------------------------------------------------------------------
def _sorted_by_score(y_true, scores):
    """Sp theo score gim dn (stable — deterministic trn tie)."""
    y = np.asarray(y_true, dtype=float)
    s = np.asarray(scores, dtype=float)
    order = np.argsort(-s, kind="stable")
    return y[order], s[order]


def _operating_point(y_true, scores, budget_frac: float) -> dict:
    """Best threshold whose empirical false-positive rate is within budget.

    Selection is threshold/tie aware: observations with the same score are
    never split by array order.  ``floor(budget*n_negative)`` is used because
    rounding up can exceed the declared FPR, especially on small test sets.
    The empty operating point is valid when the sample cannot resolve a tiny
    budget (for example 0.1% with fewer than 1,000 negatives).
    """
    ys, ss = _sorted_by_score(y_true, scores)
    n_neg = int((ys == 0).sum())
    allowed_fp = int(math.floor(float(budget_frac) * n_neg + 1e-12))
    best = {"tp": 0, "fp": 0, "threshold": float("inf")}
    if len(ys) == 0:
        return {**best, "allowed_fp": allowed_fp, "n_negative": n_neg}
    tp = fp = 0
    i = 0
    while i < len(ys):
        score = ss[i]
        j = i
        while j < len(ys) and ss[j] == score:
            if ys[j] == 1:
                tp += 1
            else:
                fp += 1
            j += 1
        if fp <= allowed_fp and tp > best["tp"]:
            best = {"tp": tp, "fp": fp, "threshold": float(score)}
        i = j
    return {**best, "allowed_fp": allowed_fp, "n_negative": n_neg}


def precision_at_budget(y_true, scores, budget_frac: float) -> tuple[float, int, int]:
    """Precision at the maximum-recall threshold satisfying the FPR budget."""
    op = _operating_point(y_true, scores, budget_frac)
    tp, fp = op["tp"], op["fp"]
    return (tp / (tp + fp) if tp + fp else 0.0), tp, fp


def average_precision(y_true, scores) -> float:
    """Threshold-based average precision with score ties handled as a group.

    A deployment threshold cannot separate equal scores. Processing ties one
    by one would make AP depend on input order and can inflate quantized or
    rule-based scorers.
    """
    ys, ss = _sorted_by_score(y_true, scores)
    total_pos = float(ys.sum())
    if total_pos == 0:
        return 0.0
    tp = fp = 0.0
    previous_recall = 0.0
    ap = 0.0
    i = 0
    while i < len(ys):
        score = ss[i]
        j = i
        while j < len(ys) and ss[j] == score:
            tp += float(ys[j] == 1)
            fp += float(ys[j] == 0)
            j += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        ap += (recall - previous_recall) * precision
        previous_recall = recall
        i = j
    return float(ap)


def select_fpr_thresholds(y_calibration, scores_calibration,
                          budgets=(0.001, 0.01)) -> dict[float, float]:
    """Select deployment thresholds on calibration data only."""
    return {float(b): float(_operating_point(y_calibration, scores_calibration,
                                             float(b))["threshold"])
            for b in budgets}


def metrics_at_thresholds(y_true, scores, thresholds: dict[float, float],
                          budgets=(0.001, 0.01)) -> dict:
    """Evaluate calibration-frozen thresholds against an untouched test set."""
    y = np.asarray(y_true, dtype=float)
    s = np.asarray(scores, dtype=float)
    total_pos = int((y == 1).sum())
    total_neg = int((y == 0).sum())
    out: dict = {}
    for b in budgets:
        budget = float(b)
        threshold = float(thresholds[budget])
        predicted = s >= threshold
        tp = int(((y == 1) & predicted).sum())
        fp = int(((y == 0) & predicted).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / total_pos if total_pos else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        allowed_fp = int(math.floor(budget * total_neg + 1e-12))
        out[budget] = {
            "fp_budget": budget, "precision": round(p, 6),
            "recall": round(r, 6), "f1": round(f1, 6),
            "tp": tp, "fp": fp, "allowed_fp": allowed_fp,
            "realized_fpr": round(fp / total_neg, 8) if total_neg else 0.0,
            "threshold": threshold, "threshold_source": "calibration",
            "budget_satisfied_on_test": fp <= allowed_fp,
        }
    out["auc_pr"] = round(average_precision(y, s), 6)
    out["accuracy"] = round(float((y == (s >= 0.5)).mean()), 6) if len(y) else 0.0
    return out


def metrics_at_budgets(y_true, scores, budgets=(0.001, 0.01)) -> dict:
    """{fp_budget: {precision, recall, f1, tp, fp}, 'auc_pr', 'accuracy'}."""
    y = np.asarray(y_true, dtype=float)
    total_pos = max(float(y.sum()), 1.0)
    out: dict = {}
    for b in budgets:
        op = _operating_point(y, scores, b)
        tp, fp = op["tp"], op["fp"]
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / total_pos
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        out[b] = {"fp_budget": float(b), "precision": round(p, 6),
                  "recall": round(r, 6), "f1": round(f1, 6),
                  "tp": tp, "fp": fp,
                  "allowed_fp": op["allowed_fp"],
                  "realized_fpr": round(fp / op["n_negative"], 8)
                  if op["n_negative"] else 0.0,
                  "threshold": op["threshold"]}
    acc = float((y == (np.asarray(scores) >= 0.5)).mean()) if len(y) else 0.0
    out["auc_pr"] = round(average_precision(y, scores), 6)
    out["accuracy"] = round(acc, 6)
    return out


# ---------------------------------------------------------------------------
# Multicall3 getEthBalance aggregate (encode calldata + decode returnData)
# ---------------------------------------------------------------------------
def _abi_word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def build_get_eth_balance_call(addr: str) -> str:
    """Calldata 1 phn t aggregate: getEthBalance(address) vi `addr`."""
    a = addr.lower().removeprefix("0x").zfill(64)
    return MULTICALL3_SELECTOR + a


def encode_aggregate_call(calls: list[tuple[str, str]]) -> str:
    """Full calldata aggregate((address,bytes)[]).

    `calls` = [(target_address, calldata), ...] — mi element l 1 call con
    (Call struct: target + data; Multicall3 dispatches tng ci).
    """
    n = len(calls)
    heads = b""
    tails = b""
    for i, (target, cd) in enumerate(calls):
        data = bytes.fromhex(cd.removeprefix("0x"))
        elem_head_offset = 32 * (n + i)  # Verified execution property
        heads += _abi_word(elem_head_offset)
        tails += (_abi_word(int(target, 16))
                  + _abi_word(64) + _abi_word(len(data))
                  + data.ljust(((len(data) + 31) // 32) * 32, b"\x00"))
    arr = _abi_word(n) + heads + tails
    return MULTICALL3_SELECTOR + arr.hex()


def decode_get_eth_balance_result(hex_str: str | None) -> tuple[bool, int] | None:
    """Decode returnData 1 element aggregate → (ok, balance); None nu d liu l.

    ABI: (bool[], uint256[]) = [offset_bools][offset_balances]
         [len_bools][ok][len_bals][balance]  (mi word 32 bytes).
    """
    if not hex_str or not isinstance(hex_str, str) or len(hex_str) < 2 + 64 * 5:
        return None
    h = hex_str[2:]
    if len(h) < 320:  # 2 heads + 2 lengths + ok + balance
        return None
    off_b = int(h[0:64], 16)   # Verified execution property
    off_u = int(h[64:128], 16)
    b0, u0 = off_b * 2, off_u * 2
    if len(h) < u0 + 128:  # Verified execution property
        return None
    if int(h[b0:b0 + 64], 16) != 1 or int(h[u0:u0 + 64], 16) != 1:
        return None
    ok = int(h[b0 + 64:b0 + 128], 16) != 0
    bal = int(h[u0 + 64:u0 + 128], 16)
    return ok, bal


def _decode_aggregate_balances(hex_str: str | None, n: int) -> list[tuple[bool, int] | None]:
    """Decode (bool[], uint256[]) aggregate returnData → list n phn t."""
    if not hex_str or len(hex_str) < 2 + 64 * (2 + 2 * n + 2):
        return [None] * n
    h = hex_str[2:]
    off_b = int(h[0:64], 16)   # Verified execution property
    off_u = int(h[64:128], 16)
    b0, u0 = off_b * 2, off_u * 2
    need = u0 + 64 * (n + 1)  # Verified execution property
    if len(h) < need:
        return [None] * n
    if int(h[b0:b0 + 64], 16) != n or int(h[u0:u0 + 64], 16) != n:
        return [None] * n
    out = []
    for i in range(n):
        ok = int(h[b0 + 64 + 64 * i:b0 + 128 + 64 * i], 16) != 0
        bal = int(h[u0 + 64 + 64 * i:u0 + 128 + 64 * i], 16)
        out.append((ok, bal) if ok else None)
    return out


def eth_get_balance_batched(client, addrs: list[str], block: int | str | None,
                            use_multicall: bool = True) -> dict[str, int]:
    """Balance ca ~50 addresses bng 1 eth_call aggregate (Multicall3).

    Fallback eth_getBalance tng account khi: block < deploy (2020 case),
    RPC does not support archive eth_call or decode failed. Read-only - no transactions sent.
    """
    from core.rpc import RpcError  # Verified execution property
    addrs = [a.lower() for a in addrs if a]
    if not addrs:
        return {}
    if isinstance(block, str) and block not in ("latest", "pending", "earliest"):
        block = int(block, 16) if block.startswith("0x") else int(block)
    if not isinstance(block, int):  # Verified execution property
        block = None
    blk_hex = hex(block) if isinstance(block, int) else (block or "latest")
    use_mc = (use_multicall
              and (block is None or block >= MULTICALL3_DEPLOY_BLOCK))
    if use_mc:
        try:
            cds = [(a, build_get_eth_balance_call(a)) for a in addrs]
            res = client.call("eth_call",
                              [{"to": MULTICALL3_ADDR,
                                "data": encode_aggregate_call(cds)}, blk_hex])
            vals = _decode_aggregate_balances(res, len(addrs))
            if any(v is not None for v in vals):
                return {a: bal for a, v in zip(addrs, vals) if v is not None
                        for bal in [v[1]]}
        except RpcError:
            pass  # Verified execution property
    out: dict[str, int] = {}
    for a in addrs:
        try:
            out[a] = client.eth_get_balance(a, blk_hex)
        except RpcError:
            continue
    return out


# ---------------------------------------------------------------------------
# Label rule cho benign set (hard-negative)
# ---------------------------------------------------------------------------
def _selector_from_input(inp: str | None) -> str | None:
    if not inp or not inp.startswith("0x") or len(inp) < 10:
        return None
    return inp[:10].lower()


def _active_epoch(sel: str, block: int | None) -> bool:
    lo, hi = _SEL_EPOCH.get(sel, (0, None))
    if block is not None and block < lo:
        return False
    if hi is not None and block is not None and block > hi:
        return False
    return True


def classify_benign_label(selectors, block: int | None = None) -> str:
    """'hard' nu c flash-loan + (swap | oracle) (guide.md E1 heuristic),
    otherwise 'benign'. Selectors are evaluated within active protocol epochs."""
    sels = {s.lower() for s in selectors if s and s.startswith("0x")}
    flash = any(s in FLASH_SELECTORS and _active_epoch(s, block) for s in sels)
    swap = any(s in SWAP_SELECTORS and _active_epoch(s, block) for s in sels)
    oracle = any(s in ORACLE_SELECTORS and _active_epoch(s, block) for s in sels)
    if (flash and swap) or (flash and oracle):
        return "hard"
    return "benign"


def selectors_from_trace(trace_cached: dict) -> list[str]:
    """Selectors t flat_calls trong cache ( trim input — selector cn nguyn)."""
    out = []
    for c in trace_cached.get("flat_calls", []):
        sel = c.get("selector")
        if sel and sel not in out:
            out.append(sel)
    return out


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _trim_input(inp: str | None) -> str | None:
    if not inp or not inp.startswith("0x") or len(inp) <= MAX_INPUT_HEX:
        return inp
    return inp[:MAX_INPUT_HEX]


def tree_to_cache(tree) -> dict | None:
    """Cy callTracer gn: ct input di (gi cu trc — subtree/fanout nguyn)."""
    if not isinstance(tree, dict):
        return tree
    out = dict(tree)
    if isinstance(out.get("input"), str):
        out["input"] = _trim_input(out["input"])
    calls = out.get("calls")
    if isinstance(calls, list):
        out["calls"] = [tree_to_cache(c) for c in calls]
    return out


def trace_to_cache(trace: dict) -> dict:
    """TraceData → dict cache (set → list, tree trim, input trim)."""
    out: dict = {}
    for k, v in trace.items():
        if k == "tree":
            out[k] = tree_to_cache(v)
        elif k == "addresses":
            out[k] = sorted(v)
        elif k == "flat_calls":
            out[k] = [{**c, "input": _trim_input(c.get("input"))} for c in v]
        else:
            out[k] = v
    return out


def trace_from_cache(cached: dict) -> dict:
    """Convert cache to TraceData (for views - no RPC needed)."""
    return {
        "tx_hash": cached.get("tx_hash"), "block": cached.get("block"),
        "source": cached.get("source"), "from": cached.get("from"),
        "to": cached.get("to"), "value": cached.get("value"),
        "input": cached.get("input"), "status": cached.get("status"),
        "gas_used": cached.get("gas_used"), "tree": cached.get("tree"),
        "flat_calls": cached.get("flat_calls") or [],
        "logs": cached.get("logs") or [],
        "addresses": set(cached.get("addresses") or []),
    }


def build_trace_row(entry: dict, trace: dict, pre: dict, post: dict,
                    status: bool | None, gas_used: int | None,
                    error: str | None) -> dict:
    """Format complete cache record for attack transaction (trace + balance pre/post + status/gas).

    Block height prioritized from trace RPC resolution.
    """
    return {
        "tx_hash": entry["tx_hash"],
        "block": trace.get("block") or entry.get("block"),
        "protocol": entry.get("protocol"),
        "attack_id": entry.get("id"),
        "attack_type": entry.get("attack_type"),
        "gt_factors": entry.get("gt_factors") or [],
        "label": "attack",
        "source": trace.get("source"),
        "trace": trace_to_cache(trace),
        "pre_balances": {k: v for k, v in (pre or {}).items()},
        "post_balances": {k: v for k, v in (post or {}).items()},
        "status": status, "gas_used": gas_used, "error": error,
    }


def build_benign_row(entry: dict, trace: dict, pre: dict, post: dict,
                     status: bool | None, gas_used: int | None,
                     error: str | None) -> dict:
    """1 dng cache cho benign/hard-negative tx (label 'benign'|'hard')."""
    return {
        "tx_hash": entry["tx_hash"],
        "block": entry.get("block"),
        "protocol": entry.get("protocol") or "block-tx",
        "attack_id": None, "attack_type": None, "gt_factors": [],
        "label": entry.get("label", "benign"),
        "source": trace.get("source"),
        "trace": trace_to_cache(trace),
        "pre_balances": {k: v for k, v in (pre or {}).items()},
        "post_balances": {k: v for k, v in (post or {}).items()},
        "status": status, "gas_used": gas_used, "error": error,
    }


def parse_cached_row(line: str) -> dict | None:
    """Parse single JSONL cache line into dict; returns None on malformed line."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict) or not d.get("tx_hash"):
        return None
    return d


def load_cache_rows(path: Path) -> dict[str, dict]:
    """c cache JSONL/JSONL.GZ → {tx_hash: row}.

    Compressed release snapshots are accepted directly so derived queues can
    retain a stable, attributable source path instead of depending on an
    ephemeral decompressed file under /tmp.
    """
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, mode="rt", encoding="utf-8") as f:
        for line in f:
            d = parse_cached_row(line)
            if d:
                out[d["tx_hash"]] = d
    return out


# ---------------------------------------------------------------------------
# Corpus attack entries
# ---------------------------------------------------------------------------
def attack_rows_from_corpus(corpus_path: Path,
                            chains=("ethereum",),
                            verified=("onchain",)) -> list[dict]:
    """Attack tx entries t corpus/incidents.jsonl (hash u tin ca tx_hashes)."""
    rows: list[dict] = []
    with open(corpus_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("chain") not in chains:
                continue
            if r.get("verified") not in verified:
                continue
            hashes = r.get("tx_hashes") or []
            if not hashes:
                continue
            rows.append({
                "id": r.get("id"),
                "protocol": r.get("protocol"),
                "attack_type": r.get("attack_type", "other"),
                "gt_factors": r.get("gt_factors") or ["unknown"],
                "tx_hash": hashes[0],
                "block": r.get("block"),
                "label": "attack",
            })
    return rows
