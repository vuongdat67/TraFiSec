"""
TraFiSec — Stage 1 Screener: bn view extractors (src/core/views.py)
==========================================================================
Mi view l 1 hm PURE: input TraceData / StateDelta (src/core/trace.py), output
dict {score ∈ [0,1], features}. Features gi nguyn  fusion (fusion.py) dng
li; score l bn chun ha [0,1] theo proposal draft §3.1:

  s₁  call structure  — percentile ca logistic score trn features call-graph
  s₂  token flow      — σ(β₀ + Σ βₖ fₖ)  (h s seed mc nh, fit li  fusion)
  s₃  state delta     — percentile trn |Δslots| log / entropy / byte-size
  s₄  economic signs  — 0.25 · (s tn hiu) ∈ {0, 0.25, ..., 1.0}

Recall bias: high scores indicate plausible exploit patterns warranting Stage 2 replay triage.
Views do not replay; read trace/state only. If view lacks data (e.g., RPC unsupported),
When debug_trace or stateDiff is unavailable, missing feature dimensions
are gracefully handled with zero baseline and explicit coverage indicators.
record in notes field without invalidating the entire pipeline.

Deterministic: fully reproducible calculation with fixed thresholds.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict

try:
    from .invariants import catalog_signal, auth_viol as _auth_viol
    _INVARIANTS_AVAILABLE = True
except ImportError:
    _INVARIANTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# openzeppelin-contracts FlashLoanReceiverBase forky flashLoan; UniswapV2Router
# getReserves; Chainlink AggregatorV3 latestRoundData — SOURCES.md RPC section)
# ---------------------------------------------------------------------------
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Execution trace analysis and verification
_FLASH_SELECTORS = {
    "0x5cffe9de": "AaveV2.flashLoan(address,address,uint256,bytes)",
    "0xab9c4b5d": "AaveV3/UniswapV3Pool.flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
    "0xf740f328": "BalancerV2.flash(address,uint256,bytes)",
    "0x78b5c2ce": "BalancerV2.flashSimple(address,address,uint256,bytes)",
    "0x641ccd83": "CreamFork.start(uint256,uint256,uint256)",
    "0xb1cd2534": "NativePool.flash(address,uint256,bytes)",
}
_ORACLE_SELECTORS = {
    "0xfeaf968c": "Chainlink.latestRoundData()",
    "0x50d25bcd": "Chainlink.latestAnswer()",
    "0x0902f1ac": "UniswapV2Pair.getReserves()",
    "0xfc57d4df": "Compound.getUnderlyingPrice(address)",
    "0x41976e09": "getPrice(address)",
    "0xd61a7847": "getPriceUsdc(address)",
    "0x59e02dd7": "peek()",
    "0x57de26a4": "read()",
}
_SWAP_SELECTORS = {
    "0x38ed1739": "UniswapV2.swapExactTokensForTokens",
    "0x8803dbee": "UniswapV2.swapTokensForExactTokens",
    "0xc04b8d59": "UniswapV3Router.exactInput",
    "0x414bf389": "UniswapV3Router.exactInputSingle",
    "0x095ea7b3": "ERC20.approve",
    "0x095ea7b2": "ERC20.approve",  # (address,uint256,uint256,uint256) variant
}
# Execution trace analysis and verification
# Execution trace analysis and verification
_KNOWN_TOKEN_CONTRACTS = {
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
}

# Execution trace analysis and verification
# * shallow-large-out "shallow-large-output" pattern — TracExp (arXiv 2601.16681)
# Execution trace analysis and verification
# Execution trace analysis and verification
# * drain-fanout (one source → many tokens → one account) — proposal draft §3.1 view 2.
# Execution trace analysis and verification
# Execution trace analysis and verification
# Execution trace analysis and verification
_CS_NNODES_50 = math.log10(20)   # Verified execution property
_CS_NNODES_S = (math.log10(80) - math.log10(20)) / 2.0   # ≈ 0.30
_CS_DEPTH_50 = 5                 # Verified execution property
_CS_DEPTH_S = 2.5
_CS_NSHALLOW_50 = 0.7            # log10(shallow-large-out nodes +1) ≈ 4 nodes
_CS_NSHALLOW_S = 0.5
_CS_FANOUT_50 = 4.0
_CS_FANOUT_S = 6.0

# Execution trace analysis and verification
# Execution trace analysis and verification
# Execution trace analysis and verification
# flow_excess = n_flows−1, evt_excess = n_events−2. Benign → excess ≈ 0.
_TF_BETA0 = -0.5                 # logit offset (benign ≈ 0.38, attack > 0.8)
_TF_B_SRC = 1.5                  # Verified execution property
_TF_B_FLOW = 1.2                 # Verified execution property
_TF_B_EVT = 0.8                  # Verified execution property

_SD_NSLOTS_50 = 0.0   # Verified execution property
_SD_NSLOTS_90 = 2.5
_SD_BYTES_50 = 3.0
_SD_BYTES_90 = 5.5


def _clip(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _percentile(z: float, mu: float, sigma: float) -> float:
    """Normalized score in [0,1] computed via logistic CDF."""
    if sigma <= 0:
        return 1.0 if z > mu else 0.0
    return _clip(1.0 / (1.0 + math.exp(-(z - mu) / sigma)))


def _hex_uint(v: object, default: int = 0) -> int:
    """Hex string → uint an ton; '0x'/'0X'/rng/None → default (khng raise).

    Empty log data ('0x') handled safely as zero value transfer.
    word) — lesson 2026-08-12: `int('0x', 16)` raise ValueError.
    """
    if not isinstance(v, str) or len(v) < 3:
        return default
    try:
        return int(v, 16)
    except (ValueError, TypeError):
        return default


def _log10_clip(x: float, lo: float = 0.0) -> float:
    return math.log10(max(x, lo)) if x > lo else 0.0


# ===========================================================================
# View 1 — Call structure (proposal §3.1 #1)
# ===========================================================================
def _tree_stats(frame: dict, depth: int) -> tuple[int, int, int]:
    """TREE-WALK: (subtree_size, subtree_maxdepth, n_leaves) ca 1 frame.
    frame cha `calls` (con trc tip) — cu trc callTracer."""
    size, max_depth, n_leaves = 1, depth, 0
    children = frame.get("calls") or []
    if not children:
        return size, depth, 1
    for sub in children:
        s, md, nl = _tree_stats(sub, depth + 1)
        size += s
        max_depth = max(max_depth, md)
        n_leaves += nl
    return size, max_depth, n_leaves


def call_structure_features(trace: dict) -> dict:
    """Features call-graph G_c: d_max, n_call, fan-out skew, shallow-large-out.

    Traverses call tree hierarchy to calculate subtree size and maximum depth.
    - d_max                  —  su call ln nht (ton cy)
    - n_call                 — s internal call edges (flat_calls, tr root)
    - fanout_max, fanout_skew — max + skew fan-out (1 frame iu khin nhiu nhnh)
    - shallow_large_out_nodes — "1 outer call → nhiu deep subcalls" (TracExp
      §analysis): frame at depth <= 1 has subtree_size >= 12 AND subtree_maxdepth >= 6.
    - n_shallow_log, n_nodes_log — log10(+1)
    - coverage: 1.0 when full callTracer is available, 0.0 under minimal fallback.
      Single-node fallback returns 0 structural score.
    """
    tree = trace.get("tree")
    calls = trace.get("flat_calls", [])
    if not tree or trace.get("source") != "callTracer":
        return {"d_max": 0, "n_call": 0, "fanout_max": 0, "fanout_skew": 0.0,
                "shallow_large_out_nodes": 0, "n_shallow_log": 0.0,
                "n_nodes_log": 0.0, "coverage": 0}

    d_max = max((c["depth"] for c in calls), default=0)
    n_call = len(calls) - 1  # Verified execution property

    fanout_per_node: Counter = Counter()
    def _fanout(node: dict) -> None:
        kids = node.get("calls") or []
        if kids:
            fanout_per_node[(node.get("from"), node.get("to"),
                             node.get("input", "0x")[:10])] += len(kids)
        for k in kids:
            _fanout(k)
    _fanout(tree)
    vals = list(fanout_per_node.values()) or [0]
    fanout_max = max(vals)
    mean_fanout = sum(vals) / len(vals)
    fanout_skew = (fanout_max / mean_fanout) if mean_fanout > 0 else 0.0

    # Execution trace analysis and verification
    n_shallow = 0
    def _shallow(node: dict, depth: int) -> None:
        nonlocal n_shallow
        size, md, _ = _tree_stats(node, depth)
        if depth <= 1 and size >= 12 and md >= depth + 6:
            n_shallow += 1
        for k in node.get("calls") or []:
            _shallow(k, depth + 1)
    _shallow(tree, 0)

    return {
        "d_max": d_max, "n_call": n_call,
        "fanout_max": fanout_max, "fanout_skew": round(fanout_skew, 3),
        "shallow_large_out_nodes": n_shallow,
        "n_shallow_log": _log10_clip(n_shallow),
        "n_nodes_log": _log10_clip(n_call),
        "coverage": 1,
    }


def view_call_structure(trace: dict) -> dict:
    """s₁ = percentile ca logistic score trn features (proposal §3.1 #1).

    Feature weights tuned for high recall: tree complexity and shallow call counts receive heavy weights.
    Tree depth and fanout skew provide complementary structural signals.
    (RPC fallback) → s₁ = 0 (view "thiu d liu").
    """
    f = call_structure_features(trace)
    if f["coverage"] == 0:
        return {"score": 0.0, "features": f}
    z1 = _percentile(f["n_nodes_log"], _CS_NNODES_50, _CS_NNODES_S)
    z2 = _percentile(f["d_max"], _CS_DEPTH_50, _CS_DEPTH_S)
    z3 = _percentile(f["n_shallow_log"], _CS_NSHALLOW_50, _CS_NSHALLOW_S)
    z4 = _percentile(f["fanout_skew"], _CS_FANOUT_50, _CS_FANOUT_S)
    score = _clip(0.35 * z1 + 0.20 * z2 + 0.30 * z3 + 0.15 * z4)
    return {"score": score, "features": f}


# ===========================================================================
# View 2 — Token flow (proposal §3.1 #2)
# ===========================================================================
# Token topics
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TOPIC_TRANSFER_SINGLE_1155 = "0xc3d5816c14702165188d492c32bb6866b62d28c780b61112b7ff980fb6b7a50d"
TOPIC_TRANSFER_BATCH_1155 = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"
TOPIC_WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
TOPIC_WETH_WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d982b6b4e85300685fd0ce49"
NATIVE_ETH_SENTINEL = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"


def token_flow_features(trace: dict) -> dict:
    """Features t Transfer/Withdraw/Deposit events + native ETH transfers.

    H tr: ERC-20, ERC-721, ERC-1155, WETH Wrap/Unwrap, Native ETH flows.
    Excess features (baseline benign = transfer 1-1):
    - n_transfer_events   — tng s Transfer/flow events
    - n_distinct_tokens   — s token khc nhau (k c native ETH)
    - fan_in: maximum distinct source accounts transferring into a single (account, token) pair.
    - fan_out = max s ch khc nhau t 1 (account, token)
    - ratio   = fan_in / fan_out  (drain-fanout proxy)
    - src_excess: count of excess source accounts flowing into the same destination.
    - flow_excess = max s lung cng (to, token) (tr 1) — monotonic accumulation
    - evt_excess  = n_events − 2 (trn baseline 1-1 transfer)
    - accumulation = max s lung cng (account, token) chuyn INTO
    - drain_fanout_log — log10(drain_nodes+1): account nhn t ≥3 (token,source)
      detects multi-asset extraction directed to a single beneficiary account.
      (proposal §3.1 view 2).
    """
    logs = trace.get("logs", [])
    transfers = []
    for log in logs:
        topics = log.get("topics", [])
        if not topics:
            continue
        t0 = topics[0].lower()
        addr = (log.get("address") or "").lower()

        # ERC-20 (3 topics) & ERC-721 (4 topics)
        if t0 == TOPIC_TRANSFER and len(topics) >= 3:
            amt = _hex_uint(topics[3]) if len(topics) >= 4 else _hex_uint(log.get("data", "0x0"))
            transfers.append({
                "token": addr,
                "frm": ("0x" + topics[1][-40:]).lower(),
                "to": ("0x" + topics[2][-40:]).lower(),
                "amt": amt,
            })
        # ERC-1155 TransferSingle: operator, from, to
        elif t0 == TOPIC_TRANSFER_SINGLE_1155 and len(topics) >= 4:
            transfers.append({
                "token": addr,
                "frm": ("0x" + topics[2][-40:]).lower(),
                "to": ("0x" + topics[3][-40:]).lower(),
                "amt": _hex_uint(log.get("data", "0x0")),
            })
        # WETH Deposit (Wrap)
        elif t0 == TOPIC_WETH_DEPOSIT and len(topics) >= 2:
            transfers.append({
                "token": addr,
                "frm": addr,
                "to": ("0x" + topics[1][-40:]).lower(),
                "amt": _hex_uint(log.get("data", "0x0")),
            })
        # WETH Withdrawal (Unwrap)
        elif t0 == TOPIC_WETH_WITHDRAWAL and len(topics) >= 2:
            transfers.append({
                "token": addr,
                "frm": ("0x" + topics[1][-40:]).lower(),
                "to": addr,
                "amt": _hex_uint(log.get("data", "0x0")),
            })

    # Execution trace analysis and verification
    top_val = _hex_uint(trace.get("value", 0))
    top_frm = (trace.get("from") or "").lower()
    top_to = (trace.get("to") or "").lower()
    if top_val > 0 and top_frm and top_to:
        transfers.append({
            "token": NATIVE_ETH_SENTINEL,
            "frm": top_frm,
            "to": top_to,
            "amt": top_val,
        })
    for call in trace.get("flat_calls", []):
        c_val = _hex_uint(call.get("value", 0))
        c_frm = (call.get("from") or "").lower()
        c_to = (call.get("to") or "").lower()
        if c_val > 0 and c_frm and c_to:
            transfers.append({
                "token": NATIVE_ETH_SENTINEL,
                "frm": c_frm,
                "to": c_to,
                "amt": c_val,
            })

    n_tf = len(transfers)
    if n_tf == 0:
        return {"n_transfer_events": 0, "n_distinct_tokens": 0,
                "fan_in": 0, "fan_out": 0, "ratio": 0.0, "drain_fanout_log": 0.0,
                "accumulation": 0, "src_excess": 0, "flow_excess": 0,
                "evt_excess": 0, "coverage": 0}

    fan_in_counter: dict[tuple, set] = defaultdict(set)
    fan_out_counter: dict[tuple, set] = defaultdict(set)
    accum: dict[tuple, int] = Counter()
    tokens = set()
    for t in transfers:
        k_in = (t["to"], t["token"])
        k_out = (t["frm"], t["token"])
        fan_in_counter[k_in].add(t["frm"])
        fan_out_counter[k_out].add(t["to"])
        accum[k_in] += 1
        tokens.add(t["token"])
    fan_in = max((len(v) for v in fan_in_counter.values()), default=0)
    fan_out = max((len(v) for v in fan_out_counter.values()), default=0)
    ratio = (fan_in / fan_out) if fan_out > 0 else 0.0
    src_excess = max((len(v) - 1 for v in fan_in_counter.values()), default=0)
    flow_excess = max(accum.values(), default=1) - 1
    evt_excess = max(n_tf - 2, 0)

    # Execution trace analysis and verification
    recv_src: dict[tuple, set] = defaultdict(set)
    for t in transfers:
        recv_src[(t["to"], t["token"])].add(t["frm"])
    drain = 0
    for (acc, tok), srcs in recv_src.items():
        sends = sum(1 for t in transfers if t["frm"] == acc and t["token"] == tok)
        if len(srcs) >= 3 and sends <= 1:
            drain += 1

    return {
        "n_transfer_events": n_tf,
        "n_distinct_tokens": len(tokens),
        "fan_in": fan_in, "fan_out": fan_out, "ratio": round(ratio, 3),
        "drain_fanout_log": _log10_clip(drain),
        "accumulation": max(accum.values(), default=0),
        "src_excess": src_excess, "flow_excess": flow_excess,
        "evt_excess": evt_excess,
        "coverage": 1,
    }


def view_token_flow(trace: dict) -> dict:
    """s₂ = σ(β₀ + Σ βₖ fₖ) (proposal §3.1 # Verified execution property

    Logistic scaling on count-based transfer graph metrics:
      logit = β₀ + β_src·log10(src_excess+1) + β_flow·log10(flow_excess+1)
                    + β_evt·log10(evt_excess+1)
    Benign (transfer 1-1): src=flow=evt_excess≈0 → score ≈ σ(−0.5) ≈ 0.38.
    Attack patterns (multi-source token funneling to attacker) receive high scores.
    """
    f = token_flow_features(trace)
    if f["coverage"] == 0:
        return {"score": 0.0, "features": f}
    logit = (_TF_BETA0
             + _TF_B_SRC * _log10_clip(f["src_excess"])
             + _TF_B_FLOW * _log10_clip(f["flow_excess"])
             + _TF_B_EVT * _log10_clip(f["evt_excess"]))
    score = _clip(1.0 / (1.0 + math.exp(-logit)))
    return {"score": score, "features": f}


# ===========================================================================
# View 3 — State delta (proposal §3.1 #3)
# ===========================================================================
def state_delta_features(delta: dict) -> dict:
    """Features t Δ = post − pre (balances + nonces + storage).

    - n_slots_log   — log10(|Δslots|+1): s account b i balance/nonce/storage
    - entropy: normalized balance delta entropy across touched accounts.
      (higher entropy indicates multi-account balance manipulation).
    - bytes_size_log — log10(total byte-size ca cc Δ value + 1)
    - coverage: 0.0 when delta data is unavailable.
    """
    balances = delta.get("balances", {}) or {}
    nonces = delta.get("nonces", {}) or {}
    storage = delta.get("storage", {}) or {}

    deltas: dict[str, float] = {}
    for a, v in balances.items():
        if abs(v) > 0:  # Verified execution property
            deltas[f"b:{a}"] = abs(v)
    for a, v in nonces.items():
        if abs(v) > 0:
            deltas[f"n:{a}"] = abs(v)
    for a, slots in storage.items():
        for slot, pair in slots.items():
            if pair and len(pair) >= 2 and pair[0] is not None and pair[1] is not None:
                d = abs(pair[1] - pair[0])
                if d > 0:
                    deltas[f"s:{a}:{slot}"] = d

    n_changed = len(deltas)
    if n_changed == 0:
        return {"n_slots_log": 0.0, "entropy": 0.0, "bytes_size_log": 0.0,
                "coverage": 0}
    total = sum(deltas.values())
    if total <= 0:
        entropy = 0.0
    else:
        entropy = -sum((v / total) * math.log2(v / total) for v in deltas.values()
                       if v > 0)
        entropy /= math.log2(n_changed) if n_changed > 1 else 1.0
        entropy = _clip(entropy)
    # Execution trace analysis and verification
    bytes_size = sum(len(hex(v)[2:]) for v in deltas.values())
    return {
        "n_slots_log": _log10_clip(n_changed),
        "entropy": round(entropy, 4),
        "bytes_size_log": _log10_clip(bytes_size),
        "coverage": 1,
    }


def view_state_delta(delta: dict, trace: dict | None = None) -> dict:
    """s₃ = percentile trn |Δslots| log, entropy, byte-size (proposal §3.1 #3).

    When state delta is empty but call trace is available:
    fallback sang `infer_state_delta_from_trace(trace)`  trch xut balance delta
    t ETH calls + ERC-20 Transfer logs.

    Integrates invariant catalog heuristic score if trace is available.
    (proposal §6.2) nh bonus signal — max 20% boost trn base percentile.
    """
    f = state_delta_features(delta)
    if f["coverage"] == 0 and trace is not None:
        try:
            from .trace import infer_state_delta_from_trace
            inferred_delta = infer_state_delta_from_trace(trace)
            f = state_delta_features(inferred_delta)
            delta = inferred_delta
        except Exception:
            pass

    if f["coverage"] == 0:
        return {"score": 0.0, "features": f}

    z1 = _percentile(f["n_slots_log"], _SD_NSLOTS_50, (_SD_NSLOTS_90 - _SD_NSLOTS_50) / 2.0)
    z2 = _percentile(f["entropy"], 0.2, 0.35)
    z3 = _percentile(f["bytes_size_log"], _SD_BYTES_50, (_SD_BYTES_90 - _SD_BYTES_50) / 2.0)
    base_score = _clip(0.5 * z1 + 0.25 * z2 + 0.25 * z3)

    # Execution trace analysis and verification
    cat_score = 0.0
    if _INVARIANTS_AVAILABLE and trace is not None:
        try:
            cat_score = catalog_signal(trace, delta)
        except Exception:
            cat_score = 0.0
    score = _clip(base_score + 0.2 * cat_score)  # catalog contributes max 20% boost
    f["catalog_score"] = round(cat_score, 4)
    return {"score": score, "features": f}


# ===========================================================================
# View 4 — Economic signs (proposal §3.1 #4)
# ===========================================================================
def _has_selector(calls: list[dict], table: dict[str, str]) -> list[str]:
    """Cc tn signal khp selector trong call tree."""
    seen = set()
    for c in calls:
        sel = c.get("selector")
        if sel and sel in table:
            seen.add(table[sel])
    return sorted(seen)


def economic_features(trace: dict) -> dict:
    """Tn hiu kinh t (mi ci l 1 flag 0/1):

    - flash_loan    — call c selector flashLoan/flash/flashSimple/start
      (Aave/Balancer/CreamFork) or borrowing callback (if selector unmatched)
      Evaluates known DeFi protocol interface patterns.
    - oracle_read   — selector Chainlink latestRoundData/latestAnswer, getReserves,
      getUnderlyingPrice...
    - price_dev     — >1 oracle read trong cng tx (iu kin cn  "manipulate
      deviations from expected rate boundaries.
    - slippage      — swap c amountOutMin == 0 (slippage = ∞ — attack
      detects zero slippage protection or unusually high swap volumes.
    - net_profit: net volume returning to origin sender exceeding outgoing volume.
      (estimated net profit extracted across Transfer events).
    """
    calls = trace.get("flat_calls", [])
    logs = trace.get("logs", [])
    flash = _has_selector(calls, _FLASH_SELECTORS)
    oracle = _has_selector(calls, _ORACLE_SELECTORS)
    swaps = _has_selector(calls, _SWAP_SELECTORS)

    price_dev = 1 if len(oracle) >= 2 or (len(oracle) == 1 and len(swaps) >= 1) else 0
    slippage = 0
    for c in calls:
        if c.get("selector") in ("0x38ed1739", "0x8803dbee", "0xc04b8d59",
                                 "0x414bf389"):
            # Execution trace analysis and verification
            inp = c.get("input") or "0x"
            if len(inp) >= 2 + 8 + 64:
                min_out_hex = inp[2 + 8 + 64: 2 + 8 + 128]
                if min_out_hex == "0" * 64:
                    slippage = 1
                    break

    # Execution trace analysis and verification
    root_from = trace.get("from")
    net: dict[tuple, int] = defaultdict(int)
    for log in logs:
        topics = log.get("topics", [])
        if len(topics) >= 3 and topics[0].lower() == TOPIC_TRANSFER:
            frm = "0x" + topics[1][-40:].lower()
            to = "0x" + topics[2][-40:].lower()
            amt = _hex_uint(log.get("data", "0x0"))
            tok = log.get("address")
            net[(frm, tok)] -= amt
            net[(to, tok)] += amt
    net_profit = 0
    if root_from:
        profit_amt = sum(v for (a, _t), v in net.items() if a == root_from.lower() and v > 0)
        out_amt = -sum(v for (a, _t), v in net.items() if a == root_from.lower() and v < 0)
        net_profit = 1 if profit_amt > 0 and profit_amt > out_amt else 0

    return {
        "flash_loan": int(bool(flash)), "oracle_read": int(bool(oracle)),
        "price_dev": price_dev, "slippage": slippage, "net_profit": net_profit,
        "n_flash_sig": len(flash), "n_oracle_sig": len(oracle),
        "n_swap_sig": len(swaps),
        "flash_sigs": flash, "oracle_sigs": oracle, "swap_sigs": swaps,
    }


def view_economic(trace: dict, delta: dict | None = None) -> dict:
    """s₄ = 0.25 · (per-signal) ∈ {0, 0.25, ..., 1.0} (proposal §3.1 #4).

    6 signals (5 gc + auth_viol t invariant catalog §6.2):
      flash_loan, oracle_read, price_dev, slippage, net_profit, auth_viol
    auth_viol: 1 nu privileged selector + large fund transfer cng tx.
    """
    f = economic_features(trace)
    # Execution trace analysis and verification
    auth_flag = 0
    if _INVARIANTS_AVAILABLE:
        try:
            auth_flag = int(_auth_viol(trace, delta or {}))
        except Exception:
            auth_flag = 0
    f["auth_viol"] = auth_flag
    signals = [f["flash_loan"], f["oracle_read"], f["price_dev"],
               f["slippage"], f["net_profit"], f["auth_viol"]]
    # Execution trace analysis and verification
    score = _clip(0.20 * sum(signals))
    return {"score": round(score, 4), "features": f}


# ===========================================================================
# Execution trace analysis and verification
# ===========================================================================
ALL_VIEWS = {
    "call_structure": (view_call_structure, "trace"),
    "token_flow": (view_token_flow, "trace"),
    "state_delta": (view_state_delta, "delta"),
    "economic": (view_economic, "trace"),
}


def evaluate_all(trace: dict, delta: dict) -> dict:
    """Chy 4 views → {name: {score, features, coverage}} + source coverage flags.

    `coverage` indicates whether feature data was successfully observed;
    used during fusion to weight available views without penalty.

    v2: truyn trace vo view_state_delta (catalog signal) v delta vo
    view_economic (auth_viol) — tt c views gi nhn y  context.
    """
    out: dict = {}
    for name, (fn, kind) in ALL_VIEWS.items():
        if name == "state_delta":
            # Execution trace analysis and verification
            res = fn(delta, trace)
        elif name == "economic":
            # Execution trace analysis and verification
            res = fn(trace, delta)
        else:
            data = delta if kind == "delta" else trace
            res = fn(data)
        cov = res["features"].get("coverage", 1)
        out[name] = {**res, "coverage": cov}
    return out
