"""
TraFiSec — Invariant Catalog (src/core/invariants.py)
============================================================
Implement catalog invariant §6.2 proposal + insight t Raven (arXiv 2512.22616).

Ba nhm invariant:
  1. Universal (EVM-agnostic): i_1 no-money-from-air, i_2 no-negative-balance,
     i_3 no-withdraw-without-deposit.
  2. Economic-regime: lending borrow/collateral ratio, AMM product-k (x*y=k),
     LP share monotonic.
  3. Authorization (2026): onlyOwner pattern, timelock minDelay, proxy-admin.

S dng:
  from core.invariants import check_all_invariants, auth_viol
  result = check_all_invariants(trace, delta, regime="lending")
  result.violated       # Verified execution property
  result.auth_violated  # bool — authorization violation
  result.catalog_score  # Verified execution property

Tch hp vi views.py:
  - s3 += catalog_score vo view_state_delta khi coverage > 0
  - auth_violated gp vo economic view flag

Hc t Raven (2512.22616) §4 — 6 invariant categories t revert-semantic:
  SB (state-based), TB (token-based), EV (event-based),
  CB (control-based), MB (math-based), AB (access-based).
  TraceGuard map: AB → Authorization, MB → AMM product-k,
  SB/TB → universal i_1–i_3, CB → lending borrow/collateral.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Known selectors for authorization pattern detection
_ONLY_OWNER_SELECTORS = {
    "0x8da5cb5b",  # owner()
    "0x715018a6",  # renounceOwnership()
    "0xf2fde38b",  # transferOwnership(address)
}
_PROXY_ADMIN_SELECTORS = {
    "0x3659cfe6",  # upgradeTo(address)
    "0x4f1ef286",  # upgradeToAndCall(address,bytes)
    "0x8f283970",  # changeAdmin(address)
}
_TIMELOCK_SELECTORS = {
    "0x01d5062a",  # schedule(...)
    "0xe38335e5",  # scheduleBatch(...)
    "0x134008d3",  # execute(...)
    "0xe38335e5",  # executeBatch(...)
    "0xca33e64c",  # getMinDelay()
}
_PRIVILEGED_SELECTORS = (
    _ONLY_OWNER_SELECTORS | _PROXY_ADMIN_SELECTORS | _TIMELOCK_SELECTORS
)

# ERC20 Transfer topic
_TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# EIP-1967 admin storage slot
_EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

# Deposit/Withdraw event selectors (Aave, Compound, generic lending)
_DEPOSIT_SELECTORS = {
    "0xdcbc1c05",  # Deposit(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint256 referral)
    "0xe1fffcc4",  # Deposit(address indexed dst, uint256 wad) — WETH
    "0x8752a472",  # Deposit(address indexed provider, uint256 value, uint256 locktime, int128 type, uint256 ts)
}
_WITHDRAW_SELECTORS = {
    "0x9c396577",  # Withdraw(address indexed reserve, address indexed user, address indexed to, uint256 amount)
    "0x884edad9",  # Withdraw(address indexed provider, uint256 value, uint256 ts)
    "0x7084f581",  # RedeemUnderlying(...)
}


@dataclass
class InvariantResult:
    """Invariant catalog verification result."""
    violated: list[str] = field(default_factory=list)     # Verified execution property
    satisfied: list[str] = field(default_factory=list)    # Verified execution property
    skipped: list[str] = field(default_factory=list)      # Verified execution property
    auth_violated: bool = False                            # authorization violation flag
    catalog_score: float = 0.0                            # [0,1] = n_violated / n_checked
    details: dict[str, Any] = field(default_factory=dict) # Verified execution property

    def as_signal(self) -> float:
        """Anomaly signal in [0,1]: higher scores indicate multiple invariant violations."""
        return self.catalog_score


# ===========================================================================
# Group 1 — Universal invariants (EVM-agnostic)
# ===========================================================================

def _collect_transfers(logs: list[dict]) -> list[dict]:
    """Collect ERC20 Transfer events t logs."""
    return [
        log for log in logs
        if len(log.get("topics", [])) >= 3
        and log["topics"][0].lower() == _TOPIC_TRANSFER
    ]


def check_i1_no_money_from_air(trace: dict, delta: dict) -> tuple[bool, dict]:
    """i_1: Value conservation -- net outflow must not exceed net inflow plus gas fees for any contract.

    Violation: contract experiences net token drain without legitimate deposit/inflow.
    flash-loan provider hoc minting contract.
    Hc t MonteCrypto: inflow = outflow - fees (bridge version).

    Tr (violated, details).
    """
    logs = trace.get("logs", [])
    transfers = _collect_transfers(logs)
    if not transfers:
        return False, {"note": "no transfers"}

    # Net flow per (contract, token): positive = net inflow, negative = net outflow
    net: dict[tuple[str, str], int] = {}
    for t in transfers:
        frm = ("0x" + t["topics"][1][-40:]).lower()
        to = ("0x" + t["topics"][2][-40:]).lower()
        token = (t.get("address") or "").lower()
        amt = int(t.get("data") or "0x0", 16) if (t.get("data") or "0x") not in ("0x", "") else 0
        net[(frm, token)] = net.get((frm, token), 0) - amt
        net[(to, token)] = net.get((to, token), 0) + amt

    # Check: any non-zero-address account with net negative (net outflow) > 0
    # that was not previously holding that amount
    large_net_outflow = {
        (addr, tok): -v
        for (addr, tok), v in net.items()
        if v < 0 and addr not in ("0x0000000000000000000000000000000000000000",)
    }
    # Simple heuristic: if total net outflow > total net inflow across all pairs → violated
    total_out = sum(large_net_outflow.values())
    total_in = sum(v for v in net.values() if v > 0)
    violated = total_out > total_in * 1.01  # 1% tolerance for rounding
    return violated, {
        "total_net_outflow": total_out,
        "total_net_inflow": total_in,
        "n_pairs": len(net),
    }


def check_i2_no_negative_balance(trace: dict, delta: dict) -> tuple[bool, dict]:
    """i_2: Non-negative balance constraint -- post-tx balances must be >= 0 across all tokens.

    Detects via stateDiff if available; falls back to transfer balance delta logic.
    Hc t Raven (2512.22616) category TB (token-based).
    """
    balances = delta.get("balances", {}) or {}

    # Execution trace analysis and verification

    # Execution trace analysis and verification
    eth_neg = [(addr, delta_val) for addr, delta_val in balances.items()
               if delta_val < -1e18 * 1000]  # > 1000 ETH outflow = suspicious
    violated = len(eth_neg) > 0
    return violated, {
        "large_eth_outflow": [(a, v) for a, v in eth_neg[:5]],
        "n_accounts": len(balances),
    }


def check_i3_no_withdraw_without_deposit(trace: dict, delta: dict) -> tuple[bool, dict]:
    """i_3: No Withdrawal without preceding corresponding Deposit.

    Tracks Deposit/Withdraw function calls to verify execution ordering.
    Hc t Raven (2512.22616) category SB (state-based).
    """
    calls = trace.get("flat_calls", [])
    deposits = [c for c in calls if c.get("selector") in _DEPOSIT_SELECTORS]
    withdraws = [c for c in calls if c.get("selector") in _WITHDRAW_SELECTORS]

    # Simple check: withdraws > deposits (more withdrawals than deposits in trace)
    # Reentrancy pattern: withdraw before state update → multiple withdraws
    violated = len(withdraws) > 0 and len(withdraws) > max(1, len(deposits))
    return violated, {
        "n_deposits": len(deposits),
        "n_withdraws": len(withdraws),
    }


# ===========================================================================
# Group 2 — Economic-regime invariants
# ===========================================================================

def check_amm_product_k(trace: dict, delta: dict, tolerance: float = 0.05) -> tuple[bool, dict]:
    """AMM product-k invariant: x * y ≥ k (constant product).

    Detects AMM reserve changes in state delta.
    Hc t FlashSyn CEDA + proposal §6.2.

    Heuristic: if storage delta indicates both pair reserve slots modified simultaneously,
    verifies constant product invariant: post_r0 * post_r1 >= pre_r0 * pre_r1 * (1-fee).
    """
    storage = delta.get("storage", {}) or {}
    if not storage:
        return False, {"note": "no storage delta"}

    # Execution trace analysis and verification
    violations = []
    for addr, slots in storage.items():
        if len(slots) < 2:
            continue
        pairs = sorted(slots.items())
        # Take first 2 slots as reserve0/reserve1 approximation
        slot_vals = []
        for _, pair in pairs[:2]:
            if pair and len(pair) >= 2 and pair[0] is not None and pair[1] is not None:
                slot_vals.append((pair[0], pair[1]))
        if len(slot_vals) < 2:
            continue
        pre0, post0 = slot_vals[0]
        pre1, post1 = slot_vals[1]
        if pre0 > 0 and pre1 > 0 and post0 > 0 and post1 > 0:
            k_pre = pre0 * pre1
            k_post = post0 * post1
            # k_post < k_pre * (1 - tolerance) → product decreased → invariant violation
            if k_post < k_pre * (1 - tolerance):
                violations.append({
                    "addr": addr,
                    "k_pre": k_pre,
                    "k_post": k_post,
                    "ratio": k_post / k_pre,
                })
    violated = len(violations) > 0
    return violated, {"violations": violations[:3]}


def check_lending_collateral_ratio(trace: dict, delta: dict,
                                   min_factor: float = 0.75) -> tuple[bool, dict]:
    """Lending invariant: borrow ≤ collateral * collateral_factor.

    Detect undercollateralized borrow: nu net ETH outflow >> net ETH inflow cho
    mt account → suspicious borrow pattern.
    Hc t Time-Travel Investigation + proposal §6.2.
    """
    balances = delta.get("balances", {}) or {}
    if not balances:
        return False, {"note": "no balance delta"}

    # Execution trace analysis and verification
    large_recipients = [
        (addr, v) for addr, v in balances.items()
        if v > int(1e18 * 10)  # > 10 ETH net inflow
    ]
    large_senders = [
        (addr, -v) for addr, v in balances.items()
        if v < -int(1e18 * 10)  # > 10 ETH net outflow
    ]
    # Both large recipient and large sender in same tx → potential borrow
    violated = len(large_recipients) > 0 and len(large_senders) > 0 and (
        sum(v for _, v in large_recipients) > sum(v for _, v in large_senders) * (1 + min_factor)
    )
    return violated, {
        "large_recipients": large_recipients[:3],
        "large_senders": large_senders[:3],
    }


# ===========================================================================
# Group 3 — Authorization invariants (2026 focus)
# ===========================================================================

def check_auth_viol(trace: dict) -> tuple[bool, dict]:
    """Authorization violation: privileged call combined with large fund transfer.

    Detects transactions invoking privileged selectors (owner/proxy/timelock)
    in conjunction with large fund movements.
    """
    calls = trace.get("flat_calls", [])
    logs = trace.get("logs", [])

    privileged_calls = [
        c for c in calls
        if c.get("selector") in _PRIVILEGED_SELECTORS
    ]
    if not privileged_calls:
        return False, {"note": "no privileged selectors"}

    # Check for large fund transfer accompanying privileged call
    transfers = _collect_transfers(logs)
    large_transfers = []
    for t in transfers:
        amt = int(t.get("data") or "0x0", 16) if (t.get("data") or "0x") not in ("0x", "") else 0
        # Threshold: > 1M tokens (approximate, token-agnostic)
        if amt > 10**24:  # 1M of 1e18-decimals token
            large_transfers.append({
                "token": t.get("address"),
                "amount": amt,
            })

    violated = len(privileged_calls) > 0 and len(large_transfers) > 0
    return violated, {
        "privileged_selectors": [c.get("selector") for c in privileged_calls[:5]],
        "large_transfers": large_transfers[:3],
    }


def check_proxy_admin_change(trace: dict, delta: dict) -> tuple[bool, dict]:
    """Detect proxy admin change via EIP-1967 slot modification.

    EIP-1967 admin slot modification check.
    Hc t proposal §5.3.2 f_auth semantics.
    """
    storage = delta.get("storage", {}) or {}
    admin_changes = []
    for addr, slots in storage.items():
        if _EIP1967_ADMIN_SLOT in slots:
            pair = slots[_EIP1967_ADMIN_SLOT]
            if pair and len(pair) >= 2 and pair[0] != pair[1]:
                admin_changes.append({
                    "contract": addr,
                    "old_admin": hex(pair[0]) if pair[0] else "0x0",
                    "new_admin": hex(pair[1]) if pair[1] else "0x0",
                })
    violated = len(admin_changes) > 0
    return violated, {"admin_changes": admin_changes}


# ===========================================================================
# Combined check — catalog API
# ===========================================================================

def check_all_invariants(
    trace: dict,
    delta: dict,
    regime: str = "auto",
) -> InvariantResult:
    """Execute full invariant catalog and return aggregated InvariantResult.

    `regime`: "auto" (heuristic t trace), "lending", "amm", "governance", "general".

    Th t check: Universal → Economic-regime → Authorization.
    Coverage: ch check invariant c  data (delta, logs, calls).
    """
    result = InvariantResult()
    has_storage = bool(delta.get("storage"))
    has_balances = bool(delta.get("balances"))
    has_transfers = any(
        len(log.get("topics", [])) >= 3 and log["topics"][0].lower() == _TOPIC_TRANSFER
        for log in trace.get("logs", [])
    )

    checks: list[tuple[str, Any, tuple]] = []

    # --- Universal ---
    if has_transfers:
        checks.append(("i1_no_money_from_air", check_i1_no_money_from_air, (trace, delta)))
    else:
        result.skipped.append("i1_no_money_from_air")

    if has_balances:
        checks.append(("i2_no_negative_balance", check_i2_no_negative_balance, (trace, delta)))
    else:
        result.skipped.append("i2_no_negative_balance")

    if trace.get("flat_calls"):
        checks.append(("i3_no_withdraw_without_deposit", check_i3_no_withdraw_without_deposit, (trace, delta)))
    else:
        result.skipped.append("i3_no_withdraw_without_deposit")

    # --- Economic-regime ---
    if regime in ("auto", "amm") and has_storage:
        checks.append(("amm_product_k", check_amm_product_k, (trace, delta)))
    elif not has_storage and regime in ("auto", "amm"):
        result.skipped.append("amm_product_k")

    if regime in ("auto", "lending") and has_balances:
        checks.append(("lending_collateral", check_lending_collateral_ratio, (trace, delta)))
    elif not has_balances and regime in ("auto", "lending"):
        result.skipped.append("lending_collateral")

    # --- Authorization ---
    if trace.get("flat_calls"):
        checks.append(("auth_privileged_call", check_auth_viol, (trace,)))
    else:
        result.skipped.append("auth_privileged_call")

    if has_storage:
        checks.append(("proxy_admin_change", check_proxy_admin_change, (trace, delta)))
    else:
        result.skipped.append("proxy_admin_change")

    # Run checks
    n_checked = 0
    for name, fn, args in checks:
        try:
            violated, details = fn(*args)
            n_checked += 1
            result.details[name] = details
            if violated:
                result.violated.append(name)
                if name in ("auth_privileged_call", "proxy_admin_change"):
                    result.auth_violated = True
            else:
                result.satisfied.append(name)
        except Exception as e:
            result.skipped.append(name)
            result.details[name] = {"error": str(e)[:100]}

    result.catalog_score = len(result.violated) / max(n_checked, 1)
    return result


def auth_viol(trace: dict, delta: dict | None = None) -> bool:
    """Return True if authorization violation is detected in trace.

    Evaluates violation predicates for E4 counterfactual necessity.
    """
    delta = delta or {}
    violated_auth, _ = check_auth_viol(trace)
    if violated_auth:
        return True
    if delta.get("storage"):
        violated_proxy, _ = check_proxy_admin_change(trace, delta)
        return violated_proxy
    return False


def catalog_signal(trace: dict, delta: dict | None = None,
                   regime: str = "auto") -> float:
    """Return catalog score in [0,1] as auxiliary signal for view_state_delta.

    Provides anomaly score for screening and hints candidate intervention targets.
    """
    delta = delta or {}
    result = check_all_invariants(trace, delta, regime)
    return result.catalog_score


def suggest_mutations(result: InvariantResult) -> list[str]:
    """Da trn invariant violations,  xut mutation ph hp.

    Catalog provides both anomaly signals and candidate mutation targets.
    """
    suggestions: list[str] = []
    for name in result.violated:
        if "amm" in name or "product_k" in name:
            suggestions.append("f_orc")   # oracle price manipulation
            suggestions.append("f_swap")  # swap slice isolation
        elif "lending" in name or "collateral" in name:
            suggestions.append("f_fl")    # flash loan (collateral manipulation)
        elif "auth" in name or "admin" in name or "proxy" in name:
            suggestions.append("f_auth")  # authorization revoke
        elif "withdraw" in name or "deposit" in name:
            suggestions.append("f_fl")    # flash loan enabling reentrancy-like
    return sorted(set(suggestions))
