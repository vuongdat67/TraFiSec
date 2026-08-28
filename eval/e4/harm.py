"""Tier 2 harm-oracle policy for E4.

Harm measurement is deliberately separate from mutation planning and replay.
Missing victims, prices, or decodable logs produce ``UNKNOWN``; they never
become zero harm.  Protocol-specific behavior is selected by the case's
declared ``harm_spec`` rather than inferred from ground-truth labels.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Protocol

from core.rpc import RpcClient, RpcError
from eval.e4.models import HarmAssessment


TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# Euler's protocol-level Liquidation event.  Keeping this as an explicit
# signature prevents an arbitrary token transfer from being interpreted as a
# liquidation-induced liability.
EULER_LIQUIDATION_TOPIC = (
    "bba0f1d6fb8b9abe2bbc543b7c13d43faba91c6f78da4700381c94041ac7267d"
)
DEFAULT_LMIN_USD = 100_000.0


class HarmOracle(Protocol):
    """Boundary for a case-specific, explicitly declared harm oracle."""

    def assess(
        self,
        receipt: dict | None,
        harm_spec: dict | None,
        *,
        disclosed_loss_usd: float | None = None,
        baseline: bool = False,
    ) -> HarmAssessment:
        ...


def _loss_from_receipt_data(
    receipt: dict,
    prices: dict,
    victims: set[str] | None = None,
) -> float | None:
    """Compute victim-side USD loss from ERC-20 Transfer logs."""
    net: dict[tuple[str, str], float] = defaultdict(float)
    for log in receipt.get("logs") or []:
        topics = log.get("topics") or []
        if len(topics) < 3 or str(topics[0]).lower().removeprefix("0x") != TRANSFER_TOPIC:
            continue
        sender = "0x" + str(topics[1])[-40:].lower()
        recipient = "0x" + str(topics[2])[-40:].lower()
        try:
            amount = int(log.get("data", "0x0"), 16)
        except (TypeError, ValueError):
            continue
        token = str(log.get("address") or "").lower()
        net[(sender, token)] -= amount
        net[(recipient, token)] += amount
    if not victims or not prices:
        return None
    per_party: dict[str, float] = {}
    valued = 0
    for (address, token), delta in net.items():
        if address not in victims:
            continue
        metadata = prices.get(token)
        if metadata is None:
            continue
        if isinstance(metadata, dict):
            price = float(metadata["usd_per_token"]) / (10 ** int(metadata.get("decimals", 18)))
        else:
            price = float(metadata)
        per_party[address] = per_party.get(address, 0.0) + delta * price
        valued += 1
    if not valued:
        return None
    return sum(max(0.0, -value) for value in per_party.values())


def loss_from_receipt(archive: RpcClient, tx_hash: str, prices: dict,
                      victims: set[str] | None = None) -> float | None:
    """Fetch a receipt, then compute its victim-side transfer loss."""
    try:
        receipt = archive.eth_get_receipt(tx_hash)
    except RpcError:
        return None
    if not receipt:
        return None
    return _loss_from_receipt_data(receipt, prices, victims=victims)


def assess_harm(
    receipt: dict | None,
    harm_spec: dict | None,
    *,
    disclosed_loss_usd: float | None = None,
    baseline: bool = False,
) -> HarmAssessment:
    """Assess declared receipt-ledger harm, fail-closed on missing inputs."""
    if baseline and disclosed_loss_usd is not None and disclosed_loss_usd > 0:
        return HarmAssessment("HARM", float(disclosed_loss_usd), "disclosed_incident_loss")
    if not receipt:
        return HarmAssessment("UNKNOWN", reason="no receipt")
    spec = harm_spec or {}
    victims = {str(item).lower() for item in spec.get("victims") or []}
    prices = spec.get("token_prices") or {}
    if not victims or not prices:
        return HarmAssessment("UNKNOWN", reason="victims/token_prices not preregistered")
    loss = _loss_from_receipt_data(receipt, prices, victims=victims)
    if loss is None:
        return HarmAssessment("UNKNOWN", reason="no priced victim transfer observed")
    threshold = float(spec.get("lmin_usd", 100_000.0))
    return HarmAssessment(
        "HARM" if loss > threshold else "NO_HARM",
        loss,
        "receipt_transfer_ledger",
        f"Lmin={threshold}",
    )


def assess_transfer_harm(target: dict, harm_spec: dict | None) -> HarmAssessment:
    """bZx-style attacker net ERC-20 Transfer-delta oracle."""
    attacker = ((harm_spec or {}).get("attacker") or "").lower()
    if not attacker:
        return HarmAssessment("UNKNOWN", reason="attacker not configured")
    deltas: dict[str, int] = {}
    saw_transfer = False
    for log in target.get("logs") or []:
        topics = [str(item).lower() for item in (log.get("topics") or [])]
        if len(topics) < 3 or topics[0].removeprefix("0x") != TRANSFER_TOPIC:
            continue
        saw_transfer = True
        sender = "0x" + topics[1][-40:]
        recipient = "0x" + topics[2][-40:]
        try:
            amount = int(str(log.get("data") or "0x0"), 16)
        except ValueError:
            continue
        token = str(log.get("address") or "").lower()
        if sender == attacker:
            deltas[token] = deltas.get(token, 0) - amount
        if recipient == attacker:
            deltas[token] = deltas.get(token, 0) + amount
    if not saw_transfer:
        return HarmAssessment("UNKNOWN", reason="target receipt has no decodable Transfer logs")
    positive = {token: delta for token, delta in deltas.items() if delta > 0}
    if positive:
        return HarmAssessment("HARM", reason=f"attacker positive Transfer delta: {positive}")
    return HarmAssessment("NO_HARM", reason="attacker has no positive net Transfer delta")


def _price_metadata(metadata: Any) -> tuple[float, int] | None:
    """Return USD-per-whole-token and decimals from explicit metadata."""
    if isinstance(metadata, dict):
        if "usd_per_token" not in metadata:
            return None
        try:
            return float(metadata["usd_per_token"]), int(metadata.get("decimals", 18))
        except (TypeError, ValueError):
            return None
    try:
        return float(metadata), 18
    except (TypeError, ValueError):
        return None


def assess_attacker_value_harm(
    target: dict,
    attacker: str,
    *,
    attacker_candidates: set[str] | None = None,
    token_prices: dict[str, Any] | None = None,
    native_price_usd: float | None = None,
    lmin_usd: float = DEFAULT_LMIN_USD,
) -> HarmAssessment:
    """Measure generic positive attacker value from B2 telemetry.

    ``target`` is the B2 target payload containing ``balance_changes`` and
    receipt ``logs``. The candidate set defaults to the transaction sender
    plus contracts created by that sender in the target call trace. Deltas
    remain attributed per address in the assessment reason.
    """
    attacker = str(attacker or "").lower()
    if not attacker:
        return HarmAssessment("UNKNOWN", reason="attacker not configured")
    candidates = ({str(item).lower() for item in attacker_candidates if item}
                  if attacker_candidates is not None else
                  attacker_candidates_from_trace(target, attacker))
    candidates.add(attacker)
    prices = {str(k).lower(): v for k, v in (token_prices or {}).items()}
    raw_deltas: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for change in target.get("balance_changes") or []:
        address = str(change.get("address") or "").lower()
        if address not in candidates:
            continue
        try:
            raw_deltas[address]["native"] += int(change.get("current", 0)) - int(change.get("previous", 0))
        except (TypeError, ValueError):
            return HarmAssessment("UNKNOWN", reason="invalid native balance change")
    for log in target.get("logs") or []:
        topics = [str(item).lower() for item in (log.get("topics") or [])]
        if len(topics) < 3 or topics[0].removeprefix("0x") != TRANSFER_TOPIC:
            continue
        sender = "0x" + topics[1][-40:]
        recipient = "0x" + topics[2][-40:]
        if sender not in candidates and recipient not in candidates:
            continue
        try:
            amount = int(str(log.get("data") or "0x0"), 16)
        except (TypeError, ValueError):
            return HarmAssessment("UNKNOWN", reason="invalid ERC20 Transfer amount")
        token = str(log.get("address") or "").lower()
        if sender in candidates:
            raw_deltas[sender][token] -= amount
        if recipient in candidates:
            raw_deltas[recipient][token] += amount
    if not raw_deltas:
        return HarmAssessment("UNKNOWN", reason="no attacker balance or Transfer delta observed")

    valued = 0.0
    unpriced_positive: list[str] = []
    positive_by_address: dict[str, dict[str, int]] = {}
    for address, deltas in raw_deltas.items():
        for asset, delta in deltas.items():
            if delta <= 0:
                continue
            positive_by_address.setdefault(address, {})[asset] = delta
            if asset == "native":
                if native_price_usd is None:
                    unpriced_positive.append(f"{address}:native")
                    continue
                valued += (delta / 10**18) * float(native_price_usd)
                continue
            metadata = _price_metadata(prices.get(asset))
            if metadata is None:
                unpriced_positive.append(f"{address}:{asset}")
                continue
            usd_per_token, decimals = metadata
            valued += (delta / 10**decimals) * usd_per_token
    if unpriced_positive:
        return HarmAssessment(
            "UNKNOWN",
            reason=f"positive candidate assets lack explicit USD prices: {unpriced_positive}",
        )
    if not positive_by_address:
        return HarmAssessment("NO_HARM", 0.0, "attacker_value_delta",
                               f"no positive net candidate value; candidates={sorted(candidates)}")
    status = "HARM" if valued > float(lmin_usd) else "NO_HARM"
    return HarmAssessment(
        status,
        valued,
        "attacker_value_delta",
        f"positive_by_address={positive_by_address}; candidates={sorted(candidates)}; Lmin={float(lmin_usd)}",
    )


def _native_balance_delta(target: dict, owner: str) -> int | None:
    """Sum all B2 native-balance transitions for one account."""
    owner = str(owner or "").lower()
    if not owner:
        return None
    changes = [item for item in (target.get("balance_changes") or [])
               if str(item.get("address") or "").lower() == owner]
    if not changes:
        return None
    delta = 0
    for item in changes:
        try:
            delta += int(item["current"]) - int(item["previous"])
        except (KeyError, TypeError, ValueError):
            return None
    return delta


def parse_prestate_native_balance_delta(diff: dict, owner: str) -> int | None:
    """Extract one account's native balance delta from Geth diffMode output."""
    owner = str(owner or "").lower()
    pre = diff.get("pre") if isinstance(diff, dict) else None
    post = diff.get("post") if isinstance(diff, dict) else None
    if not isinstance(pre, dict) or not isinstance(post, dict):
        return None
    pre_acc = next((value for key, value in pre.items()
                    if str(key).lower() == owner), None)
    post_acc = next((value for key, value in post.items()
                     if str(key).lower() == owner), None)
    if not isinstance(pre_acc, dict) or not isinstance(post_acc, dict):
        return None
    def quantity(value: object) -> int:
        if isinstance(value, int):
            return value
        text = str(value)
        return int(text, 16) if text.lower().startswith("0x") else int(text)

    try:
        return quantity(post_acc["balance"]) - quantity(pre_acc["balance"])
    except (KeyError, TypeError, ValueError):
        return None


def fetch_prestate_native_balance_delta(archive: RpcClient, tx_hash: str,
                                        owner: str) -> int | None:
    """Fetch the historical whole-transaction native balance delta."""
    try:
        diff = archive.call("debug_traceTransaction", [
            tx_hash,
            {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}},
        ])
    except RpcError:
        return None
    return parse_prestate_native_balance_delta(diff, owner)


def _token_transfer_delta(target: dict, owner: str, token: str) -> int | None:
    owner, token = str(owner).lower(), str(token).lower()
    delta = 0
    seen = False
    for log in target.get("logs") or []:
        topics = [str(item).lower() for item in (log.get("topics") or [])]
        if (len(topics) < 3 or topics[0].removeprefix("0x") != TRANSFER_TOPIC
                or str(log.get("address") or "").lower() != token):
            continue
        sender, recipient = "0x" + topics[1][-40:], "0x" + topics[2][-40:]
        if owner not in {sender, recipient}:
            continue
        try:
            amount = int(str(log.get("data") or "0x0"), 16)
        except (TypeError, ValueError):
            return None
        seen = True
        if recipient == owner:
            delta += amount
        if sender == owner:
            delta -= amount
    # An explicitly present B2/archive log collection with no matching
    # transfer is a measured zero at the target boundary.  A missing ``logs``
    # field remains unknown and is handled by the caller.
    return delta if seen or isinstance(target.get("logs"), list) else None


def parse_trace_token_transfer_delta(trace: dict, owner: str,
                                     token: str) -> int | None:
    """Extract a protected ERC-20 delta from recursive callTracer withLog."""
    logs: list[dict] = []
    def walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        logs.extend(node.get("logs") or [])
        for child in node.get("calls") or []:
            walk(child)
    walk(trace)
    return _token_transfer_delta({"logs": logs}, owner, token)


def fetch_trace_token_transfer_delta(archive: RpcClient, tx_hash: str,
                                     owner: str, token: str) -> int | None:
    """Fetch archive callTracer logs for one protected ERC-20 delta."""
    try:
        trace = archive.call("debug_traceTransaction", [
            tx_hash, {"tracer": "callTracer", "tracerConfig": {"withLog": True}},
        ])
    except RpcError:
        return None
    return parse_trace_token_transfer_delta(trace, owner, token)


def assess_pool_balance_delta(
    target: dict,
    harm_spec: dict | None,
    *,
    archive_delta_wei: int | None = None,
) -> HarmAssessment:
    """Measure protected Fulcrum native-ETH debit in USD.

    ERC-20 logs are deliberately excluded: WETH is a separate ledger asset.
    For a baseline, local B2 telemetry must agree with archive diffMode.
    """
    spec = harm_spec or {}
    owner = str(spec.get("protected_owner") or "").lower()
    asset = str(spec.get("protected_asset") or "").lower()
    token = str(spec.get("protected_token") or "").lower()
    if not owner or asset not in {"native eth", "eth", "native", "weth"}:
        return HarmAssessment("UNKNOWN", source="pool_balance_delta",
                              reason="protected native-ETH owner/asset not configured")
    try:
        price = float(spec["native_price_usd"])
        lmin = float(spec.get("lmin_usd", DEFAULT_LMIN_USD))
    except (KeyError, TypeError, ValueError):
        return HarmAssessment("UNKNOWN", source="pool_balance_delta",
                              reason="native price or Lmin is invalid")
    local_delta = (_native_balance_delta(target, owner) if asset != "weth"
                   else _token_transfer_delta(target, owner, token))
    if local_delta is None:
        return HarmAssessment("UNKNOWN", source="pool_balance_delta",
                              reason=f"no valid B2 {asset} transitions for {owner}")
    if archive_delta_wei is not None and local_delta != int(archive_delta_wei):
        return HarmAssessment(
            "UNKNOWN", source="pool_balance_delta",
            reason=(f"B2/archive native delta mismatch for {owner}: "
                    f"b2={local_delta} archive={int(archive_delta_wei)}"),
        )
    debit_wei = max(0, -local_delta)
    loss_usd = (debit_wei / 10**18) * price
    status = "HARM" if loss_usd > lmin else "NO_HARM"
    return HarmAssessment(
        status, loss_usd, "pool_balance_delta",
        (f"owner={owner}; asset={asset}; delta_wei={local_delta}; "
         f"debit_wei={debit_wei}; eth_usd={price}; Lmin={lmin}; "
         f"archive_crosscheck={'matched' if archive_delta_wei is not None else 'not_run'}"),
    )


def _transfer_delta_for_token(target: dict, owner: str, token: str) -> int | None:
    """Return one account's ERC-20 delta for a declared token."""
    return _token_transfer_delta(target, owner, token)


def assess_euler_bad_debt_delta(target: dict, harm_spec: dict | None) -> HarmAssessment:
    """Measure Euler's realized uncollateralized-liability lower bound.

    This is deliberately narrower than total protocol bad debt.  It measures
    the declared violator's post-target dToken liability, less the violator's
    remaining eToken collateral valued at a preregistered exchange rate.  The
    oracle is eligible only when the target emits Euler's Liquidation event
    from the declared protocol address.  Missing logs, prices, or the event
    remain ``UNKNOWN``.

    Amounts are raw 18-decimal token units; ``collateral_underlying_per_token``
    is an underlying-token amount per whole eToken, frozen before replay.
    """
    spec = harm_spec or {}
    required = ("violator", "debt_token", "collateral_token",
                "collateral_underlying_per_token", "debt_price_usd",
                "collateral_price_usd", "liquidation_event_address")
    missing = [key for key in required if key not in spec]
    if missing:
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason=f"missing preregistered fields: {missing}")
    try:
        violator = str(spec["violator"]).lower()
        debt_token = str(spec["debt_token"]).lower()
        collateral_token = str(spec["collateral_token"]).lower()
        debt_price = float(spec["debt_price_usd"])
        collateral_price = float(spec["collateral_price_usd"])
        collateral_rate = float(spec["collateral_underlying_per_token"])
        lmin = float(spec.get("lmin_usd", DEFAULT_LMIN_USD))
        pre_debt = int(spec.get("pre_debt_balance", 0))
        pre_collateral = int(spec.get("pre_collateral_balance", 0))
    except (TypeError, ValueError):
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="invalid numeric/address metadata")
    if not violator or not debt_token or not collateral_token or min(
            debt_price, collateral_price, collateral_rate, lmin) < 0:
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="invalid non-negative ledger metadata")

    logs = target.get("logs")
    if not isinstance(logs, list):
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="target logs unavailable")
    event_topic = str(spec.get("liquidation_event_topic", EULER_LIQUIDATION_TOPIC)).lower().removeprefix("0x")
    event_address = str(spec["liquidation_event_address"]).lower()
    event_seen = any(
        isinstance(log, dict)
        and str(log.get("address") or "").lower() == event_address
        and (log.get("topics") or [])
        and str(log["topics"][0]).lower().removeprefix("0x") == event_topic
        for log in logs
    )
    if not event_seen:
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="declared Euler Liquidation event not observed")
    debt_delta = _transfer_delta_for_token(target, violator, debt_token)
    collateral_delta = _transfer_delta_for_token(target, violator, collateral_token)
    if debt_delta is None or collateral_delta is None:
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="dToken/eToken transfer ledger incomplete")
    debt_after = pre_debt + debt_delta
    collateral_after = pre_collateral + collateral_delta
    if debt_after < 0 or collateral_after < 0:
        return HarmAssessment("UNKNOWN", source="euler_bad_debt_delta",
                              reason="ledger produced negative post-target balance")
    debt_usd = debt_after / 10**18 * debt_price
    collateral_usd = collateral_after / 10**18 * collateral_rate * collateral_price
    loss_usd = max(0.0, debt_usd - collateral_usd)
    status = "HARM" if loss_usd > lmin else "NO_HARM"
    return HarmAssessment(
        status, loss_usd, "euler_bad_debt_delta",
        (f"violator={violator}; debt_after={debt_after}; collateral_after={collateral_after}; "
         f"debt_usd={debt_usd}; collateral_usd={collateral_usd}; Lmin={lmin}; "
         "quantity=uncollateralized_violator_liability_lower_bound"),
    )


def created_addresses_from_trace(trace: dict | list | None, root_attacker: str) -> set[str]:
    """Return CREATE destinations attributable to the target transaction sender."""
    candidates = {str(root_attacker or "").lower()} if root_attacker else set()
    pending = [trace] if isinstance(trace, dict) else list(trace or [])
    frames: list[dict] = []
    while pending:
        frame = pending.pop()
        if not isinstance(frame, dict):
            continue
        frames.append(frame)
        pending.extend(frame.get("calls") or [])
    changed = True
    while changed:
        changed = False
        for frame in frames:
            creator = str(frame.get("from") or "").lower()
            created = str(frame.get("to") or "").lower()
            if (str(frame.get("type") or "").upper() in {"CREATE", "CREATE2"}
                    and creator in candidates and created and created not in candidates):
                candidates.add(created)
                changed = True
    candidates.discard(str(root_attacker or "").lower())
    return candidates


def attacker_candidates_from_trace(target: dict, attacker: str) -> set[str]:
    """Build the sender-plus-CREATE candidate set from B2 call telemetry."""
    if not attacker:
        return set()
    return {str(attacker).lower()} | created_addresses_from_trace(
        target.get("call_trace"), attacker)


def resolve_attacker_address(tx: dict | None, override: str | None = None) -> str | None:
    """Use an explicit attacker override, otherwise the target tx ``from``."""
    address = override or (tx or {}).get("from")
    return str(address).lower() if address else None


class ReceiptLedgerOracle:
    """Generic victim-transfer oracle used when a case declares token prices."""

    def assess(self, receipt, harm_spec, *, disclosed_loss_usd=None, baseline=False):
        return assess_harm(
            receipt,
            harm_spec,
            disclosed_loss_usd=disclosed_loss_usd,
            baseline=baseline,
        )


class TransferDeltaOracle:
    """Case-specific attacker transfer-delta oracle, currently used by bZx."""

    def assess(self, receipt, harm_spec, *, disclosed_loss_usd=None, baseline=False):
        return assess_transfer_harm(receipt or {}, harm_spec)


class AttackerValueOracle:
    """Generic attacker-value oracle using explicit case price metadata."""

    def assess(self, receipt, harm_spec, *, disclosed_loss_usd=None, baseline=False):
        spec = harm_spec or {}
        return assess_attacker_value_harm(
            receipt or {},
            spec.get("attacker", ""),
            token_prices=spec.get("token_prices"),
            native_price_usd=spec.get("native_price_usd"),
            lmin_usd=float(spec.get("lmin_usd", DEFAULT_LMIN_USD)),
        )


class PoolBalanceOracle:
    """Protected native-ETH pool ledger oracle."""

    def assess(self, receipt, harm_spec, *, disclosed_loss_usd=None, baseline=False):
        return assess_pool_balance_delta(receipt or {}, harm_spec)


class EulerBadDebtOracle:
    """Narrow, explicitly declared Euler liability oracle."""

    def assess(self, receipt, harm_spec, *, disclosed_loss_usd=None, baseline=False):
        return assess_euler_bad_debt_delta(receipt or {}, harm_spec)


def create_harm_oracle(harm_spec: dict | None) -> HarmOracle:
    """Select only from explicit case metadata; never infer a label."""
    oracle_name = str((harm_spec or {}).get("oracle") or "")
    if oracle_name.endswith("_transfer_delta"):
        return TransferDeltaOracle()
    if oracle_name == "attacker_value_delta":
        return AttackerValueOracle()
    if oracle_name == "pool_balance_delta":
        return PoolBalanceOracle()
    if oracle_name == "euler_bad_debt_delta":
        return EulerBadDebtOracle()
    return ReceiptLedgerOracle()
