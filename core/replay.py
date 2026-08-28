"""
TraFiSec Core -- Replayer: deterministic transaction replay on local Anvil fork
================================================================================
Replays transactions on a local fork via JSON-RPC (`eth_sendTransaction` with
auto-impersonation), capturing receipt status, logs, and gasUsed.

Mid-block dependencies:
If the target transaction resides at index k > 0 within block b, the state depends on
the prefix 0..k-1 transactions. The replayer executes prefix warmup sequentially
prior to replaying the target transaction, ensuring identical pre-state for both
fidelity baselines and mutation branches.
"""
from __future__ import annotations

from .fork import ForkRunner
from .outcome import Outcome, ReplayResult
from .rpc import RpcClient, RpcError


_MAX_DIAGNOSTIC_CHARS = 8192


class Replayer:
    def __init__(self, fork: ForkRunner, archive: RpcClient | None = None,
                 timeout: int = 240, transactions: dict[str, dict] | None = None):
        self.fork = fork
        self.archive = archive
        # Archive acquisition is normally performed before replay.  Keeping a
        # small injectable transaction cache makes the local engine usable
        # offline and prevents it from silently reaching back to the provider.
        self.transactions = transactions or {}
        self.timeout = timeout
        self.last_error: str = ""
        self.data_override: str | None = None  # Verified execution property
        self.start_cap: int | None = None  # Verified execution property
        self.start_cap_ratio: float | None = None  # Verified execution property
        self.data: str | None = None  # Verified execution property

    # Execution trace analysis and verification
    def tx_parts(self, tx_hash: str) -> dict:
        tx = self.transactions.get(tx_hash)
        if tx is None and self.archive is not None:
            tx = self.archive.eth_get_transaction(tx_hash)
        if not tx:
            raise RpcError(f"transaction cache miss: {tx_hash}")
        self.data = tx.get("input") or "0x"
        return tx

    def mainnet_gas(self, tx_hash: str) -> int | None:
        if self.archive is None:
            return None
        rec = self.archive.eth_get_receipt(tx_hash)
        return int(rec.get("gasUsed", "0x0"), 16) if rec else None

    # ---- resend ----
    def _send(self, tx: dict) -> tuple[bool | None, int | None, dict | None]:
        """Resend tx gc trn fork qua JSON-RPC; None = fail/timeout."""
        self.last_error = ""
        # No archive-side fee estimation is needed: Anvil already impersonates
        # the historical sender for this local-only transaction.
        return self._send_via_http(tx)

    def _send_via_http(self, tx: dict) -> tuple[bool | None, int | None, dict | None]:
        """Fallback when command line exceeds 32K chars: eth_sendTransaction via JSON-RPC.
        + poll receipt (anvil fork, --unlocked t --auto-impersonate nn khng cn sign).
        Retry 520/429; tr (status, gasUsed, receipt)."""
        import time as _time
        to = tx.get("to")
        data = self.data_override or tx.get("input") or "0x"
        if self.start_cap is not None and self.data_override is None:
            from .mutate import start_cap_override  # Verified execution property
            ov = start_cap_override(data, self.start_cap)
            if ov is not None:
                data = ov
                self.data_override = ov
        elif self.start_cap_ratio is not None and self.data_override is None:
            from .mutate import START_SELECTOR, start_cap_override  # lazy import
            if (data.startswith("0x") and len(data) == 2 + 8 + 192
                    and data[2:10].lower() == START_SELECTOR):
                original_amount = int(data[2 + 8 + 64:2 + 8 + 128], 16)
                scaled_amount = int(original_amount * self.start_cap_ratio)
                ov = start_cap_override(data, scaled_amount)
                if ov is not None:
                    data = ov
                    self.data_override = ov
        payload = {
            "from": tx["from"], "to": to, "value": tx["value"],
            "gas": tx["gas"], "data": data,
        }
        # Preserve the transaction fee type.  A legacy pre-London tx has only
        # gasPrice; mapping that value into maxFeePerGas makes Anvil reject the
        # replay on a pre-London fork with -32602.
        max_fee = tx.get("maxFeePerGas")
        priority_fee = tx.get("maxPriorityFeePerGas")
        if max_fee is not None:
            payload["maxFeePerGas"] = max_fee
            if priority_fee is not None:
                payload["maxPriorityFeePerGas"] = priority_fee
        elif tx.get("gasPrice") is not None:
            payload["gasPrice"] = tx["gasPrice"]
        for attempt in range(3):
            try:
                from .rpc import RpcClient as _RC2
                h = _RC2(self.fork.url, timeout=self.timeout, attempts=1).call(
                    "eth_sendTransaction", [payload])
            except RpcError as e:
                # Preserve the fork/archive diagnostic.  Returning None alone
                # collapses an upstream 503, an Anvil fork read failure, and a
                # local timeout into the same opaque UNOBSERVED row.
                self.last_error = str(e)[:_MAX_DIAGNOSTIC_CHARS]
                if "520" in str(e) or "429" in str(e):
                    _time.sleep(2 * (attempt + 1))
                    continue
                return None, None, None
            break
        else:
            return None, None, None
        deadline = _time.time() + self.timeout
        from .rpc import RpcClient as _RC  # Verified execution property
        fork_client = _RC(self.fork.url, timeout=self.timeout, attempts=1)
        while _time.time() < deadline:
            rec = fork_client.eth_get_receipt(h)
            if rec:
                st = rec.get("status")
                ok = st in ("0x1", 1)
                return (True if ok else False, int(rec.get("gasUsed", "0x0") or "0x0", 16), rec)
            _time.sleep(0.5)
        self.last_error = f"receipt polling exceeded {self.timeout}s after eth_sendTransaction"
        return None, None, None

    # ---- warm-up mid-block ----
    def warmup(self, prior_hashes: list[str], gas_limit_multiplier: float = 1.5) -> list[str]:
        """Replay tx idx 0..k−1 trc target (mid-block reconstruction).

        Anvil/fork gas accounting can be higher than the historical receipt for
        a prefix transaction.  Give warm-up calls bounded headroom; this does
        not alter calldata/value/state semantics and avoids mistaking local
        out-of-gas for a historical revert.
        """
        if gas_limit_multiplier < 1:
            raise ValueError("warm-up gas limit multiplier must be >= 1")
        failed = []
        self.warmup_failures: list[dict] = []
        for h in prior_hashes:
            try:
                tx = self.tx_parts(h)
            except RpcError as exc:
                failed.append(h)
                self.warmup_failures.append({"tx_hash": h, "observed": False,
                                             "status": None, "reason": str(exc)[:512]})
                continue
            if gas_limit_multiplier > 1 and tx.get("gas"):
                tx = dict(tx)
                tx["gas"] = hex(max(int(tx["gas"], 16),
                                   int(int(tx["gas"], 16) * gas_limit_multiplier)))
            # Historical senders may have enough ETH for actual gas used but
            # not Anvil's upfront gas-limit affordability check. Temporarily
            # top up only those senders and subtract the same delta after the
            # receipt, preserving the sender's balance delta.
            topup = 0
            sender = tx.get("from")
            st = None
            local = RpcClient(self.fork.url, timeout=min(self.timeout, 30), attempts=1)
            try:
                gas_price = getattr(self, "gas_price", None)
                if gas_price is None:
                    gas_price = int(tx.get("gasPrice", "0x0"), 16)
                required = int(tx.get("gas", "0x0"), 16) * int(gas_price)
                required += int(tx.get("value", "0x0"), 16)
                before = local.eth_get_balance(sender, "latest") if sender else 0
                if sender and before < required:
                    top_balance = 1 << 120
                    local.anvil_set_balance(sender, hex(top_balance))
                    topup = top_balance - before
                st, _, _ = self._send(tx)
            finally:
                if topup and sender:
                    try:
                        after = local.eth_get_balance(sender, "latest")
                        local.anvil_set_balance(sender, hex(max(0, after - topup)))
                    except RpcError:
                        self.warmup_failures.append({
                            "tx_hash": h, "observed": st is not None,
                            "status": st, "reason": "failed to restore warm-up balance top-up",
                        })
            if st is None or st is False:
                historical_status = None
                if self.archive is not None:
                    try:
                        historical = self.archive.eth_get_receipt(h)
                        historical_status = historical.get("status") if historical else None
                    except RpcError:
                        historical_status = None
                # A reverted prefix tx still consumes its nonce/gas and is a
                # valid part of the historical block. Only reject a local
                # revert when the archive says the historical tx succeeded.
                if st is False and historical_status in ("0x0", 0, False):
                    self.warmup_failures.append({
                        "tx_hash": h, "observed": True, "status": False,
                        "historical_status": historical_status,
                        "reason": "historical warm-up revert accepted",
                    })
                    continue
                failed.append(h)
                self.warmup_failures.append({"tx_hash": h, "observed": st is not None,
                                             "status": st,
                                             "reason": self.last_error or
                                             ("warm-up EVM revert" if st is False else "warm-up transport failure")})
        return failed

    # ---- replay target ----
    def replay(self, tx_hash: str, mainnet_gas: int | None = None) -> ReplayResult:
        tx = self.tx_parts(tx_hash)
        st, gas, rec = self._send(tx)
        if st is None:
            detail = f" | local-rpc: {self.last_error}" if self.last_error else ""
            return ReplayResult(Outcome.UNOBSERVED,
                                observed=False, error_kind="transport_or_timeout",
                                note=(f"send fail/timeout (timeout={self.timeout}s; "
                                      f"outcome unobserved){detail}"))
        if not st:
            return ReplayResult(Outcome.REVERTED, status=False, gas_used=gas,
                                mainnet_gas=mainnet_gas, receipt=rec,
                                note=f"status 0x0, gas {gas}")
        mainnet_note = "N/A" if mainnet_gas is None else str(mainnet_gas)
        delta_note = "N/A" if mainnet_gas is None else f"{self.gas_delta(gas, mainnet_gas):.1f}%"
        return ReplayResult(Outcome.EXECUTED_UNKNOWN, status=True, gas_used=gas,
                            mainnet_gas=mainnet_gas, receipt=rec,
                            note=f"status 0x1, gas {gas} vs mainnet {mainnet_note} (Δ{delta_note})")

    @staticmethod
    def gas_delta(gas: int, mainnet_gas: int | None) -> float:
        if not mainnet_gas:
            return 0.0
        return (gas - mainnet_gas) / mainnet_gas * 100
