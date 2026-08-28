"""
TraFiSec -- E5 Replay Fidelity Benchmark Runner
===============================================
Evaluates deterministic replay fidelity on local Anvil forks at target block heights,
benchmarking execution consistency and post-state cell match rates against mainnet ground truth.

Fidelity Criteria:
  1. Execution-level (run_fidelity): Receipt status matching and gas delta <= 10%.
  2. State-delta (run_state_delta): Cell-level comparison over touched storage and balances
     extracted via `debug_traceTransaction prestateTracer diffMode`. Ground truth is the exact
     transaction post-state diff, avoiding interference from subsequent block transactions.

Security Invariant:
  All replays execute strictly on a local Anvil fork; no transactions are ever sent to mainnet.
"""
from __future__ import annotations

import csv
import json
import random
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from core.env import load_dotenv, resolve_rpc, resolve_trace_rpc
from core.fork import ForkRunner
from core.outcome import Outcome, ReplayResult
from core.replay import Replayer
from core.rpc import RpcClient, RpcError

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DEFAULT = REPO_ROOT / "corpus" / "incidents.jsonl"
RESULTS_DIR = REPO_ROOT / "eval" / "results"
CSV_PATH = RESULTS_DIR / "e5_fidelity.csv"
FROZEN_SET_DEFAULT = Path(__file__).with_name("fidelity_set_v2.json")

FIDELITY_PORT = 8546  # Verified execution property
FIDELITY_MAX_DELTA_PCT = 10.0  # Δ gas ≤ 10% so mainnet = PASS (outcome.fidelity_pass)
REPLAYER_TIMEOUT = 240  # Verified execution property
LOCAL_RPC_TIMEOUT = 30.0  # Short Anvil calls: one bounded attempt.
RPC_SLEEP = 0.3  # Verified execution property
MAX_STATE_CELLS = 3000  # Verified execution property

# Execution trace analysis and verification
ATTACK_TYPES = ["flash-loan", "oracle", "reentrancy", "governance/access",
                "accounting", "precision", "bridge", "token", "rug-pull", "other"]

# Execution trace analysis and verification
# Execution trace analysis and verification
TOKEN_BALANCE_SLOTS: dict[str, list[int]] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": [0],      # USDT (6)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": [0],      # USDC (6)
    "0x6b175474e89094c44da98b954eedeac495271d0f": [0],      # DAI (18)
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": [3],      # WETH (18) balanceOf map slot 3
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": [0],      # WBTC (8)
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": [0],      # wstETH (18)
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": [0],      # stETH (18)
    "0x514910771af9ca656af840dff83e8264ecf986ca": [3],      # LINK (18)
    "0x853d955acef822db058eb8505911ed77f175b99e": [0],      # FRAX (18)
    "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2": [0],      # MKR (18)
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": [0],      # UNI (18)
    "0xae78736cd615f374d3085123a210448e74fc6393": [0],      # rETH (18)
    "0x4e3fbd56cd56c3e72c1403e103b45db9da5b9d2b": [3],      # CVX (18)
}


def _local_client(url: str, replay_timeout: int | float,
                  *, timeout_cap: float | None = LOCAL_RPC_TIMEOUT) -> RpcClient:
    """Create a bounded local client.

    Short state/alignment calls retain the 30-second cap.  Long-running
    ``anvil_mine`` is the explicit exception and passes ``timeout_cap=None``
    so its separately configured budget is not silently truncated.
    """
    timeout = float(replay_timeout)
    if timeout_cap is not None:
        timeout = min(timeout_cap, timeout)
    return RpcClient(url, timeout=timeout, attempts=1)


def _norm(value) -> str:
    """Chun ho cell value: None/'0x'/'0x0'/'' -> '0x0', cn li str lower."""
    if value is None:
        return "0x0"
    s = str(value).lower()
    if s in ("", "0x", "0x0"):
        return "0x0"
    return s


# ---- archive client (module-level, init on demand) ----
_ARCHIVE_CLIENT: RpcClient | None = None


def get_archive(rpc: str | None = None) -> RpcClient:
    global _ARCHIVE_CLIENT
    load_dotenv()
    if _ARCHIVE_CLIENT is None:
        _ARCHIVE_CLIENT = RpcClient(rpc or resolve_rpc() or "")
    return _ARCHIVE_CLIENT


def get_trace_client(archive: RpcClient, chain: str = "mainnet",
                     timeout: float = 30.0) -> RpcClient:
    """Return the trace-only client; all non-trace data stays on ``archive``."""
    load_dotenv()
    trace_rpc = resolve_trace_rpc(chain)
    if not trace_rpc or trace_rpc == getattr(archive, "url", None):
        return archive
    return RpcClient(trace_rpc, timeout=timeout, attempts=2)


# ---- data model ----
@dataclass
class FidelityCase:
    """Independent attack case record in E5 benchmark set."""

    case_id: str
    protocol: str
    attack_type: str
    tx_hash: str
    block: int
    tx_index: int  # index tx trong block (k)
    chain: str = "mainnet"
    mainnet_gas: int | None = None
    prior_hashes: list[str] = field(default_factory=list)
    note: str = ""
    reason: str = ""  # Verified execution property


def load_corpus(corpus_path) -> list[dict]:
    """Load JSONL corpus file into list of dict records."""
    rows = []
    with open(corpus_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_fidelity_set(path: str | Path = FROZEN_SET_DEFAULT) -> tuple[list[FidelityCase], dict]:
    """Load the preregistered fixed set without RPC-based reselection."""
    set_path = Path(path)
    payload = json.loads(set_path.read_text(encoding="utf-8"))
    rows = payload.get("cases", [])
    required = ("case_id", "tx_hash", "block", "tx_index", "mainnet_gas")
    invalid = []
    for row in rows:
        missing = [field for field in required
                   if field not in row or row[field] is None or row[field] == ""]
        gas = row.get("mainnet_gas")
        if gas is not None and (not isinstance(gas, int) or isinstance(gas, bool) or gas <= 0):
            missing.append("mainnet_gas(positive integer)")
        if missing:
            invalid.append(f"{row.get('case_id', '<unknown>')}: {', '.join(missing)}")
    if invalid:
        raise ValueError(
            f"invalid frozen fidelity set {set_path}: required fields missing/invalid: "
            + "; ".join(invalid)
        )
    cases = [FidelityCase(
        case_id=row["case_id"], protocol=row.get("protocol", ""),
        attack_type=row.get("attack_type", "other"), tx_hash=row["tx_hash"],
        block=int(row["block"]), tx_index=int(row["tx_index"]),
        mainnet_gas=row["mainnet_gas"], reason=row.get("reason", "fixed set"),
        chain=row.get("chain", "mainnet"),
        note="preregistered fixed set",
    ) for row in rows]
    meta = {
        "total_onchain": len(cases),
        "type_dist": dict(Counter(case.attack_type for case in cases)),
        "reasons": [f"frozen set: {set_path.name}; no RPC reselection"],
        "set_name": payload.get("name"),
        "set_file": str(Path(path)),
    }
    return cases, meta


def _retry_rpc(rng: random.Random, fn, attempts: int = 3, base_sleep: float = 1.0):
    """Short retry loop for RPC timeouts."""
    for a in range(attempts):
        try:
            return fn()
        except RpcError:
            if a == attempts - 1:
                raise
            time.sleep(base_sleep * (a + 1) + rng.random() * 0.5)
    return None


def _archive_get_tx(rng: random.Random, h: str) -> dict | None:
    return _retry_rpc(rng, lambda: get_archive().eth_get_transaction(h))


def _archive_receipt_gas(rng: random.Random, h: str) -> int:
    def _try() -> int:
        rec = get_archive().eth_get_receipt(h)
        if not rec:
            raise RpcError(f"receipt unavailable for {h}")
        raw_gas = rec.get("gasUsed")
        if not raw_gas:
            raise RpcError(f"receipt for {h} has no gasUsed")
        try:
            gas = int(raw_gas, 16)
        except (TypeError, ValueError) as exc:
            raise RpcError(f"receipt for {h} has invalid gasUsed={raw_gas!r}") from exc
        if gas <= 0:
            raise RpcError(f"receipt for {h} has non-positive gasUsed={gas}")
        return gas

    return _retry_rpc(rng, _try)


def _distribute_round_robin(candidates: list[FidelityCase], n: int) -> list[FidelityCase]:
    """Select n cases distributed round-robin across attack types."""
    groups: dict[str, list[FidelityCase]] = {}
    for c in candidates:
        groups.setdefault(c.attack_type, []).append(c)
    picked: list[FidelityCase] = []
    keys = list(groups.keys())
    while len(picked) < n:
        progressed = False
        for k in keys:
            if len(picked) >= n:
                break
            if groups[k]:
                picked.append(groups[k].pop(0))
                progressed = True
        if not progressed:
            break
    return picked


def select_fidelity_set(corpus_path=CORPUS_DEFAULT, n: int = 20,
                        seed: int | None = 42) -> tuple[list[FidelityCase], dict]:
    """Select n attack cases from onchain set deterministically using seed."""
    meta = {"total_onchain": 0, "type_dist": {}, "skipped_no_block": 0, "reasons": []}
    rows = load_corpus(corpus_path)
    onchain = [r for r in rows if r.get("verified") == "onchain"]
    meta["total_onchain"] = len(onchain)
    meta["type_dist"] = {t: sum(1 for r in onchain if r.get("attack_type") == t)
                         for t in ATTACK_TYPES}

    rng = random.Random(seed)  # deterministic
    resolved: list[FidelityCase] = []
    seen_hashes: set[str] = set()
    for r in onchain:
        hashes = [h for h in (r.get("tx_hashes") or []) if h not in seen_hashes]
        if not hashes:
            meta["reasons"].append(f"{r.get('id')}: no tx_hashes — skip")
            continue
        for h in hashes:
            try:
                tx = _archive_get_tx(rng, h)
            except RpcError:
                tx = None
            if not tx:
                meta["skipped_no_block"] += 1
                continue
            blk = int(tx.get("blockNumber"), 16)
            k = int(tx.get("transactionIndex"), 16)
            seen_hashes.add(h)
            resolved.append(FidelityCase(
                case_id=r.get("id", h), protocol=r.get("protocol", ""),
                attack_type=r.get("attack_type") or "other", tx_hash=h,
                block=blk, tx_index=k,
                chain=r.get("chain", "mainnet"),
                mainnet_gas=_archive_receipt_gas(rng, h),
                note=f"block {blk} k={k}",
            ))
            break  # Verified execution property

    # Execution trace analysis and verification
    resolved.sort(key=lambda c: (c.tx_index, c.block, c.case_id))

    k0 = [c for c in resolved if c.tx_index == 0]
    krest = [c for c in resolved if c.tx_index > 0]

    picked = _distribute_round_robin(k0, n)
    for c in picked:
        c.reason = "k=0 (no warmup) + type coverage"
    if len(picked) < n:
        need = n - len(picked)
        rest_pick = _distribute_round_robin(sorted(krest, key=lambda c: (c.tx_index, c.block)), need)
        for c in rest_pick:
            c.reason = f"k={c.tx_index} (mid-block, warmup prior) + type coverage"
        picked += rest_pick

    meta["reasons"].append(
        f"resolved {len(resolved)} tx trn RPC (k=0: {len(k0)}, k>0: {len(krest)}); "
        f"picked {len(picked)} (k=0: {sum(1 for c in picked if c.tx_index == 0)})")
    return picked, meta


def _resolve_prior_hashes(archive: RpcClient, tx_hash: str, block: int,
                          tx_index: int) -> list[str]:
    """Retrieve transaction hashes for indices 0..k-1 within the same block (prefix warmup).

    Returns empty list if k=0 or if archive node does not return block transactions.
    Logs fallback note if prefix warmup cannot be completed.
    """
    if tx_index <= 0:
        return []
    try:
        blk = archive.call("eth_getBlockByNumber", [hex(block), True])
    except RpcError:
        return []
    txs = blk.get("transactions", []) if isinstance(blk, dict) else []
    if len(txs) <= tx_index:
        return []
    return [t.get("hash") for t in txs[:tx_index] if t.get("hash")]


def _block_context(archive: RpcClient, block: int) -> dict:
    """Retrieve timestamp and baseFeePerGas for target block from archive."""
    try:
        b = archive.call("eth_getBlockByNumber", [hex(block), False])
    except RpcError:
        return {}
    if not isinstance(b, dict):
        return {}
    out = {}
    if b.get("timestamp"):
        out["timestamp"] = _hex_int(b["timestamp"])
    if b.get("baseFeePerGas"):
        out["base_fee"] = _hex_int(b["baseFeePerGas"])
    return out


def _hex_int(value, default: int = 0) -> int:
    """Safely convert hex string to int with default fallback."""
    if not value:
        return default
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return default


def _miner_address(archive: RpcClient, block: int) -> str | None:
    """Extract block miner/coinbase address for cell-level exclusion."""
    try:
        b = archive.call("eth_getBlockByNumber", [hex(block), False])
    except RpcError:
        return None
    if isinstance(b, dict) and b.get("miner"):
        return str(b["miner"]).lower()
    return None


def _mainnet_gas_price(archive: RpcClient, tx_hash: str) -> int | None:
    """Calculate effective mainnet gas price for transaction."""
    try:
        rec = archive.eth_get_receipt(tx_hash)
    except RpcError:
        rec = None
    if isinstance(rec, dict) and rec.get("effectiveGasPrice"):
        return _hex_int(rec["effectiveGasPrice"])
    try:
        tx = archive.eth_get_transaction(tx_hash)
        blk = archive.call("eth_getBlockByNumber",
                           [tx.get("blockNumber"), False]) if isinstance(tx, dict) else None
    except RpcError:
        return None
    if not isinstance(tx, dict):
        return None
    base = _hex_int(blk.get("baseFeePerGas")) if isinstance(blk, dict) else 0
    max_fee = _hex_int(tx.get("maxFeePerGas"))
    prio = _hex_int(tx.get("maxPriorityFeePerGas"))
    if max_fee:
        return min(max_fee, prio + base)
    return _hex_int(tx.get("gasPrice"))


class E5Replayer(Replayer):
    """Replayer with explicit mainnet gas-price alignment for fee-cell fidelity."""

    def __init__(self, fork, archive, timeout: int = 240,
                 gas_price: int | None = None,
                 mine_timeout: float | None = None):
        super().__init__(fork, archive, timeout=timeout)
        self.gas_price = gas_price
        self.mine_timeout = (LOCAL_RPC_TIMEOUT if mine_timeout is None
                             else float(mine_timeout))
        if self.mine_timeout <= 0:
            raise ValueError("mine_timeout must be positive")
        self.mine_telemetry: dict = {}

    def _send(self, tx: dict) -> tuple[bool | None, int | None, dict | None]:
        """Send directly via Anvil JSON-RPC; never invoke cast/feeHistory."""
        self.last_error = ""
        return self._send_via_http(tx)

    def _send_via_http(self, tx: dict, data: str | None = None, to=None,
                       timeout: int | None = None) -> tuple[bool | None, int | None, dict | None]:
        """Send transaction via HTTP eth_sendTransaction with impersonation."""
        data = data if data is not None else (self.data_override or tx.get("input") or "0x")
        to = tx.get("to") if to is None else to
        timeout = self.timeout if timeout is None else timeout
        client = _local_client(self.fork.url, timeout)
        params: dict = {"from": tx["from"], "value": tx["value"], "gas": hex(int(tx["gas"], 16))}
        if to and to not in ("0x", "0x" + "00" * 20):
            params["to"] = to
        if data and data != "0x":
            params["data"] = data
        replay_gas_price = self.gas_price
        if replay_gas_price is not None:
            params["gasPrice"] = hex(replay_gas_price)
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        res = None
        for attempt in range(3):
            try:
                res = client.call("eth_sendTransaction", [params])
                break
            except RpcError as e:
                msg = str(e)
                if "520" not in msg and "429" not in msg:
                    self.last_error = f"eth_sendTransaction: {e}"[:180]
                    return None, None, None
                time.sleep(RPC_SLEEP * (attempt + 1))
        if res is None:
            self.last_error = "eth_sendTransaction: 520/429 sau 3 ln retry"
            return None, None, None
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        rec = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                rec = client.call("eth_getTransactionReceipt", [res])
            except RpcError:
                rec = None
            if rec:
                break
            time.sleep(RPC_SLEEP)
        if not rec:
            self.last_error = "receipt None after send (poll ht timeout)"
            return None, None, None
        st = rec.get("status")
        gas = int(rec.get("gasUsed", "0x0"), 16)
        if st == "0x1":
            return True, gas, rec
        return False, gas, rec

    def _pending_params(self, tx: dict, data: str | None = None,
                        use_mainnet_fee: bool = False) -> dict:
        """Build an eth_sendTransaction payload without mining/polling.

        Explicit historical nonces are important when several transactions are
        queued before the single target block is mined.
        """
        payload: dict = {
            "from": tx["from"], "value": tx.get("value", "0x0"),
            "gas": hex(int(tx.get("gas", "0x0"), 16)),
        }
        to = tx.get("to")
        if to and to not in ("0x", "0x" + "00" * 20):
            payload["to"] = to
        calldata = data if data is not None else (self.data_override or tx.get("input") or "0x")
        if calldata and calldata != "0x":
            payload["data"] = calldata
        if tx.get("nonce") is not None:
            payload["nonce"] = tx["nonce"]
        if use_mainnet_fee and self.gas_price is not None:
            payload["gasPrice"] = hex(self.gas_price)
        elif tx.get("gasPrice") is not None:
            payload["gasPrice"] = tx["gasPrice"]
        elif self.gas_price is not None:
            payload["gasPrice"] = hex(self.gas_price)
        return payload

    def submit_pending(self, tx: dict, use_mainnet_fee: bool = False) -> str | None:
        """Queue a transaction on ``--no-mining`` Anvil and return its hash."""
        try:
            return _local_client(self.fork.url, self.timeout).call(
                "eth_sendTransaction", [self._pending_params(
                    tx, use_mainnet_fee=use_mainnet_fee)])
        except RpcError as exc:
            self.last_error = f"eth_sendTransaction pending: {exc}"[:8192]
            return None

    def mine_pending(self) -> None:
        """Mine exactly one block, using the dedicated mine timeout.

        The telemetry is intentionally kept on the replayer so callers can
        attach it to a fail-closed diagnostic without changing verdict
        semantics.
        """
        client = _local_client(self.fork.url, self.mine_timeout, timeout_cap=None)
        started_at = time.time()
        started = time.monotonic()
        before = None
        try:
            before = client.eth_block_number()
        except RpcError:
            # The mine request remains the primary operation; block telemetry
            # is best-effort and must not turn a mine attempt into a verdict.
            pass
        try:
            client.call("anvil_mine", [])
        except RpcError:
            self.mine_telemetry = {
                "started_at": started_at,
                "finished_at": time.time(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
                "block_before": before,
                "block_after": None,
                "completed": False,
                "timeout_s": self.mine_timeout,
            }
            raise
        after = None
        try:
            after = client.eth_block_number()
        except RpcError:
            pass
        self.mine_telemetry = {
            "started_at": started_at,
            "finished_at": time.time(),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "block_before": before,
            "block_after": after,
            "completed": True,
            "timeout_s": self.mine_timeout,
        }

    def _receipt(self, tx_hash: str) -> dict | None:
        deadline = time.time() + self.timeout
        client = _local_client(self.fork.url, self.timeout)
        while time.time() < deadline:
            rec = client.call("eth_getTransactionReceipt", [tx_hash])
            if rec:
                return rec
            time.sleep(RPC_SLEEP)
        self.last_error = f"receipt polling exceeded {self.timeout}s after batch mine"
        return None

    def replay_same_block(self, prior_hashes: list[str], target_hash: str,
                          mainnet_gas: int | None = None,
                          gas_limit_multiplier: float = 1.5) -> ReplayResult:
        """Queue prefix + target and mine them in one historical block.

        Anvil cannot rewind ``block.number`` after mining.  Sending the full
        block as pending transactions is therefore the only supported way to
        make every transaction observe the target block's number/timestamp.
        """
        self.warmup_failures = []
        queued: list[tuple[str, str]] = []
        local = _local_client(self.fork.url, self.timeout)
        topups: dict[str, int] = {}
        for h in [*prior_hashes, target_hash]:
            try:
                tx = self.tx_parts(h)
            except RpcError as exc:
                self.warmup_failures.append({"tx_hash": h, "observed": False,
                                             "status": None, "reason": str(exc)[:512]})
                return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                    error_kind="warmup_failed",
                                    note="batch prefix/target transaction cache miss")
            if h != target_hash and gas_limit_multiplier > 1 and tx.get("gas"):
                tx = dict(tx)
                tx["gas"] = hex(max(int(tx["gas"], 16),
                                    int(int(tx["gas"], 16) * gas_limit_multiplier)))
            sender = tx.get("from")
            if sender and sender not in topups:
                gas_price = self.gas_price or int(tx.get("gasPrice", "0x0"), 16)
                required = int(tx.get("gas", "0x0"), 16) * gas_price
                required += int(tx.get("value", "0x0"), 16)
                before = local.eth_get_balance(sender, "latest")
                if before < required:
                    top_balance = 1 << 120
                    local.anvil_set_balance(sender, hex(top_balance))
                    topups[sender] = top_balance - before
            tx_hash = self.submit_pending(tx, use_mainnet_fee=(h == target_hash))
            if not tx_hash:
                self.warmup_failures.append({"tx_hash": h, "observed": False,
                                             "status": None, "reason": self.last_error})
                return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                    error_kind="warmup_failed",
                                    note="batch transaction submission failed")
            queued.append((h, tx_hash))
        try:
            self.mine_pending()
        except RpcError as exc:
            self.last_error = str(exc)[:8192]
            telemetry = self.mine_telemetry
            if telemetry:
                self.last_error = (
                    f"{self.last_error} | anvil_mine telemetry: "
                    f"elapsed_ms={telemetry['elapsed_ms']}, "
                    f"block_before={telemetry['block_before']}, "
                    f"block_after={telemetry['block_after']}, "
                    f"timeout_s={telemetry['timeout_s']}"
                )[:8192]
            return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                error_kind="warmup_failed",
                                note=f"batch mine failed: {self.last_error}")
        for historical_hash, local_hash in queued[:-1]:
            rec = self._receipt(local_hash)
            status = rec.get("status") if rec else None
            historical_status = None
            if self.archive is not None:
                try:
                    original = self.archive.eth_get_receipt(historical_hash)
                    historical_status = original.get("status") if original else None
                except RpcError:
                    pass
            if rec is None or (status != "0x1" and historical_status not in ("0x0", 0, False)):
                self.warmup_failures.append({"tx_hash": historical_hash,
                                             "observed": rec is not None,
                                             "status": status,
                                             "reason": self.last_error or "warm-up transaction failed"})
        target_rec = self._receipt(queued[-1][1])
        if target_rec is None:
            return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                error_kind="transport_or_timeout",
                                note=f"target receipt unavailable: {self.last_error}")
        for sender, topup in topups.items():
            try:
                after = local.eth_get_balance(sender, "latest")
                local.anvil_set_balance(sender, hex(max(0, after - topup)))
            except RpcError as exc:
                self.warmup_failures.append({"tx_hash": sender, "observed": True,
                                             "status": None,
                                             "reason": f"failed to restore balance top-up: {exc}"})
        gas = int(target_rec.get("gasUsed", "0x0"), 16)
        telemetry = self.mine_telemetry
        mine_note = ""
        if telemetry:
            mine_note = (
                f" | anvil_mine telemetry: elapsed_ms={telemetry['elapsed_ms']}, "
                f"block_before={telemetry['block_before']}, "
                f"block_after={telemetry['block_after']}, "
                f"timeout_s={telemetry['timeout_s']}"
            )
        if target_rec.get("status") != "0x1":
            return ReplayResult(Outcome.REVERTED, status=False, gas_used=gas,
                                mainnet_gas=mainnet_gas,
                                receipt=target_rec,
                                note=f"status 0x0, gas {gas}{mine_note}")
        return ReplayResult(Outcome.EXECUTED_UNKNOWN, status=True, gas_used=gas,
                            mainnet_gas=mainnet_gas,
                            receipt=target_rec,
                            note=(f"status 0x1, gas {gas} vs mainnet {mainnet_gas} "
                                  f"(batch same-block replay){mine_note}"))

def _align_fork_block(fork, archive: RpcClient, block: int, timeout: int) -> dict:
    """Apply mainnet timestamp and basefee to Anvil fork (local only - no mainnet interaction).

    Sets block.timestamp to target block timestamp rather than host clock time.
    attack (2024) → oracle/time-gate cell lch. Set basefee  anvil setNextBlock
    Applies gas-price and context alignment.
    """
    ctx = _block_context(archive, block)
    if not ctx:
        return {}
    try:
        fc = _local_client(fork.url, timeout)
        # Pre-London blocks have no baseFeePerGas.  Modern Anvil otherwise
        # retains a non-zero default, which makes zero-fee warm-up sends wait
        # or fail despite the historical chain accepting the prefix.
        try:
            fc.call("anvil_setNextBlockBaseFeePerGas", [hex(ctx.get("base_fee", 0))])
        except RpcError:
            # Some Anvil versions reject the base-fee override for pre-London
            # forks.  Timestamp alignment remains independently required.
            pass
        if ctx.get("timestamp") is not None:
            fc.call("anvil_setNextBlockTimestamp", [hex(ctx["timestamp"])])
    except RpcError:
        # Keep the fetched context visible to the manifest even when the local
        # override is unavailable; callers can distinguish partial alignment.
        return {**ctx, "alignment_error": "local block-context override failed"}
    return ctx


def run_fidelity(case: FidelityCase, rpc: str, archive: RpcClient,
                 port: int = FIDELITY_PORT, timeout: int = REPLAYER_TIMEOUT,
                 align_block: bool = True, mine_timeout: float | None = None,
                 **_) -> ReplayResult:
    """Execution-level fidelity benchmark: fork at block-1, warmup prefix, replay target."""
    state_block = case.block - 1
    gas_price = _mainnet_gas_price(archive, case.tx_hash) if align_block else None
    with ForkRunner(rpc, state_block, port=port,
                    upstream_timeout_ms=timeout * 1000,
                    no_mining=True) as fork:
        if align_block:
            _align_fork_block(fork, archive, case.block, timeout)
        rp = E5Replayer(fork, archive, timeout=timeout, gas_price=gas_price,
                        mine_timeout=mine_timeout)
        prior = list(case.prior_hashes) if case.prior_hashes else _resolve_prior_hashes(
            archive, case.tx_hash, case.block, case.tx_index)
        if case.tx_index > 0 and len(prior) != case.tx_index:
            return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                error_kind="warmup_failed",
                                note=(f"warm-up prefix incomplete: expected {case.tx_index}, "
                                      f"got {len(prior)} (fail-closed)"))
        # Prefix txs may need bounded headroom on a fork (historical receipt
        # gas is still retained in the cache); target keeps its original gas.
        result = rp.replay_same_block(prior, case.tx_hash, case.mainnet_gas,
                                       gas_limit_multiplier=1.5)
        if isinstance(getattr(rp, "warmup_failures", None), list) and rp.warmup_failures:
            detail = "; ".join(
                f"{item.get('tx_hash','')[:12]}:{item.get('status')}:{str(item.get('reason',''))[:160]}"
                for item in rp.warmup_failures[:3]
            )
            return ReplayResult(Outcome.UNOBSERVED, observed=False,
                                error_kind="warmup_failed",
                                note=f"batch warm-up failed | {detail}")
        if not result.observed and fork.proc and fork.proc.poll() is not None:
            detail = fork.diagnostics()
            if detail:
                result.note = f"{result.note} | anvil exited: {detail}"
    return result


# ---- state-delta (cell-match) ----
def _snapshot_cells(client: RpcClient, post_map: dict, block: str) -> dict | None:
    """Read a complete cell snapshot; return None on any transport failure."""
    out: dict[str, dict] = {}
    for addr, spec in post_map.items():
        acct: dict = {}
        if "balance" in spec:
            try:
                # Execution trace analysis and verification
                # Execution trace analysis and verification
                acct["balance"] = _norm(hex(client.eth_get_balance(addr, block)))
            except RpcError:
                return None
        if "nonce" in spec:
            try:
                # Execution trace analysis and verification
                acct["nonce"] = _norm(client.call("eth_getTransactionCount", [addr, block]))
            except RpcError:
                return None
        if "code" in spec:
            try:
                acct["code"] = _norm(client.eth_get_code(addr, block))
            except RpcError:
                return None
        storage = spec.get("storage")
        if isinstance(storage, dict):
            slots = {}
            for slot, _ in storage.items():
                try:
                    # eth_getStorageAt returns a 32-byte padded word while
                    # prestateTracer.diffMode emits EVM quantities. Canonicalize
                    # both sides or every leading-zero storage value mismatches.
                    slots[slot] = _quantity(client.eth_get_storage(addr, slot, block))
                except RpcError:
                    return None
            acct["storage"] = slots
        out[addr] = acct
    return out


def _quantity(value) -> str | None:
    """Canonical EVM quantity for diff-tracer/RPC comparison."""
    if value is None:
        return None
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        try:
            return hex(int(value, 16)) if value.startswith("0x") else hex(int(value))
        except ValueError:
            return _norm(value)
    return _norm(value)


def _normalize_diff_post(post_map: dict) -> dict:
    """Normalize per-transaction post-state emitted by prestateTracer.

    Balance, nonce and storage are EVM quantities; code is bytecode and must
    retain leading zero bytes.  This is the only valid mainnet target for a
    transaction at index k because ``eth_get*@block`` returns end-of-block
    state after transactions k+1..n.
    """
    out: dict[str, dict] = {}
    for addr, raw in post_map.items():
        if not isinstance(raw, dict):
            continue
        acct: dict = {}
        if "balance" in raw:
            acct["balance"] = _quantity(raw.get("balance"))
        if "nonce" in raw:
            acct["nonce"] = _quantity(raw.get("nonce"))
        if "code" in raw:
            acct["code"] = _norm(raw.get("code"))
        if isinstance(raw.get("storage"), dict):
            acct["storage"] = {slot: _quantity(value)
                               for slot, value in raw["storage"].items()}
        out[addr] = acct
    return out


def _cell_keys(spec: dict) -> list[str]:
    keys = [k for k in ("balance", "nonce", "code") if k in spec]
    storage = spec.get("storage")
    if isinstance(storage, dict):
        keys += [f"storage:{s}" for s in storage]
    return keys


def _match_cells(pre: dict | None, post: dict | None, mn: dict | None,
                 cells: list[str]) -> tuple[int, int, int]:
    """So tng cell: tr (ok, bad, err)."""
    ok = bad = err = 0
    if pre is None or post is None or mn is None:
        return 0, 0, len(cells)
    for c in cells:
        if c == "balance":
            p2, mv = post.get("balance"), mn.get("balance")
        elif c == "nonce":
            p2, mv = post.get("nonce"), mn.get("nonce")
        elif c == "code":
            p2, mv = post.get("code"), mn.get("code")
        elif c.startswith("storage:"):
            s = c.split(":", 1)[1]
            p2 = (post.get("storage") or {}).get(s)
            mv = (mn.get("storage") or {}).get(s)
        else:
            err += 1
            continue
        if p2 is None or mv is None:
            err += 1
            continue
        if p2 == mv:
            ok += 1
        else:
            bad += 1
    return ok, bad, err


def run_state_delta(case: FidelityCase, rpc: str, archive: RpcClient,
                    port: int = FIDELITY_PORT, timeout: int = REPLAYER_TIMEOUT,
                    max_cells: int = MAX_STATE_CELLS,
                    state_diff: dict | None = None,
                    mine_timeout: float | None = None, **_) -> dict:
    """Cell-level comparison: verifies pre/post state against mainnet touched cells.

    Mainnet cell set t `debug_traceTransaction prestateTracer diffMode`
    (account → balance/nonce/code/storage) — xc nh cell no tx  chm.
    Ground truth is the exact per-transaction post-state diff from prestateTracer.
    Avoids full block post-state which includes changes from subsequent transactions.
    Ensures precise transaction-level isolation on touched cells.
    sau warmup; post-state t fork sau replay S.

    Tr dict metrics: {n_cells, match, match_rate, mode, note, state_errors,
    per_account}. mode = "prestate-diff" | "calltracer-fallback" | "none".
    """
    if state_diff is not None:
        diff = state_diff
    else:
        trace = get_trace_client(archive, case.chain, timeout=timeout)
        try:
            diff = trace.call("debug_traceTransaction",
                              [case.tx_hash, {"tracer": "prestateTracer",
                                              "tracerConfig": {"diffMode": True}}])
        except RpcError as e:
            return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                    "observed": False, "replay_status": None,
                    "note": f"state unavailable: prestateTracer transport failure ({type(e).__name__})",
                    "state_errors": 1, "per_account": {}}
    if not isinstance(diff, dict) or not diff.get("post"):
        return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "observed": False, "replay_status": None,
                "note": "state unavailable: prestateTracer.diffMode has no post map",
                "state_errors": 1, "per_account": {}}

    post_map = diff["post"]
    state_block = case.block - 1
    gas_price = _mainnet_gas_price(archive, case.tx_hash)

    # Execution trace analysis and verification
    with ForkRunner(rpc, state_block, port=port,
                    upstream_timeout_ms=timeout * 1000,
                    no_mining=True) as fork:
        _align_fork_block(fork, archive, case.block, timeout)
        rp = E5Replayer(fork, archive, timeout=timeout, gas_price=gas_price,
                        mine_timeout=mine_timeout)
        prior = list(case.prior_hashes) if case.prior_hashes else _resolve_prior_hashes(
            archive, case.tx_hash, case.block, case.tx_index)
        if case.tx_index > 0 and len(prior) != case.tx_index:
            return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                    "observed": False, "replay_status": None,
                    "note": "state unavailable: incomplete mid-block warm-up prefix",
                    "state_errors": 1, "per_account": {}}
        fork_client = _local_client(fork.url, timeout)
        pre = _snapshot_cells(fork_client, post_map, "latest")
        if pre is None:
            return {
                "n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "observed": False, "replay_status": None,
                "note": "state-delta unavailable: incomplete pre-replay fork snapshot",
                "state_errors": 1, "per_account": {},
            }
        result = rp.replay_same_block(prior, case.tx_hash, case.mainnet_gas,
                                       gas_limit_multiplier=1.5)
        if isinstance(getattr(rp, "warmup_failures", None), list) and rp.warmup_failures:
            return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                    "observed": False, "replay_status": None,
                    "note": "state unavailable: batch warm-up transaction failed",
                    "state_errors": 1, "per_account": {}}
        if not result.observed or result.status is not True:
            return {
                "n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "observed": result.observed, "replay_status": result.status,
                "note": "state-delta unavailable: state replay was not successfully observed",
                "state_errors": 1, "per_account": {},
            }
        post = _snapshot_cells(fork_client, post_map, "latest")
        if post is None:
            return {
                "n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "observed": result.observed, "replay_status": result.status,
                "note": "state-delta unavailable: incomplete post-replay fork snapshot",
                "state_errors": 1, "per_account": {},
            }

    # (2) mainnet target = per-transaction post-state from the tracer.
    mn_post = _normalize_diff_post(post_map)

    # (3) match rate.
    excluded = _miner_address(archive, case.block)
    fee_sender = None
    try:
        target_tx = archive.eth_get_transaction(case.tx_hash)
        fee_sender = str(target_tx.get("from", "")).lower() if target_tx else None
    except RpcError:
        fee_sender = None
    fee_price = gas_price or 0
    fee_delta = ((case.mainnet_gas or 0) - (result.gas_used or 0)) * fee_price
    keys = sorted(post_map.keys())
    total = match = errors = 0
    truncated = False
    excluded_cells = 0
    excluded_fee_cells = 0
    per_account: dict[str, dict] = {}
    for addr in keys:
        cells = _cell_keys(post_map[addr])
        if addr == excluded:  # Verified execution property
            excluded_cells += len(cells)
            continue
        # The sender balance includes the transaction fee.  A bounded local
        # gas deviation can therefore create one deterministic balance-only
        # mismatch even when every contract/storage post-state cell matches.
        # Exclude it only when the observed difference is exactly explained by
        # (mainnet_gas - local_gas) * effectiveGasPrice; never hide an arbitrary
        # sender-balance mismatch.
        if (addr == fee_sender and "balance" in cells and fee_delta != 0
                and (post.get(addr) or {}).get("balance") is not None
                and (mn_post.get(addr) or {}).get("balance") is not None):
            try:
                observed_delta = (int((post[addr] or {})["balance"], 16)
                                  - int((mn_post[addr] or {})["balance"], 16))
            except (KeyError, TypeError, ValueError):
                observed_delta = None
            if observed_delta == fee_delta:
                cells = [cell for cell in cells if cell != "balance"]
                excluded_fee_cells += 1
        if total + len(cells) > max_cells:  # Verified execution property
            truncated = True
            break
        ok, bad, err = _match_cells(pre.get(addr), post.get(addr), mn_post.get(addr), cells)
        total += len(cells)
        match += ok
        errors += err
        per_account[addr] = {"ok": ok, "bad": bad, "err": err}

    rate = (match / total) if total else 0.0
    note = (f"prestate-diff cell-match {match}/{total} ({rate:.1%}) on "
            f"{len(per_account)} accounts (GT = transaction-local diff.post); "
            f"replay status={result.status} "
            f"gas={result.gas_used} vs mainnet {result.mainnet_gas}")
    if excluded_cells:
        note += f"; EXCLUDED miner {excluded} ({excluded_cells} cells: anvil artifact)"
    if excluded_fee_cells:
        note += (f"; EXCLUDED sender fee accounting ({excluded_fee_cells} cell: "
                 f"Δgas={case.mainnet_gas - result.gas_used}, "
                 f"effectiveGasPrice={fee_price})")
    if truncated:
        note += f"; TRUNCATED at {max_cells} cells (RPC t — cap theo MAX_STATE_CELLS)"
    if case.tx_index > 0 and not prior:
        note += "; mid-block k>0 khng warmup (archive khng tr full block tx)"
    return {"n_cells": total, "match": match, "match_rate": rate, "mode": "prestate-diff",
            "observed": result.observed, "replay_status": result.status,
            "note": note, "state_errors": errors, "per_account": per_account}


def _state_delta_fallback(case: FidelityCase, rpc: str, archive: RpcClient,
                          port: int, timeout: int, note: str = "") -> dict:
    """Fallback: account t callTracer (from/to), so balance + storage balance token."""
    trace = get_trace_client(archive, case.chain, timeout=timeout)
    try:
        tr = trace.call("debug_traceTransaction",
                          [case.tx_hash, {"tracer": "callTracer"}])
    except RpcError:
        return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "note": "state-delta skipped: no prestateTracer nor callTracer "
                        "(execution-level fidelity remains valid for E5 baseline)",
                "state_errors": 1, "per_account": {}}
    addrs: set[str] = set()
    stack = [tr] if isinstance(tr, dict) else []
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for a in (node.get("from"), node.get("to")):
            if a:
                addrs.add(a.lower())
        stack.extend(node.get("calls") or [])
    addrs = {a for a in addrs
             if a and a != "0x0000000000000000000000000000000000000000"}
    if not addrs:
        return {"n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "note": "callTracer no addresses — state-delta skipped",
                "state_errors": 1, "per_account": {}}

    state_block = case.block - 1
    gas_price = _mainnet_gas_price(archive, case.tx_hash)
    with ForkRunner(rpc, state_block, port=port,
                    upstream_timeout_ms=timeout * 1000) as fork:
        _align_fork_block(fork, archive, case.block, timeout)
        rp = E5Replayer(fork, archive, timeout=timeout, gas_price=gas_price)
        prior = list(case.prior_hashes) if case.prior_hashes else _resolve_prior_hashes(
            archive, case.tx_hash, case.block, case.tx_index)
        if prior:
            rp.warmup(prior)
        fk = _local_client(fork.url, timeout)
        pre = {a: _fallback_snapshot(fk, a, "latest") for a in addrs}
        result = rp.replay(case.tx_hash, case.mainnet_gas)
        post = {a: _fallback_snapshot(fk, a, "latest") for a in addrs}

    mn = {}
    for a in addrs:
        try:
            mn[a] = _fallback_snapshot(archive, a, hex(case.block))
        except RpcError:
            mn[a] = {}

    total = match = errors = 0
    for a in addrs:
        for key in (pre.get(a) or {}):
            total += 1
            p2 = (post.get(a) or {}).get(key)
            mv = (mn.get(a) or {}).get(key)
            if p2 is None or mv is None:
                errors += 1
                continue
            if p2 == mv:
                match += 1
    rate = (match / total) if total else 0.0
    return {"n_cells": total, "match": match, "match_rate": rate,
            "mode": "calltracer-fallback",
            "note": (note + f"callTracer fallback cell-match {match}/{total} ({rate:.1%}) "
                     f"on {len(addrs)} addrs (balance+token slot); replay status="
                     f"{result.status} gas={result.gas_used} vs mainnet {result.mainnet_gas}"),
            "state_errors": errors, "per_account": {}}


def _fallback_snapshot(client: RpcClient, addr: str, block: str) -> dict:
    """Balance + storage balance-slot token (fallback). So chui chnh xc."""
    out: dict[str, str | None] = {"balance": _norm(client.eth_get_balance(addr, block))}
    for slot in TOKEN_BALANCE_SLOTS.get(addr.lower(), []):
        try:
            out[f"token_balance_slot{slot}"] = _norm(client.eth_get_storage(addr, hex(slot), block))
        except RpcError:
            out[f"token_balance_slot{slot}"] = None
    return out


# ---- orchestration + CSV ----
def _aggregate_case_bad_cells(run: dict) -> str:
    """M t cell bad/err gn (cho CSV note)."""
    per = run.get("per_account") or {}
    bad_desc = []
    for a, v in per.items():
        if v.get("bad") or v.get("err"):
            bad_desc.append(f"{a[:8]}..(ok{v['ok']}/bad{v['bad']}/err{v['err']})")
    return "; ".join(bad_desc[:4])


def run_fidelity_case(case: FidelityCase, rpc: str, archive: RpcClient,
                      port: int = FIDELITY_PORT, timeout: int = REPLAYER_TIMEOUT,
                      state_delta: bool = True, run_id: str = "",
                      state_diff: dict | None = None,
                      mine_timeout: float | None = None, **_) -> dict:
    """Chy  1 case: execution fidelity + state-delta. Tr row dict (CSV)."""
    fid = run_fidelity(case, rpc, archive, port=port, timeout=timeout,
                       mine_timeout=mine_timeout)
    run = {}
    if state_delta and fid.observed and fid.status is True:
        try:
            run = run_state_delta(case, rpc, archive, port=port, timeout=timeout,
                                  state_diff=state_diff,
                                  mine_timeout=mine_timeout)
        except (RpcError, OSError, TimeoutError) as exc:
            run = {
                "n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
                "observed": False, "replay_status": None,
                "note": ("state-delta unavailable after valid execution: "
                         f"{type(exc).__name__}"),
                "state_errors": 1, "per_account": {},
            }
    elif state_delta:
        reason = ("execution replay unobserved" if not fid.observed
                  else f"execution replay status={fid.status}")
        run = {
            "n_cells": 0, "match": 0, "match_rate": 0.0, "mode": "none",
            "observed": False, "replay_status": fid.status,
            "note": f"state-delta skipped: {reason}",
            "state_errors": 1, "per_account": {},
        }

    gas_delta = fid.gas_delta_pct
    execution_pass = fid.fidelity_pass(FIDELITY_MAX_DELTA_PCT)
    state_eligible = bool(run and run.get("mode") == "prestate-diff"
                          and run.get("n_cells", 0) > 0
                          and run.get("state_errors", 0) == 0
                          and run.get("observed", True)
                          and run.get("replay_status", True) is True)
    state_pass = bool(state_eligible and run.get("match_rate", 0.0) >= 0.95)
    joint_pass = bool(execution_pass and state_pass)

    note_parts = [fid.note]
    if run:
        note_parts.append(run.get("note") or "")
        bad = _aggregate_case_bad_cells(run)
        if bad:
            note_parts.append("cells: " + bad)
    note = " | ".join(p for p in note_parts if p)

    return {
        "run_id": run_id,
        "fidelity_schema": "transaction-local-v2",
        "case": case.case_id,
        "protocol": case.protocol,
        "attack_type": case.attack_type,
        "tx_hash": case.tx_hash,
        "block": case.block,
        "tx_index": case.tx_index,
        "mutation": "fidelity",
        "outcome": fid.outcome.value,
        "observed": fid.observed,
        "status": fid.status,
        "gas_used": fid.gas_used,
        "mainnet_gas": fid.mainnet_gas,
        "gas_delta_pct": round(gas_delta, 2) if isinstance(gas_delta, float) else "",
        "execution_pass": execution_pass,
        "state_eligible": state_eligible,
        "state_pass": state_pass,
        "joint_pass": joint_pass,
        "pass": execution_pass,  # legacy alias; paper tables use explicit fields
        "state_cells": run.get("n_cells", 0) if run else 0,
        "state_match": run.get("match_rate", 0.0) if run else 0.0,
        "state_errors": run.get("state_errors", 0) if run else 0,
        "state_mode": run.get("mode", "none") if run else "none",
        "failure_reason": ("transport_timeout" if not fid.observed and fid.error_kind != "warmup_failed"
                            else "warmup_failed" if fid.error_kind == "warmup_failed"
                            else "evm_revert" if fid.status is False else None),
        "reason": case.reason,
        "note": note,
    }


CSV_COLUMNS = ["run_id", "fidelity_schema", "case", "protocol", "attack_type", "tx_hash", "block", "tx_index",
               "mutation", "outcome", "observed", "status", "gas_used", "mainnet_gas",
               "gas_delta_pct", "execution_pass", "state_eligible", "state_pass",
               "joint_pass", "pass", "state_cells", "state_match", "state_errors",
               "state_mode", "failure_reason", "case_latency_ms", "reason", "note"]


def write_csv(rows: list[dict], path=CSV_PATH) -> Path:
    """Incremental idempotent writes within a run; independent runs are immutable."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, dict] = {}
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                key = f"{r.get('run_id') or 'legacy'}\x1f{r.get('case', '')}"
                existing[key] = r
    for r in rows:
        key = f"{r.get('run_id') or 'legacy'}\x1f{r['case']}"
        existing[key] = r
    # Execution trace analysis and verification
    new_keys = [f"{r.get('run_id') or 'legacy'}\x1f{r['case']}" for r in rows]
    ordered_keys = new_keys + [k for k in existing if k not in set(new_keys)]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for k in ordered_keys:
            if k in existing:
                w.writerow({c: existing[k].get(c, "") for c in CSV_COLUMNS})
    return path


def case_manifest(row: dict, *, run_id: str, prior_count: int = 0,
                  cache_dir: str | Path | None = None) -> dict:
    """Serialize the stable Phase-1 contract for one case."""
    def as_bool(value) -> bool:
        return value is True or str(value).lower() == "true"

    observed = as_bool(row.get("observed"))
    state_cells = int(row.get("state_cells") or 0)
    matched = round(float(row.get("state_match") or 0.0) * state_cells)
    return {
        "run_id": run_id,
        "provider": "alchemy",
        "case": row.get("case"),
        "tx_hash": row.get("tx_hash"),
        "block": row.get("block"),
        "tx_index": row.get("tx_index"),
        "state_block": (int(row["block"]) - 1 if row.get("block") is not None else None),
        "prior_count": prior_count,
        "execution": {
            "observed": observed,
            "status": row.get("status"),
            "gas_used": row.get("gas_used"),
            "mainnet_gas": row.get("mainnet_gas"),
            "gas_delta_pct": row.get("gas_delta_pct"),
            "pass": as_bool(row.get("execution_pass")),
        },
        "state": {
            "mode": row.get("state_mode", "none"),
            "eligible": as_bool(row.get("state_eligible")),
            "cells": state_cells,
            "matched": matched,
            "match_rate": row.get("state_match", 0.0),
            "pass": as_bool(row.get("state_pass")),
        },
        "joint_pass": as_bool(row.get("joint_pass")),
        "failure_reason": row.get("failure_reason"),
        "cache_dir": str(cache_dir) if cache_dir else None,
    }


def load_results(path=CSV_PATH) -> list[dict]:
    if not Path(path).exists():
        return []
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarize(results: list[dict]) -> dict:
    """Aggregate execution and state fidelity with explicit denominators."""
    n = len(results)
    if n == 0:
        return {"n": 0, "attempted": 0, "observed": 0, "transport_errors": 0,
                "evm_reverts": 0, "pass": 0, "execution_pass": 0,
                "pass_rate": 0.0, "execution_pass_rate_observed": 0.0,
                "state_eligible": 0, "state_pass": 0, "state_pass_rate": 0.0,
                "joint_pass": 0, "joint_pass_rate": 0.0,
                "intervals": {}, "by_attack_type": {}, "fails": [],
                "warmup_failures": 0, "latency_ms_median": None, "latency_ms_p95": None}

    def yes(r: dict, field: str, fallback: str | None = None,
            default: bool = False) -> bool:
        v = r.get(field)
        if (v is None or v == "") and fallback:
            v = r.get(fallback)
        if v is None or v == "":
            return default
        return str(v) == "True"

    def observed_row(r: dict) -> bool:
        if r.get("observed") not in (None, ""):
            return yes(r, "observed")
        return r.get("outcome") not in ("UNOBSERVED", "ERROR", "")

    from .statistics import wilson_interval

    observed = sum(observed_row(r) for r in results)
    transport = n - observed
    reverts = sum(
        1 for r in results
        if observed_row(r) and (r.get("outcome") == "REVERTED"
                                or (r.get("status") not in (None, "")
                                    and not yes(r, "status")))
    )
    passed = sum(1 for r in results if yes(r, "execution_pass", "pass"))
    eligible = sum(1 for r in results if yes(r, "state_eligible"))
    state_passed = sum(1 for r in results if yes(r, "state_pass"))
    joint = sum(1 for r in results if yes(r, "joint_pass"))
    warmup_failures = sum(1 for r in results if r.get("failure_reason") == "warmup_failed")
    latencies = sorted(float(r["case_latency_ms"]) for r in results
                       if r.get("case_latency_ms") not in (None, ""))
    def percentile(values: list[float], p: float) -> float | None:
        if not values:
            return None
        index = min(len(values) - 1, max(0, int((len(values) - 1) * p)))
        return values[index]
    by_type: dict[str, dict] = {}
    for r in results:
        t = r.get("attack_type") or "?"
        d = by_type.setdefault(t, {"n": 0, "pass": 0})
        d["n"] += 1
        if yes(r, "execution_pass", "pass"):
            d["pass"] += 1
    fails = [{"case": r.get("case"), "outcome": r.get("outcome"),
              "gas_delta_pct": r.get("gas_delta_pct"),
              "state_cells": r.get("state_cells"), "state_match": r.get("state_match"),
              "note": (r.get("note") or "")[:120]}
             for r in results if not yes(r, "execution_pass", "pass")]
    return {"n": n, "attempted": n, "observed": observed,
            "observed_rate": observed / n,
            "transport_errors": transport, "evm_reverts": reverts,
            "pass": passed, "execution_pass": passed,
            "pass_rate": passed / n,
            "execution_pass_rate_observed": passed / observed if observed else 0.0,
            "state_eligible": eligible, "state_pass": state_passed,
            "state_pass_rate": state_passed / eligible if eligible else 0.0,
            "joint_pass": joint, "joint_pass_rate": joint / n if n else 0.0,
            "warmup_failures": warmup_failures,
            "latency_ms_median": percentile(latencies, 0.5),
            "latency_ms_p95": percentile(latencies, 0.95),
            "intervals": {
                "observed/attempted": wilson_interval(observed, n),
                "execution_pass/observed": wilson_interval(passed, observed),
                "state_pass/state_eligible": wilson_interval(state_passed, eligible),
                "joint_pass/attempted": wilson_interval(joint, n),
            },
            "by_attack_type": by_type, "fails": fails}
