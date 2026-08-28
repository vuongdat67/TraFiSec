"""
TraFiSec — Stage 1 Screener: trace + state-delta fetching (src/core/trace.py)
=====================================================================================
Read-only: Screener does not replay transactions (Stage 2 task). This module only fetches
trace + state delta t archive RPC v normalize thnh mt dict thng nht
(TraceData) cho cc view (views.py) — hon ton offline-testable.

Tch hn hai lp (theo feedback user: network vs pure):
  * FETCH  — `TraceFetcher` (network): gi RPC. Mt ni duy nht chm mng.
  * PARSE  — `parse_call_tracer` / `parse_tx_receipt` (pure): dict → TraceData.
             Khng I/O, deterministic, unit-test vi dict mu.

RPC strategy: queries `debug_traceTransaction` when supported
(with callTracer + withLog for tree structure and logs); falls back gracefully on error.
timeout th FALLBACK sang `eth_getTransactionByHash` + `eth_getTransactionReceipt`
(logs from receipt). Under fallback mode, call tree contains single top-level node + logs.
c logs vn  d liu (token-flow, economic), cn chiu su call b gim.

TraceData — normalized dict:
  {
    "tx_hash": str, "block": int|None, "source": "callTracer"|"tx+receipt",
    "from": str, "to": str|None, "value": int, "input": str,
    "status": bool|None, "gas_used": int|None,
    "tree": Frame(root),               # Verified execution property
    "flat_calls": [Call, ...],          # Verified execution property
    "logs": [Log, ...],                 # Verified execution property
    "addresses": set[str],              # Verified execution property
  }

Security: URL/key loaded exclusively from .env via environment loader - never hardcoded.
Windows: file c/ghi UTF-8; stdout reconfigure UTF-8.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Execution trace analysis and verification
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from .rpc import RpcClient, RpcError  # noqa: E402

# Execution trace analysis and verification
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_MAX_FLAT = 10_000  # Verified execution property


class TraceFetchError(RuntimeError):
    """Khng fetch c trace (tx khng tn ti / RPC khng ph / network)."""


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _norm_addr(a: str | None) -> str | None:
    return a.lower() if a else None


def _int(v: object, default: int = 0) -> int:
    if v is None:
        return default
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 16)
    except ValueError:
        return default


def _selector(input_hex: str | None) -> str | None:
    if not input_hex or not input_hex.startswith("0x") or len(input_hex) < 10:
        return None
    return input_hex[:10].lower()


def _walk_frames(frame: dict, out: list, depth: int) -> None:
    """DFS frame callTracer → flat_calls. Frame l dict chun ca callTracer."""
    if len(out) >= _MAX_FLAT:
        return
    frm = _norm_addr(frame.get("from"))
    to = _norm_addr(frame.get("to"))
    typ = (frame.get("type") or "CALL").upper()
    inp = frame.get("input") or "0x"
    out.append({
        "from": frm, "to": to, "type": typ,
        "value": _int(frame.get("value")),
        "selector": _selector(inp), "input": inp,
        "depth": depth,
        "revert": bool(frame.get("revertReason")),
        "gas": _int(frame.get("gas"), -1),
    })
    for sub in frame.get("calls", []) or []:
        _walk_frames(sub, out, depth + 1)


def _collect_logs(frame: dict, out: list) -> None:
    """Gom logs t frame callTracer (c `logs` nu tracerConfig.withLog=true)."""
    for log in frame.get("logs", []) or []:
        out.append({
            "address": _norm_addr(log.get("address")),
            "topics": [str(t).lower() for t in log.get("topics", [])],
            "data": log.get("data") or "0x",
            "logIndex": _int(log.get("logIndex"), -1),
        })
    for sub in frame.get("calls", []) or []:
        _collect_logs(sub, out)


def parse_call_tracer(tx_hash: str, res: object,
                      tx_from: str | None = None, tx_to: str | None = None,
                      block: int | None = None) -> dict:
    """Pure: kt qu debug_traceTransaction (tracer=callTracer) → TraceData."""
    if res is None:
        raise TraceFetchError(f"{tx_hash}: callTracer tr v null")
    tree = res if isinstance(res, dict) else {}
    logs: list[dict] = []
    _collect_logs(tree, logs)
    flat: list[dict] = []
    _walk_frames(tree, flat, 0)
    if not flat:
        # Execution trace analysis and verification
        tree = {"from": tx_from, "to": tx_to, "type": "CALL",
                "value": "0x0", "input": "0x", "calls": []}
        _walk_frames(tree, flat, 0)
    addr = {c["from"] for c in flat if c["from"]}
    addr |= {c["to"] for c in flat if c["to"]}
    addr |= {log["address"] for log in logs if log["address"]}
    return {
        "tx_hash": tx_hash, "block": block, "source": "callTracer",
        "from": _norm_addr(tx_from) or (flat[0]["from"] if flat else None),
        "to": _norm_addr(tx_to) or (flat[0]["to"] if flat else None),
        "value": flat[0]["value"] if flat else 0,
        "input": flat[0]["input"] if flat else "0x",
        "status": None, "gas_used": None,
        "tree": tree, "flat_calls": flat, "logs": logs,
        "addresses": addr,
    }


def parse_tx_receipt(tx_hash: str, tx: dict, receipt: dict) -> dict:
    """Pure fallback builder: parses eth_getTransactionByHash + receipt when debug_trace is unavailable.

    Constructs minimal single-node call tree with receipt event logs.
    """
    frm = _norm_addr(tx.get("from"))
    to = _norm_addr(tx.get("to"))
    inp = tx.get("input") or "0x"
    value = _int(tx.get("value"))
    flat = [{
        "from": frm, "to": to, "type": "CREATE" if not to else "CALL",
        "value": value, "selector": _selector(inp), "input": inp,
        "depth": 0, "revert": False, "gas": _int(tx.get("gas"), -1),
    }]
    logs = []
    for log in receipt.get("logs", []) or []:
        logs.append({
            "address": _norm_addr(log.get("address")),
            "topics": [str(t).lower() for t in log.get("topics", [])],
            "data": log.get("data") or "0x",
            "logIndex": _int(log.get("logIndex"), -1),
        })
    addr = {frm} | ({to} if to else set()) | {
        log["address"] for log in logs if log["address"]
    }
    block_hx = tx.get("blockNumber")
    return {
        "tx_hash": tx_hash,
        "block": int(block_hx, 16) if isinstance(block_hx, str) and len(block_hx) > 2 else (None if block_hx in (None, "0x") else block_hx),
        "source": "tx+receipt",
        "from": frm, "to": to, "value": value, "input": inp,
        "status": receipt.get("status") in ("0x1", 1),
        "gas_used": _int(receipt.get("gasUsed"), -1),
        "tree": flat[0], "flat_calls": flat, "logs": logs, "addresses": addr,
    }


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
class TraceFetcher:
    """Fetch trace + state delta t archive RPC, c cache.

    - `use_debug_trace=True` mc nh: th debug_traceTransaction; fallback t
      Handles unsupported tracer RPC responses gracefully.
    - Requires block height for state delta extraction.
    """

    def __init__(self, client: RpcClient, use_debug_trace: bool = True):
        self.client = client
        self.use_debug_trace = use_debug_trace
        self._cache: dict[str, dict] = {}

    # ---- trace ----
    def fetch_trace(self, tx_hash: str) -> dict:
        if tx_hash in self._cache:
            return self._cache[tx_hash]
        data = self._fetch_impl(tx_hash)
        self._cache[tx_hash] = data
        return data

    def _fetch_impl(self, tx_hash: str) -> dict:
        # Execution trace analysis and verification
        if self.use_debug_trace:
            try:
                res = self.client.call(
                    "debug_traceTransaction",
                    [tx_hash, {"tracer": "callTracer",
                               "tracerConfig": {"withLog": True,
                                                "onlyTopCall": False}}],
                )
                data = parse_call_tracer(tx_hash, res)
                if data.get("block") is None:
                    data["block"] = self._resolve_block(tx_hash)
                return data
            except RpcError as e:
                # Execution trace analysis and verification
                note = str(e)
                if "unsupported" in note.lower() or "403" in note \
                        or "method" in note.lower() or "not found" in note.lower():
                    pass  # Verified execution property
                else:
                    # Execution trace analysis and verification
                    pass
        # Execution trace analysis and verification
        try:
            tx = self.client.eth_get_transaction(tx_hash)
            if not tx:
                raise TraceFetchError(
                    f"{tx_hash}: tx not found trn RPC (khng ph / hash sai)")
            receipt = self.client.eth_get_receipt(tx_hash)
        except RpcError as e:
            raise TraceFetchError(f"{tx_hash}: RPC error khi fetch tx: {e}") from e
        return parse_tx_receipt(tx_hash, tx, receipt or {})

    # ---- state delta ----
    def state_delta(self, tx_hash: str, block: int | None = None,
                    max_accounts: int = 64) -> dict:
        """Extract pre/post state delta (balances, nonces, and storage) for touched accounts.

        If archive RPC supports stateDiffTracer, extracts full storage diff;
        otherwise queries pre/post balance and nonce via
        eth_getBalance / eth_getTransactionCount across touched accounts
        (capped by max_accounts).
        If stateDiff is unavailable, storage defaults to empty dict
        and state_delta evaluates balance/nonce delta accordingly.
        """
        trace = self.fetch_trace(tx_hash)
        blk = block if block is not None else trace.get("block")
        if blk is None:
            blk = self._resolve_block(tx_hash)
        pre = (blk - 1) if blk is not None else "latest"
        addrs = sorted(trace.get("addresses", set()))[:max_accounts]

        # Execution trace analysis and verification
        if self.use_debug_trace:
            try:
                res = self.client.call(
                    "debug_traceTransaction",
                    [tx_hash, {"tracer": "stateDiffTracer"}],
                )
                if isinstance(res, dict):
                    return self._parse_state_diff(tx_hash, blk, res)
            except RpcError:
                pass

            # Execution trace analysis and verification
            try:
                res = self.client.call(
                    "debug_traceTransaction",
                    [tx_hash, {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}],
                )
                if isinstance(res, dict):
                    return self._parse_prestate_diff(tx_hash, blk, res)
            except RpcError:
                pass

        balances: dict[str, int] = {}
        nonces: dict[str, int] = {}
        for a in addrs:
            try:
                pre_bal = self.client.eth_get_balance(a, pre)
                post_bal = self.client.eth_get_balance(a, blk if blk is not None else "latest")
                balances[a] = post_bal - pre_bal
            except RpcError:
                continue
            try:
                pre_n = _int(self.client.call("eth_getTransactionCount", [a, pre]) or "0x0")
                post_n = _int(self.client.call(
                    "eth_getTransactionCount", [a, blk if blk is not None else "latest"]) or "0x0")
                nonces[a] = post_n - pre_n
            except RpcError:
                continue

        if balances or nonces:
            return {
                "tx_hash": tx_hash, "block": blk, "pre_block": pre,
                "method": "balances+nonces",
                "balances": balances, "nonces": nonces, "storage": {},
                "accounts_checked": len(addrs),
            }

        # Execution trace analysis and verification
        return infer_state_delta_from_trace(trace)

    def _resolve_block(self, tx_hash: str) -> int | None:
        """Retrieve transaction block number when debug_trace does not return it."""
        try:
            tx = self.client.eth_get_transaction(tx_hash)
        except RpcError:
            return None
        if not tx:
            return None
        bh = tx.get("blockNumber")
        return int(bh, 16) if isinstance(bh, str) else bh

    @staticmethod
    def _parse_state_diff(tx_hash: str, block: int | None, res: dict) -> dict:
        """Parse stateDiffTracer response into structured StateDelta object."""
        balances: dict[str, int] = {}
        nonces: dict[str, int] = {}
        storage: dict[str, dict[str, list[int | None]]] = {}
        for addr, diff in (res or {}).items():
            a = _norm_addr(addr) or addr
            if not isinstance(diff, dict):
                continue
            bal = diff.get("balance")
            if isinstance(bal, dict) and "from" in bal and "to" in bal:
                balances[a] = _int(bal["to"]) - _int(bal["from"])
            n = diff.get("nonce")
            if isinstance(n, dict) and "from" in n and "to" in n:
                nonces[a] = _int(n["to"]) - _int(n["from"])
            st = diff.get("storage")
            if isinstance(st, dict):
                for slot, v in st.items():
                    if isinstance(v, dict) and "from" in v:
                        storage.setdefault(a, {})[str(slot).lower()] = [
                            _int(v.get("from"), -1), _int(v.get("to"), -1)]
        return {
            "tx_hash": tx_hash, "block": block,
            "pre_block": block - 1 if block is not None else None,
            "method": "stateDiff",
            "balances": balances, "nonces": nonces, "storage": storage,
            "accounts_checked": len(balances) + len(nonces) + len(storage),
        }

    @staticmethod
    def _parse_prestate_diff(tx_hash: str, block: int | None, res: dict) -> dict:
        """Pure: kt qu prestateTracer (diffMode: {pre: ..., post: ...}) → StateDelta."""
        balances: dict[str, int] = {}
        nonces: dict[str, int] = {}
        storage: dict[str, dict[str, list[int | None]]] = {}

        pre_map = res.get("pre", {}) if "pre" in res else res
        post_map = res.get("post", {}) if "post" in res else {}

        all_addrs = set(pre_map.keys()) | set(post_map.keys())
        for addr in all_addrs:
            a = _norm_addr(addr) or addr
            pre_acc = pre_map.get(addr, {}) or {}
            post_acc = post_map.get(addr, {}) or {}

            # Balance
            pre_bal = _int(pre_acc.get("balance"), 0) if pre_acc else 0
            post_bal = _int(post_acc.get("balance"), 0) if post_acc else pre_bal
            if post_bal != pre_bal:
                balances[a] = post_bal - pre_bal

            # Nonce
            pre_n = _int(pre_acc.get("nonce"), 0) if pre_acc else 0
            post_n = _int(post_acc.get("nonce"), 0) if post_acc else pre_n
            if post_n != pre_n:
                nonces[a] = post_n - pre_n

            # Storage
            pre_st = pre_acc.get("storage", {}) or {}
            post_st = post_acc.get("storage", {}) or {}
            all_slots = set(pre_st.keys()) | set(post_st.keys())
            for slot in all_slots:
                s_key = str(slot).lower()
                val_pre = _int(pre_st.get(slot), -1) if slot in pre_st else 0
                val_post = _int(post_st.get(slot), -1) if slot in post_st else val_pre
                if val_pre != val_post:
                    storage.setdefault(a, {})[s_key] = [val_pre, val_post]

        return {
            "tx_hash": tx_hash, "block": block,
            "pre_block": block - 1 if block is not None else None,
            "method": "prestateTracer",
            "balances": balances, "nonces": nonces, "storage": storage,
            "accounts_checked": len(balances) + len(nonces) + len(storage),
        }


def infer_state_delta_from_trace(trace: dict) -> dict:
    """Pure offline extraction: c tnh balance & storage diff t ETH calls & Transfer logs.

    Provides baseline state delta when archive RPC lacks debug_trace or running cached.
    - ETH transfers t top-level tx v internal calls.
    - Token balance changes t ERC-20 Transfer logs.
    - Nonce change cho sender tx.
    """
    balances: dict[str, int] = {}
    nonces: dict[str, int] = {}
    storage: dict[str, dict[str, list[int | None]]] = {}

    sender = _norm_addr(trace.get("from"))
    to_addr = _norm_addr(trace.get("to"))
    top_val = _int(trace.get("value", 0))

    if sender:
        nonces[sender] = 1
        if top_val > 0:
            balances[sender] = balances.get(sender, 0) - top_val
            if to_addr:
                balances[to_addr] = balances.get(to_addr, 0) + top_val

    # Internal ETH calls
    for call in trace.get("flat_calls", []):
        c_val = _int(call.get("value", 0))
        c_from = _norm_addr(call.get("from"))
        c_to = _norm_addr(call.get("to"))
        if c_val > 0 and c_from and c_to:
            balances[c_from] = balances.get(c_from, 0) - c_val
            balances[c_to] = balances.get(c_to, 0) + c_val

    # ERC-20 Transfer logs -> pseudo-storage / token balance delta
    for log in trace.get("logs", []):
        topics = log.get("topics", [])
        if len(topics) >= 3 and topics[0].lower() == TOPIC_TRANSFER:
            token = _norm_addr(log.get("address")) or ""
            t_from = ("0x" + topics[1][-40:]).lower()
            t_to = ("0x" + topics[2][-40:]).lower()
            amt = _int(log.get("data", "0x0"))
            if amt > 0 and token:
                # Storage entry cho token contract
                slot_from = f"bal:{t_from[-8:]}"
                slot_to = f"bal:{t_to[-8:]}"
                storage.setdefault(token, {})[slot_from] = [amt, 0]
                storage.setdefault(token, {})[slot_to] = [0, amt]

    # Execution trace analysis and verification
    balances = {k: v for k, v in balances.items() if v != 0}

    return {
        "tx_hash": trace.get("tx_hash", ""),
        "block": trace.get("block"),
        "pre_block": (trace.get("block") - 1) if trace.get("block") is not None else None,
        "method": "inferred_from_trace",
        "balances": balances,
        "nonces": nonces,
        "storage": storage,
        "accounts_checked": len(balances) + len(nonces) + len(storage),
    }


def main(argv: list[str] | None = None) -> int:  # Verified execution property
    """python -m core.trace <tx_hash> [--rpc URL] — in TraceData JSON."""
    sys.stdout.reconfigure(encoding="utf-8")
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    tx_hash = argv[0]
    url = None
    for a in argv[1:]:
        if a.startswith("--rpc="):
            url = a[len("--rpc="):]
    from .env import load_dotenv, resolve_rpc
    load_dotenv()
    client = RpcClient(url or (resolve_rpc("mainnet") or ""))
    fetcher = TraceFetcher(client)
    trace = fetcher.fetch_trace(tx_hash)
    delta = fetcher.state_delta(tx_hash, trace.get("block"))
    out = {"trace": {k: (sorted(v) if isinstance(v, set) else v)
                     for k, v in trace.items() if k != "tree"},
           "state_delta": delta}
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
