"""Probe remote ``debug_traceCall`` state overrides.

This module deliberately stays separate from the Anvil replayer.  It is a
diagnostic adapter for archive RPCs: transaction/block/receipt data come from
the configured archive provider and the provider executes the call remotely.
It never sends a transaction.

Providers have exposed two wire shapes in the wild, so the runner tries the
canonical Geth shape first (trace config, then state overrides) and optionally
the provider-specific nested shape.  A successful baseline is required before
an override result is considered meaningful.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from core.env import load_dotenv, resolve_rpc, resolve_trace_rpc
from core.rpc import RpcClient, RpcError


@dataclass
class TraceCallResult:
    mode: str
    observed: bool
    status: bool | None
    gas_used: int | None
    error: str | None
    elapsed_ms: int


def _quantity(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def _status_and_gas(result: object) -> tuple[bool | None, int | None]:
    """Extract status/gas from common callTracer and structLog responses."""
    if not isinstance(result, dict):
        return None, None
    gas = _quantity(result.get("gasUsed"))
    if gas is None:
        gas = _quantity(result.get("gas"))
    failed = result.get("failed")
    if isinstance(failed, bool):
        return not failed, gas
    if result.get("error"):
        return False, gas
    # A successful trace normally has no error/failed field.  Keep status None
    # when the provider returned an opaque trace rather than inventing receipt
    # semantics from it.
    return True, gas


def _call_object(tx: dict) -> dict:
    """Build a debug call object from an eth_getTransactionByHash response."""
    out = {
        "from": tx.get("from"),
        "to": tx.get("to"),
        "data": tx.get("input") or "0x",
        "value": tx.get("value") or "0x0",
        "gas": tx.get("gas") or "0x0",
    }
    for key in ("gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"):
        if tx.get(key) is not None:
            out[key] = tx[key]
    return {k: v for k, v in out.items() if v is not None}


def trace_call(client: RpcClient, tx: dict, block: int,
               state_overrides: dict | None = None,
               shape: str = "geth") -> TraceCallResult:
    """Execute one remote trace call, without broadcasting a transaction."""
    call = _call_object(tx)
    trace_config = {"tracer": "callTracer", "timeout": "30s"}
    block_tag = hex(block)
    if shape == "geth":
        params = [call, block_tag, trace_config]
        if state_overrides is not None:
            params.append(state_overrides)
    elif shape == "nested":
        # Some provider APIs document the override as an option beside tracer.
        params = [call, block_tag, {**trace_config,
                                    "stateOverrides": state_overrides or {}}]
    else:
        raise ValueError(f"unknown traceCall shape: {shape}")
    started = time.monotonic()
    try:
        result = client.call("debug_traceCall", params)
        status, gas = _status_and_gas(result)
        return TraceCallResult(shape, True, status, gas, None,
                               round((time.monotonic() - started) * 1000))
    except RpcError as exc:
        return TraceCallResult(shape, False, None, None, str(exc)[:512],
                               round((time.monotonic() - started) * 1000))


def run_probe(rpc: str, tx_hash: str, block: int, override: dict | None = None,
              output: Path | None = None) -> dict:
    client = RpcClient(rpc, timeout=45, attempts=1)
    tx = client.eth_get_transaction(tx_hash)
    receipt = client.eth_get_receipt(tx_hash)
    if not tx:
        raise RpcError(f"transaction not found: {tx_hash}")
    baseline = trace_call(client, tx, block)
    results = [baseline]
    if override is not None:
        results.extend(trace_call(client, tx, block, override, shape)
                       for shape in ("geth", "nested"))
    payload = {
        "tx_hash": tx_hash,
        "block": block,
        "mainnet_receipt": {
            "status": receipt.get("status") if receipt else None,
            "gas_used": _quantity(receipt.get("gasUsed")) if receipt else None,
        },
        "baseline": asdict(baseline),
        "overrides": [asdict(item) for item in results[1:]],
        "baseline_gate": {
            "observed": baseline.observed,
            "gas_matches_receipt": (
                baseline.gas_used is not None and receipt is not None and
                baseline.gas_used == _quantity(receipt.get("gasUsed"))),
            "status_matches_receipt": (
                baseline.status is not None and receipt is not None and
                baseline.status == (_quantity(receipt.get("status")) == 1)),
        },
        "note": ("Remote trace only; no transaction broadcast. An override is "
                 "not causal evidence unless the baseline gate passes."),
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tx", required=True)
    parser.add_argument("--block", type=int, required=True)
    parser.add_argument("--rpc", default=None)
    parser.add_argument("--trace-provider", action="store_true",
                        help="use configured QuickNode trace endpoint")
    parser.add_argument("--override-json", default=None,
                        help="JSON object keyed by address, e.g. {address:{code:0x...}}")
    parser.add_argument("--same-code-override", action="store_true",
                        help="override tx.to with its historical code (capability probe)")
    parser.add_argument("--zero-code-override", action="store_true",
                        help="override tx.to with STOP runtime (diagnostic only)")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    load_dotenv()
    rpc = args.rpc or (resolve_trace_rpc("mainnet") if args.trace_provider
                       else resolve_rpc())
    if not rpc:
        parser.error("missing archive RPC")
    override = json.loads(args.override_json) if args.override_json else None
    if args.same_code_override:
        probe_client = RpcClient(rpc, timeout=45, attempts=1)
        probe_tx = probe_client.eth_get_transaction(args.tx)
        if not probe_tx or not probe_tx.get("to"):
            parser.error("transaction has no contract target for same-code override")
        code = probe_client.eth_get_code(probe_tx["to"], hex(args.block - 1))
        override = {probe_tx["to"]: {"code": code}}
    if args.zero_code_override:
        probe_client = RpcClient(rpc, timeout=45, attempts=1)
        probe_tx = probe_client.eth_get_transaction(args.tx)
        if not probe_tx or not probe_tx.get("to"):
            parser.error("transaction has no contract target for zero-code override")
        override = {probe_tx["to"]: {"code": "0x00"}}
    payload = run_probe(rpc, args.tx, args.block, override,
                        Path(args.output) if args.output else None)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
