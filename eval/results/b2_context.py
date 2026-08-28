"""Acquire the bounded B2 context for one mid-block transaction.

This is archive acquisition only.  It does not execute transactions and does
not pretend that the existing target-only diff cache is enough for a Geth
replayer.  The output is a deterministic, fail-closed input directory for the
future go-ethereum runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from core.env import (load_dotenv, resolve_rpc_candidates,
                          resolve_trace_rpc_candidates)
from core.rpc import RpcClient, RpcError
from eval.replay_context import provider_identity, redacted_diagnostic


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def acquire(archive: RpcClient, trace: RpcClient, *, tx_hash: str,
            block_number: int, tx_index: int, out: Path,
            timeout_s: float = 60.0, full_block: bool = False) -> dict:
    block = archive.call("eth_getBlockByNumber", [hex(block_number), True])
    if not isinstance(block, dict):
        raise RpcError("target block unavailable")
    txs = block.get("transactions") or []
    if len(txs) <= tx_index or txs[tx_index].get("hash", "").lower() != tx_hash.lower():
        raise RpcError("block transaction list does not contain target at tx_index")
    selected = txs if full_block else txs[:tx_index + 1]
    expected_selected = len(txs) if full_block else tx_index + 1
    if len(selected) != expected_selected:
        raise RpcError("prefix is incomplete")

    _write(out / "block.json", block)
    _write(out / "case.json", {
        "tx_hash": tx_hash, "block": block_number, "tx_index": tx_index,
        "state_block": block_number - 1, "prefix_count": tx_index,
        "full_block": full_block,
        "archive_provider": provider_identity(archive.last_endpoint),
        "trace_provider": provider_identity(trace.last_endpoint),
        "chain_rules": {
            "expected_fork": "istanbul",
            "berlin": False, "london": False,
            "note": "resolved by B2 runner from go-ethereum MainnetChainConfig",
        },
    })
    _write(out / "transactions.json", selected)
    receipts: list[dict] = []
    traces: list[dict] = []
    failures: list[dict] = []
    started = time.monotonic()
    for index, tx in enumerate(selected):
        h = tx.get("hash")
        try:
            receipt = archive.eth_get_receipt(h)
            if not receipt:
                raise RpcError("receipt unavailable")
            trace_result = trace.call("debug_traceTransaction", [h, {
                "tracer": "prestateTracer",
            }])
            if not isinstance(trace_result, dict) or not trace_result:
                raise RpcError("prestateTracer returned empty result")
            receipts.append({"index": index, "tx_hash": h, "receipt": receipt})
            traces.append({"index": index, "tx_hash": h, "trace": trace_result})
        except Exception as exc:
            failures.append({"index": index, "tx_hash": h,
                             "failure_class": "archive_trace_failure",
                             "diagnostic": redacted_diagnostic(exc)})
            break
    _write(out / "receipts.json", receipts)
    _write(out / "prestates.json", traces)
    manifest = {
        "schema_version": 1, "tx_hash": tx_hash, "block": block_number,
        "tx_index": tx_index, "prefix_count": tx_index,
        "full_block": full_block,
        "transaction_count": len(selected), "receipt_count": len(receipts),
        "prestate_count": len(traces), "failures": failures,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "archive_provider": provider_identity(archive.last_endpoint),
        "trace_provider": provider_identity(trace.last_endpoint),
        "input_hashes": {name: _sha(out / name) for name in
                         ("case.json", "block.json", "transactions.json",
                          "receipts.json", "prestates.json")},
        "ready_for_geth_runner": not failures and len(traces) == len(selected),
        "note": ("Prestate acquisition only; no execution performed. The Go "
                 "runner must still validate chain rules and per-tx gas/status."),
    }
    _write(out / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tx", required=True)
    parser.add_argument("--block", type=int, required=True)
    parser.add_argument("--tx-index", type=int, required=True)
    parser.add_argument("--full-block", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--archive-rpc", default=None)
    parser.add_argument("--trace-rpc", default=None)
    args = parser.parse_args()
    load_dotenv()
    archive_candidates = ((args.archive_rpc,) if args.archive_rpc else
                          resolve_rpc_candidates("mainnet"))
    trace_candidates = ((args.trace_rpc,) if args.trace_rpc else
                        resolve_trace_rpc_candidates("mainnet"))
    archive_url = archive_candidates[0] if archive_candidates else None
    trace_url = trace_candidates[0] if trace_candidates else None
    if not archive_url or not trace_url:
        parser.error("archive and trace RPC are required")
    archive = RpcClient(archive_url, timeout=60, attempts=2,
                        fallback_urls=archive_candidates[1:])
    trace = RpcClient(trace_url, timeout=60, attempts=2,
                      fallback_urls=trace_candidates[1:])
    result = acquire(archive, trace, tx_hash=args.tx, block_number=args.block,
                     tx_index=args.tx_index, out=args.out, full_block=args.full_block)
    print(json.dumps(result, indent=2))
    return 0 if result["ready_for_geth_runner"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
