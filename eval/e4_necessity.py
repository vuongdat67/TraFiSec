"""Official candidate-driven B2 entrypoint for E4 v2.

This module is the composition root for a single preregistered candidate:
queue row -> archive/trace inputs -> prepared B2 context -> acceptance gate ->
``eval.e4.execution.run_necessity``.  It deliberately contains no verdict
policy; verdicts remain owned by ``eval/e4/verdict.py`` and execution remains
owned by ``eval/e4/execution.py``.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from eval.b2_adapter import run as run_b2
from eval.b2_proofs import acquire as acquire_proofs
from eval.e4.execution import run_necessity
from eval.e4.models import Case
from eval.e4.planner import build_mutation_plan
from eval.e4.pricing import harm_spec_from_manifest, load_price_manifest
from eval.e4.reporting import build_evidence_graph, write_csv
from eval.necessity import mutation_factor
from eval.results.b2_context import acquire as acquire_context
from core.env import (load_dotenv, resolve_rpc_candidates,
                          resolve_trace_rpc_candidates)
from core.rpc import RpcClient, RpcError


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_QUEUE = ROOT / "eval" / "results" / "e4_v2_selected_candidates.csv"
DEFAULT_TRACE_CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
DEFAULT_PRICE_MANIFEST = ROOT / "eval" / "e4_price_manifest.json"


def load_candidate(path: Path, case_id: str) -> dict[str, str]:
    """Load exactly one candidate row; reject ambiguous or missing input."""
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("case_id") == case_id]
    if len(rows) != 1:
        raise ValueError(f"expected exactly one candidate {case_id!r}, found {len(rows)}")
    required = {"case_id", "tx_hash", "block", "blind_candidate_factors",
                "supported_from_cache", "runtime_oracle_mode", "tier"}
    missing = sorted(required - set(rows[0]))
    if missing:
        raise ValueError("candidate row missing fields: " + ", ".join(missing))
    row = rows[0]
    if row["runtime_oracle_mode"] != "external-price-feed":
        raise ValueError(
            f"candidate {case_id} is not runtime-supported external-price-feed: "
            f"{row['runtime_oracle_mode']}"
        )
    if int(row["tier"]) > 2:
        raise ValueError(f"candidate {case_id} exceeds the Phase 4 Tier 2 limit")
    return row


def load_trace_cache(path: Path) -> dict[str, dict]:
    traces: dict[str, dict] = {}
    if not path.is_file():
        return traces
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid trace cache JSON at line {line_number}") from exc
        tx_hash = str(row.get("tx_hash") or "").lower()
        if tx_hash:
            traces[tx_hash] = (row.get("trace") or {}).get("tree") or row.get("trace") or {}
    return traces


def _rpc_clients() -> tuple[RpcClient, RpcClient | None]:
    archive_urls = resolve_rpc_candidates("mainnet")
    if not archive_urls:
        raise RuntimeError("no archive RPC configured")
    archive = RpcClient(archive_urls[0], timeout=60, attempts=2,
                        fallback_urls=archive_urls[1:])
    trace_urls = resolve_trace_rpc_candidates("mainnet")
    trace = None
    if trace_urls:
        trace = RpcClient(trace_urls[0], timeout=60, attempts=2,
                          fallback_urls=trace_urls[1:])
    return archive, trace


def _case_from_row(row: dict[str, str], archive: RpcClient,
                   trace: dict, manifest: dict) -> Case:
    tx = archive.eth_get_transaction(row["tx_hash"])
    receipt = archive.eth_get_receipt(row["tx_hash"])
    if not tx or not receipt:
        raise RpcError(f"transaction or receipt unavailable: {row['case_id']}")
    actual_block = int(str(tx["blockNumber"]), 16)
    expected_block = int(row["block"])
    if actual_block != expected_block:
        raise ValueError(f"queue block {expected_block} != archive block {actual_block}")
    harm_spec = harm_spec_from_manifest(archive, manifest, expected_block - 1,
                                        tx["from"])
    protocol = row.get("protocol_name") or row["case_id"]
    return Case(
        row["case_id"], protocol, "preregistered-candidate", row["tx_hash"],
        block=expected_block, tx_index=int(tx["transactionIndex"], 16),
        mainnet_gas=int(receipt["gasUsed"], 16),
        extra={"harm_spec": harm_spec, "candidate_row": row},
        trace=trace,
    )


def _supported_factors(row: dict[str, str]) -> set[str]:
    return {factor.rstrip("?") for factor in row["supported_from_cache"].split("+")
            if factor.strip()}


def run_candidate(row: dict[str, str], *, archive: RpcClient,
                  trace_rpc: RpcClient | None, context: Path,
                  price_manifest: Path = DEFAULT_PRICE_MANIFEST,
                  trace_cache: Path = DEFAULT_TRACE_CACHE,
                  run_id: str | None = None, timeout: int = 900,
                  acquire: bool = True,
                  planner_discovered: bool = False) -> list[dict]:
    """Run one candidate through the official B2 execution path."""
    trace = load_trace_cache(trace_cache).get(row["tx_hash"].lower(), {})
    if not trace and trace_rpc is None:
        raise RuntimeError("candidate has no cached call trace and no trace RPC configured")
    manifest = load_price_manifest(price_manifest)
    case = _case_from_row(row, archive, trace, manifest)
    if acquire and not (context / "prestate_proofs.json").is_file():
        if trace_rpc is None:
            raise RuntimeError("trace RPC is required to acquire the B2 context")
        acquire_context(archive, trace_rpc, tx_hash=case.tx_hash,
                        block_number=case.block, tx_index=case.tx_index,
                        out=context, timeout_s=60.0)
        acquire_proofs(context, archive)
    if not (context / "prestate_proofs.json").is_file():
        raise RuntimeError(f"B2 context is incomplete: {context}")

    gate = run_b2(context, timeout=timeout)
    candidate_factors = _supported_factors(row)
    run_id = run_id or f"e4-v2-{case.case_id}"
    if not gate.payload.get("acceptance_gate", False):
        mutations = []
        planner_notes = ["mutation skipped because B2 acceptance gate failed"]
    else:
        plan = build_mutation_plan(case, archive, trace_rpc=trace_rpc)
        mutations = (list(plan.mutations) if planner_discovered else
                     [mutation for mutation in plan.mutations
                      if mutation_factor(str(mutation)) in candidate_factors])
        planner_notes = plan.notes
    rows = run_necessity(case, mutations, archive=archive, b2_context=context,
                         run_id=run_id, timeout=timeout)
    output_dir = ROOT / "eval" / "results" / "runs" / run_id
    write_csv(rows, output_dir / "e4_necessity.csv")
    (output_dir / "e4_evidence_graph.json").write_text(
        json.dumps(build_evidence_graph(rows), indent=2) + "\n", encoding="utf-8")
    (output_dir / "run_diagnostics.json").write_text(json.dumps({
        "candidate": row,
        "acceptance_gate": gate.payload.get("acceptance_gate", False),
        "all_gas_match": gate.payload.get("all_gas_match"),
        "all_status_match": gate.payload.get("all_status_match"),
        "prestate_proof_verified": gate.proof_verified,
        "planner_notes": planner_notes,
    }, indent=2) + "\n", encoding="utf-8")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--trace-cache", type=Path, default=DEFAULT_TRACE_CACHE)
    parser.add_argument("--price-manifest", type=Path, default=DEFAULT_PRICE_MANIFEST)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--no-acquire", action="store_true")
    args = parser.parse_args(argv)
    load_dotenv()
    row = load_candidate(args.queue, args.candidate_id)
    archive, trace_rpc = _rpc_clients()
    rows = run_candidate(row, archive=archive, trace_rpc=trace_rpc,
                         context=args.context, price_manifest=args.price_manifest,
                         trace_cache=args.trace_cache, run_id=args.run_id,
                         timeout=args.timeout, acquire=not args.no_acquire)
    print(json.dumps([{
        key: row.get(key) for key in
        ("case", "mutation", "outcome", "harm_S", "harm_Sm", "verdict",
         "per_tx_gas_match", "prestate_proof_verified", "override_applied", "note")
    } for row in rows], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
