"""Legacy fixed-set flash-loan runner.

Deprecated for new runs: use ``python -m eval.e4_necessity`` with one queue
row.  Retained because it records the historical three-case f_fl experiment.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.env import load_dotenv, resolve_rpc_candidates, resolve_trace_rpc_candidates
from core.rpc import RpcClient
from eval.b2_adapter import run as run_b2
from eval.e4.execution import run_necessity
from eval.e4.models import Case
from eval.e4.planner import build_mutation_plan
from eval.e4.pricing import harm_spec_from_manifest, load_price_manifest
from eval.e4.reporting import build_evidence_graph, write_csv
from eval.necessity import mutation_factor
from eval.results.b2_context import acquire as acquire_context
from eval.b2_proofs import acquire as acquire_proofs


ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "eval" / "e4_fixed_set_v2.json"
CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
MANIFEST = ROOT / "eval" / "e4_price_manifest.json"
CASE_IDS = [
    "defihacklabs-sizeflashloanlooping-2025-08-15",
    "defihacklabs-yeth-2025-12-01",
    "defihacklabs-thetanuts-2026-06-15",
]


def main() -> int:
    load_dotenv()
    archive_urls = resolve_rpc_candidates("mainnet")
    trace_urls = resolve_trace_rpc_candidates("mainnet")
    archive = RpcClient(archive_urls[0], timeout=60, attempts=2, fallback_urls=archive_urls[1:])
    trace_rpc = RpcClient(trace_urls[0], timeout=60, attempts=2, fallback_urls=trace_urls[1:])
    fixed = {row["case_id"]: row for row in json.loads(FIXED.read_text())["cases"]}
    cache = {}
    for line in CACHE.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            cache[row["tx_hash"].lower()] = row
    manifest = load_price_manifest(MANIFEST)

    for case_id in CASE_IDS:
        row = fixed[case_id]
        tx = archive.eth_get_transaction(row["tx_hash"])
        receipt = archive.eth_get_receipt(row["tx_hash"])
        if not tx or not receipt:
            raise RuntimeError(f"archive transaction/receipt unavailable: {case_id}")
        tx_index = int(tx["transactionIndex"], 16)
        block = int(row["block"])
        slug = case_id.removeprefix("defihacklabs-")
        context = ROOT / "eval" / "results" / "runs" / f"b2-context-{slug}-20260824"
        if not (context / "prestates.json").is_file():
            acquire_context(archive, trace_rpc, tx_hash=row["tx_hash"], block_number=block,
                            tx_index=tx_index, out=context, timeout_s=60.0)
            acquire_proofs(context, archive)
        trace = (cache[row["tx_hash"].lower()].get("trace") or {}).get("tree")
        harm_spec = harm_spec_from_manifest(archive, manifest, block - 1, tx["from"])
        case = Case(case_id, "", "flash-loan", row["tx_hash"], block=block,
                    tx_index=tx_index, mainnet_gas=int(receipt["gasUsed"], 16),
                    extra={"harm_spec": harm_spec}, trace=trace)
        plan = build_mutation_plan(case, archive, trace_rpc=trace_rpc)
        mutations = [m for m in plan.mutations if mutation_factor(str(m)) == "f_fl"]
        run_id = f"e4-{case_id}-fl-20260824"
        gate = run_b2(context, timeout=900)
        if not gate.payload.get("acceptance_gate", False):
            rows = run_necessity(case, [], archive=archive, b2_context=context,
                                 run_id=run_id, timeout=900)
            out_dir = ROOT / "eval" / "results" / "runs" / run_id
            write_csv(rows, out_dir / "e4_necessity.csv")
            (out_dir / "gate_failure.json").write_text(json.dumps({
                "acceptance_gate": False,
                "all_gas_match": gate.payload.get("all_gas_match"),
                "all_status_match": gate.payload.get("all_status_match"),
                "prestate_proof_verified": gate.proof_verified,
                "planner_notes": plan.notes,
            }, indent=2) + "\n", encoding="utf-8")
            print(case_id, "SKIP_MUTATION_GATE", plan.notes)
            continue
        rows = run_necessity(case, mutations, archive=archive, b2_context=context,
                             run_id=run_id, timeout=900)
        out_dir = ROOT / "eval" / "results" / "runs" / run_id
        write_csv(rows, out_dir / "e4_necessity.csv")
        (out_dir / "e4_evidence_graph.json").write_text(
            json.dumps(build_evidence_graph(rows), indent=2) + "\n", encoding="utf-8")
        print(case_id, json.dumps([
            {key: item.get(key) for key in
             ("mutation", "outcome", "harm_S", "harm_Sm", "verdict",
              "per_tx_gas_match", "prestate_proof_verified", "override_applied")}
            for item in rows
        ]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
