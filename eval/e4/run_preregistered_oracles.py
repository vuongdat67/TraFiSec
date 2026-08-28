"""Legacy fixed-set oracle runner.

Deprecated for new runs: use ``python -m eval.e4_necessity`` with one row from
the selected-candidate CSV.  This file is retained as a historical replay
recipe for the Phase 1 fixed-set oracle experiments.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from core.env import load_dotenv, resolve_rpc_candidates, resolve_trace_rpc_candidates
from core.mutate import AmmReservePin
from core.rpc import RpcClient
from eval.e4.execution import run_necessity
from eval.e4.planner import build_mutation_plan
from eval.e4.pricing import harm_spec_from_manifest, load_price_manifest
from eval.e4.models import Case
from eval.e4.reporting import build_evidence_graph, write_csv
from eval.b2_adapter import run as run_b2


ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "eval" / "e4_fixed_set_v2.json"
TRIAGE = ROOT / "eval" / "results" / "e4_oracle_mode_triage_fixed20.csv"
CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
MANIFEST = ROOT / "eval" / "e4_price_manifest.json"


def _load_rows() -> tuple[dict[str, dict], dict[str, dict]]:
    fixed = {row["case_id"]: row for row in json.loads(FIXED.read_text())["cases"]}
    triage = {row["case_id"]: row for row in csv.DictReader(TRIAGE.open())}
    cache = {}
    for line in CACHE.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            cache[str(row.get("tx_hash", "")).lower()] = row
    return fixed, {case_id: cache[row["tx_hash"].lower()] for case_id, row in fixed.items()
                   if row["tx_hash"].lower() in cache and
                   (triage.get(case_id, {}).get("classification") == "external-price-feed" or
                    case_id.endswith("sashatoken-2024-10-06"))}


def _tx_index(archive: RpcClient, tx_hash: str) -> tuple[int, str, int]:
    tx = archive.eth_get_transaction(tx_hash)
    if not tx:
        raise RuntimeError(f"transaction unavailable: {tx_hash}")
    receipt = archive.eth_get_receipt(tx_hash) or {}
    return int(tx["transactionIndex"], 16), tx["from"].lower(), int(receipt.get("gasUsed", "0x0"), 16)


def main() -> int:
    load_dotenv()
    archive_urls = resolve_rpc_candidates("mainnet")
    trace_urls = resolve_trace_rpc_candidates("mainnet")
    archive = RpcClient(archive_urls[0], timeout=60, attempts=2, fallback_urls=archive_urls[1:])
    trace_rpc = RpcClient(trace_urls[0], timeout=60, attempts=2, fallback_urls=trace_urls[1:])
    manifest = load_price_manifest(MANIFEST)
    fixed, cache = _load_rows()
    case_ids = sorted(cache)
    for case_id in case_ids:
        row = fixed[case_id]
        tx_index, sender, gas = _tx_index(archive, row["tx_hash"])
        harm_spec = harm_spec_from_manifest(archive, manifest, int(row["block"]) - 1, sender)
        case = Case(case_id, "", "oracle", row["tx_hash"], block=int(row["block"]),
                    tx_index=tx_index, mainnet_gas=gas,
                    extra={"harm_spec": harm_spec},
                    trace=(cache[case_id].get("trace") or {}).get("tree"))
        context_name = "-".join(case_id.removeprefix("defihacklabs-").split("-")[:-3])
        context_date = "20260822" if case_id.endswith("sashatoken-2024-10-06") else "20260823"
        context = ROOT / "eval" / "results" / "runs" / f"b2-context-{context_name}-{context_date}"
        if not context.is_dir():
            raise RuntimeError(f"missing prepared context: {context}")
        gate = run_b2(context, timeout=900)
        if not gate.payload.get("acceptance_gate", False):
            run_id = f"e4-{case_id}-preregistered-orc-20260823"
            rows = run_necessity(case, [], archive=archive, b2_context=context,
                                 run_id=run_id, timeout=900)
            out_dir = ROOT / "eval" / "results" / "runs" / run_id
            out = out_dir / "e4_necessity.csv"
            write_csv(rows, out)
            (out_dir / "gate_failure.json").write_text(
                json.dumps({"acceptance_gate": False, "observed": gate.observed,
                            "status": gate.status, "gas": gate.gas_used,
                            "all_gas_match": gate.payload.get("all_gas_match"),
                            "all_status_match": gate.payload.get("all_status_match"),
                            "prestate_proof_verified": gate.proof_verified}, indent=2) + "\n",
                encoding="utf-8")
            print(case_id, "SKIP_MUTATION_GATE", json.dumps({
                "all_gas_match": gate.payload.get("all_gas_match"),
                "all_status_match": gate.payload.get("all_status_match"),
                "proof": gate.proof_verified,
            }))
            continue
        if case_id.endswith("sashatoken-2024-10-06"):
            pool = "0xb23fc1241e1bc1a5542a438775809d38099838fe"
            prestate = json.loads((context / "prestates.json").read_text())[0]["trace"][pool]
            slot = "0x" + "00" * 31 + "08"
            mutation = AmmReservePin(pool, {slot: prestate["storage"][slot]})
            mutations = [mutation]
        else:
            plan = build_mutation_plan(case, archive, trace_rpc=trace_rpc)
            mutations = plan.mutations
        run_id = f"e4-{case_id}-preregistered-orc-20260823"
        rows = run_necessity(case, mutations, archive=archive, b2_context=context,
                             run_id=run_id, timeout=600)
        out_dir = ROOT / "eval" / "results" / "runs" / run_id
        out = out_dir / "e4_necessity.csv"
        write_csv(rows, out)
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
