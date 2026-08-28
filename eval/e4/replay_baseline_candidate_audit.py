"""Baseline-only audit for CREATE-derived attacker candidates.

This intentionally runs no mutation branch. It produces a separate run
artifact so the existing Phase 1 results remain untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.env import load_dotenv, resolve_rpc_candidates, resolve_trace_rpc_candidates
from core.rpc import RpcClient
from eval.b2_adapter import run as run_b2
from eval.e4.execution import run_necessity
from eval.e4.models import Case
from eval.e4.pricing import harm_spec_from_manifest, load_price_manifest
from eval.e4.reporting import build_evidence_graph, write_csv


ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "eval" / "e4_fixed_set_v2.json"
TRIAGE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
MANIFEST = ROOT / "eval" / "e4_price_manifest.json"

CASE_IDS = {
    "defihacklabs-rnspay-2025-03-06",
    "defihacklabs-unverified-6f7a-2025-08-22",
    "defihacklabs-sbr-token-2025-03-07",
}
CONTEXT_NAMES = {
    "defihacklabs-rnspay-2025-03-06": "rnspay",
    "defihacklabs-unverified-6f7a-2025-08-22": "unverified-6f7a",
    "defihacklabs-sbr-token-2025-03-07": "sbr-token",
}


def main() -> int:
    load_dotenv()
    archive_urls = resolve_rpc_candidates("mainnet")
    trace_urls = resolve_trace_rpc_candidates("mainnet")
    archive = RpcClient(archive_urls[0], timeout=60, attempts=2, fallback_urls=archive_urls[1:])
    # Resolve the configured trace provider once so this audit retains the
    # same provider-role metadata as the normal pipeline; no trace RPC call is
    # made because the target traces come from the immutable local cache.
    _ = trace_urls
    fixed = {row["case_id"]: row for row in json.loads(FIXED.read_text())["cases"]}
    cache = {}
    for line in TRIAGE.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            cache[row["tx_hash"].lower()] = row
    manifest = load_price_manifest(MANIFEST)
    for case_id in sorted(CASE_IDS):
        row = fixed[case_id]
        context_name = CONTEXT_NAMES[case_id]
        context = ROOT / "eval" / "results" / "runs" / f"b2-context-{context_name}-20260823"
        transactions = json.loads((context / "transactions.json").read_text())
        target_tx = next(item for item in transactions if item["hash"].lower() == row["tx_hash"].lower())
        target_index = int(target_tx["transactionIndex"], 16)
        receipts = json.loads((context / "receipts.json").read_text())
        gas = int(receipts[target_index]["receipt"]["gasUsed"], 16)
        sender = target_tx["from"].lower()
        harm_spec = harm_spec_from_manifest(archive, manifest, int(row["block"]) - 1, sender)
        case = Case(case_id, "", "oracle", row["tx_hash"], block=int(row["block"]),
                    tx_index=target_index, mainnet_gas=gas,
                    extra={"harm_spec": harm_spec},
                    trace=(cache[row["tx_hash"].lower()]["trace"] or {}).get("tree"))
        gate = run_b2(context, timeout=900)
        run_id = f"e4-{case_id}-baseline-candidate-audit-20260823"
        if not gate.payload.get("acceptance_gate", False):
            print(case_id, "SKIP_BASELINE_GATE", gate.payload.get("acceptance_gate"))
            continue
        rows = run_necessity(case, [], archive=archive, b2_context=context,
                             run_id=run_id, timeout=900)
        out_dir = ROOT / "eval" / "results" / "runs" / run_id
        write_csv(rows, out_dir / "e4_necessity.csv")
        (out_dir / "e4_evidence_graph.json").write_text(
            json.dumps(build_evidence_graph(rows), indent=2) + "\n", encoding="utf-8")
        print(case_id, json.dumps([
            {key: item.get(key) for key in
             ("mutation", "outcome", "harm_S", "positive_candidate_delta_usd", "verdict",
              "per_tx_gas_match", "prestate_proof_verified")}
            for item in rows if item.get("mutation") == "fidelity"
        ]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
