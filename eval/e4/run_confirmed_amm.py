"""Legacy evidence-confirmed AMM runner.

Deprecated for new runs: use ``python -m eval.e4_necessity`` with one queue
row after the storage-layout evidence has been separately confirmed.  This
recipe remains for provenance of the packed-slot experiments.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.env import load_dotenv, resolve_rpc_candidates
from core.mutate import AmmReservePin
from core.rpc import RpcClient
from eval.b2_adapter import run as run_b2
from eval.e4.execution import run_necessity
from eval.e4.models import Case
from eval.e4.pricing import harm_spec_from_manifest, load_price_manifest
from eval.e4.reporting import build_evidence_graph, write_csv

ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "defihacklabs-veth-2024-11-14": ("veth", ["0x582d17d24127cfdcbc8c4e0a40c12d77b2e7a48d"]),
    "defihacklabs-rnspay-2025-03-06": ("rnspay", ["0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"]),
    "defihacklabs-unverified-6f7a-2025-08-22": ("unverified-6f7a", ["0x94b0a3d511b6ecdb17ebf877278ab030acb0a878", "0xa478c2975ab1ea89e8196811f51a7b7ade33eb11"]),
    "defihacklabs-sbr-token-2025-03-07": ("sbr-token", ["0x3431c535ddfb6dd5376e5ded276f91deaa864ff2"]),
}


def main() -> int:
    load_dotenv()
    urls = resolve_rpc_candidates("mainnet")
    archive = RpcClient(urls[0], timeout=60, attempts=2, fallback_urls=urls[1:])
    manifest = load_price_manifest(ROOT / "eval/e4_price_manifest.json")
    fixed = {x["case_id"]: x for x in json.loads((ROOT / "eval/e4_fixed_set_v2.json").read_text())["cases"]}
    cache = {json.loads(line)["tx_hash"].lower(): json.loads(line)
             for line in (ROOT / "eval/results/e1_trace_cache.jsonl").read_text().splitlines() if line.strip()}
    for case_id, (slug, pools) in CASES.items():
        item = fixed[case_id]
        tx = archive.eth_get_transaction(item["tx_hash"])
        receipt = archive.eth_get_receipt(item["tx_hash"])
        context = ROOT / f"eval/results/runs/b2-context-{slug}-20260823"
        gate = run_b2(context, timeout=900)
        case = Case(case_id, "", "oracle", item["tx_hash"], block=item["block"],
                    tx_index=int(tx["transactionIndex"], 16),
                    mainnet_gas=int(receipt["gasUsed"], 16),
                    extra={"harm_spec": harm_spec_from_manifest(
                        archive, manifest, item["block"] - 1, tx["from"])},
                    trace=(cache[item["tx_hash"].lower()].get("trace") or {}).get("tree"))
        if not gate.payload.get("acceptance_gate", False):
            print(case_id, "SKIP_GATE", gate.payload.get("all_gas_match"), gate.payload.get("all_status_match"))
            continue
        accounts = {}
        for row in json.loads((context / "prestates.json").read_text()):
            accounts.update(row.get("trace") or {})
        slot = "0x" + "00" * 31 + "08"
        overrides = {pool: accounts[pool]["storage"][slot] for pool in pools}
        run_id = f"e4-{case_id}-packed-amm-20260823"
        rows = run_necessity(case, [AmmReservePin(pools[0], {slot: overrides[pools[0]]})],
                             archive=archive, b2_context=context, run_id=run_id, timeout=900)
        # Keep all confirmed pool overrides in the evidence note; the current
        # primitive is intentionally one-target and this run validates the
        # first traced price pool without guessing a multi-pool causal scope.
        out_dir = ROOT / "eval/results/runs" / run_id
        write_csv(rows, out_dir / "e4_necessity.csv")
        (out_dir / "e4_evidence_graph.json").write_text(json.dumps(build_evidence_graph(rows), indent=2) + "\n")
        print(case_id, [{k: row.get(k) for k in ("mutation", "harm_S", "harm_Sm", "verdict", "per_tx_gas_match", "prestate_proof_verified", "override_applied")} for row in rows])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
