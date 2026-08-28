"""
TraFiSec -- E4 Counterfactual Necessity CLI
===========================================
Discovers intervention candidates from trace/state only, executes them on a local
fork, and scores against ground truth strictly after counterfactual verdicts are fixed.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

from core.env import load_dotenv, resolve_rpc, resolve_trace_rpc_candidates
from core.rpc import RpcClient, RpcError
from corpus.scripts.audit_ground_truth import validate_annotation, validate_review_record
from corpus.scripts.audit_review_workflow import audit_e4_files

from .necessity import (
    CORPUS_DEFAULT,
    NECESSITY_PORT,
    REPO_ROOT,
    RESULTS_DIR,
    RPC_SLEEP,
    Case,
    _aggregate,
    _resolve_trace,
    build_mutation_plan,
    build_evidence_graph,
    load_corpus,
    load_results,
    run_necessity,
    score_rows,
    write_csv,
)
from .e4_sensitivity import analyze as analyze_sensitivity
from .run_manifest import redact_command_args, utc_run_id, write_manifest

ANNOTATIONS_DEFAULT = REPO_ROOT / "corpus" / "annotations" / "e4_annotations.jsonl"
TRACE_CACHE_DEFAULT = REPO_ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
FIXED_SET_DEFAULT = REPO_ROOT / "eval" / "e4_fixed_set_v2.json"
REVIEW_SUBMISSION_DIR = REPO_ROOT / "corpus" / "annotations" / "review_submissions"

# Execution trace analysis and verification
# Execution trace analysis and verification
# Execution trace analysis and verification
# Execution trace analysis and verification
DEMO_CASE_IDS = [
    "pilot-cream-oracle",
    "pilot-euler-flashloan",
    "pilot-wazirx-safe",
]

# Execution trace analysis and verification
PILOT_DEMO: dict[str, dict] = {
    "pilot-bzx": {
        "case_id": "pilot-bzx",
        "protocol": "bZx (Feb 2020)",
        "attack_type": "flash-loan/oracle",
        "tx_hash": "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838",
        "block": 9484688, "tx_index": 28, "prior_hashes": [],
        "mainnet_gas": 3_109_043,
        "gt_factors": ["f_fl"], "chain": "mainnet",
        "extra": {"harm_spec": {
            "oracle": "pool_balance_delta",
            "protected_owner": "0x77f973fcaf871459aa58cd81881ce453759281bc",
            "protected_asset": "WETH",
            "protected_token": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "native_price_usd": 285.03100632480714,
            "lmin_usd": 100000.0,
            "valuation_source": "Uniswap V1 ETH/DAI at block 9484687",
        }},
        "notes": "B2 validation pilot; harm uses target receipt Transfer deltas",
    },
    "pilot-cream-oracle": {
        "case_id": "pilot-cream-oracle",
        "protocol": "Cream Finance (Aug 2021)",
        "attack_type": "flash-loan borrow + self-liquidation (Uniswap V2 flash swap)",
        "tx_hash": "0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e",
        "block": 13125071,
        "tx_index": 1,
        "prior_hashes": ["0xcbeb112334414c146b36f4c0b8816960aff01fe6b5ad28fc64b19867adb17b35"],
        "gt_factors": ["f_fl", "f_swap"],
        "chain": "mainnet",
        "source_url": "https://rekt.news/cream-rekt",
        "notes": "Uniswap V2 flash swap (pair 0x21b8065d) + cap-slice borrow; oracle Chainlink price constant → f_orc N/A",
    },
    "pilot-euler-flashloan": {
        "case_id": "pilot-euler-flashloan",
        "protocol": "Euler Finance (Mar 2023)",
        "attack_type": "flash-loan + accounting manipulation (donate-to-inflate)",
        "tx_hash": "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d",
        "block": 16817996,
        "tx_index": 0,
        "mainnet_gas": 1_949_994,
        "prior_hashes": [],
        "gt_factors": ["f_fl"],
        "chain": "mainnet",
        "extra": {"harm_spec": {
                      "oracle": "euler_bad_debt_delta",
                      "violator": "0x583c21631c48d442b5c0e605d624f54a0b366c72",
                      "debt_token": "0x6085bc95f506c326dcbcd7a6dd6c79fbc18d4686",
                      "collateral_token": "0xe025e3ca2be02316033184551d4d3aa22024d9dc",
                      "pre_debt_balance": 0,
                      "pre_collateral_balance": 0,
                      "collateral_underlying_per_token": 1.0220703626,
                      "debt_price_usd": 1.0,
                      "collateral_price_usd": 1.0,
                      "liquidation_event_address": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                      "liquidation_event_topic": "bba0f1d6fb8b9abe2bbc543b7c13d43faba91c6f78da4700381c94041ac7267d",
                      "lmin_usd": 100000.0,
                  },
                  "oracle_mutation_na": True,
                  "euler_patched_runtime": "eval/fixtures/euler_pr199_etoken_artifact.json"},
        "source_url": "https://rekt.news/euler-rekt",
        "notes": "Aave V2 flash loan (0x7d2768de); oracle price constant → f_orc N/A",
    },
    "pilot-wazirx-safe": {
        "case_id": "pilot-wazirx-safe",
        "protocol": "WazirX (Jul 2024) — GnosisSafe key compromise",
        "attack_type": "signer-key compromise (off-chain), execTransaction withdraw",
        "tx_hash": "0x48164d3adbab78c2cb9876f6e17f88e321097fcd14cadd57556866e4ef3e185d",
        "block": 20331565,
        "tx_index": 0,
        "prior_hashes": [],
        "gt_factors": ["f_auth"],
        "chain": "mainnet",
        "source_url": "https://rekt.news/wazirx-rekt",
        "notes": "GnosisSafe 4-of-6 -> permission-gated, AuthRevoke not applicable",
    },
}


def _load_trace_cache(path: Path) -> dict[str, dict]:
    """Load local E1 callTracer trees, indexed by transaction hash."""
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid trace cache JSON at line {line_no}: {exc}") from exc
            trace = row.get("trace") or {}
            tx_hash = row.get("tx_hash") or trace.get("tx_hash")
            tree = trace.get("tree")
            if tx_hash and isinstance(tree, dict):
                out[tx_hash.lower()] = tree
    return out


def _trace_from_cache(cache: dict[str, dict], tx_hash: str) -> dict | None:
    return cache.get((tx_hash or "").lower())


def _warmup_guard(case: Case, max_warmup_tx: int) -> str | None:
    """Refuse expensive mid-block replay before starting Anvil.

    E4 must not silently replay only a suffix: that would create an invalid
    pre-state.  A case over the budget is therefore INCONCLUSIVE, not a pass.
    """
    if max_warmup_tx <= 0 or case.tx_index <= max_warmup_tx:
        return None
    return (f"preflight: tx index {case.tx_index} requires {case.tx_index} "
            f"warmup txs; limit={max_warmup_tx}")


def _pilot_case(cid: str, archive: RpcClient, trace_cache: dict[str, dict] | None = None,
                trace_mode: str = "cache-first") -> Case | None:
    """Case t pilot registry (block c, replay verified) — khng cn corpus row."""
    cfg = PILOT_DEMO.get(cid)
    if not cfg:
        return None
    case = Case(**cfg)
    case.trace = _trace_from_cache(trace_cache or {}, case.tx_hash)
    if case.trace is None and trace_mode != "cache-only":
        try:
            case.trace = _resolve_trace(archive, case.tx_hash)
        except RpcError:
            pass
    return case


def _ensure_utf8() -> None:
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and "utf" not in sys.stderr.encoding.lower():
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _safe_hex_int(v: str | None, default: int = 0) -> int:
    """int(v, 16) an ton: '0x' / '' / None → default, khng raise ValueError."""
    if not v or not isinstance(v, str):
        return default
    v = v.strip()
    if v in ("", "0x", "0X"):
        return default
    try:
        return int(v, 16)
    except ValueError:
        return default


def _row_from_corpus(j: dict, archive: RpcClient,
                     trace_cache: dict[str, dict] | None = None,
                     trace_mode: str = "cache-first") -> Case:
    """Chuyn corpus row → Case (resolve block/index qua RPC nu cn)."""
    tx_hash = (j.get("tx_hashes") or [None])[0]
    if not tx_hash:
        raise RpcError(f"{j.get('id')}: khng c tx_hashes")
    ann = j.get("_causal_annotation") or {}
    case = Case(
        case_id=j.get("id") or tx_hash,
        protocol=j.get("protocol") or "",
        attack_type=j.get("attack_type") or "other",
        tx_hash=tx_hash,
        block=j.get("block"),  # None → resolve trong run_necessity
        gt_factors=["unknown"],
        chain=j.get("chain") or "mainnet",
        loss_usd=j.get("loss_usd"),
        notes=j.get("notes") or "",
        source_url=j.get("source_url") or "",
        extra={
            "harm_spec": ann.get("harm_spec") or j.get("harm_spec"),
            "paper_eligible": bool(ann),
            "label_source": "causal_sidecar_v2" if ann else "legacy_inventory",
        },
    )
    # Execution trace analysis and verification
    try:
        tx = archive.eth_get_transaction(tx_hash)
        if tx:
            blk = _safe_hex_int(tx.get("blockNumber"), 0)
            case.block = case.block or (blk if blk else None)
            case.tx_index = _safe_hex_int(tx.get("transactionIndex"), 0)
            rec = archive.eth_get_receipt(tx_hash)
            if rec:
                case.mainnet_gas = _safe_hex_int(rec.get("gasUsed", "0x0"), 0)
        case.trace = _trace_from_cache(trace_cache or {}, tx_hash)
        if case.trace is None and trace_mode != "cache-only":
            case.trace = _resolve_trace(archive, tx_hash)
    except RpcError:
        pass
    return case


def _planner_view(case: Case) -> Case:
    """Expose only execution evidence to the intervention planner."""
    return replace(
        case,
        protocol="",
        attack_type="other",
        gt_factors=["unknown"],
        loss_usd=None,
        notes="",
        source_url="",
        extra={
            "skip_optional_mutation": case.extra.get("oracle_mutation_na", False),
            "euler_patched_runtime": case.extra.get("euler_patched_runtime"),
        },
    )


def _select_cases(rows: list[dict], ids: list[str] | None,
                  only_clear_gt: bool) -> list[dict]:
    """Filter corpus rows by case IDs or known ground-truth factors."""
    if ids:
        # Execution trace analysis and verification
        pilot = [PILOT_DEMO[i] for i in ids if i in PILOT_DEMO]
        idset = set(ids)
        return pilot + [r for r in rows if (r.get("id") or "") in idset]
    if only_clear_gt:
        return [r for r in rows if (r.get("gt_factors") or []) != ["unknown"]
                and r.get("verified") == "onchain"]
    return [r for r in rows if r.get("verified") == "onchain"]


def _load_annotations(path: Path, inventory_by_id: dict[str, dict]) -> dict[str, dict]:
    """Load only adjudicated annotations that satisfy the paper contract."""
    if not path.is_file():
        return {}
    out = {}
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            row = json.loads(line)
            case_id = str(row.get("case_id") or f"line:{line_number}")
            if case_id in seen:
                raise ValueError(f"duplicate causal annotation: {case_id}")
            seen.add(case_id)
            if (row.get("eligibility") or {}).get("status") != "eligible":
                continue
            errors = validate_annotation(row, inventory_by_id.get(case_id))
            if errors:
                raise ValueError(f"paper-eligible annotation {case_id} invalid: {errors}")
            out[case_id] = row
    return out


def _load_review_records(path: Path, inventory_by_id: dict[str, dict]) -> dict[str, dict]:
    """Load all completed review records, including adjudicated ineligible rows."""
    if not path.is_file():
        return {}
    out: dict[str, dict] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        case_id = str(row.get("case_id") or f"line:{line_number}")
        if case_id in out:
            raise ValueError(f"duplicate causal review: {case_id}")
        errors = validate_review_record(row, inventory_by_id.get(case_id))
        if errors:
            raise ValueError(f"incomplete independent review {case_id}: {errors}")
        out[case_id] = row
    return out


def _load_fixed_set(path: Path, inventory_by_id: dict[str, dict]) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases") or []
    ids = [str(item.get("case_id") or "") for item in cases]
    if len(cases) != 20 or len(set(ids)) != 20 or any(not case_id for case_id in ids):
        raise ValueError("E4 paper fixed set must contain exactly 20 unique case IDs")
    selected: list[dict] = []
    for item in cases:
        case_id = str(item["case_id"])
        inventory = inventory_by_id.get(case_id)
        if inventory is None:
            raise ValueError(f"fixed-set case absent from corpus: {case_id}")
        expected = str(item.get("tx_hash") or "").lower()
        actual = {str(value).lower() for value in inventory.get("tx_hashes") or []}
        if expected not in actual:
            raise ValueError(f"fixed-set tx mismatch: {case_id}")
        selected.append(inventory)
    return selected


def _ineligible_row(run_id: str, row: dict, review: dict) -> dict:
    return {
        "run_id": run_id, "planner": "blind-v2", "case": row.get("id"),
        "paper_eligible": False, "label_source": "causal_sidecar_v2",
        "factor_gt": "blinded_not_scored", "mutation": "ineligible",
        "candidate_factor": "", "outcome": "", "observed": False,
        "fidelity_pass": "", "execution_preserving": "",
        "behavior_changed": "", "harm_S": "UNKNOWN", "harm_Sm": "UNKNOWN",
        "loss_S": "", "loss_Sm": "", "dloss": "", "lmin_usd": "",
        "valuation_source": "", "control_type": "", "control_pass": "",
        "verdict": "INELIGIBLE", "cause": "", "factor_match": "not_scored",
        "factor_confusion": "not_scored",
        "note": str((review.get("eligibility") or {}).get("reason") or "ineligible"),
    }


def _preflight_skip_row(run_id: str, case: Case, factor_gt: list[str], note: str) -> dict:
    return {
        "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
        "paper_eligible": bool(case.extra.get("paper_eligible")),
        "label_source": case.extra.get("label_source", "legacy_inventory"),
        "factor_gt": "+".join(factor_gt) or "unknown",
        "mutation": "preflight_skip", "candidate_factor": "",
        "outcome": "UNOBSERVED", "observed": False, "fidelity_pass": False,
        "execution_preserving": "", "behavior_changed": "",
        "harm_S": "UNKNOWN", "harm_Sm": "UNKNOWN", "loss_S": "",
        "loss_Sm": "", "dloss": "", "lmin_usd": "", "valuation_source": "",
        "control_type": "", "control_pass": "", "verdict": "INCONCLUSIVE",
        "cause": "", "factor_match": "not_scored", "factor_confusion": "not_scored",
        "note": note,
    }


def _legacy_main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    _ensure_utf8()
    load_dotenv()

    parser = argparse.ArgumentParser(description="E4 Counterfactual Necessity runner")
    parser.add_argument("--all", action="store_true",
                        help="Run all on-chain test incidents")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of cases to execute (0 = all selected)")
    parser.add_argument("--cases", nargs="*", default=[],
                        help="Filter by specific incident IDs (e.g., --cases firetoken)")
    parser.add_argument("--clear-gt", action="store_true",
                        help="Filter only cases with known ground-truth factors")
    parser.add_argument("--resume", action="store_true",
                        help="Resume run matching --run-id")
    parser.add_argument("--run-id", default=None,
                        help="Unique run ID; auto-generated if omitted")
    parser.add_argument("--list", action="store_true",
                        help="List selected cases and exit without starting fork")
    parser.add_argument("--rpc", default=None, help="Archive RPC endpoint (default from .env)")
    parser.add_argument("--trace-cache", default=str(TRACE_CACHE_DEFAULT),
                        help="Local callTracer cache path")
    parser.add_argument("--trace-rpc", default=None,
                        help="Dedicated trace RPC endpoint; archive defaults to --rpc/.env")
    parser.add_argument("--trace-mode", choices=("cache-first", "cache-only", "live"),
                        default="cache-first",
                        help="Trace retrieval strategy: cache-first, cache-only, or live")
    parser.add_argument("--max-warmup-tx", type=int, default=100,
                        help="Skip cases requiring more warmup transactions than limit (0 = disable)")
    parser.add_argument("--port", type=int, default=NECESSITY_PORT,
                        help=f"Local Anvil fork port (default: {NECESSITY_PORT})")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Replay execution timeout in seconds")
    parser.add_argument("--b2-context", default=None,
                        help="Prepared go-ethereum B2 context; fail-closed, no Anvil fallback")
    parser.add_argument("--corpus", default=None,
                        help="Path to incidents corpus JSONL file")
    parser.add_argument("--annotations", default=str(ANNOTATIONS_DEFAULT),
                        help="Causal annotations sidecar JSONL path")
    parser.add_argument("--eligible-only", action="store_true",
                        help="Filter only incidents with complete causal annotations")
    parser.add_argument("--sham-control", action="store_true",
                        help="Execute unrelated-state sham mutation control per incident")
    parser.add_argument("--force-baseline", action="store_true",
                        help="Run fidelity baseline even when planner generates no mutations")
    parser.add_argument("--joint-pairs", action="store_true",
                        help="Evaluate blind pairwise interventions on fresh forks")
    parser.add_argument("--paper-fixed20", action="store_true",
                        help="Strict E4 fixed-20 mode: dual review, sham control, no replacement")
    parser.add_argument("--fixed-set", default=str(FIXED_SET_DEFAULT),
                        help="Frozen blind fixed-20 incident set JSON path")
    parser.add_argument("--reviewer-a", default=str(REVIEW_SUBMISSION_DIR / "e4_reviewer_a.jsonl"))
    parser.add_argument("--reviewer-b", default=str(REVIEW_SUBMISSION_DIR / "e4_reviewer_b.jsonl"))
    parser.add_argument("--out", default=None,
                        help="CSV output path (defaults to eval/results/runs/<run-id>/e4_necessity.csv)")
    parser.add_argument("--json-out", action="store_true",
                        help="Print output as JSON records")
    parser.add_argument("--verbose-errors", action="store_true",
                        help="Print verbose diagnostics upon execution failure")
    args = parser.parse_args(argv)
    trace_cache = {} if args.trace_mode == "live" else _load_trace_cache(Path(args.trace_cache))
    print(f"trace cache: {len(trace_cache)} tx ({args.trace_mode})")

    if args.paper_fixed20:
        incompatible = []
        for name, active in (
            ("--all", args.all), ("--limit", bool(args.limit)),
            ("--cases", bool(args.cases)), ("--clear-gt", args.clear_gt),
            ("--resume", args.resume),
        ):
            if active:
                incompatible.append(name)
        if incompatible:
            parser.error("--paper-fixed20 forbids: " + ", ".join(incompatible))
        args.eligible_only = True
        args.sham_control = True
        args.joint_pairs = True

    run_id = args.run_id or utc_run_id("e4")
    if args.resume and not args.run_id:
        parser.error("--resume requires --run-id to prevent accidental multi-run mixing")
    out_path = (Path(args.out) if args.out else
                RESULTS_DIR / "runs" / run_id / "e4_necessity.csv")
    if args.paper_fixed20 and out_path.exists():
        parser.error("paper run requires a new output path; reuse/resume is forbidden")

    rows = load_corpus(args.corpus or CORPUS_DEFAULT)
    inventory_by_id = {str(row.get("id")): row for row in rows if row.get("id")}
    annotations = _load_annotations(Path(args.annotations), inventory_by_id)
    rows = [{**row, "_causal_annotation": annotations.get(row.get("id"))}
            for row in rows]
    attempted: list[dict] = []
    reviews: dict[str, dict] = {}
    if args.paper_fixed20:
        try:
            workflow = audit_e4_files(
                Path(args.reviewer_a), Path(args.reviewer_b), Path(args.fixed_set),
                Path(args.annotations),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"E4 independent-review workflow invalid: {exc}")
        if (not workflow.get("ready_for_adjudication") or
                not (workflow.get("final_sidecar") or {}).get("valid")):
            parser.error("E4 paper run requires two complete frozen review packets "
                         "and an exact vote-preserving adjudicated sidecar")
        attempted_raw = _load_fixed_set(Path(args.fixed_set), inventory_by_id)
        reviews = _load_review_records(Path(args.annotations), inventory_by_id)
        missing_reviews = [row["id"] for row in attempted_raw if row["id"] not in reviews]
        if missing_reviews:
            parser.error("fixed-20 independent review incomplete: " + ", ".join(missing_reviews))
        attempted = [
            {**row, "_causal_annotation": annotations.get(row.get("id"))}
            for row in attempted_raw
        ]
        selected = list(attempted)
    elif args.cases:
        selected = _select_cases(rows, args.cases, only_clear_gt=False)
    elif args.all:
        selected = _select_cases(rows, None, only_clear_gt=False)
    else:  # Verified execution property
        selected = _select_cases(rows, DEMO_CASE_IDS, only_clear_gt=False)
        if not selected:  # Verified execution property
            selected = _select_cases(rows, None, only_clear_gt=True)
    if args.eligible_only and not args.paper_fixed20:
        selected = [row for row in selected if row.get("_causal_annotation")]

    print(f"== E4 set ({len(selected)} cases; {len(rows)} corpus) ==")
    for j in selected:
        jid = j.get("id") or j.get("case_id") or "?"
        tx = (j.get("tx_hashes") or [j.get("tx_hash") or ""])[0]
        print(f"  {jid:<40} labels=blinded tx={str(tx)[:14]}...")
    if args.list:
        return 0

    rpc = args.rpc or resolve_rpc()
    if not rpc:
        raise SystemExit("Cn archive RPC: --rpc hoc ARCHIVE_RPC/ALCHEMY_API_KEY trong .env")
    archive = RpcClient(rpc, timeout=args.timeout)
    trace_candidates = ((args.trace_rpc,) if args.trace_rpc else
                        resolve_trace_rpc_candidates("mainnet"))
    trace_url = trace_candidates[0] if trace_candidates else rpc
    trace_client = RpcClient(trace_url, timeout=args.timeout,
                             fallback_urls=trace_candidates[1:])

    limit = args.limit or len(selected)
    todo = selected[:limit]
    placeholders: list[dict] = []
    if args.paper_fixed20:
        placeholders = [
            _ineligible_row(run_id, row, reviews[row["id"]])
            for row in attempted if not row.get("_causal_annotation")
        ]
        todo = [row for row in attempted if row.get("_causal_annotation")]
    if args.resume:
        done = load_results(out_path)
        done_cases = {r.get("case") for r in done if r.get("run_id") == run_id}
        todo = [j for j in todo if (j.get("id") or j.get("case_id") or "?") not in done_cases]
        if len(todo) < limit:
            print(f"\n== Resume: skipping {limit - len(todo)} cases already in CSV ==")
    print(f"\n== Running {len(todo)}/{len(selected)} cases (Anvil port {args.port}) ==")
    if not todo:
        print("\nNo remaining cases to execute (all cases present in CSV).")
        return 0

    manifest_path = out_path.with_name("manifest.json")
    write_manifest(
        manifest_path, run_id=run_id, experiment="E4-counterfactual-necessity-v2",
        repository=REPO_ROOT,
        inputs={"corpus": args.corpus or CORPUS_DEFAULT,
                "causal_annotations": args.annotations,
                "trace_cache": args.trace_cache,
                "reviewer_a": args.reviewer_a, "reviewer_b": args.reviewer_b,
                "fixed_set": args.fixed_set},
        parameters={
            "planner": "blind-v2", "port": args.port, "timeout_s": args.timeout,
            "trace_mode": args.trace_mode, "trace_cache_entries": len(trace_cache),
            "max_warmup_tx": args.max_warmup_tx,
            "selected_cases": [j.get("id") or j.get("case_id") for j in todo],
            "fixed_attempted_cases": [j.get("id") for j in attempted],
            "harm_oracle_required_for_cause": True,
            "paper_eligible_only": args.eligible_only,
            "sham_control": args.sham_control,
            "joint_pairs": args.joint_pairs,
            "paper_fixed20": args.paper_fixed20,
            "no_replacement": args.paper_fixed20,
        },
        command=redact_command_args([sys.executable, "-m", "eval.necessity_cli", *argv]),
    )
    print(f"run-id: {run_id}\nmanifest: {manifest_path}")

    # Execution trace analysis and verification
    # Execution trace analysis and verification
    out_rows: list[dict] = list(placeholders)
    if placeholders:
        write_csv(placeholders, path=out_path)
    t0 = time.time()
    for i, j in enumerate(todo, 1):
        case_id = j.get("id") or j.get("case_id") or "?"
        print(f"\n[{i}/{len(todo)}] {case_id} ({j.get('attack_type')})")
        try:
            case = (_pilot_case(case_id, archive, trace_cache, args.trace_mode)
                    or _row_from_corpus(j, archive, trace_cache, args.trace_mode))
            warmup_note = _warmup_guard(case, args.max_warmup_tx)
            if warmup_note:
                print(f"  skip trc fork: {warmup_note}")
                scoring_gt = list(
                    (j.get("_causal_annotation") or {}).get("root_cause_gt")
                    or case.gt_factors or ["unknown"]
                )
                row = _preflight_skip_row(run_id, case, scoring_gt, warmup_note)
                out_rows.append(row)
                write_csv([row], path=out_path)
                continue
            if case.trace is None and args.trace_mode != "cache-only":
                case.trace = _resolve_trace(trace_client, case.tx_hash)
            plan = build_mutation_plan(_planner_view(case), archive,
                                       trace_rpc=trace_client)
            # Deliberately open labels only after the blind planner has returned.
            scoring_gt = list(
                (j.get("_causal_annotation") or {}).get("root_cause_gt") or
                case.gt_factors or ["unknown"]
            )
            if not plan.mutations:
                print(f"  plan empty: {plan.notes}")
            for n in plan.notes:
                print(f"  # note: {n}")
            print(f"  mutations: {[str(m) for m in plan.mutations] or '—'}")
            if not plan.mutations and not args.sham_control and not args.force_baseline:
                print("  (skip -- no applicable mutation; recording placeholder row)")
                row = {
                    "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
                    "paper_eligible": bool(case.extra.get("paper_eligible")),
                    "label_source": case.extra.get("label_source", "legacy_inventory"),
                    "factor_gt": "+".join(scoring_gt) or "unknown",
                    "mutation": "no_mutation", "candidate_factor": "",
                    "outcome": "", "observed": "", "fidelity_pass": "",
                    "execution_preserving": "", "behavior_changed": "",
                    "harm_S": "UNKNOWN", "harm_Sm": "UNKNOWN",
                    "loss_S": "", "loss_Sm": "", "dloss": "",
                    "lmin_usd": "", "valuation_source": "",
                    "control_type": "", "control_pass": "",
                    "verdict": "UNSUPPORTED", "cause": "",
                    "factor_match": "not_scored", "factor_confusion": "not_scored",
                    "note": "; ".join(plan.notes),
                }
                out_rows.append(row)
                write_csv([row], path=out_path)
                continue
            # Execution trace analysis and verification
            n_mutations = len(plan.mutations)
            if n_mutations > 1:
                time.sleep(RPC_SLEEP * n_mutations * 2)
            # Execution trace analysis and verification
            last_err: Exception | None = None
            for attempt in range(1 if args.paper_fixed20 else 2):
                try:
                    case_rows = run_necessity(case, plan.mutations, rpc=rpc, archive=archive,
                                             port=args.port, timeout=args.timeout,
                                             run_id=run_id,
                                             include_sham=args.sham_control,
                                             include_joint=args.joint_pairs,
                                             b2_context=args.b2_context)
                    case_rows = score_rows(
                        case_rows, scoring_gt,
                        paper_eligible=bool(case.extra.get("paper_eligible")),
                    )
                    last_err = None
                    break
                except OSError as e:
                    last_err = e
                    print(f"  WARN: OSError attempt {attempt+1}: {e} — retry...")
                    time.sleep(5)
                except RpcError as e:
                    if "429" in str(e) or "Too Many" in str(e):
                        last_err = e
                        print(f"  WARN: 429 attempt {attempt+1}: {e} — retry sau 10s...")
                        time.sleep(10)
                    else:
                        raise
            if last_err is not None:
                raise last_err
            out_rows.extend(case_rows)
            for r in case_rows:
                print(f"  {r['mutation']:<12} outcome={r['outcome']:<16} "
                      f"verdict={r['verdict'] or '-':<28} factor_match={r['factor_match']}")
                if args.verbose_errors and r.get("note"):
                    note = r["note"]
                    if "cast:" in note or "transport" in note.lower():
                        print(f"    diagnostic: {note}")
            write_csv(case_rows, path=out_path)
            time.sleep(RPC_SLEEP)
        except Exception as e:  # Verified execution property
            print(f"  ERROR: {e}")
            row = {
                "run_id": run_id, "planner": "blind-v2", "case": case_id,
                "paper_eligible": bool(j.get("_causal_annotation")),
                "label_source": ("causal_sidecar_v2" if j.get("_causal_annotation")
                                 else "legacy_inventory"),
                "factor_gt": "+".join(
                    (j.get("_causal_annotation") or {}).get("root_cause_gt") or
                    ["unknown"]),
                "mutation": "preflight_skip", "candidate_factor": "", "outcome": "UNOBSERVED",
                "observed": False, "fidelity_pass": False,
                "execution_preserving": False, "behavior_changed": False,
                "harm_S": "UNKNOWN", "harm_Sm": "UNKNOWN",
                "loss_S": "", "loss_Sm": "", "dloss": "",
                "lmin_usd": "", "valuation_source": "",
                "control_type": "", "control_pass": "",
                "verdict": "INCONCLUSIVE-transport", "cause": "", "factor_match": "not_scored",
                "factor_confusion": "not_scored",
                "note": f"exception: {type(e).__name__}: {e}",
            }
            out_rows.append(row)
            write_csv([row], path=out_path)

    out_path = write_csv(out_rows, path=out_path)
    persisted_rows = load_results(out_path)
    agg = _aggregate(persisted_rows)
    summary_path = out_path.with_name("e4_summary.json")
    summary_path.write_text(json.dumps(agg, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8", newline="\n")
    sensitivity = analyze_sensitivity(persisted_rows)
    sensitivity_path = out_path.with_name("e4_sensitivity.json")
    sensitivity_path.write_text(
        json.dumps(sensitivity, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    graph_path = out_path.with_name("e4_evidence_graph.json")
    graph_path.write_text(
        json.dumps(build_evidence_graph(persisted_rows), indent=2,
                   ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"\n== Done. CSV: {out_path} ({len(out_rows)} rows) trong {time.time() - t0:.0f}s ==")
    print(f"factor-match (scored only): {agg['factor_match']} "
          f"({agg['factor_match_rate']:.1%}) | necessity coverage: "
          f"{agg['necessity_coverage']:.1%} | true revert-rate: "
          f"{agg['revert_rate']:.1%} | transport-error: "
          f"{agg['transport_error_rate']:.1%} | rows={agg['n']}")
    case_d = agg["case_denominators"]
    intervention_d = agg["intervention_denominators"]
    print("case denominator chain: " + " -> ".join(
        f"{name}={case_d[name]}" for name in (
            "attempted", "eligible", "observed", "execution_preserved",
            "intervention_valid", "harm_measured", "scored")
    ))
    print("intervention chain: " + " -> ".join(
        f"{name}={intervention_d[name]}" for name in (
            "attempted", "observed", "execution_preserved",
            "intervention_valid", "harm_measured", "scored")
    ))
    print(f"confusion: {agg['confusion']} | inconclusive: {agg['inconclusive_reasons']}")
    print(f"controls: {agg['controls']} | sensitivity: {sensitivity_path} | "
          f"graph: {graph_path}")
    print(f"joint interventions: {agg['joint_interventions']}")
    for m, d in sorted(agg["by_mutation"].items()):
        print(f"  {m:<12} n={d['n']} revert={d['revert']} cause={d['cause']}")

    if args.json_out:
        print(json.dumps({"rows": out_rows, "summary": agg}, ensure_ascii=False, indent=1))
    return 0


from eval.e4.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
