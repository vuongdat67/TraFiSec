"""
TraFiSec — E5 Replay Fidelity CLI
==========================================
Replay n attack tx t corpus ln anvil fork (port 8546) ti block ng, o
execution-level fidelity (status+gas vs mainnet, Δ≤10%=PASS) + state-delta
cell-match (prestateTracer diffMode). Ghi eval/results/e5_fidelity.csv.

Usage:
  python -m eval.fidelity_cli --n 20 --limit 5     # Verified execution property
  python -m eval.fidelity_cli --n 20               # full 20 tx
  python -m eval.fidelity_cli --n 20 --seed 7      # Verified execution property
  python -m eval.fidelity_cli --list               # Verified execution property
  python -m eval.fidelity_cli --limit 1 --rpc-timeout 20 --rpc-attempts 2

Security: Private RPC keys loaded strictly from .env.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .fidelity import (
    CORPUS_DEFAULT,
    FIDELITY_PORT,
    FROZEN_SET_DEFAULT,
    REPO_ROOT,
    RESULTS_DIR,
    RPC_SLEEP,
    load_results,
    load_fidelity_set,
    run_fidelity_case,
    case_manifest,
    select_fidelity_set,
    summarize,
    write_csv,
)
from .e5_preflight import verify_preflight
from core.env import load_dotenv, resolve_rpc
from core.rpc import RpcClient
from .run_manifest import redact_command_args, utc_run_id, write_manifest


def _ensure_utf8() -> None:
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and "utf" not in sys.stderr.encoding.lower():
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _print_set(cases, meta) -> None:
    print(f"\n== E5 set ({len(cases)} cases t {meta.get('total_onchain', 0)} onchain) ==")
    print(f"type dist corpus : {json.dumps(meta.get('type_dist', {}), ensure_ascii=False)}")
    for c in cases:
        print(f"  {c.case_id:<34} type={c.attack_type:<16} k={c.tx_index} "
              f"block={c.block} gas={c.mainnet_gas} | {c.reason}")
    for r in meta.get("reasons", []):
        print(f"  # {r}")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    _ensure_utf8()
    load_dotenv()

    parser = argparse.ArgumentParser(description="E5 Replay Fidelity runner")
    parser.add_argument("--n", type=int, default=20, help="Number of attack cases in evaluation set")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of cases to execute (0 = all selected)")
    parser.add_argument("--cases", default="",
                        help="comma-separated case IDs from the fixed set")
    parser.add_argument("--resume", action="store_true",
                        help="Resume run matching --run-id")
    parser.add_argument("--run-id", default=None, help="Unique run ID; auto-generated if omitted")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    parser.add_argument("--set-file", type=Path, default=FROZEN_SET_DEFAULT,
                        help="fixed JSON case set (default: eval/fidelity_set_v2.json)")
    parser.add_argument("--resample", action="store_true",
                        help="reselect cases from corpus through RPC instead of fixed set")
    parser.add_argument("--list", action="store_true",
                        help="List selected cases and exit without executing replay")
    parser.add_argument("--no-state", action="store_true",
                        help="Evaluate execution-level fidelity only (skip state-delta comparison)")
    parser.add_argument("--rpc", default=None, help="Archive RPC endpoint (default from .env)")
    parser.add_argument("--fork-rpc", default=None,
                        help="optional read-only RPC used by Anvil lazy state fetches; tracer RPC remains --rpc")
    parser.add_argument("--port", type=int, default=FIDELITY_PORT,
                        help=f"Local Anvil fork port (default: {FIDELITY_PORT})")
    parser.add_argument("--timeout", type=int, default=480,
                        help="Replay execution timeout in seconds")
    parser.add_argument("--mine-timeout", type=float, default=30.0,
                        help="Dedicated timeout for anvil_mine in seconds")
    parser.add_argument("--rpc-timeout", type=float, default=20.0,
                        help="Timeout per archive JSON-RPC request in seconds")
    parser.add_argument("--rpc-attempts", type=int, default=2,
                        help="Maximum retry attempts for archive RPC requests")
    parser.add_argument("--corpus", default=None, help="Path to incidents corpus JSONL file")
    parser.add_argument("--out", default=None,
                        help="CSV output path (defaults to eval/results/runs/<run-id>/e5_fidelity.csv)")
    parser.add_argument("--json-out", action="store_true",
                        help="Print output as JSON records")
    parser.add_argument("--paper-fixed20", action="store_true",
                        help="fail-closed primary fixed-20 mode; forbids partial/resampled/resumed runs")
    parser.add_argument("--preflight-manifest", type=Path, default=None,
                        help="e5_preflight.json from a recent successful k=0 gate")
    parser.add_argument("--preflight-max-age-hours", type=int, default=24)
    args = parser.parse_args(argv)
    if args.resume and not args.run_id:
        parser.error("--resume cn --run-id")
    if args.timeout <= 0:
        parser.error("--timeout phi > 0")
    if args.mine_timeout <= 0:
        parser.error("--mine-timeout phi > 0")
    if args.rpc_timeout <= 0:
        parser.error("--rpc-timeout phi > 0")
    if args.rpc_attempts < 1:
        parser.error("--rpc-attempts phi >= 1")
    if args.preflight_max_age_hours < 1:
        parser.error("--preflight-max-age-hours phi >= 1")
    if args.paper_fixed20:
        forbidden = []
        if args.n != 20:
            forbidden.append("--n must be 20")
        if args.limit:
            forbidden.append("--limit")
        if args.cases:
            forbidden.append("--cases")
        if args.resume:
            forbidden.append("--resume")
        if args.resample:
            forbidden.append("--resample")
        if args.no_state:
            forbidden.append("--no-state")
        if forbidden:
            parser.error("paper fixed-20 forbids: " + ", ".join(forbidden))
        if args.preflight_manifest is None:
            parser.error("--paper-fixed20 requires --preflight-manifest")

    cases, meta = (select_fidelity_set(args.corpus or CORPUS_DEFAULT, n=args.n, seed=args.seed)
                   if args.resample else load_fidelity_set(args.set_file))
    if args.cases:
        requested = {value.strip() for value in args.cases.split(",") if value.strip()}
        cases = [case for case in cases if case.case_id in requested]
        missing = requested - {case.case_id for case in cases}
        if missing:
            parser.error(f"unknown case IDs: {', '.join(sorted(missing))}")
    cases = cases[:args.n]
    _print_set(cases, meta)
    if args.list:
        return 0

    # Fixed-set listing above is intentionally offline. Resolve/create the RPC
    # client only after that early return so a stale or unreachable endpoint can
    # never make ``--list`` hang.
    rpc = args.rpc or resolve_rpc()
    if not rpc:
        raise SystemExit("Cn archive RPC: --rpc hoc ARCHIVE_RPC/ALCHEMY_API_KEY trong .env")
    archive = RpcClient(rpc, timeout=args.rpc_timeout, attempts=args.rpc_attempts)
    fork_rpc = args.fork_rpc or rpc
    run_id = args.run_id or utc_run_id("e5")
    out_path = (Path(args.out) if args.out else
                RESULTS_DIR / "runs" / run_id / "e5_fidelity.csv")
    if args.paper_fixed20:
        if len(cases) != 20:
            parser.error("paper fixed-20 requires exactly 20 frozen cases")
        try:
            preflight_payload = json.loads(
                args.preflight_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"invalid preflight manifest: {exc}")
        errors = verify_preflight(
            preflight_payload, args.set_file, rpc, fork_rpc,
            max_age_hours=args.preflight_max_age_hours,
        )
        if errors:
            parser.error("preflight gate failed: " + ", ".join(errors))
        if out_path.exists():
            parser.error("paper fixed-20 output already exists; use a new run-id")
    if not cases:
        print("\nNo cases could be resolved on RPC - stopping.")
        return 1

    limit = args.limit or len(cases)
    todo = cases[:limit]
    if args.resume:
        done = {r.get("case") for r in load_results(out_path)
                if r.get("run_id") == run_id}
        todo = [c for c in todo if c.case_id not in done]
        if len(todo) < limit:
            print(f"\n== Resume: skipping {limit - len(todo)} cases already in CSV ==")
    print(f"\n== Replaying {len(todo)}/{len(cases)} transactions on Anvil port {args.port} "
          f"(rate-limit {RPC_SLEEP}s between transactions) ==")
    if not todo:
        print("\nNo remaining cases to execute (all cases present in CSV).")
        return 0

    manifest_inputs = {"corpus": args.corpus or CORPUS_DEFAULT,
                       "fixed_set": args.set_file}
    if args.preflight_manifest:
        manifest_inputs["preflight"] = args.preflight_manifest
    write_manifest(
        out_path.with_name("manifest.json"), run_id=run_id,
        experiment="E5-replay-fidelity-v2", repository=REPO_ROOT,
        inputs=manifest_inputs,
        parameters={"n": args.n, "limit": args.limit, "seed": args.seed,
                    "cases": args.cases,
                    "replay_timeout_s": args.timeout,
                    "mine_timeout_s": args.mine_timeout,
                    "archive_rpc_timeout_s": args.rpc_timeout,
                    "archive_rpc_attempts": args.rpc_attempts,
                    "state_delta": not args.no_state,
                    "split_archive_and_fork_rpc": bool(args.fork_rpc),
                    "state_target": "prestateTracer.diff.post",
                    "paper_fixed20": args.paper_fixed20,
                    "replacement_policy": "none" if args.paper_fixed20 else "diagnostic"},
        command=redact_command_args([sys.executable, "-m", "eval.fidelity_cli", *argv]),
    )

    rows = []
    t0 = time.time()
    for i, case in enumerate(todo, 1):
        print(f"\n[{i}/{len(todo)}] {case.case_id} ({case.attack_type}) "
              f"k={case.tx_index} block={case.block}")
        case_started = time.monotonic()
        try:
            row = run_fidelity_case(case, fork_rpc, archive, port=args.port,
                                    timeout=args.timeout, state_delta=not args.no_state,
                                    run_id=run_id, mine_timeout=args.mine_timeout)
        except Exception as e:  # Verified execution property
            row = {
                "run_id": run_id, "fidelity_schema": "transaction-local-v2",
                "case": case.case_id, "protocol": case.protocol,
                "attack_type": case.attack_type, "tx_hash": case.tx_hash,
                "block": case.block, "tx_index": case.tx_index, "mutation": "fidelity",
                "outcome": "ERROR", "observed": False, "status": "",
                "gas_used": "", "mainnet_gas": "", "gas_delta_pct": "",
                "execution_pass": False, "state_eligible": False,
                "state_pass": False, "joint_pass": False, "pass": False, "state_cells": 0,
                "state_match": 0.0, "state_errors": 1, "state_mode": "none",
                "failure_reason": "transport_timeout", "case_latency_ms": "",
                "reason": case.reason, "note": f"exception: {e}",
            }
        row["case_latency_ms"] = round((time.monotonic() - case_started) * 1000, 1)
        rows.append(row)
        case_dir = out_path.parent / "cases"
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / f"{case.case_id}.json").write_text(
            json.dumps(case_manifest(row, run_id=run_id, prior_count=case.tx_index),
                       indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8", newline="\n")
        print(f"  -> {row['outcome']:<16} pass={row['pass']} "
              f"gas={row['gas_used']}/{row['mainnet_gas']} Δ={row['gas_delta_pct']}% "
              f"state {row['state_cells']} cells match={row['state_match']:.1%} [{row['state_mode']}]")
        time.sleep(RPC_SLEEP)

    out_path = write_csv(rows, path=out_path)
    summary = summarize(rows)
    summary_path = out_path.with_name("e5_summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8", newline="\n")
    print(f"\n== Completed. CSV: {out_path} ({len(rows)} rows) in "
          f"{time.time() - t0:.0f}s ==")

    if args.json_out:
        print(json.dumps({"rows": rows, "summary": summary}, ensure_ascii=False,
                         indent=1))
        return 0

    _print_summary(summary, len(todo))
    if limit < len(cases):
        print(f"NOTE: executed {limit}/{len(cases)} cases -- run full set with: "
              f"python -m eval.fidelity_cli --n {args.n}")
    return 0


def _print_summary(s: dict, n_run: int) -> None:
    print(f"\n== Summary ({s['attempted']} attempted) ==")
    print(f"  observed               {s['observed']}/{s['attempted']} "
          f"({s['observed_rate']:.1%})")
    print(f"  execution-pass/observed {s['execution_pass']}/{s['observed']} "
          f"({s['execution_pass_rate_observed']:.1%})")
    print(f"  state-pass/eligible     {s['state_pass']}/{s['state_eligible']} "
          f"({s['state_pass_rate']:.1%})")
    print(f"  joint-pass/attempted    {s['joint_pass']}/{s['attempted']} "
          f"({s['joint_pass_rate']:.1%})")
    print(f"  transport={s['transport_errors']} | EVM-revert={s['evm_reverts']}")
    for t, d in sorted(s["by_attack_type"].items()):
        print(f"  {t:<18} {d['pass']}/{d['n']}")
    if s["fails"]:
        print("\nFails:")
        for f in s["fails"]:
            print(f"  - {f['case']:<34} outcome={f['outcome']} Δ={f['gas_delta_pct']}% "
                  f"state={f['state_cells']}c/{f['state_match']:.1%} | {f['note']}")


if __name__ == "__main__":
    raise SystemExit(main())
