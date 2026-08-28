"""
TraFiSec Pilot CLI -- single case execution runner:
==================================================================================
Automatically loads environment variables from .env (core.env.load_dotenv) — without requiring manual environment exports.

Usage:
  python -m core.run_case --case cream \
      --tx 0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e \
      --block 13125071 --prior 0xcbeb1123... \
      --mutation f_fl:0x21b8065d10f73EE2e260e5B47D3344d3Ced7596E

Mutations — c php "name:arg[,arg]":
  f_fl:<provider>                    suppress flash-loan borrowing at provider address
  f_orc:<oracle>:<stub_bytecode>     pin oracle storage return with stub bytecode
  f_swap:<calldata_override>         override swap calldata with slippage parameter
  f_auth:<proxy>                     zero EIP-1967 admin storage slot
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .env import load_dotenv, resolve_rpc
from .mutate import (AuthRevoke, FlashLoanDisable, OraclePin,
                     ShamStorageWrite, SwapSlice)
from .outcome import Outcome
from .runner import CaseConfig, CaseRunner, summarize


def _parse_mutation(spec: str, runner=None):
    name, _, args = spec.partition(":")
    parts = [p for p in re.split(r"[,:]", args) if p] if args else []
    if name == "f_fl":
        if not parts or not parts[0]:
            raise SystemExit("f_fl requires provider address: f_fl:0xADDR")
        return FlashLoanDisable(parts[0])
    if name == "f_orc":
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise SystemExit("f_orc cn oracle + stub bytecode: f_orc:0xORACLE:0xSTUB")
        return OraclePin(parts[0], parts[1])
    if name == "f_swap":
        if not parts or not parts[0]:
            raise SystemExit("f_swap cn: f_swap:0xCALldata (override) hoc f_swap:CAP (cap word2)")
        if parts[0].startswith("0x"):
            # Execution trace analysis and verification
            return SwapSlice(parts[0])
        # Execution trace analysis and verification
        return SwapSlice(start_cap=int(parts[0], 0) if parts[0] else 0)
    if name == "f_auth":
        if not parts or not parts[0]:
            raise SystemExit("f_auth requires proxy address: f_auth:0xPROXY")
        return AuthRevoke(parts[0])
    if name == "control_sham":
        return ShamStorageWrite()
    raise SystemExit(f"Unknown mutation: {name!r} (supported: f_fl, f_orc, f_swap, f_auth)")


def _ensure_utf8() -> None:
    """Ensure UTF-8 standard stream encoding on Windows console."""
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    _ensure_utf8()
    load_dotenv()  # Verified execution property

    parser = argparse.ArgumentParser(description="TraceGuard pilot case runner (OOP)")
    parser.add_argument("--case", required=True)
    parser.add_argument("--tx", required=True, help="tx hash attack (verify ngun trc!)")
    parser.add_argument("--block", type=int, required=True, help="tx block")
    parser.add_argument("--state-block", type=int, default=None,
                        help="fork block (mc nh tx_block−1)")
    parser.add_argument("--prior", action="append", default=[],
                        help="mt tx prior; lp --prior cho tng warm-up tx")
    parser.add_argument("--mutation", action="append", default=[],
                        help="f_fl:ADDR / f_orc:ADDR:STUB / f_swap:CALldata / f_auth:PROXY")
    parser.add_argument("--victim", action="append", default=[],
                        help="label:address:ASSET[,ASSET] (snapshot inside fork)")
    parser.add_argument("--attacker", default=None,
                        help="attacker address for separate native-ETH profit delta")
    parser.add_argument("--profit-holder", action="append", default=[],
                        help="label:address:ETH[,WETH,WBTC] for separate profit ledger")
    parser.add_argument("--protocol", default="")
    parser.add_argument("--attack", default="")
    parser.add_argument("--chain", default="mainnet")
    parser.add_argument("--rpc", default=None, help="archive RPC (mc nh .env)")
    parser.add_argument("--out", default=None, help="th mc output (mc nh pilot/case_<name>)")
    parser.add_argument("--no-fidelity-gas", action="store_true",
                        help="Skip mainnet gas comparison")
    parser.add_argument("--cache-dir", default=None,
                        help="th mc cache metadata RPC ca case")
    parser.add_argument("--offline", action="store_true",
                        help="ch dng cache local; cache miss s dng")
    args = parser.parse_args(argv)

    rpc = args.rpc or resolve_rpc(args.chain)
    if not rpc:
        raise SystemExit("Cn archive RPC cho block metadata: --rpc hoc ARCHIVE_RPC/ALCHEMY_API_KEY")

    cache_dir = (args.cache_dir or
                 str(Path(__file__).parents[2] / ".cache" / "cases" /
                     f"{args.case}-block-{args.state_block or args.block - 1}"))
    victims = []
    for spec in args.victim:
        fields = spec.split(":", 2)
        if len(fields) != 3 or not fields[0] or not fields[1].startswith("0x"):
            raise SystemExit("--victim cn label:0xADDRESS:ETH[,WBTC]")
        victims.append({"label": fields[0], "address": fields[1],
                        "assets": [x for x in fields[2].split(",") if x]})
    profit_holders = []
    for spec in args.profit_holder:
        fields = spec.split(":", 2)
        if len(fields) != 3 or not fields[0] or not fields[1].startswith("0x"):
            raise SystemExit("--profit-holder cn label:0xADDRESS:ETH[,WETH,WBTC]")
        profit_holders.append({"label": fields[0], "address": fields[1],
                               "assets": [x for x in fields[2].split(",") if x]})
    cfg = CaseConfig(name=args.case, tx_hash=args.tx, tx_block=args.block,
                     state_block=args.state_block, prior_txs=list(args.prior),
                     protocol=args.protocol, attack_type=args.attack, chain=args.chain,
                     victims=victims,
                     attacker_address=args.attacker,
                     profit_holders=profit_holders,
                     cache_dir=cache_dir,
                     offline=args.offline)
    runner = CaseRunner(cfg, rpc, out_dir=args.out,
                        cache_dir=cache_dir, offline=args.offline)

    print(f"== {cfg.protocol or cfg.name} ({cfg.attack_type}) "
          f"tx_block={cfg.tx_block} state_block={cfg.state_block}")
    fid = runner.run_fidelity(verify_gas=not args.no_fidelity_gas)
    print(f"fidelity: {fid.outcome.value} {fid.note}")
    if not fid.fidelity_pass() and not args.no_fidelity_gas:
        print("⚠  FIDELITY FAIL -- baseline execution mismatch; executing mutations for diagnosis.")
    if fid.fidelity_pass():
        print(f"  fidelity PASS (gas Δ{fid.gas_delta_pct:+.1f}%)")

    mutations = [_parse_mutation(m, runner) for m in args.mutation]
    results = runner.run_mutations(mutations)
    print(summarize(results))
    print(f"== Done. outcomes: {runner.outcomes_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
