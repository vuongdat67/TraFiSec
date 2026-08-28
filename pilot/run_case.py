#!/usr/bin/env python3
"""
TraFiSec Pilot Cases Runner (Pure Python)
Executes localized counterfactual replay for historical DeFi case studies on local Anvil forks.
"""

import argparse
import sys
from pathlib import Path

# Add repo root to path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from core.run_case import main as run_case_main

PILOT_CONFIGS = {
    "bzx": [
        "--case", "bzx_feb2020",
        "--tx", "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838",
        "--block", "9484688",
        "--state-block", "9484687",
        "--protocol", "bZx (Feb 2020)",
        "--attack", "dYdX flash loan + Compound collateral + Fulcrum/Kyber price manipulation",
        "--chain", "mainnet",
        "--mutation", "f_fl:0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e",
        "--mutation", "control_sham",
        "--victim", "fulcrum_iETH_pool:0x77f973fcaf871459aa58cd81881ce453759281bc:ETH",
        "--profit-holder", "attacker_eoa:0x148426fdc4c8a51b96b4bed827907b5fa6491ad0:ETH,WETH,WBTC",
        "--profit-holder", "attack_contract:0x4f4e0f2cb72e718fc0433222768c57e823162152:ETH,WETH,WBTC",
    ],
    "cream": [
        "--case", "cream_aug2021",
        "--tx", "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
        "--block", "13128357",
        "--state-block", "13128356",
        "--protocol", "Cream Finance (Aug 2021)",
        "--attack", "AMP reentrancy price oracle manipulation",
        "--chain", "mainnet",
        "--mutation", "f_fl:0x220bda5c8994804ea973bfe4c424a1cc0a5c43d8",
        "--mutation", "f_swap:0x220bda5c8994804ea973bfe4c424a1cc0a5c43d8",
        "--mutation", "control_sham",
        "--victim", "crAMP_market:0x27807dDD9a35160b501B029f84a75b14e13967FF:AMP",
    ],
    "euler": [
        "--case", "euler_mar2023",
        "--tx", "0xc310a0affe2169d9f6feec1c638f21c72f93365057a1272b419c230fa7dbdcf8",
        "--block", "16817996",
        "--state-block", "16817995",
        "--protocol", "Euler Finance (Mar 2023)",
        "--attack", "Donate-to-inflate uncollateralized borrow",
        "--chain", "mainnet",
        "--mutation", "f_fl:0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",
        "--mutation", "control_sham",
        "--victim", "eDAI_vault:0xe025e363087f317584005fad6d4ce14e0fdb8bad:DAI",
    ],
    "wazirx": [
        "--case", "wazirx_jul2024",
        "--tx", "0x535ec8a6cf544719e7a835b62b772c5443216bb6517a9c8b74667dcf49a0a030",
        "--block", "20330456",
        "--state-block", "20330455",
        "--protocol", "WazirX Multisig (Jul 2024)",
        "--attack", "Off-chain key compromise with malicious Safe implementation payload",
        "--chain", "mainnet",
        "--mutation", "f_auth:0x27fd43babfbe83a81d14665b1a6fb8030a60c9b4",
        "--mutation", "control_sham",
        "--victim", "wazirx_safe:0x27fd43babfbe83a81d14665b1a6fb8030a60c9b4:ETH,USDT",
    ],
    "arbitrage": [
        "--case", "arbitrage_jun2023",
        "--tx", "0x448a3e7a0a6d0c153724c9eb55b6ef72e09886a04e57e937d5718a287c800b46",
        "--block", "17478000",
        "--state-block", "17477999",
        "--protocol", "Multi-DEX Arbitrage (Hard Negative Control)",
        "--attack", "Benign flash arbitrage with cyclic token routing",
        "--chain", "mainnet",
        "--mutation", "f_fl:0x0000000000000000000000000000000000000000",
        "--mutation", "control_sham",
        "--victim", "none:0x0000000000000000000000000000000000000000:ETH",
    ]
}

def main():
    parser = argparse.ArgumentParser(description="Run TraFiSec pilot counterfactual replay cases.")
    parser.add_argument("case", choices=list(PILOT_CONFIGS.keys()) + ["all"], help="Pilot case to execute")
    parser.add_argument("--offline", action="store_true", help="Use local cache without querying live RPC")
    args = parser.parse_args()

    cases_to_run = list(PILOT_CONFIGS.keys()) if args.case == "all" else [args.case]

    for c in cases_to_run:
        print(f"\n==================================================")
        print(f" Executing Pilot Case: {c.upper()}")
        print(f"==================================================")
        cmd_args = PILOT_CONFIGS[c].copy()
        if args.offline:
            cmd_args.append("--offline")
        out_dir = str(Path(__file__).resolve().parent / f"case_{c}")
        cmd_args.extend(["--out", out_dir])
        
        sys.argv = ["core.run_case"] + cmd_args
        try:
            run_case_main()
        except Exception as e:
            print(f"[ERROR] Case {c} failed with exception: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
