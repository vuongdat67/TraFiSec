# TraFiSec (TraceGuard-DeFi)

**TraceGuard-DeFi (TraFiSec)** is an automated two-stage framework for decentralized finance (DeFi) security incident triage, combining multi-view transaction screening with validity-aware counterfactual replay on local Ethereum archive forks.

---

## Overview

DeFi protocols compose autonomous smart contracts that lock tens of billions of dollars in on-chain value. While composability enables protocol innovation, it also creates an inherent **shape ambiguity problem**: benign high-frequency market interactions (such as multi-DEX arbitrage, liquidations, and collateral rebalancing) exhibit structural execution signatures identical to malicious attacks (deep invocation trees, uncollateralized flash loans, and large price dislocations).

TraFiSec resolves this ambiguity via a sequential two-stage architecture:
1. **Stage 1 (Calibrated Multi-View Screener):** Extracts complementary behavioral views (Call Structure, Token Flow, and Economic Actions) from raw execution traces and scores candidates using a temperature-calibrated logistic model under strict false positive rate (FPR) budgets.
2. **Stage 2 (Validity-Aware Counterfactual Replay):** Forks Ethereum Mainnet at the pre-incident block state ($b-1$) and executes blind counterfactual mutations (flash loan suppression, oracle pinning, calldata slicing, and authority revocation). A formal **Outcome Guard** separates confirmed causal factors from inconclusive reverts and execution preconditions, preventing false attribution.

---

## System Architecture

```
[Ethereum Block Stream]
         │
         ▼
[Stage 1: Multi-View Feature Extraction]
  ├── Call Structure View (v_call): Invocations, depth, fan-out, delegatecalls
  ├── Token Flow View (v_token): ERC-20 transfer graphs, cyclic routing, sinks
  └── Economic Action View (v_econ): Flash borrowing, oracle reads, DEX swaps
         │
         ▼
[Calibrated Logistic Screener (Platt Scaling)]
  └── Frozen Operating Threshold (tau_0.01 = 0.0898 @ 1% FPR budget)
         │ (Candidates only)
         ▼
[Stage 2: Deterministic Local Fork Replay (Anvil / B2)]
  └── Reproduce exact pre-state at block b-1 via transaction warm-up (0..k-1)
         │
         ▼
[Blind Counterfactual Interventions]
  ├── f_fl:   Flash Loan Suppression
  ├── f_orc:  Oracle Storage Pinning
  ├── f_swap: Parameterized Slippage Slicing
  └── f_auth: Proxy Admin Revocation
         │
         ▼
[Validity and Outcome Guard]
  ├── CAUSE:       Tx succeeds (OK) and Net Victim Loss <= L_min ($100,000)
  ├── NO_EFFECT:   Tx succeeds (OK) and Net Victim Loss > L_min
  ├── REVERT:      EVM Reversion (Inconclusive precondition / invalid mutation)
  └── UNOBSERVED:  Transport Timeout / RPC Unavailable
```

---

## Benchmark Corpus

The evaluation benchmark contains **4,308 Ethereum transaction traces** across three strata:
- **Verified Exploits ($n = 80$):** High-impact DeFi exploits (2024--2026) spanning eight attack families (governance bypass, accounting errors, oracle manipulation, token logic, flash loans, precision loss, rug pulls, and bridge exploits).
- **Background Negatives ($n = 3,381$):** Temporally co-located transactions sampled from the same incident blocks.
- **Structural Near-Negatives ($n = 847$):** Hard benign transactions (MEV arbitrageurs and liquidation bots) mined via selector complexity rules.

---

## Repository Structure

```
TraFiSec/
├── core/                 # Core execution engine (fork, replay, mutate, outcome)
│   ├── env.py            # Environment & RPC provider resolution
│   ├── fork.py           # Anvil local fork lifecycle management
│   ├── fusion.py         # Multi-view feature fusion & calibration
│   ├── invariants.py     # Execution invariant checkers
│   ├── loss.py           # Loss & profit accounting engine
│   ├── mutate.py         # Mutation primitives (f_fl, f_orc, f_swap, f_auth)
│   ├── outcome.py        # Formal outcome taxonomy and outcome guard
│   ├── replay.py         # JSON-RPC transaction replayer with auto-impersonation
│   ├── rpc.py            # JSON-RPC client with structured EVM error handling
│   ├── run_case.py       # Single incident replay harness
│   ├── runner.py         # Batch execution manager
│   ├── screener.py       # Stage 1 screening pipeline
│   ├── trace.py          # Parity trace parser & call tree builder
│   └── views.py          # Multi-view behavioral feature extractors
├── eval/                 # Scientific evaluation suite (E1 to E6)
│   ├── e1_train.py       # Feature extraction & screener training
│   ├── e2_ablation.py    # Multi-view feature ablation experiments
│   ├── e4/               # E4 Causal necessity planning & execution
│   ├── e6_latency.py     # E6 Pipeline latency benchmarks
│   ├── fidelity.py       # E5 Execution and state fidelity benchmarking
│   ├── fidelity_cli.py   # CLI for fidelity validation
│   ├── necessity.py      # E4 Counterfactual necessity analysis
│   └── plots/            # Publication-quality matplotlib figure generators
├── corpus/               # Audited incident benchmark dataset
│   ├── dataset.py        # Dataset loader and integrity verifier
│   ├── incidents.jsonl   # 80 verified Ethereum exploit incidents
│   ├── background.jsonl  # 3,381 background negative transactions
│   └── hard_negatives.jsonl # 847 structural near-negative transactions
├── pilot/                # Detailed case study runners and doc specifications
│   ├── run_case.py       # Unified cross-platform case study CLI
│   └── docs/             # Technical incident breakdowns
├── tools/                # Diagnostic scripts and Geth-EVM replayer
│   └── geth-replay/      # Go-Ethereum replayer with state proof verification
├── tests/                # 6 consolidated pytest test suites (196 tests)
├── paper/                # IEEE RIVF 2026 manuscript source and build script
├── report/               # Undergraduate graduation thesis report (UIT format)
└── docs/                 # Formal architecture and reproduction specifications
```

---

## Getting Started

### Prerequisites
- **Python:** $\ge 3.10$
- **Foundry (Anvil):** $\ge 1.7.0$ (for local Ethereum state forking)
- **Ethereum Archive RPC:** Alchemy Growth or QuickNode Archive access with `debug_traceTransaction` support.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vuongdat67/TraFiSec.git
   cd TraFiSec
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Linux/macOS:
   source .venv/bin/activate
   # Windows:
   .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your archive RPC keys
   ```

---

## Reproducing Empirical Results

### E1: Standard Screening Evaluation
Train and evaluate the calibrated multi-view screener:
```bash
python -m eval.e1_cli --mode stratified
```
- **Reference Output:** AUPRC = 0.641, Recall = 0.500, Precision = 0.667, Realized FPR = 0.74% (at targeted 1% FPR budget $\tau_{0.01} = 0.0898$).

### E2: Structural Near-Negative Exposure (Hard MEV / Arbitrage)
Evaluate screener degradation against complex arbitrage and liquidation traffic:
```bash
python -m eval.e1_cli --include-near-negatives
```
- **Reference Output:** AUPRC drops to 0.557, Realized FPR inflates 22x to 16.77%.

### E4 & E5: Replay Fidelity and Causal Verification
Run the deterministic replay and state fidelity verification suite:
```bash
python -m eval.fidelity_cli --dataset corpus/incidents.jsonl
python -m eval.necessity_cli --case cream
```

### Pilot Incident Case Studies
Execute individual pilot incident case studies on local Anvil forks:
```bash
python pilot/run_case.py --case cream
python pilot/run_case.py --case euler
python pilot/run_case.py --case arbitrage
```

### Running Test Suite
Execute the consolidated pytest suite (196 tests):
```bash
python -m pytest tests/
```

---

## Building the Manuscripts

### Scientific Paper (IEEE RIVF 2026 Format, 6 Pages)
```bash
cd paper
python build_paper.py
```
- Outputs `paper/main.pdf` (6 pages, IEEEtran format). Intermediate auxiliary files are isolated in `paper/ex/`.

### Graduation Thesis (UIT Report Format, Vietnamese)
```bash
cd report
python build_report.py
```
- Outputs `report/main.pdf`.

---

## Citation

If you find this work useful in your research, please cite:

```bibtex
@inproceedings{vuong2026traceguard,
  author    = {Thanh-Dat Vuong and Ba-Quan Nguyen and Tuan-Dung Tran},
  title     = {{TraceGuard-DeFi: Validity-Aware Screening and Counterfactual Replay for DeFi Security Incident Triage}},
  booktitle = {Proceedings of the 20th International Conference on Computing and Communication Technologies (RIVF)},
  year      = {2026}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
