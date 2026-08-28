"""
TraFiSec -- Evaluation package: E1-E7 experimental pipelines
============================================================
Implements reproducible evaluation experiments for DeFi incident screening
and validity-aware counterfactual replay.

Modules:
  - `eval.fidelity` / `eval.fidelity_cli`: E5 Replay Fidelity benchmark
  - `eval.necessity` / `eval.necessity_cli`: E4 Counterfactual Necessity benchmark
  - `eval.e1_train` / `eval.e1_baselines`: E1 Multi-view screener training and baseline comparisons
  - `eval.e2_ablation`: E2 Feature view ablation study
  - `eval.hard_negative_evaluation`: E3 Structural near-negative stress testing
  - `eval.e6_latency`: E6 Runtime profiling and throughput evaluation

General Conventions:
  - All replays run on a local Anvil fork; never broadcast transactions to mainnet.
  - Archive RPC endpoints are loaded strictly from .env and never committed.
  - Distinct experiments bind isolated local ports (8545 pilot / 8546 E5 / 8547 E4).
"""
from __future__ import annotations
