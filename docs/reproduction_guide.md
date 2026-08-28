# TraFiSec: Experimental Reproduction Guide

This guide details the step-by-step procedure to reproduce the empirical evaluation (E1 through E6) reported in the paper.

---

## 1. Environment Setup

```bash
# 1. Clone repository
git clone https://github.com/your-org/TraFiSec.git
cd TraFiSec

# 2. Virtual environment setup
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Configure RPC keys in .env
cp .env.example .env
```

---

## 2. Research Questions and CLI Commands

### RQ1: Multi-View Screening on Standard Traffic (E1)
Evaluates the temperature-calibrated logistic screener on the fixed 60/20 incident stratified split:
```bash
python -m eval.e1_cli --mode stratified
```
- **Key Metrics:** AUPRC = 0.641, Recall = 0.500, Precision = 0.667, Realized FPR = 0.74% (at $\tau_{0.01} = 0.0898$).

### RQ2: Generalization under Distribution Shifts (E2)
Evaluates chronological holdout and leave-one-family-out cross-validation:
```bash
python -m eval.e1_cli --mode chronological
python -m eval.e1_cli --mode leave_one_family_out
```

### RQ3: Structural Near-Negatives (E3)
Tests screener vulnerability to complex benign arbitrage and liquidation traffic:
```bash
python -m eval.e1_cli --include-near-negatives
```
- **Key Finding:** AUPRC drops to 0.557, FPR increases 22x to 16.77%.

### RQ4: View Ablation Study (E2-Ablation)
Ablates individual behavioral views to measure feature contribution:
```bash
python -m eval.e2_ablation
```

### RQ5: Validity-Aware Replay Mechanics (E4/E5)
Replays verified incidents under counterfactual mutations on local Anvil forks:
```bash
# Replay fidelity benchmarking
python -m eval.fidelity_cli --dataset corpus/incidents.jsonl

# Necessity attribution on pilot incidents
python -m eval.necessity_cli --case cream
python -m eval.necessity_cli --case euler

# Pilot cross-platform case runner
python pilot/run_case.py --case cream
python pilot/run_case.py --case euler
python pilot/run_case.py --case wazirx
python pilot/run_case.py --case arbitrage
```

---

## 3. Building Documents

```bash
# Compile IEEE RIVF 2026 paper (6 pages)
cd paper
python build_paper.py

# Compile UIT graduation thesis (Vietnamese)
cd ../report
python build_report.py
```
