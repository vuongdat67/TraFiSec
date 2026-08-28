# TraFiSec: API Reference

## 1. Core Python Module (`core`)

### `core.replay.Replayer`
High-performance Ethereum transaction replayer using direct Anvil JSON-RPC with `--auto-impersonate`.

```python
from core.replay import Replayer

replayer = Replayer(rpc_url="http://127.0.0.1:8545")
receipt = replayer.replay_transaction(tx_hash="0x...", warmup_txs=["0x...", "0x..."])
print(receipt.status, receipt.gas_used)
```

### `core.mutate.MutationPlan`
Defines counterfactual interventions applied to local fork state prior to replaying the target transaction.

- `FlashLoanSuppression(provider_address)`: Intercepts and zeroes flash-borrow returns.
- `OraclePinning(oracle_address, price_slot_value)`: Overwrites price feed storage slots.
- `SwapSlicing(ratio=0.75)`: Scales slippage parameters in top-level calldata.
- `ProxyAdminRevocation(proxy_address)`: Clears EIP-1967 admin storage slot.

### `core.outcome.OutcomeGuard`
Formal outcome classifier enforcing validity and harm reduction contracts.

```python
from core.outcome import classify_outcome, Verdict

verdict = classify_outcome(
    baseline_loss=1_500_000,
    mutated_loss=0,
    reverted=False,
    l_min=100_000
)
assert verdict == Verdict.CAUSE
```

---

## 2. Evaluation CLI Suite (`eval`)

### Multi-View Screener (`eval.e1_cli`)
```bash
python -m eval.e1_cli [--mode stratified | chronological | leave_one_family_out] [--include-near-negatives]
```

### State Fidelity Verification (`eval.fidelity_cli`)
```bash
python -m eval.fidelity_cli --dataset corpus/incidents.jsonl
```

### Causal Necessity Verification (`eval.necessity_cli`)
```bash
python -m eval.necessity_cli --case cream --lmin 100000
```

### Pilot Replay Harness (`pilot/run_case.py`)
```bash
python pilot/run_case.py --case <cream|euler|wazirx|bzx|radiant|arbitrage>
```

---

## 3. Go EVM Replay Engine (`tools/geth-replay`)

Direct bytecode replayer utilizing `go-ethereum` core EVM.

```bash
cd tools/geth-replay
./geth-replay -trace <path_to_prestate_trace.json> -verify-proofs
```
- **Inputs:** `prestateTracer` snapshot containing storage slots, balances, nonces, and bytecodes.
- **Outputs:** Gas consumed, execution receipt status, Merkle state trie proof verification.
