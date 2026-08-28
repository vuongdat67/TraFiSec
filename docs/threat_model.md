# TraFiSec: Threat Model and Assumptions

## 1. Operating Environment
TraFiSec operates in an asynchronous, post-incident triage and forensic investigation setting. The primary objective is to analyze transactions flagged from high-throughput block streams or reported in security incident queues.

## 2. Adversary Model
We consider an adversary $\mathcal{A}$ with the following capabilities:
- **Arbitrary Capital Access:** $\mathcal{A}$ can borrow unbounded uncollateralized capital via flash loans or flash mints within a single execution transaction.
- **Cross-Contract Composability:** $\mathcal{A}$ can construct arbitrary call graphs chaining multiple decentralized protocols (lending pools, AMMs, yield aggregators, cross-chain bridges).
- **Public Mempool Visibility:** $\mathcal{A}$ can observe pending transactions and execute atomic front-running, back-running, or sandwich bundles.
- **Contract Deployment:** $\mathcal{A}$ can deploy custom exploiter smart contracts containing arbitrary execution logic and callback hooks.

## 3. Assumptions
1. **EVM Determinism:** Local execution on a faithfully restored pre-state block $b-1$ with transaction index warm-up ($0..k-1$) deterministically reproduces on-chain execution outcomes.
2. **Victim Identifiability:** Victim protocols, affected pool contracts, and token addresses are deterministically resolvable from the transaction trace and receipt event logs.
3. **Price Oracle Determinism:** Spot exchange rates and oracle price feeds used for USD loss valuation are fixed to the historical block timestamp to avoid valuation drift.
4. **Intervention Library Scope:** The four intervention primitives ($f_{\text{fl}}, f_{\text{orc}}, f_{\text{swap}}, f_{\text{auth}}$) cover the dominant vulnerability classes of historical single-transaction DeFi incidents.
