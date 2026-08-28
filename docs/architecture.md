# TraFiSec: System Architecture Specification

## 1. Architectural Philosophy

TraFiSec addresses the fundamental tension in blockchain security operations: **throughput vs. causal veracity**.
- High-throughput ingestion requires sub-millisecond screening over block streams.
- Accurate incident verification requires stateful EVM replay and causal intervention.

TraFiSec resolves this via a pipelined, two-stage architecture:

```
+-----------------------------------------------------------------------+
|                       Stage 1: Multi-View Screening                   |
|                                                                       |
|  [Block Trace] --->  Call Structure View (v_call)                     |
|                --->  Token Flow View (v_token)    ---> [Fusion & Cal.]|
|                --->  Economic Action View (v_econ)                    |
+-----------------------------------------------------------------------+
                                   |
                             (Candidate Tx)
                                   v
+-----------------------------------------------------------------------+
|                    Stage 2: Counterfactual Replay                     |
|                                                                       |
|  [Archive RPC] --->  Anvil Local Fork at (b-1)                        |
|                --->  Prefix Warm-up (0..k-1)                          |
|                --->  Mutation Injection (f_fl, f_orc, f_swap, f_auth) |
|                --->  Outcome Guard Classification (CAUSE / REVERT)    |
+-----------------------------------------------------------------------+
```

---

## 2. Stage 1: Feature Views

### 2.1. Call Structure View ($\mathbf{v}_{\text{call}} \in \mathbb{R}^{d_1}$)
Captures execution tree topology:
- Maximum call depth
- Branching fan-out factor
- Delegatecall frequency and delegate-to-call ratio
- Number of distinct contract interfaces invoked

### 2.2. Token Flow View ($\mathbf{v}_{\text{token}} \in \mathbb{R}^{d_2}$)
Captures value movement across tokens:
- ERC-20 Transfer event topology
- Balance volatility across involved addresses
- Cycle detection in transfer directed graphs
- Terminal fund sink identification

### 2.3. Economic Action View ($\mathbf{v}_{\text{econ}} \in \mathbb{R}^{d_3}$)
Captures DeFi interaction primitives:
- Uncollateralized flash loan borrows / mints
- Oracle storage slot reads and price feed queries
- Multi-hop decentralized exchange (DEX) swaps
- Proxy administration and ownership transfers

---

## 3. Stage 2: Intervention Primitives

1. **Flash Loan Suppression ($f_{\text{fl}}$):** Suppresses execution callbacks from lending pools or zeroes returned liquidity.
2. **Oracle Pinning ($f_{\text{orc}}$):** Overwrites price storage slots with pre-manipulation values.
3. **Swap Slicing ($f_{\text{swap}}$):** Parameterizes calldata amounts and slippage limits to test price impact dependence.
4. **Proxy Revocation ($f_{\text{auth}}$):** Modifies EIP-1967 admin slots to revoke unauthorized administrative control.
5. **Health Check Injection ($f_{\text{health\_check}}$):** Restores protocol invariant checks at critical state transition boundaries.

---

## 4. Formal Outcome Taxonomy

$$\Omega(T_x') =
\begin{cases}
\text{CAUSE}, & \text{if Execution OK} \land \mathcal{L}(T_x', \mathcal{S}') \le L_{\text{min}} \\
\text{NO\_EFFECT}, & \text{if Execution OK} \land \mathcal{L}(T_x', \mathcal{S}') > L_{\text{min}} \\
\text{REVERT}, & \text{if EVM Reverts} \\
\text{UNOBSERVED}, & \text{if Transport / RPC Timeout}
\end{cases}$$

- $L_{\text{min}} = \$100{,}000$ (preregistered victim harm threshold).
- An EVM revert is formally treated as a necessary precondition, not a confirmed causal factor.
