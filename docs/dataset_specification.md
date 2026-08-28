# TraFiSec: Benchmark Dataset Specification

## 1. Dataset Overview

The TraFiSec benchmark corpus consists of **4,308 audited Ethereum transactions** spanning three distinct strata:

| Stratum | Transaction Count | Description | Primary Role |
| :--- | :--- | :--- | :--- |
| **Verified Exploits** | 80 | Historical high-impact DeFi exploit transactions (2024--2026). | Positive ground truth for evaluation. |
| **Background Negatives** | 3,381 | Open-world benign transactions sampled from the same incident blocks. | Standard negative distribution. |
| **Structural Near-Negatives** | 847 | Hard benign transactions (MEV arbitrageurs, liquidation bots, multi-hop DEX swaps). | Stress testing detector discrimination under structural ambiguity. |

---

## 2. Attack Families ($n = 80$)

The verified exploits cover eight dominant DeFi vulnerability families:

1. **Governance & Access Control ($n = 26$):** Unauthorized admin role claims, signature forgery, governance proposal hijacking.
2. **Accounting Errors ($n = 25$):** Precision loss, rounding errors, deposit/withdraw invariant violations, donate-to-inflate accounting bugs.
3. **Oracle Manipulation ($n = 12$):** Spot price manipulation on AMM liquidity pools (Uniswap V2/V3, Curve, Balancer).
4. **Token Logic Hazards ($n = 7$):** Reentrancy in ERC-777 callbacks, burn fee miscalculations, deflationary token bugs.
5. **Flash Loan Misuse ($n = 4$):** Deep atomic leverage without collateral requirements to magnify protocol logic flaws.
6. **Precision Loss ($n = 3$):** Truncation in reward calculations and debt interest accrual.
7. **Rug-Pulls & Exit Scams ($n = 2$):** Malicious developer backdoors and liquidity drains.
8. **Bridge Exploits ($n = 1$):** Cross-chain bridge message verification failures.

---

## 3. Behavioral Feature Views

Each transaction trace is mapped into three lightweight feature views:

### $\mathbf{v}_{\text{call}}$: Call Structure View
- `max_depth`: Maximum call tree invocation depth.
- `fan_out`: Maximum child invocations from a single frame.
- `delegatecall_count`: Number of `DELEGATECALL` opcodes executed.
- `distinct_interfaces`: Count of distinct contract interfaces invoked.

### $\mathbf{v}_{\text{token}}$: Token Flow View
- `erc20_transfers`: Number of ERC-20 Transfer events emitted.
- `balance_volatility`: Ratio of gross token movement to net wallet delta.
- `cycle_detected`: Boolean flag indicating cyclic token transfer routes.
- `terminal_sinks`: Count of terminal addresses absorbing net token balances.

### $\mathbf{v}_{\text{econ}}$: Economic Action View
- `flash_loan_invocations`: Detected flash loan borrow/mint function selectors.
- `oracle_reads`: Static calls and state reads to known price feeds.
- `swap_hops`: Multi-hop decentralized exchange swap calls.
- `admin_calls`: Proxy upgrade or administrative ownership calls.
