# Case 1 — bZx (Feb 2020): flash-loan price manipulation

## Historical target

- **Chain:** Ethereum mainnet.
- **Target block:** `9484688`.
- **State block:** `9484687`.
- **Transaction:** `0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838`.
- **Transaction index:** `28/79`; replay requires **28 warm-up transactions**.
- **Mainnet status/gas:** success, `3,109,043` gas (`gasUsed=0x2f70b3`).
- **Attack shape:** dYdX flash loan of 10,000 ETH → Compound collateral/112 wBTC →
  5x Fulcrum/bZx short → Kyber/Uniswap price impact → repay dYdX.

## Current evaluation

The old September 2020 self-transfer case was removed. The runner now targets this
February 2020 transaction and initially evaluates `f_fl` against the historical
dYdX SoloMargin provider:

```text
f_fl provider: 0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e

Validated contract roles from historical view calls are Fulcrum iETH
`0x77f973fcaf871459aa58cd81881ce453759281bc` (`symbol=iETH`,
`name=Fulcrum ETH iToken`) and Compound cWBTC
`0xc11b1268c1a384e55c48c2391d8d480264a3a7f4` (`symbol=cWBTC`). The earlier
`0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5` candidate was cETH, which
explained the misleading `loss_S=-5500 ETH` snapshot.

Separate profit holders are the attacker EOA
`0x148426fdc4c8a51b96b4bed827907b5fa6491ad0` and attack contract
`0x4f4e0f2cb72e718fc0433222768c57e823162152`; their asset deltas are recorded
separately from protocol loss.
```

`f_swap` is not applied by guessing: the top-level calldata is a packed attacker
payload, so the swap/oracle intervention site must be identified from call trace
before mutation.

## Reproducibility

The first run downloads the 28 prior transactions and builds the local Anvil
pre-state cache under `.cache/cases/bzx_feb2020-block-9484687/`. Later runs can
use `--offline` with the same manifest.

## Caveat

This case is separate from the September 2020 bZx self-transfer/accounting exploit.
No September 2020 transaction or outcome is used here.

## Mainnet gas reference

The reference comes from `eth_getTransactionReceipt` for the target transaction
`0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838` on the
archive RPC, queried on 2026-08-21. The receipt reports `status=0x1`, block
`9484688`, transaction index `28`, and `gasUsed=3,109,043`.
