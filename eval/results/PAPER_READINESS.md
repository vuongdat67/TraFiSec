# Paper readiness — generated evidence report

This file is the only paper-readiness source of truth. It separates measured facts, qualified preliminary evidence, retired artifacts, and external blockers.

## Paper-eligible measurements

- E1 fixed stratified split: AUPRC=0.641; calibration-targeted 1% FPR gives recall=0.500, precision=0.667, realized FPR=0.74% (budget met; TP=10, FP=5).
- E1 split-sensitivity analysis: 30 resamples, mean AUPRC=0.672; the calibration-targeted 1% FPR was met on 24/30 test resamples. Mean realized FPR=0.63%; mean recall=0.510. These are dependent resamples, not independent datasets.
- E1 seed-42 uncertainty: positive-incident/negative-block cluster bootstrap (1000 replicates; 37 negative blocks) gives AUPRC 95% interval [0.440, 0.830].
- E1 chronological holdout: AUPRC=0.837; calibration-targeted 1% FPR gives recall=0.750, precision=0.857, realized FPR=0.67% (budget met; TP=12, FP=2).
- E3 structural near-negative holdout: AUPRC=0.557; calibration-targeted 1% FPR gives recall=0.938, precision=0.096, realized FPR=16.77% (budget exceeded on test; TP=15, FP=142).
- Token-flow-covered sensitivity (diagnostic): AUPRC=0.622; calibration-targeted 1% FPR gives recall=0.474, precision=0.643, realized FPR=1.56% (budget exceeded on test; TP=9, FP=5).
- E2 held-family transfer: 6 primary families (n>=3); rare families remain diagnostic.
- View ablation AUPRC: full=0.641, without call structure=0.592, without token flow=0.593, without economic view=0.621. Removing state delta has no effect because its coverage is zero.
- Dataset audit: 80 incidents and 3381 open-world background negatives; 847 structural near negatives; 0 explicitly verified hard negatives.
- E6 capacity sensitivity: 86 workers at p50 and 392 at p95 for 10,000 candidates/day at 70% utilization. This supports offline/asynchronous triage only, not a real-time deployment claim.

## Qualified preliminary evidence

- Legacy E5 execution-only sample: 13/20 execution-pass; 7 failures are transport/timeouts. Legacy state-match percentages are invalid.
- An unscoped corrected-state E5 pilot contains 5/20 cases with 0 joint passes. It is preserved as a partial legacy artifact and cannot support a fidelity rate.
- E5 v2 fresh fixed-20 run: attempted=20/20; execution-pass=12/20; state-eligible=12/20; state-pass=12/12; joint-pass=12/20. 8 cases were unobserved transport/fork failures, including 7 warm-up/batch-mine failures; this remains a qualified preliminary run, not a clean fidelity denominator.
- E5 provider robustness comparison: initial Alchemy joint-pass=12/20, QuickNode joint-pass=19/20; the seven Alchemy-only failures were retuned and passed 7/7. On the comparable 19-case set, both providers achieved 19/19 joint-pass; one shared local-warmup timeout was excluded. This is pipeline robustness evidence, not a provider-fidelity gap.
- The 2026-08-13 frozen-set k=0 infrastructure preflight contains 1 row and 0 observed receipts. Direct archive/tracer probes passed, but local-fork replay timed out within its configured 300 s replay bound (305 s process guard) and is labeled UNOBSERVED, not REVERTED. It is infrastructure evidence, not an E5 denominator.
- E4 fixed benchmark queue: 0/20 complete review pairs. Separately, the bZx and Euler deep case studies together received four structured review records converging on CAUSE (4/4 recorded votes); reviewer externality is not claimed until provenance artifacts are retained. This pilot does not estimate population-level causal accuracy.
- Local E4 validity fixture: positive-control=PASS, sham-control=PASS, joint-control=PASS. This validates local Anvil mutation mechanics, not incident-level causal accuracy.
- Blind E4 preregistration queue: 63 trace-supported candidates, including 39 with an offline-supported factor; attack type and legacy mechanism labels are omitted. A fixed 20-case attempted set is frozen; completed independent review pairs=0/20; final sidecar valid=False.
- E4 causal case-study scope (deep validation track): bZx and Euler are the official deep causal studies with validated B2 intervention results, produced under their own dedicated validation process: four structured review records across the two cases (4/4 recorded votes), B2 acceptance gates, per-transaction gas/status and Merkle-proof checks, mutation-specific causal signatures, harm-oracle checks, and regression against known fixtures. Reviewer externality is not claimed until provenance artifacts are retained. This is separate from the fixed 20-case benchmark queue and does not estimate population-level causal accuracy. USM is an attempted external-price-feed candidate, but is excluded from causal evaluation after B2 stopped on unsupported EIP-7702 transaction type 0x4.
- E4 candidate-expansion track: new candidates beyond the bZx/Euler case studies use self-consistency re-derivation (independent double re-derivation by the same annotator) in place of two-reviewer adjudication, due to single-annotator resource constraints. This applies only to this track, not to the fixed preregistered benchmark queue below.
- Causal-necessity claim boundary: we evaluate causal necessity for the subset of candidates whose oracle mechanism is an external price-feed getter supported by the current B2 mutation engine. AMM-reserve price manipulation is identified during screening but excluded from causal evaluation in this version.
- E4 v2 runtime-support limitation: the E1 heuristic labels `getReserves()` (`0x0902f1ac`) as an oracle signal, but the current B2 planner supports only external price-feed getters through `OracleStubProvider`. All 8 initial v2 selections were AMM-reserve cases and produced no runtime `f_orc` mutation. The AMM-reserve group is excluded from causal-accuracy claims in this version; a storage mutation provider is future work.
- After restricting selection to runtime-supported external price feeds and Tier 1–2 (allowing partial cache), only 1 candidate meets the criteria. The preregistered minimum of 5 is therefore not met; no forced N=5 selection is reported.
- The sole Tier 1/full-cache external-feed candidate (USM) completed archive context and all 2,070 transaction-relevant Merkle proofs, but B2 stopped before replay because three prefix transactions use EIP-7702 type 0x4, unsupported by the pinned go-ethereum v1.14.12 runner. It is reported as attempted but fidelity-inconclusive, not as a causal verdict.

### Known limitations identified during E4/B2 screening

| Limitation | Evidence | Consequence |
|---|---|---|
| Sender validation | SizeFlashLoanLooping contains non-EOA senders in the replay prefix. | B2 fidelity is inconclusive; the case is not converted into causal evidence. |
| AMM-reserve planner mismatch | The E1 heuristic marks `getReserves()` as an oracle getter, while the current planner supports external price-feed code overrides only; 8 initial v2 selections fell into this group. | AMM cases are excluded from causal claims; storage-level mutation remains future work. |
| Transaction-type support | USM has three prefix transactions of EIP-7702 type `0x4`; pinned go-ethereum v1.14.12 rejects them before replay. | USM is attempted but `INCONCLUSIVE-fidelity-unsupported-tx-type`; no oracle causal verdict is reported. |

- Hard-negative annotation queue: 160 pending candidates; 19 fall within the frozen 216000-block window; review records=0; paper-eligible verified hard negatives=0. Frozen-threshold evaluation claim-eligible=False. Only the separate schema-v2 two-reviewer audit can upgrade a queue row.

## Retired or unsupported claims

- The old E4 3/3 result is retired: candidate selection used mechanism labels and the mutated branch lacked a valid harm oracle.
- Legacy E5 state-match values compared against end-of-block state and must never be quoted.
- Internal rule/static/balance scorers are proxies, not faithful DeFiScope, SmartAxe, or MonteCrypto implementations.
- The measured screener is three-view. State delta has zero coverage.
- Token-flow coverage differs sharply by label (79/80 incidents versus 1602/3381 background); semantic contribution cannot be fully separated from transaction-complexity/coverage shift.
- Structural near negatives are not manually verified protocol/time-matched hard negatives.
- Factor necessity alone does not distinguish a security exploit from legitimate arbitrage; a preregistered security objective and victim harm ledger are required.
- The corpus has one incident per protocol, so held-protocol generalization is not statistically identifiable from the current data.

## Resolved scope decisions

- This paper permanently scopes the measured screener to the three views with observed coverage; state delta remains an unmeasured future extension.
- This paper retains internal diagnostic proxies and ablation only, and makes no faithful-baseline or SOTA-superiority claim.

## Submission blockers requiring new external evidence

1. Two reviewers must independently annotate and adjudicate the fixed 20-case preregistered E4 benchmark queue specifically (not the bZx/Euler case studies or the self-consistency candidate-expansion track) before it can support a benchmark-level causal-accuracy claim; report attempted/eligible/observed/valid/harm-measured denominators plus inconclusive reasons.
2. E5 v2 fixed-20 infrastructure remains unresolved: the latest fresh run has execution-pass=12/20, state-eligible=12/20, state-pass=12/12, and joint-pass=12/20; a stable archive/fork route is required before claiming a clean fidelity denominator.
3. A manually verified, protocol/time-matched hard-negative set is required; background negatives cannot substitute for it.
4. Run the offline artifact on Linux/CI; compare the semantic fingerprint and retain Anvil, Cast, Python, package, RPC-capability and image/version metadata.
