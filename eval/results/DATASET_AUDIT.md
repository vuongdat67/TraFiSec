# Dataset audit — generated

This report describes label and feature evidence without upgrading any annotation.

## Inventory

- Cache lines: 3560; unique transaction hashes: 3560; duplicate occurrences: 0; malformed: 0.
- Evaluation-eligible rows: 3461 (80 attacks, 3381 background negatives).
- Explicit verified hard negatives: 0; structural near negatives: 847.
- Attack protocols: 80 unique for 80 incidents; multi-incident protocols: 0.

## View coverage

| Label | call_structure | token_flow | state_delta | economic |
|---|---:|---:|---:|---:|
| attack | 80 | 79 | 80 | 80 |
| benign | 3381 | 1602 | 3381 | 3381 |

## Constraints

- Background negatives are open-world assumed-benign examples, not exhaustively verified benign ground truth.
- Structural near negatives are mined by generic selectors/complexity and are not manually verified protocol/time matches.
- The cache contains no explicit hard-negative rows under the current classifier.
- State-delta coverage is zero; measured screening results use three available views.
- Token-flow coverage differs by label (79/80 attacks versus 1602/3381 background), so coverage-conditioned sensitivity must accompany semantic ablation claims.
- Every attack protocol appears once, so a meaningful held-protocol estimate cannot be computed from this corpus.
