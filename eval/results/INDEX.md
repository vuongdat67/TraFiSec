# TraceGuard evaluation index

This is a navigation map, not a replacement for immutable run metadata.
Top-level artifacts are grouped by experiment below. Historical run directories
remain under [`runs/`](runs/) and should be cited by their exact run ID.

## E1 — screening and model baselines

- `e1_main.csv`, `e1_evaluation.json`, `e1_model.json`, `e1_manifest.json`
- `e1_baselines.csv`
- `e1/e1_rf.json` — frozen Random Forest model-choice baseline
- `e1_trace_cache.jsonl` — local expanded cache; release source is under
  `../artifacts/e1_trace_cache.jsonl.gz`

## E2/E3 — ablation and robustness

- `e2_ablation.csv`
- `e1_e3_robustness.csv`, `e1_e3_robustness.json`
- `e1_e3_manifest.json`

## E4 — causal replay and review

### Frozen systematic runs

- [`runs/e4-stage2-authoritative-20260826/`](runs/e4-stage2-authoritative-20260826/)
  — q00–q04 authoritative run and original review round
- [`runs/e4-stage2-extension-20260827-q05-q15-r3/`](runs/e4-stage2-extension-20260827-q05-q15-r3/)
  — q05–q15 extension run and reviewer bundle
- `e4_stage2_subset_manifest.json` — original q00–q04 frozen manifest
- `e4_stage2_subset_q05_q15_manifest.json` — q05–q15 extension manifest
- `e4/e4_adjudication_summary.json` — E4 adjudication aggregate summary
- `e4/e4_baseline_gate_pass_manifest.json` — baseline gate manifest
- `e4/triage/` — E4 AMM/storage triage snapshots

### E4 pilot and diagnostic evidence

Relevant pilot/diagnostic runs use the prefixes `e4-`, `b2-`, `bzx-`, and
`euler-` under `runs/`. The exact run ID and its metadata are authoritative;
similarly named retries are not interchangeable.

## E5 — replay fidelity

Relevant runs use the `e5-` prefix under `runs/`, especially:

- `runs/e5-v2-fixed20-20260823/`
- `runs/e5-alchemy-retune7-20260825/`
- `runs/e5-replicate-provider2-20260825/`

Preflight, diagnostic, and retry runs remain in the vault but are not pooled
without an explicit artifact audit.

## E6 — latency and capacity

- `e6_latency.csv`
- `runs/` entries with `e6` or latency-specific metadata, when present

## Audits and supporting artifacts

- `PAPER_READINESS.md`
- `citation_audit.json`, `claim_audit.json`, `path_audit.json`
- `dataset_audit.json`, `dataset_audit_manifest.json`
- `ground_truth_audit.json`, `ground_truth_audit.csv`
- `review_workflow_audit.json`
- `hard_negative_audit.json`, `hard_negative_evaluation.json`

## Legacy and raw material

- [`legacy/`](legacy/) — explicitly retired result tables
- [`raw_logs/`](raw_logs/) — raw command logs; never paper evidence by itself
- [`runs/`](runs/) — immutable run vault, including failed/debug attempts

## Status rule

An artifact is paper-citable only when its source run, inputs, hashes, and
failure classification are identifiable. A convenient filename or a successful
process exit is not enough.
