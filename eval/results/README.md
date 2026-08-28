# Evaluation artifacts

`PAPER_READINESS.md` is the only generated paper-readiness source of truth.
Current paper-facing artifacts remain in this directory; historical outputs are
kept under `legacy/`, and raw execution logs under `raw_logs/`.

For navigation by experiment, see [`INDEX.md`](INDEX.md). The `runs/` directory
is an immutable run vault grouped by run ID; its contents are not silently
renamed or pooled when a new index is created.

## Current artifacts

- `e1_main.csv`, `e1_evaluation.json`, `e1_model.json`, `e1_manifest.json`:
  fixed split with FPR thresholds selected on calibration data.
- `e1/e1_rf.json`: one frozen Random Forest comparison on the same authoritative
  E1 cache and fit/calibration/test identities. It records cache/split hashes,
  fixed RF configuration, calibration temperature, calibration-derived
  thresholds, 1% operating-point metrics, confusion counts, and canonical
  Logistic reference metrics. This is a model-choice baseline, not a new E1
  split or a paper-integrated claim.
- `e1_e3_robustness.*`, `e1_e3_manifest.json`: split sensitivity,
  chronological, held-family, and structural near-negative evaluations.
- `e2_ablation.csv`: view ablation using the same calibration-only threshold
  policy. Despite the historical filename, this is an ablation, not E2.
- `dataset_audit.*`, `dataset_audit_manifest.json`: label/coverage audit.
- `ground_truth_audit.*`: causal-label eligibility audit.
- `claim_audit.json`: machine-checked agreement between generated evidence and
  the numerical claims in both authoritative paper drafts.
- `e4_preregistration_queue.*`: blind trace-supported human-review queue; no
  row is causal ground truth.
- `hard_negative_review_queue.*`: 160 pending matched-control candidates; no row
  is verified benign until two-reviewer adjudication. The 216,000-block matching
  window is frozen in the queue; 27 current candidates are inside it.
- `review_workflow_audit.json`: exact review-packet completeness, disagreement,
  identity and final-sidecar vote-preservation gate; it never fills labels.
- `hard_negative_evaluation.json`: frozen E1-threshold FPR on only validated
  matched negatives; an empty verified set yields `null`, never a zero-FPR claim.
- `runs/`: run-scoped replay attempts; infrastructure preflights are not pooled.
- `E5_RPC_PREFLIGHT.md`: provider-capability diagnosis; not an E5 result.
- `e6_latency.csv`: measured replay latency and capacity sensitivity.
- `corpus_diversity.csv`: descriptive corpus table; not a numbered experiment.

The uncompressed local trace cache is ignored because it is large. A
deterministic 4.9 MB gzip release and both compressed/decompressed hashes are
stored under `eval/artifacts/`.

## E1 Random Forest reproduction

Use the released cache in a run-scoped directory; do not use or overwrite a
different live cache:

```bash
run_dir="$(mktemp -d /tmp/traceguard-e1-rf-XXXXXX)"
gzip -dc eval/artifacts/e1_trace_cache.jsonl.gz > "$run_dir/e1_trace_cache.jsonl"
python3 -m eval.e1_rf --cache "$run_dir/e1_trace_cache.jsonl"
```

The runner uses `scikit-learn==1.7.2`, seed `42`, `200` trees, `max_depth=6`,
`min_samples_leaf=2`, `class_weight=balanced_subsample`, and `n_jobs=1`.
Calibration is the canonical E1 ECE-minimizing temperature scaling procedure;
the threshold is selected from calibration data only. The primary artifact was
generated once from the released cache and is not retuned on test results.
