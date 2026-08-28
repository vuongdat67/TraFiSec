# Retired evaluation artifacts

Files here are preserved for auditability and must not be quoted as current
results.

- E4 legacy output used mechanism-label-guided intervention planning and did
  not have a valid mutated-branch harm oracle.
- E5 legacy state percentages used end-of-block state rather than the
  transaction-local `prestateTracer.diff.post` target. Only the separately
  qualified execution outcome counts may be inspected historically.
- `e5_fidelity_v2_partial.csv` used the corrected target but contains only five
  unscoped cases; it is not the preregistered fixed-20 result.
- The old E3 false-positive table predates calibration-frozen thresholds.
- `e7_corpus_diversity.csv` used obsolete E7 numbering; the current descriptive
  table is `../corpus_diversity.csv`.
