"""Generate the single conservative source of truth for paper readiness."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "eval" / "results"


def _csv(name: str) -> list[dict]:
    path = RESULTS / name
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _json(name: str, default: dict | None = None) -> dict:
    path = RESULTS / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else (default or {})


def _latest_run_csv(prefix: str) -> list[dict]:
    candidates = sorted(
        (path for path in (RESULTS / "runs").glob(f"{prefix}*/e5_fidelity.csv")
         if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return []
    with candidates[0].open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _mean(rows: list[dict], field: str) -> float:
    values = [float(row[field]) for row in rows if row.get(field) not in (None, "")]
    return sum(values) / len(values) if values else 0.0


def _true(value: object) -> bool:
    return str(value).lower() == "true"


def _op_line(label: str, row: dict | None) -> str:
    if not row:
        return f"- {label}: missing."
    ok = _true(row.get("budget_satisfied_on_test"))
    qualifier = "budget met" if ok else "budget exceeded on test"
    return (f"- {label}: AUPRC={float(row['auc_pr']):.3f}; calibration-targeted "
            f"1% FPR gives recall={float(row['recall']):.3f}, "
            f"precision={float(row['precision']):.3f}, realized FPR="
            f"{100 * float(row['realized_fpr']):.2f}% ({qualifier}; "
            f"TP={row['tp']}, FP={row['fp']}).")


def generate() -> str:
    main = _csv("e1_main.csv")
    robust = _csv("e1_e3_robustness.csv")
    gt = _json("ground_truth_audit.json")
    dataset = _json("dataset_audit.json")
    robustness = _json("e1_e3_robustness.json")
    hard_queue = _json("hard_negative_review_queue.json")
    hard_audit = _json("hard_negative_audit.json")
    hard_evaluation = _json("hard_negative_evaluation.json")
    review_workflow = _json("review_workflow_audit.json")
    e4_queue = _json("e4_preregistration_queue.json")
    controls = _json("validity_controls.json")
    e5_legacy = _csv("legacy/e5_fidelity.csv")
    e5_v2 = _csv("legacy/e5_fidelity_v2_partial.csv")
    e5_v2_fixed20 = _latest_run_csv("e5-v2-fixed20-")
    provider_comparison = _json(
        "runs/e5-replicate-provider2-20260825/provider_comparison.json")
    alchemy_retune = _json(
        "runs/e5-alchemy-retune7-20260825-net/e5_summary.json")
    e5_preflight_path = (RESULTS / "runs" /
                         "e5-preflight-20260813-full300s" / "e5_fidelity.csv")
    if e5_preflight_path.exists():
        with e5_preflight_path.open(encoding="utf-8", newline="") as handle:
            e5_preflight = list(csv.DictReader(handle))
    else:
        e5_preflight = []
    e6 = _csv("e6_latency.csv")
    ablation = _csv("e2_ablation.csv")

    fixed = next((row for row in main if row.get("fp_budget") == "0.01"), None)
    repeated = [row for row in robust
                if row.get("experiment") == "E1-repeated-stratified"
                and row.get("fp_budget") == "0.01"]
    temporal = next((row for row in robust if row.get("experiment") == "E1-temporal"
                     and row.get("fp_budget") == "0.01"), None)
    near = next((row for row in robust if row.get("experiment") == "E3-near-negative"
                 and row.get("fp_budget") == "0.01"), None)
    token_covered = next((row for row in robust
                          if row.get("experiment") == "E3-token-flow-covered"
                          and row.get("fp_budget") == "0.01"), None)
    held = [row for row in robust if row.get("experiment") == "E2-held-family"
            and row.get("fp_budget") == "0.01" and row.get("family_primary") == "True"]
    full_ablation = next((row for row in ablation if row.get("config") == "full"
                          and row.get("fp_budget") == "0.01"), None)
    no_call = next((row for row in ablation if row.get("config") == "no_call_structure"
                    and row.get("fp_budget") == "0.01"), None)
    no_flow = next((row for row in ablation if row.get("config") == "no_token_flow"
                    and row.get("fp_budget") == "0.01"), None)
    no_econ = next((row for row in ablation if row.get("config") == "no_economic"
                    and row.get("fp_budget") == "0.01"), None)

    exec_pass = sum(_true(row.get("pass")) for row in e5_legacy)
    transport = sum(("timeout" in (row.get("note") or "").lower()
                     or "transport" in (row.get("note") or "").lower())
                    for row in e5_legacy if not _true(row.get("pass")))
    v2_joint = sum(_true(row.get("pass")) for row in e5_v2)
    v2_execution = sum(_true(row.get("execution_pass")) for row in e5_v2_fixed20)
    v2_state_eligible = sum(_true(row.get("state_eligible")) for row in e5_v2_fixed20)
    v2_state_pass = sum(_true(row.get("state_pass")) for row in e5_v2_fixed20)
    v2_joint_pass = sum(_true(row.get("joint_pass")) for row in e5_v2_fixed20)
    v2_transport = sum(not _true(row.get("observed")) for row in e5_v2_fixed20)
    v2_warmup = sum(row.get("failure_reason") == "warmup_failed"
                    for row in e5_v2_fixed20)
    workers50 = next((row["value"] for row in e6
                      if row.get("metric") == "workers_required_at_p50"), "?")
    workers95 = next((row["value"] for row in e6
                      if row.get("metric") == "workers_required_at_p95"), "?")
    eligible = dataset.get("eligible", {})
    bootstrap = robustness.get("bootstrap", {})
    auc_interval = bootstrap.get("intervals", {}).get("auc_pr", {})

    lines = [
        "# Paper readiness — generated evidence report",
        "",
        "This file is the only paper-readiness source of truth. It separates measured "
        "facts, qualified preliminary evidence, retired artifacts, and external blockers.",
        "",
        "## Paper-eligible measurements",
        "",
        _op_line("E1 fixed stratified split", fixed),
        (f"- E1 split-sensitivity analysis: {len(repeated)} resamples, mean AUPRC="
         f"{_mean(repeated, 'auc_pr'):.3f}; the calibration-targeted 1% FPR was met "
         f"on {sum(_true(row.get('budget_satisfied_on_test')) for row in repeated)}/"
         f"{len(repeated)} test resamples. Mean realized FPR={100 * _mean(repeated, 'realized_fpr'):.2f}%; "
         f"mean recall={_mean(repeated, 'recall'):.3f}. These are dependent resamples, "
         "not independent datasets." if repeated else "- E1 split sensitivity: missing."),
        (f"- E1 seed-42 uncertainty: positive-incident/negative-block cluster bootstrap "
         f"({bootstrap.get('n_boot', '?')} replicates; "
         f"{bootstrap.get('n_negative_clusters', '?')} negative blocks) gives AUPRC "
         f"95% interval [{float(auc_interval['low']):.3f}, "
         f"{float(auc_interval['high']):.3f}]."
         if auc_interval else "- E1 bootstrap uncertainty: missing."),
        _op_line("E1 chronological holdout", temporal),
        _op_line("E3 structural near-negative holdout", near),
        (_op_line("Token-flow-covered sensitivity (diagnostic)", token_covered)
         if token_covered else "- Token-flow-covered sensitivity: missing."),
        f"- E2 held-family transfer: {len(held)} primary families (n>=3); rare families remain diagnostic.",
        (f"- View ablation AUPRC: full={float(full_ablation['auc_pr']):.3f}, "
         f"without call structure={float(no_call['auc_pr']):.3f}, without token flow="
         f"{float(no_flow['auc_pr']):.3f}, without economic view={float(no_econ['auc_pr']):.3f}. "
         "Removing state delta has no effect because its coverage is zero."
         if all((full_ablation, no_call, no_flow, no_econ)) else "- View ablation: missing."),
        (f"- Dataset audit: {eligible.get('attack', '?')} incidents and "
         f"{eligible.get('benign', '?')} open-world background negatives; "
         f"{eligible.get('structural_near_negative', '?')} structural near negatives; "
         f"{eligible.get('explicit_hard_negative', '?')} explicitly verified hard negatives."),
        f"- E6 capacity sensitivity: {workers50} workers at p50 and {workers95} at p95 "
        "for 10,000 candidates/day at 70% utilization. This supports offline/asynchronous "
        "triage only, not a real-time deployment claim.",
        "",
        "## Qualified preliminary evidence",
        "",
        f"- Legacy E5 execution-only sample: {exec_pass}/{len(e5_legacy)} execution-pass; "
        f"{transport} failures are transport/timeouts. Legacy state-match percentages are invalid.",
        f"- An unscoped corrected-state E5 pilot contains {len(e5_v2)}/20 cases "
        f"with {v2_joint} joint passes. It is preserved as a partial legacy artifact and cannot support a fidelity rate.",
        (f"- E5 v2 fresh fixed-20 run: attempted={len(e5_v2_fixed20)}/20; "
         f"execution-pass={v2_execution}/20; state-eligible={v2_state_eligible}/20; "
         f"state-pass={v2_state_pass}/{v2_state_eligible}; joint-pass={v2_joint_pass}/20. "
         f"{v2_transport} cases were unobserved transport/fork failures, including "
         f"{v2_warmup} warm-up/batch-mine failures; this remains a qualified preliminary "
         "run, not a clean fidelity denominator."
         if e5_v2_fixed20 else "- E5 v2 fresh fixed-20 run: missing."),
        (f"- E5 provider robustness comparison: initial Alchemy joint-pass="
         f"{provider_comparison.get('provider_1', {}).get('joint_pass', '?')}/"
         f"{provider_comparison.get('provider_1', {}).get('attempted', '?')}, "
         f"QuickNode joint-pass={provider_comparison.get('provider_2', {}).get('joint_pass', '?')}/"
         f"{provider_comparison.get('provider_2', {}).get('attempted', '?')}; the seven Alchemy-only "
         f"failures were retuned and passed {alchemy_retune.get('joint_pass', '?')}/"
         f"{alchemy_retune.get('attempted', '?')}. On the comparable 19-case set, both providers "
         "achieved 19/19 joint-pass; one shared local-warmup timeout was excluded. This is "
         "pipeline robustness evidence, not a provider-fidelity gap."
         if provider_comparison and alchemy_retune else "- E5 provider robustness comparison: missing."),
        (f"- The 2026-08-13 frozen-set k=0 infrastructure preflight contains "
         f"{len(e5_preflight)} row and "
         f"{sum(_true(row.get('observed')) for row in e5_preflight)} observed receipts. "
         "Direct archive/tracer probes passed, but local-fork replay timed out within "
         "its configured 300 s replay bound (305 s process guard) and is labeled "
         "UNOBSERVED, not REVERTED. It is "
         "infrastructure evidence, not an E5 denominator."
         if e5_preflight else "- Current E5 infrastructure preflight artifact: missing."),
        f"- E4 fixed benchmark queue: {(review_workflow.get('e4') or {}).get('reviewed_complete', 0)}/20 "
        "complete review pairs. Separately, the bZx and Euler deep case studies together received "
        "four structured review records converging on CAUSE (4/4 recorded votes); reviewer externality is not claimed "
        "until provenance artifacts are retained. This pilot does not estimate population-level "
        "causal accuracy.",
        (f"- Local E4 validity fixture: positive-control="
         f"{'PASS' if controls.get('positive_control_pass') else 'FAIL'}, sham-control="
         f"{'PASS' if controls.get('sham_control_pass') else 'FAIL'}, joint-control="
         f"{'PASS' if controls.get('joint_control_pass') else 'FAIL'}. This validates local "
         "Anvil mutation mechanics, not incident-level causal accuracy."),
        f"- Blind E4 preregistration queue: {e4_queue.get('queue_rows', 0)} trace-supported candidates, "
        f"including {e4_queue.get('with_cache_supported_factor', 0)} with an offline-supported factor; "
        "attack type and legacy mechanism labels are omitted. A fixed 20-case attempted set is frozen; "
        f"completed independent review pairs="
        f"{(review_workflow.get('e4') or {}).get('reviewed_complete', 0)}/20; "
        f"final sidecar valid={bool(((review_workflow.get('e4') or {}).get('final_sidecar') or {}).get('valid'))}.",
        "- E4 causal case-study scope (deep validation track): bZx and Euler are the official deep causal studies with validated B2 intervention results, produced under their own dedicated validation process: four structured review records across the two cases (4/4 recorded votes), B2 acceptance gates, per-transaction gas/status and Merkle-proof checks, mutation-specific causal signatures, harm-oracle checks, and regression against known fixtures. Reviewer externality is not claimed until provenance artifacts are retained. This is separate from the fixed 20-case benchmark queue and does not estimate population-level causal accuracy. USM is an attempted external-price-feed candidate, but is excluded from causal evaluation after B2 stopped on unsupported EIP-7702 transaction type 0x4.",
        "- E4 candidate-expansion track: new candidates beyond the bZx/Euler case studies use self-consistency re-derivation (independent double re-derivation by the same annotator) in place of two-reviewer adjudication, due to single-annotator resource constraints. This applies only to this track, not to the fixed preregistered benchmark queue below.",
        "- Causal-necessity claim boundary: we evaluate causal necessity for the subset of candidates whose oracle mechanism is an external price-feed getter supported by the current B2 mutation engine. AMM-reserve price manipulation is identified during screening but excluded from causal evaluation in this version.",
        "- E4 v2 runtime-support limitation: the E1 heuristic labels `getReserves()` (`0x0902f1ac`) as an oracle signal, but the current B2 planner supports only external price-feed getters through `OracleStubProvider`. All 8 initial v2 selections were AMM-reserve cases and produced no runtime `f_orc` mutation. The AMM-reserve group is excluded from causal-accuracy claims in this version; a storage mutation provider is future work.",
        "- After restricting selection to runtime-supported external price feeds and Tier 1–2 (allowing partial cache), only 1 candidate meets the criteria. The preregistered minimum of 5 is therefore not met; no forced N=5 selection is reported.",
        "- The sole Tier 1/full-cache external-feed candidate (USM) completed archive context and all 2,070 transaction-relevant Merkle proofs, but B2 stopped before replay because three prefix transactions use EIP-7702 type 0x4, unsupported by the pinned go-ethereum v1.14.12 runner. It is reported as attempted but fidelity-inconclusive, not as a causal verdict.",
        "",
        "### Known limitations identified during E4/B2 screening",
        "",
        "| Limitation | Evidence | Consequence |",
        "|---|---|---|",
        "| Sender validation | SizeFlashLoanLooping contains non-EOA senders in the replay prefix. | B2 fidelity is inconclusive; the case is not converted into causal evidence. |",
        "| AMM-reserve planner mismatch | The E1 heuristic marks `getReserves()` as an oracle getter, while the current planner supports external price-feed code overrides only; 8 initial v2 selections fell into this group. | AMM cases are excluded from causal claims; storage-level mutation remains future work. |",
        "| Transaction-type support | USM has three prefix transactions of EIP-7702 type `0x4`; pinned go-ethereum v1.14.12 rejects them before replay. | USM is attempted but `INCONCLUSIVE-fidelity-unsupported-tx-type`; no oracle causal verdict is reported. |",
        "",
        f"- Hard-negative annotation queue: {hard_queue.get('queue_rows', 0)} pending candidates; "
        f"{hard_queue.get('within_preregistered_window', 0)} fall within the frozen "
        f"{hard_queue.get('preregistered_window_blocks', '?')}-block window; "
        f"review records={hard_audit.get('annotation_records', 0)}; paper-eligible "
        f"verified hard negatives={hard_audit.get('paper_eligible_hard_negatives', 0)}. "
        f"Frozen-threshold evaluation claim-eligible="
        f"{hard_evaluation.get('claim_eligible', False)}. Only the separate schema-v2 "
        "two-reviewer audit can upgrade a queue row.",
        "",
        "## Retired or unsupported claims",
        "",
        "- The old E4 3/3 result is retired: candidate selection used mechanism labels and the mutated branch lacked a valid harm oracle.",
        "- Legacy E5 state-match values compared against end-of-block state and must never be quoted.",
        "- Internal rule/static/balance scorers are proxies, not faithful DeFiScope, SmartAxe, or MonteCrypto implementations.",
        "- The measured screener is three-view. State delta has zero coverage.",
        "- Token-flow coverage differs sharply by label (79/80 incidents versus 1602/3381 background); semantic contribution cannot be fully separated from transaction-complexity/coverage shift.",
        "- Structural near negatives are not manually verified protocol/time-matched hard negatives.",
        "- Factor necessity alone does not distinguish a security exploit from legitimate arbitrage; a preregistered security objective and victim harm ledger are required.",
        "- The corpus has one incident per protocol, so held-protocol generalization is not statistically identifiable from the current data.",
        "",
        "## Resolved scope decisions",
        "",
        "- This paper permanently scopes the measured screener to the three views with observed coverage; state delta remains an unmeasured future extension.",
        "- This paper retains internal diagnostic proxies and ablation only, and makes no faithful-baseline or SOTA-superiority claim.",
        "",
        "## Submission blockers requiring new external evidence",
        "",
        "1. Two reviewers must independently annotate and adjudicate the fixed 20-case preregistered E4 benchmark queue specifically (not the bZx/Euler case studies or the self-consistency candidate-expansion track) before it can support a benchmark-level causal-accuracy claim; report attempted/eligible/observed/valid/harm-measured denominators plus inconclusive reasons.",
        (f"2. E5 v2 fixed-20 infrastructure remains unresolved: the latest fresh run has "
         f"execution-pass={v2_execution}/20, state-eligible={v2_state_eligible}/20, "
         f"state-pass={v2_state_pass}/{v2_state_eligible}, and joint-pass={v2_joint_pass}/20; "
         "a stable archive/fork route is required before claiming a clean fidelity denominator."
         if e5_v2_fixed20 else
         "2. E5 v2 must finish the fixed 20-case run on a stable archive RPC; report execution, state-eligible, state-pass, and joint-pass separately."),
        "3. A manually verified, protocol/time-matched hard-negative set is required; background negatives cannot substitute for it.",
        "4. Run the offline artifact on Linux/CI; compare the semantic fingerprint and retain Anvil, Cast, Python, package, RPC-capability and image/version metadata.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    text = generate()
    path = RESULTS / "PAPER_READINESS.md"
    path.write_text(text, encoding="utf-8", newline="\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
