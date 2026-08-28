"""E4 reporting: aggregation, CSV persistence and evidence graph."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from eval.statistics import wilson_interval

CSV_COLUMNS = [
    "run_id", "planner", "case", "paper_eligible", "label_source", "factor_gt",
    "mutation", "candidate_factor", "mutation_kind", "causal_signature", "ratio",
    "execution_status", "invariant_status", "outcome", "observed", "fidelity_pass",
    "execution_preserving", "intervention_valid", "validity_reason", "behavior_changed",
    "harm_S", "harm_Sm", "positive_candidate_delta_usd",
    "positive_candidate_delta_usd_mutated", "delta_positive_candidate_usd",
    "lmin_usd", "valuation_source",
    "control_type", "control_pass", "intervention_order", "joint_factors", "joint_verdict",
    "baseline_gas_used", "mutation_gas_used", "gas_limit", "gas_margin", "out_of_gas",
    "same_block_context", "per_tx_gas_match", "prestate_proof_verified", "target_status",
    "revert_reason", "execution_diverged_by_mutation_error", "call_trace_equal",
    "baseline_call_count", "mutation_call_count", "call_trace_first_diff", "override_applied",
    "verdict", "cause", "factor_match", "factor_confusion", "note",
]


def _yes(row: dict, field: str) -> bool:
    return str(row.get(field)) == "True"


def aggregate(rows: list[dict]) -> dict:
    """Aggregate E4 without hiding coverage or unsupported cases."""
    from eval.necessity import mutation_factor
    n = len(rows)
    if n == 0:
        return {"n": 0, "factor_match": 0, "factor_match_rate": 0.0,
                "necessity_coverage": 0.0, "revert_rate": 0.0,
                "transport_error_rate": 0.0, "case_denominators": {},
                "intervention_denominators": {}, "inconclusive_reasons": {},
                "confusion": {}, "intervals": {}, "controls": {},
                "joint_interventions": {}, "by_mutation": {}}
    case_ids = {r.get("case") for r in rows if r.get("case")}
    eligible_cases = {r.get("case") for r in rows if _yes(r, "paper_eligible")}
    excluded = {"fidelity", "no_mutation", "error", "ineligible", "control_sham"}
    control_rows = [r for r in rows if r.get("mutation") == "control_sham"]
    joint_rows = [r for r in rows if str(r.get("mutation") or "").startswith("joint[")]
    mut_rows = [r for r in rows if r.get("mutation") not in excluded and not str(r.get("mutation") or "").startswith("joint[")]
    eligible_mut = [r for r in mut_rows if _yes(r, "paper_eligible")]
    scored = [r for r in eligible_mut if r.get("factor_match") in ("match", "no_match")]
    matches = sum(r.get("factor_match") == "match" for r in scored)
    reverts = sum(r.get("outcome") == "REVERTED" and _yes(r, "observed") for r in eligible_mut)
    cause_cases = {r.get("case") for r in eligible_mut if r.get("verdict") == "CAUSE"}
    transport = sum(not _yes(r, "observed") for r in eligible_mut)
    observed_mut = [r for r in eligible_mut if _yes(r, "observed")]
    execution_mut = [r for r in eligible_mut if _yes(r, "execution_preserving")]
    valid_mut = [r for r in execution_mut if (_yes(r, "intervention_valid") if "intervention_valid" in r else _yes(r, "execution_preserving")) and _yes(r, "behavior_changed")]
    harm_mut = [r for r in valid_mut if r.get("harm_S") == "HARM" and r.get("harm_Sm") in ("HARM", "NO_HARM")]
    observed_cases = {r.get("case") for r in observed_mut}
    execution_cases = {r.get("case") for r in execution_mut}
    valid_cases = {r.get("case") for r in valid_mut}
    harm_cases = {r.get("case") for r in harm_mut}
    scored_cases = {r.get("case") for r in scored}
    confusion = Counter(r.get("factor_confusion") for r in scored)
    inconclusive = Counter(str(r.get("verdict") or "missing") for r in eligible_mut if str(r.get("verdict") or "").startswith("INCONCLUSIVE"))
    by_mutation: dict[str, dict] = {}
    for row in eligible_mut:
        name = row.get("candidate_factor") or mutation_factor(str(row.get("mutation", "?")))
        item = by_mutation.setdefault(name, {"n": 0, "observed": 0, "valid": 0, "harm_measured": 0, "revert": 0, "cause": 0, "scored": 0, "match": 0, "confusion": {"TP": 0, "FP": 0, "FN": 0, "TN": 0}})
        item["n"] += 1; item["observed"] += _yes(row, "observed"); item["valid"] += row in valid_mut
        item["harm_measured"] += row in harm_mut; item["revert"] += row.get("outcome") == "REVERTED"
        item["cause"] += row.get("cause") == "1"; item["scored"] += row.get("factor_match") in ("match", "no_match"); item["match"] += row.get("factor_match") == "match"
        cell = str(row.get("factor_confusion") or "")
        if cell in item["confusion"]: item["confusion"][cell] += 1
    for item in by_mutation.values():
        item["accuracy"] = item["match"] / item["scored"] if item["scored"] else None
        item["accuracy_wilson_95"] = wilson_interval(item["match"], item["scored"])
    eligible_n = len(eligible_cases)
    return {"n": n, "factor_match": matches, "factor_match_rate": matches / len(scored) if scored else 0.0,
        "necessity_coverage": len(cause_cases) / eligible_n if eligible_n else 0.0,
        "revert_rate": reverts / len(eligible_mut) if eligible_mut else 0.0,
        "transport_error_rate": transport / len(eligible_mut) if eligible_mut else 0.0,
        "case_denominators": {"attempted": len(case_ids), "eligible": eligible_n, "observed": len(observed_cases), "execution_preserved": len(execution_cases), "intervention_valid": len(valid_cases), "harm_measured": len(harm_cases), "scored": len(scored_cases)},
        "intervention_denominators": {"attempted": len(eligible_mut), "observed": len(observed_mut), "execution_preserved": len(execution_mut), "intervention_valid": len(valid_mut), "harm_measured": len(harm_mut), "scored": len(scored)},
        "inconclusive_reasons": dict(inconclusive), "confusion": {key: confusion.get(key, 0) for key in ("TP", "FP", "FN", "TN")},
        "intervals": {"factor_accuracy": wilson_interval(matches, len(scored)), "cause_case_coverage": wilson_interval(len(cause_cases), eligible_n)},
        "controls": {"sham_attempted": len(control_rows), "sham_pass": sum(_yes(r, "control_pass") for r in control_rows), "sham_fail": sum(str(r.get("control_pass")) == "False" for r in control_rows), "sham_inconclusive": sum(r.get("control_pass") in ("", None) for r in control_rows)},
        "joint_interventions": {"attempted": len(joint_rows), "observed": sum(_yes(r, "observed") for r in joint_rows), "pair_cause": sum(r.get("verdict") == "CAUSE" for r in joint_rows), "joint_cause": sum(r.get("joint_verdict") == "JOINT_CAUSE" for r in joint_rows), "redundant_with_single": sum(r.get("joint_verdict") == "REDUNDANT_WITH_SINGLE" for r in joint_rows), "exact_match": sum(r.get("factor_match") == "joint_exact_match" for r in joint_rows), "no_match": sum(r.get("factor_match") == "joint_no_match" for r in joint_rows), "inconclusive": sum(str(r.get("verdict") or "").startswith("INCONCLUSIVE") for r in joint_rows)},
        "by_mutation": by_mutation}


def write_csv(rows: list[dict], path: str | Path) -> Path:
    """Upsert rows by run/case/mutation without mixing experiment runs."""
    target = Path(path); target.parent.mkdir(parents=True, exist_ok=True); existing: dict[str, dict] = {}
    legacy_fields = {
        "loss_S": "positive_candidate_delta_usd",
        "loss_Sm": "positive_candidate_delta_usd_mutated",
        "dloss": "delta_positive_candidate_usd",
    }
    if target.exists():
        with target.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                for old, new in legacy_fields.items():
                    if not row.get(new) and row.get(old):
                        row[new] = row[old]
                key = (row.get("run_id") or "legacy", row.get("case", ""), row.get("mutation", "")); existing["\x1f".join(key)] = row
    for row in rows:
        for old, new in legacy_fields.items():
            if new not in row and old in row:
                row[new] = row[old]
        key = (str(row.get("run_id") or "legacy"), str(row.get("case", "")), str(row.get("mutation", ""))); existing["\x1f".join(key)] = row
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS); writer.writeheader()
        for row in existing.values(): writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})
    return target


def load_results(path: str | Path) -> list[dict]:
    if not Path(path).exists(): return []
    with Path(path).open(encoding="utf-8") as handle: return list(csv.DictReader(handle))


def build_evidence_graph(rows: list[dict]) -> dict:
    """Build a replay tree retaining failures and all mutation branches."""
    cases = []
    for case_id in sorted({str(row.get("case") or "") for row in rows if row.get("case")}):
        case_rows = [row for row in rows if str(row.get("case")) == case_id]; nodes, edges = [], []
        for row in case_rows:
            mutation = str(row.get("mutation") or "")
            nodes.append({"id": f"{case_id}:{mutation}", "mutation": mutation, "intervention_order": row.get("intervention_order") or 0, "candidate_factor": row.get("candidate_factor") or "", "joint_factors": row.get("joint_factors") or "", "observed": row.get("observed"), "execution_preserving": row.get("execution_preserving"), "behavior_changed": row.get("behavior_changed"), "harm_S": row.get("harm_S"), "harm_Sm": row.get("harm_Sm"), "verdict": row.get("verdict"), "joint_verdict": row.get("joint_verdict"), "control_type": row.get("control_type"), "control_pass": row.get("control_pass")})
            if mutation not in ("fidelity", "ineligible", "error", "no_mutation"):
                edges.append({"from": f"{case_id}:fidelity", "to": f"{case_id}:{mutation}", "operation": "remove_factor", "factors": row.get("joint_factors") or row.get("candidate_factor") or "unknown"})
        cases.append({"case": case_id, "nodes": nodes, "edges": edges})
    return {"schema_version": 1, "semantics": "fresh-fork counterfactual branches; no omitted failures", "cases": cases}
