"""Build blinded, run-scoped reviewer packets for the E4 Stage-2 run."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval.e4_stage2_subset import ROOT, sha256_file

DEFAULT_RUN = ROOT / "eval" / "results" / "runs" / "e4-stage2-authoritative-20260826"

_SYSTEM_LABELS = {
    "cause", "factor_match", "intervention_valid", "validity_reason", "verdict",
}
_OBSERVABLE_FIELDS = (
    "mutation", "mutation_kind", "causal_signature", "observed", "fidelity_pass",
    "execution_preserving", "behavior_changed", "baseline_gas_used", "mutation_gas_used",
    "gas_limit", "gas_margin", "out_of_gas", "same_block_context", "per_tx_gas_match",
    "prestate_proof_verified", "target_status", "revert_reason",
    "execution_diverged_by_mutation_error", "call_trace_equal", "baseline_call_count",
    "mutation_call_count", "call_trace_first_diff", "override_applied",
    "positive_candidate_delta_usd", "positive_candidate_delta_usd_mutated",
    "delta_positive_candidate_usd", "lmin_usd", "valuation_source", "note",
)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest_for_run(run_dir: Path, metadata: dict) -> dict:
    """Load the exact subset manifest recorded by this run."""
    recorded = (metadata.get("inputs") or {}).get("subset_manifest", {}).get("path")
    path = ROOT / recorded if recorded else ROOT / "eval" / "results" / "e4_stage2_subset_manifest.json"
    return _read_json(path)


def _observable_row(row: dict) -> dict:
    """Keep execution/harm evidence while removing system conclusions."""
    result = {key: row.get(key) for key in _OBSERVABLE_FIELDS if key in row}
    if _SYSTEM_LABELS & result.keys():
        raise AssertionError("review evidence leaked a system label")
    return result


def _case_packet(run_dir: Path, selected: dict, case_summary: dict,
                 reviewer: str, run_metadata: dict) -> dict:
    rows = case_summary.get("rows") or []
    if not rows:
        raise ValueError(f"case has no frozen evidence rows: {selected['case_id']}")
    artifact_hashes = case_summary.get("artifact_hashes") or {}
    return {
        "packet_schema_version": 1,
        "packet_type": "E4-stage2-independent-review",
        "reviewer": reviewer,
        "run_id": run_metadata["run_id"],
        "queue_index": selected["queue_index"],
        "case_id": selected["case_id"],
        "tx_hash": selected["tx_hash"],
        "block": selected["block"],
        "provenance": {
            "run_metadata_sha256": sha256_file(run_dir / "run_metadata.json"),
            "system_summary_sha256": sha256_file(run_dir / "systematic_subset_summary.json"),
            "provenance_audit_sha256": sha256_file(run_dir / "provenance_audit.json"),
            "raw_artifact_hashes": artifact_hashes,
        },
        "evidence": {
            "baseline": _observable_row(rows[0]),
            "mutations": [_observable_row(row) for row in rows[1:]],
        },
        "review": {
            "baseline_valid": "pending",
            "harm_measurable": "pending",
            "mutation_validity": "pending",
            "causal_classification": "pending",
            "eligibility_reason": "",
            "evidence_references": [],
            "reviewer_note": "",
        },
    }


def build_packets(run_dir: Path = DEFAULT_RUN) -> list[dict]:
    """Build the same frozen evidence packet for each independent reviewer."""
    run_dir = run_dir.resolve()
    metadata = _read_json(run_dir / "run_metadata.json")
    manifest = _manifest_for_run(run_dir, metadata)
    summary = _read_json(run_dir / "systematic_subset_summary.json")
    if metadata.get("run_id") != run_dir.name:
        raise ValueError("run metadata identity does not match run directory")
    selected_cases = manifest.get("selected_cases") or []
    if not selected_cases:
        raise ValueError("review packet requires at least one selected case")
    if summary.get("selected") != len(selected_cases) or len(summary.get("results") or []) != len(selected_cases):
        raise ValueError("systematic summary is incomplete")
    case_summaries = {item["case_id"]: item for item in summary["results"]}
    packets = []
    for reviewer in ("reviewer_a", "reviewer_b"):
        rows = []
        for selected in manifest["selected_cases"]:
            case_summary = case_summaries.get(selected["case_id"])
            if case_summary is None:
                raise ValueError(f"missing case summary: {selected['case_id']}")
            rows.append(_case_packet(run_dir, selected, case_summary, reviewer, metadata))
        packets.append({"reviewer": reviewer, "cases": rows})
    return packets


def render_review_form(run_dir: Path = DEFAULT_RUN) -> str:
    """Render one human-friendly form shared by both independent reviewers."""
    run_dir = run_dir.resolve()
    metadata = _read_json(run_dir / "run_metadata.json")
    manifest = _manifest_for_run(run_dir, metadata)
    lines = [
        "# TraceGuard E4 Stage-2 Independent Review Form",
        "",
        "> Fill one copy for all five cases. Do not view the other reviewer's form.",
        "> `REVERT` is an observed execution result; it is not automatically causal.",
        "",
        f"- Run: `{metadata['run_id']}`",
        "- Reviewer: `[fill: reviewer_a or reviewer_b]`",
        "- Submitted at (UTC): `[fill]`",
        "- Source packet filename: `[fill]`",
        "- Source packet SHA-256: `[fill or leave for freeze script]`",
        "",
        "## Allowed answers",
        "",
        "- Evidence sufficient: `yes` / `no`",
        "- Baseline valid: `yes` / `no` / `inconclusive`",
        "- Harm measurable: `yes` / `no` / `unknown`",
        "- Mutation valid/applicable: `yes` / `no` / `inconclusive`",
        "- Proposed outcome: `CAUSE` / `NO_EFFECT` / `REVERT` / `INCONCLUSIVE`",
        "- Confidence: `high` / `medium` / `low`",
        "",
    ]
    for selected in manifest["selected_cases"]:
        lines.extend([
            f"## Case {selected['queue_index']}: {selected['case_id']}",
            "",
            f"- Transaction: `{selected['tx_hash']}`",
            f"- Block: `{selected['block']}`",
            "- Evidence sufficient: `[yes/no]`",
            "- Baseline valid: `[yes/no/inconclusive]`",
            "- Harm measurable: `[yes/no/unknown]`",
            "- Mutation valid/applicable: `[yes/no/inconclusive]`",
            "- Proposed outcome: `[CAUSE/NO_EFFECT/REVERT/INCONCLUSIVE]`",
            "- Confidence: `[high/medium/low]`",
            "- Evidence references: `[artifact path or hash]`",
            "- Rationale: ",
            "",
        ])
    return "\n".join(lines) + "\n"


def write_form_template(run_dir: Path = DEFAULT_RUN) -> Path:
    run_dir = run_dir.resolve()
    output_dir = run_dir / "review_packets"
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "review_form_template.md"
    path.write_text(render_review_form(run_dir), encoding="utf-8", newline="\n")
    return path


def write_packets(run_dir: Path = DEFAULT_RUN) -> dict:
    run_dir = run_dir.resolve()
    packets = build_packets(run_dir)
    output_dir = run_dir / "review_packets"
    output_dir.mkdir(exist_ok=False)
    outputs = []
    for packet in packets:
        path = output_dir / f"{packet['reviewer']}.json"
        path.write_text(json.dumps(packet, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        outputs.append(str(path.relative_to(ROOT)))
    form_path = output_dir / "review_form_template.md"
    form_path.write_text(render_review_form(run_dir), encoding="utf-8", newline="\n")
    outputs.append(str(form_path.relative_to(ROOT)))
    return {
        "run_id": run_dir.name,
        "case_count": len(packets[0]["cases"]),
        "reviewers": ["reviewer_a", "reviewer_b"],
        "aggregate_outcome_included": False,
        "outputs": outputs,
        "raw_votes": "separate append-only files; not generated by this command",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--form-only", action="store_true")
    args = parser.parse_args(argv)
    if args.form_only:
        path = write_form_template(args.run)
        print(json.dumps({"form": str(path.relative_to(ROOT))}, ensure_ascii=False))
    else:
        print(json.dumps(write_packets(args.run), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
