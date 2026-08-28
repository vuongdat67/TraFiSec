"""Generate a conservative, machine-readable audit of the E1 trace cache.

This audit does not assign new labels.  It reports what can and cannot be
supported by the current cache: duplicate handling, label provenance, attack
family/protocol coverage, view availability, and structural near negatives.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .e1_common import parse_cached_row
from .e1_robustness import _is_near_negative
from .e1_train import RESULTS_DIR, build_dataset
from .run_manifest import portable_path, utc_run_id, write_manifest

ROOT = Path(__file__).resolve().parent.parent
CACHE_DEFAULT = RESULTS_DIR / "e1_trace_cache.jsonl"


def audit(cache: Path) -> dict:
    line_count = malformed = 0
    hashes: list[str] = []
    raw_labels: Counter[str] = Counter()
    raw_status: Counter[str] = Counter()
    raw_errors = 0
    with cache.open(encoding="utf-8") as handle:
        for line in handle:
            line_count += 1
            row = parse_cached_row(line)
            if row is None:
                malformed += 1
                continue
            hashes.append(row["tx_hash"].lower())
            raw_labels[str(row.get("label") or "missing")] += 1
            raw_status[str(row.get("status"))] += 1
            raw_errors += int(bool(row.get("error")))

    ds = build_dataset(cache)
    attacks = [r for r in ds["rows"] if r["label"] == "attack"]
    benign = [r for r in ds["rows"] if r["label"] == "benign"]
    coverage = {
        label: {
            view: sum(ds["scores"][r["tx_hash"]].get(view) is not None for r in rows)
            for view in next(iter(ds["scores"].values())).keys()
        }
        for label, rows in (("attack", attacks), ("benign", benign))
    } if ds["scores"] else {}
    near = [r for r in benign if _is_near_negative(r["row"])]
    protocols = Counter(str(r.get("protocol") or "missing") for r in attacks)
    benign_protocols = Counter(str(r.get("protocol") or "missing") for r in benign)
    blocks = [int(r["block"]) for r in attacks if r.get("block") is not None]
    duplicate_occurrences = line_count - malformed - len(set(hashes))

    return {
        "cache": portable_path(cache, ROOT.resolve()),
        "raw": {
            "line_count": line_count,
            "unique_hashes": len(set(hashes)),
            "duplicate_occurrences": duplicate_occurrences,
            "malformed_lines": malformed,
            "label_counts_before_dedup": dict(raw_labels),
            "status_counts_before_dedup": dict(raw_status),
            "rows_with_error": raw_errors,
        },
        "eligible": {
            "total": len(ds["rows"]),
            "attack": len(attacks),
            "benign": len(benign),
            "explicit_hard_negative": len(ds["hard_rows"]),
            "structural_near_negative": len(near),
        },
        "attack": {
            "family_counts": dict(Counter(r["attack_type"] for r in attacks)),
            "unique_protocols": len(protocols),
            "protocols_with_multiple_incidents": {
                key: value for key, value in protocols.items() if value > 1
            },
            "block_min": min(blocks) if blocks else None,
            "block_max": max(blocks) if blocks else None,
        },
        "benign": {
            "protocol_field_counts": dict(benign_protocols),
            "manually_verified_protocol_matched": 0,
            "label_semantics": "background transaction not present in the incident inventory",
        },
        "view_coverage": coverage,
        "scientific_constraints": [
            "Background negatives are open-world assumed-benign examples, not exhaustively verified benign ground truth.",
            "Structural near negatives are mined by generic selectors/complexity and are not manually verified protocol/time matches.",
            "The cache contains no explicit hard-negative rows under the current classifier.",
            "State-delta coverage is zero; measured screening results use three available views.",
            (
                "Token-flow coverage differs by label "
                f"({coverage['attack'].get('token_flow', 0)}/{coverage['attack'].get('call_structure', 0)} "
                f"attacks versus {coverage['benign'].get('token_flow', 0)}/"
                f"{coverage['benign'].get('call_structure', 0)} background), so coverage-conditioned "
                "sensitivity must accompany semantic ablation claims."
            ),
            "Every attack protocol appears once, so a meaningful held-protocol estimate cannot be computed from this corpus.",
        ],
    }


def render_markdown(data: dict) -> str:
    e = data["eligible"]
    raw = data["raw"]
    lines = [
        "# Dataset audit — generated",
        "",
        "This report describes label and feature evidence without upgrading any annotation.",
        "",
        "## Inventory",
        "",
        f"- Cache lines: {raw['line_count']}; unique transaction hashes: {raw['unique_hashes']}; "
        f"duplicate occurrences: {raw['duplicate_occurrences']}; malformed: {raw['malformed_lines']}.",
        f"- Evaluation-eligible rows: {e['total']} ({e['attack']} attacks, {e['benign']} background negatives).",
        f"- Explicit verified hard negatives: {e['explicit_hard_negative']}; structural near negatives: {e['structural_near_negative']}.",
        f"- Attack protocols: {data['attack']['unique_protocols']} unique for {e['attack']} incidents; "
        f"multi-incident protocols: {len(data['attack']['protocols_with_multiple_incidents'])}.",
        "",
        "## View coverage",
        "",
        "| Label | call_structure | token_flow | state_delta | economic |",
        "|---|---:|---:|---:|---:|",
    ]
    for label in ("attack", "benign"):
        cov = data["view_coverage"].get(label, {})
        lines.append(f"| {label} | {cov.get('call_structure', 0)} | {cov.get('token_flow', 0)} | "
                     f"{cov.get('state_delta', 0)} | {cov.get('economic', 0)} |")
    lines += ["", "## Constraints", ""]
    lines += [f"- {item}" for item in data["scientific_constraints"]]
    lines.append("")
    return "\n".join(lines)


def run(cache: Path = CACHE_DEFAULT, out_dir: Path = RESULTS_DIR) -> dict:
    data = audit(cache)
    run_id = utc_run_id("dataset-audit")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "dataset_audit.json"
    md_path = out_dir / "DATASET_AUDIT.md"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8", newline="\n")
    md_path.write_text(render_markdown(data), encoding="utf-8", newline="\n")
    manifest_path = out_dir / "dataset_audit_manifest.json"
    write_manifest(manifest_path, run_id=run_id, experiment="dataset-audit",
                   repository=ROOT, inputs={"trace_cache": cache},
                   parameters={}, command=[],
                   extra={"outputs": [str(json_path), str(md_path)]})
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the immutable E1 trace cache")
    parser.add_argument("--cache", type=Path, default=CACHE_DEFAULT)
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    data = run(args.cache, args.out_dir)
    print(render_markdown(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
