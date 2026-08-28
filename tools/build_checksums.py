"""Build or verify the exact release-snapshot checksum inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "eval" / "artifacts"
JSON_PATH = ARTIFACTS / "release_inventory.json"
SUMS_PATH = ARTIFACTS / "SHA256SUMS"

STATIC_TARGETS = (
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    ".github/workflows/ci.yml",
    "CITATION.cff",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "requirements.txt",
    "pyproject.toml",

    "corpus/SCHEMA.md",
    "corpus/annotations/README.md",
    "corpus/incidents.jsonl",
    "corpus/annotations/e4.schema.json",
    "corpus/annotations/hard_negative.schema.json",
    "corpus/annotations/review_submissions/README.md",
    "corpus/annotations/review_packets/e4_reviewer_a.jsonl",
    "corpus/annotations/review_packets/e4_reviewer_b.jsonl",
    "corpus/annotations/review_packets/hard_negatives_reviewer_a.jsonl",
    "corpus/annotations/review_packets/hard_negatives_reviewer_b.jsonl",
    "eval/artifacts/cache_release_manifest.json",
    "eval/artifacts/e1_trace_cache.jsonl.gz",
    "eval/artifacts/semantic_fingerprint.json",
    "eval/config/paper.json",
    "eval/fidelity_set_v2.json",
    "eval/e4_fixed_set_v2.json",
    "eval/results/PAPER_READINESS.md",
    "eval/results/README.md",
    "eval/results/DATASET_AUDIT.md",
    "eval/results/E5_RPC_PREFLIGHT.md",
    "eval/results/citation_audit.json",
    "eval/results/claim_audit.json",
    "eval/results/dataset_audit.json",
    "eval/results/dataset_audit_manifest.json",
    "eval/results/corpus_diversity.csv",
    "eval/results/path_audit.json",
    "eval/results/review_workflow_audit.json",
    "eval/results/e1_evaluation.json",
    "eval/results/e1_manifest.json",
    "eval/results/e1_e3_manifest.json",
    "eval/results/e1_main.csv",
    "eval/results/e1_baselines.csv",
    "eval/results/e1_model.json",
    "eval/results/e1_e3_robustness.csv",
    "eval/results/e1_e3_robustness.json",
    "eval/results/e2_ablation.csv",
    "eval/results/e4_preregistration_queue.json",
    "eval/results/e4_preregistration_queue.csv",
    "eval/results/e4_preregistration_manifest.json",
    "eval/results/e4_sensitivity.json",
    "eval/results/e6_latency.csv",
    "eval/results/ground_truth_audit.json",
    "eval/results/ground_truth_audit.csv",
    "eval/results/hard_negative_review_queue.json",
    "eval/results/hard_negative_review_queue.csv",
    "eval/results/hard_negative_review_queue_manifest.json",
    "eval/results/hard_negative_audit.json",
    "eval/results/hard_negative_audit.csv",
    "eval/results/hard_negative_evaluation.json",
    "eval/results/validity_controls.json",
    "eval/results/legacy/e5_fidelity.csv",
    "eval/results/legacy/e5_fidelity_v2_partial.csv",
    "eval/results/raw_logs/e5_preflight_runs/e5-v2-public-preflight6-20260813/e5_fidelity.csv",
    "eval/results/raw_logs/e5_preflight_runs/e5-v2-public-preflight6-20260813/manifest.json",
    "eval/results/runs/e5-preflight-20260813-full300s/e5_fidelity.csv",
    "eval/results/runs/e5-preflight-20260813-full300s/e5_preflight.json",
    "eval/results/runs/e5-preflight-20260813-full300s/manifest.json",
    "figures/fig1_architecture.png",
    "figures/fig1_architecture.svg",
    "figures/fig2_evidence_example.png",
    "figures/fig2_evidence_example.svg",
    "figures/fig3_e1_prcurve.png",
    "figures/fig3_e1_prcurve.svg",
    "docs/research/baseline_feasibility.md",
    "docs/en/draft.md",
    "docs/vi/draft.md",
    "docs/research/guide_legacy.md",
    "docs/research/pilot.md",
    "docs/en/proposal_legacy.md",
    "docs/research/scope.md",
    "docs/en/paper.md",
    "docs/vi/paper.md",
    "docs/references.bib",
    "docs/research/design_decisions.md",
    "docs/research/sources.md",
    "docs/plan.md",
    "docs/release_checklist.md",
    "docs/vi/master_report_legacy.md",
    "pilot/README.md",
    "pilot/setup_archive.md",
)

SOURCE_GLOBS = (
    "src/**/*.py",
    "pilot/**/*.py",
    "pilot/**/*.md",
    "pilot/**/*.csv",
    "pilot/**/*.sol",
    "pilot/oraclestub/*.json",
    "eval/*.py",
    "eval/legacy/*.py",
    "eval/artifacts/*.md",
    "eval/results/*.md",
    "eval/results/legacy/*.md",
    "eval/results/raw_logs/*.md",
    "eval/results/runs/*.md",
    "corpus/*.py",
    "corpus/scripts/*.py",
    "corpus/annotations/*.jsonl",
    "corpus/annotations/review_submissions/*.jsonl",
    "tests/*.py",
    "tools/*.py",
    "figures/*.mmd",
    "docs/**/*.md",
    "docs/**/*.bib",
    "tools/*.css",
    "tools/package*.json",
    "tools/puppeteer-config.json",
)




def discover_targets(root: Path = ROOT) -> tuple[str, ...]:
    """Return every declared artifact plus all reproducibility-critical code."""
    targets = set(STATIC_TARGETS)
    for pattern in SOURCE_GLOBS:
        targets.update(
            path.relative_to(root).as_posix()
            for path in root.glob(pattern)
            if path.is_file() and "__pycache__" not in path.parts
        )
    return tuple(sorted(targets))


TARGETS = discover_targets()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe(root: Path, relative: str) -> dict:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(f"release artifact missing: {relative}")
    return {"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)}


def build(root: Path = ROOT) -> dict:
    return {
        "schema_version": 1,
        "algorithm": "SHA-256",
        "entries": [describe(root, relative) for relative in TARGETS],
    }


def verify(data: dict, root: Path = ROOT,
           expected_targets: tuple[str, ...] | None = None) -> list[str]:
    errors: list[str] = []
    if expected_targets is not None:
        recorded = {entry.get("path", "") for entry in data.get("entries", [])}
        expected = set(expected_targets)
        errors.extend(f"not inventoried: {path}" for path in sorted(expected - recorded))
        errors.extend(f"unexpected inventory entry: {path}"
                      for path in sorted(recorded - expected))
    for expected in data.get("entries", []):
        relative = expected.get("path", "")
        try:
            actual = describe(root, relative)
        except FileNotFoundError:
            errors.append(f"missing: {relative}")
            continue
        if actual["bytes"] != expected.get("bytes"):
            errors.append(f"size mismatch: {relative}")
        if actual["sha256"] != expected.get("sha256"):
            errors.append(f"hash mismatch: {relative}")
    return errors


def write(data: dict) -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8",
                         newline="\n")
    lines = [f"{entry['sha256']}  {entry['path']}" for entry in data["entries"]]
    SUMS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
        errors = verify(data, expected_targets=TARGETS)
        if errors:
            print("Release checksum verification failed:")
            print("\n".join(f"- {error}" for error in errors))
            return 1
        print(f"Release checksum verification passed ({len(data['entries'])} files).")
        return 0
    data = build()
    write(data)
    print(f"Release checksum inventory written ({len(data['entries'])} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
