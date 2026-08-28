"""Cross-platform, fail-closed offline artifact reproduction."""
from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
CACHE_GZ = ROOT / "eval" / "artifacts" / "e1_trace_cache.jsonl.gz"


def run(*args: str) -> None:
    print(f"\n$ {' '.join(args)}", flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def ensure_cache() -> None:
    if CACHE.exists():
        return
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(CACHE_GZ, "rb") as source, CACHE.open("wb") as target:
        shutil.copyfileobj(source, target)


def main() -> int:
    os.environ.setdefault("PYTHONUTF8", "1")
    ensure_cache()
    py = sys.executable
    run("ruff", "check", "src", "eval", "corpus/scripts", "tests", "tools")
    run(py, "-m", "pytest", "-q")
    run(py, "-m", "compileall", "-q", "src", "pilot", "eval", "corpus", "tests", "tools")
    run(py, "-m", "eval.e1_train", "--scale", "A1")
    run(py, "-m", "eval.e1_robustness", "--seeds", "30", "--bootstrap", "1000")
    run(py, "-m", "eval.e1_baselines", "--scale", "A1")
    run(py, "-m", "eval.e2_ablation")
    run(py, "-m", "eval.dataset_audit")
    run(py, "-m", "eval.corpus_diversity")
    run(py, "-m", "eval.e4_preregistration")
    run(py, "-m", "eval.hard_negative_queue", "--per-incident", "2")
    run(py, "corpus/scripts/build_review_packets.py")
    run(py, "corpus/scripts/audit_review_workflow.py")
    run(py, "corpus/scripts/audit_ground_truth.py")
    run(py, "corpus/scripts/audit_hard_negatives.py")
    run(py, "-m", "eval.hard_negative_evaluation")
    run(py, "-m", "eval.validity_controls")
    run(py, "-m", "eval.e4_sensitivity")
    run(py, "corpus/scripts/check.py")
    run(py, "-m", "eval.make_fig3_e1")
    run(py, "-m", "eval.research_report")
    run(py, "tools/audit_claims.py")
    run(py, "tools/audit_citations.py")
    run(py, "tools/build_semantic_fingerprint.py")
    run(py, "tools/verify_figures.py")
    for figure in ("fig1_architecture.svg", "fig2_evidence_example.svg"):
        run(py, "tools/check_canvas.py", f"figures/{figure}")
        run(py, "tools/check_overlap.py", f"figures/{figure}")
    run(py, "tools/audit_secrets.py")
    run(py, "tools/audit_paths.py")
    run(py, "-m", "eval.cache_release", "--check")
    run(py, "tools/build_checksums.py")
    run(py, "tools/build_checksums.py", "--check")
    if (ROOT / ".git").exists():
        run("git", "diff", "--check")
    print("\nOffline artifact reproduction completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
