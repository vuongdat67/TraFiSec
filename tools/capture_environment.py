"""Capture host/tool/package provenance for a replication run."""
from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.run_manifest import runtime_provenance, sha256_file  # noqa: E402


def capture() -> dict:
    packages = {}
    for distribution in metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip().lower()
        if name:
            packages[name] = distribution.version
    return {
        "schema_version": 1,
        "runtime": runtime_provenance(),
        "installed_packages": dict(sorted(packages.items())),
        "requirements_sha256": sha256_file(ROOT / "requirements.txt"),
        "semantic_fingerprint_sha256": sha256_file(
            ROOT / "eval" / "artifacts" / "semantic_fingerprint.json"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    payload = capture()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"Runtime provenance written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
