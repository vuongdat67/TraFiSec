"""Fail closed when release-facing text artifacts expose host-specific paths."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_checksums import TARGETS  # noqa: E402

REPORT = ROOT / "eval" / "results" / "path_audit.json"

# Keep the fragments split so this source file does not flag itself when it is
# later added to a broader release inventory.
PATH_PATTERNS = (
    re.compile(r"\b[A-Za-z]:" + r"\\"),
    re.compile("/" + "artifact/"),
    re.compile(r"/(?:home|Users)/[^/\s]+/"),
)


def suspicious_lines(text: str) -> list[int]:
    """Return 1-based line numbers containing a host-specific absolute path."""
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if any(pattern.search(line) for pattern in PATH_PATTERNS)
    ]


def candidate_paths(root: Path = ROOT) -> list[Path]:
    paths = {root / relative for relative in TARGETS}
    paths.update((root / "eval" / "results").glob("*manifest.json"))
    raw_logs = root / "eval" / "results" / "raw_logs"
    for suffix in ("*.log", "*.err", "*.json", "*.csv", "*.md", "*.txt"):
        paths.update(raw_logs.rglob(suffix))
    paths.add(root / "tools" / "puppeteer-config.json")
    paths.discard(Path(__file__).resolve())
    return sorted(paths)


def audit(root: Path = ROOT) -> dict:
    issues: list[dict[str, object]] = []
    scanned = 0
    for path in candidate_paths(root):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        lines = suspicious_lines(text)
        if lines:
            issues.append({
                "path": path.relative_to(root).as_posix(),
                "lines": lines,
            })
    return {
        "schema_version": 1,
        "status": "pass" if not issues else "fail",
        "files_scanned": scanned,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args(argv)
    result = audit()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8",
                           newline="\n")
    if result["issues"]:
        print("Release path audit failed:")
        for issue in result["issues"]:
            print(f"- {issue['path']}: lines {issue['lines']}")
        return 1
    print(f"Release path audit passed ({result['files_scanned']} text artifacts).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
