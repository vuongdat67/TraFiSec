"""Fail when tracked-style artifact files appear to contain credentials.

The scanner reports only file and line number; it never echoes a candidate
secret. Real local ``.env`` files are intentionally excluded.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "ex", "runs", "paper", "report"}
EXCLUDED_FILES = {".env"}
TEXT_SUFFIXES = {
    "", ".csv", ".err", ".json", ".jsonl", ".log", ".md", ".ps1",
    ".py", ".toml", ".tsv", ".txt", ".yaml", ".yml",
}

URL_TOKEN_PATTERNS = (
    re.compile(r"alchemy\.com/v2/([^\s\"'|]+)", re.IGNORECASE),
    re.compile(r"infura\.io/v3/([^\s\"'|]+)", re.IGNORECASE),
    re.compile(r"[?&](?:api_?key|dkey)=([^\s\"'&|]+)", re.IGNORECASE),
)
PREFIX_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:alch_|sk-|ghp_|github_pat_)[A-Za-z0-9_-]{12,}",
    re.IGNORECASE,
)
SAFE_MARKERS = (
    "redacted", "example", "your", "replace", "dummy", "demo", "xxxx",
    "key", "os.environ", "getenv", "<archive_rpc_url>", "<alchemy_or_quicknode_url>",
)
SAFE_PLACEHOLDER_VALUES = {"credential", "<api_key>", "<alchemy_key>", "<quicknode_endpoint>"}


def _safe_token(token: str) -> bool:
    normalized = token.strip("<>[]{}()$%")
    return (
        not normalized
        or normalized.lower() in SAFE_PLACEHOLDER_VALUES
        or any(marker in normalized.lower() for marker in SAFE_MARKERS)
    )


def suspicious_lines(text: str) -> list[int]:
    """Return one-based line numbers containing credential-like material."""
    findings: list[int] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        suspicious = any(
            not _safe_token(match.group(1))
            for pattern in URL_TOKEN_PATTERNS
            for match in pattern.finditer(line)
        )
        if not suspicious:
            match = PREFIX_PATTERN.search(line)
            suspicious = bool(match and not _safe_token(match.group(0)))
        if suspicious:
            findings.append(line_no)
    return findings


def candidate_files() -> list[Path]:
    out: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.name in EXCLUDED_FILES:
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES and path.stat().st_size <= 25_000_000:
            out.append(path)
    return sorted(out)


def audit() -> dict:
    findings: list[tuple[Path, int]] = []
    for path in candidate_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend((path, line_no) for line_no in suspicious_lines(text))
    return {
        "status": "PASS" if not findings else "FAIL",
        "findings": [(str(p.relative_to(ROOT)), l) for p, l in findings],
        "errors": [f"{p}:{l} contains suspicious credential" for p, l in findings],
    }


def main() -> int:
    res = audit()
    if res["status"] == "FAIL":
        print("Credential-like material found (values suppressed):")
        for finding in res["errors"]:
            print(f"  {finding}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
