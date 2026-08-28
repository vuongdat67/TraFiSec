"""Check that paper LaTeX citations and BibTeX stay synchronized."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAPER_TEX = ROOT / "paper" / "main.tex"
PAPER_BIB = ROOT / "paper" / "references.bib"

BIB_KEY = re.compile(r"@\w+\{\s*([^,\s]+)\s*,")
CITE_CMD = re.compile(r"\\cite(?:\[[^\]]*\])?\{([^}]+)\}")


def bibliography_keys(text: str) -> list[str]:
    return BIB_KEY.findall(text)


def citation_keys(text: str) -> set[str]:
    keys: set[str] = set()
    for group in CITE_CMD.findall(text):
        for k in group.split(","):
            k = k.strip()
            if k:
                keys.add(k)
    return keys


def audit(root: Path = ROOT) -> dict:
    tex_path = root / "paper" / "main.tex"
    bib_path = root / "paper" / "references.bib"
    errors: list[str] = []

    if not tex_path.exists() or not bib_path.exists():
        return {"status": "PASS", "errors": []}

    bib_list = bibliography_keys(bib_path.read_text(encoding="utf-8"))
    bib = set(bib_list)

    if len(bib_list) != len(bib):
        errors.append("duplicate bibliography key in references.bib")

    cited = citation_keys(tex_path.read_text(encoding="utf-8"))
    missing = cited - bib
    if missing:
        errors.append(f"main.tex cites undefined BibTeX keys: {sorted(missing)}")

    return {
        "status": "PASS" if not errors else "FAIL",
        "bibliography_entries": len(bib),
        "cited_entries": len(cited),
        "errors": errors,
    }


def main() -> int:
    res = audit()
    if res["status"] == "FAIL":
        print("[FAIL] Citation mismatches detected:", file=sys.stderr)
        for err in res["errors"]:
            print(f"  * {err}", file=sys.stderr)
        return 1
    print(f"[PASS] All {res['cited_entries']} citations in main.tex resolve correctly in references.bib ({res['bibliography_entries']} entries).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
