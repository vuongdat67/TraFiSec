"""Compare two semantic fingerprints with cross-host float tolerance.

The offline pipeline must reproduce the *scientific semantics* of the
published evidence on any supported host. Float outputs from BLAS/libm and
scipy's L-BFGS-B can differ in their last few bits between Windows/macOS and
Linux even after canonicalization to 9 decimals: a value that rounds to
0.513561437 on one host may produce 0.513561437 on Linux (or occasionally a
boundary-crossing 0.513561436). Integer counts, hashes, strings, nested
structure, and list *order* must match exactly; floats must match within an
absolute tolerance far tighter than any number the paper quotes (paper numbers
use at most 3-4 significant figures).

This is a deliberate replacement for `cmp`: byte-identity was too strict for a
cross-platform scientific replay.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

TOLERANCE = 1e-5  # cross-host BLAS/libm/L-BFGS-B: canonical 9-decimal floats can
# differ in their last few digits between Windows and Linux (observed up to 4.4e-6
# on a hard-negative frozen threshold). 1e-5 is still ~10x tighter than any number
# the paper quotes (3-4 significant figures), so it keeps catching real drift.


def _float_close(a: float, b: float) -> bool:
    return abs(a - b) <= TOLERANCE * max(1.0, abs(a), abs(b))


def _diff(a, b, path: str) -> list[str]:
    """Return a list of human-readable mismatches between a and b."""
    if a is None or b is None:
        return [] if a is b else [f"{path}: None != {b!r}"]
    if isinstance(a, float) or isinstance(b, float):
        try:
            return [] if _float_close(float(a), float(b)) else \
                [f"{path}: float {a!r} != {b!r}"]
        except (TypeError, ValueError):
            return [f"{path}: float vs non-float {a!r} != {b!r}"]
    if isinstance(a, int) and isinstance(b, int):
        return [] if a == b else [f"{path}: int {a} != {b}"]
    if isinstance(a, str) or isinstance(b, str):
        return [] if a == b else [f"{path}: str {a!r} != {b!r}"]

    if isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            missing = set(a) - set(b)
            extra = set(b) - set(a)
            issues = []
            if missing:
                issues.append(f"{path}: keys only in first: {sorted(missing)}")
            if extra:
                issues.append(f"{path}: keys only in second: {sorted(extra)}")
            return issues
        issues: list[str] = []
        for key in sorted(a):
            issues.extend(_diff(a[key], b[key], f"{path}.{key}"))
        return issues

    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: list length {len(a)} != {len(b)}"]
        issues = []
        for i, (x, y) in enumerate(zip(a, b)):
            issues.extend(_diff(x, y, f"{path}[{i}]"))
        return issues

    return [f"{path}: type {type(a).__name__} != {type(b).__name__}: {a!r} != {b!r}"]


def compare(submitted: Path, regenerated: Path,
            report_out: Path | None = None) -> bool:
    a = json.loads(submitted.read_text(encoding="utf-8"))
    b = json.loads(regenerated.read_text(encoding="utf-8"))
    mismatches = _diff(a, b, "$")
    ok = not mismatches
    report_lines = [
        f"submitted = {submitted}",
        f"regenerated = {regenerated}",
        "MATCH" if ok else
        f"MISMATCH ({len(mismatches)} difference(s), float tolerance {TOLERANCE:.0e})",
    ]
    if not ok:
        report_lines.append("Differences:")
        report_lines.extend(f"  {line}" for line in mismatches[:200])
    text = "\n".join(report_lines)
    if report_out is not None:
        report_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("submitted", type=Path,
                        help="committed semantic fingerprint")
    parser.add_argument("regenerated", type=Path,
                        help="fingerprint produced by pipeline on this host")
    parser.add_argument("--report", type=Path, default=None,
                        help="optional report file path")
    args = parser.parse_args(argv)
    return 0 if compare(args.submitted, args.regenerated, args.report) else 1


if __name__ == "__main__":
    raise SystemExit(main())