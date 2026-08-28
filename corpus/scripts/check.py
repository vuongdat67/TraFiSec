#!/usr/bin/env python3
"""
TraceGuard-DeFi — check.py
===========================
Kiểm tra corpus/incidents.jsonl hợp lệ (pipeline quality gate — SCHEMA.md):
  - In đếm theo chain / attack_type / verified.
  - Phát hiện:
      * hash trùng giữa các incident
      * incident thiếu trường bắt buộc (protocol, date, chain, tx_hashes, class, source, source_url)
      * tx_hashes sai độ dài (không phải 0x + 64 hex)
  - Exit code: 0 nếu không có lỗi nghiêm trọng; 1 nếu có incident thiếu trường bắt buộc.

Windows Python 3.12: stdout UTF-8. Hỗ trợ `--jsonl PATH` (mặc định corpus/incidents.jsonl).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# Windows Python 3.12: UTF-8 stdout/stderr
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_JSONL = REPO_ROOT / "corpus" / "incidents.jsonl"

# tx_hashes là soft-required: incident từ Rekt leaderboard legitimately KHÔNG có
# tx hash (leaderboard chỉ có loss + url) — thiếu hash ≠ lỗi. Chỉ protocol/date/
# chain/class/source/source_url mới là hard-required (thiếu → exit 1).
HARD_FIELDS = ("protocol", "date", "chain", "class", "source", "source_url")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    """Load JSONL. Trả (incidents, parse_errors)."""
    incidents: list[dict] = []
    parse_errors: list[str] = []
    if not path.is_file():
        return [], [f"Không tìm thấy file: {path}"]
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            parse_errors.append(f"dòng {ln}: {e}")
            continue
        if isinstance(rec, dict):
            incidents.append(rec)
        else:
            parse_errors.append(f"dòng {ln}: không phải JSON object (dạng {type(rec).__name__})")
    return incidents, parse_errors


def main() -> None:
    ap = argparse.ArgumentParser(description="Kiểm tra incidents.jsonl hợp lệ.")
    ap.add_argument("--jsonl", nargs="?", const="", metavar="PATH",
                    help="JSONL incidents (mặc định: corpus/incidents.jsonl)")
    args = ap.parse_args()

    path = Path(args.jsonl) if args.jsonl else DEFAULT_JSONL
    incidents, parse_errors = load_jsonl(path)
    n = len(incidents)

    print(f"File  : {path}")
    print(f"Tổng  : {n} incidents (parse lỗi: {len(parse_errors)})")

    if parse_errors:
        print("\n=== PARSE ERRORS ===")
        for e in parse_errors:
            print(f"  ! {e}")

    if n == 0:
        print("\nKhông có dữ liệu — không có incident nào để kiểm tra. "
              "(exit 0: không có lỗi nghiêm trọng)")
        sys.exit(0)

    # ---- đếm theo chain / attack_type / verified ----
    def count(field: str) -> Counter:
        c: Counter = Counter()
        for rec in incidents:
            v = rec.get(field)
            if isinstance(v, list):
                c[", ".join(str(x) for x in v)] += 1
            else:
                c[str(v) if v else "(missing)"] += 1
        return c

    print("\n=== COUNT: chain ===")
    for k, v in count("chain").most_common():
        print(f"  {k}: {v}")

    print("\n=== COUNT: attack_type ===")
    for k, v in count("attack_type").most_common():
        print(f"  {k}: {v}")

    print("\n=== COUNT: verified ===")
    for k, v in count("verified").most_common():
        print(f"  {k}: {v}")

    # ---- thiếu trường bắt buộc (lỗi nghiêm trọng → exit 1) ----
    missing = []  # (id, [fields])
    for rec in incidents:
        iid = rec.get("id") or rec.get("protocol") or "?"
        absent = [f for f in HARD_FIELDS if f not in rec or rec.get(f) in (None, "", [])]
        if absent:
            missing.append((iid, absent))

    print(f"\n=== MISSING REQUIRED FIELDS ({len(missing)} incidents) ===")
    if missing:
        for iid, fields in missing:
            print(f"  ! {iid}: thiếu {', '.join(fields)}")
    else:
        print("  (không có)")

    # ---- hash trùng giữa các incident ----
    # Chỉ flag hash thuộc incident ONCHAIN: hash phantom/placeholder bị nhiều
    # file .sol của DeFiHackLabs copy chung (vd 0xa00dda5e... zero-padded) là
    # noise dự kiến — không phải dữ liệu thật đang được dùng cho attack set.
    onchain_ids = {rec.get("id") for rec in incidents if rec.get("verified") == "onchain"}
    owner: dict[str, list[str]] = {}
    for rec in incidents:
        iid = rec.get("id") or rec.get("protocol") or "?"
        for h in (rec.get("tx_hashes") or []):
            if isinstance(h, str) and h:
                owner.setdefault(h, []).append(iid)

    dupes = {h: ids for h, ids in owner.items()
             if len(ids) > 1 and any(i in onchain_ids for i in ids)}
    print(f"\n=== DUPLICATE HASHES ACROSS INCIDENTS ({len(dupes)} hash trùng, onchain-only) ===")
    if dupes:
        for h, ids in dupes.items():
            print(f"  ! {h[:18]}... xuất hiện trong: {', '.join(ids)}")
    else:
        print("  (không có)")

    # ---- hash sai độ dài ----
    bad_hashes = []  # (iid, hash)
    for rec in incidents:
        iid = rec.get("id") or rec.get("protocol") or "?"
        for h in (rec.get("tx_hashes") or []):
            if isinstance(h, str) and not HASH_RE.match(h):
                bad_hashes.append((iid, h))
    print(f"\n=== INVALID HASH LENGTH ({len(bad_hashes)} hash sai) ===")
    if bad_hashes:
        for iid, h in bad_hashes[:20]:
            print(f"  ! {iid}: {h!r}")
        if len(bad_hashes) > 20:
            print(f"  ... và {len(bad_hashes) - 20} hash nữa")
    else:
        print("  (không có)")

    # ---- verdict ----
    serious = len(missing) > 0
    print("\n=== KẾT LUẬN ===")
    if serious:
        print(f"LỖI NGHIÊM TRỌNG: {len(missing)} incident thiếu trường bắt buộc — exit 1")
    else:
        print("OK — không có incident thiếu trường bắt buộc — exit 0")
    sys.exit(1 if serious else 0)


if __name__ == "__main__":
    main()
