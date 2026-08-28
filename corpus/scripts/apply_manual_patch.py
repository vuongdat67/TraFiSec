"""
TraceGuard-DeFi corpus — apply_manual_patch.py: merge manual label patch vào incidents.jsonl
==============================================================================================
Pipeline bước 5.5 (sau label.py, trước check.py): agent/researcher ghi nhãn thủ công
(bằng chứng từ postmortem / PoC .sol) vào corpus/raw/manual_label_patch.jsonl, script này
merge ngược vào incidents.jsonl theo id.

Patch format (1 JSON/line):
  {id, attack_type, gt_factors, evidence, sources}
  - attack_type: taxonomy SCHEMA.md §1 (bắt buộc, in VALID_TYPES)
  - gt_factors: list factor CAUSE (có thể rỗng/["unknown"] nếu không có bằng chứng — KHÔNG đoán)
  - evidence: 1-2 câu mô tả cơ chế từ nguồn
  - sources: list URL nguồn đã đọc

Hành vi:
  - ghi đè attack_type (nếu khác)
  - ghi đè gt_factors (kể cả ["unknown"] — ghi đè auto-label cũ nếu evidence cho thấy sai)
  - nối "sources" + evidence vào notes (không ghi đè)
  - id không tìm thấy → warn (không crash)
  - không sửa record không có trong patch

Usage:
    python corpus/scripts/apply_manual_patch.py            # merge patch vào incidents.jsonl
    python corpus/scripts/apply_manual_patch.py --dry-run  # in diff, không ghi
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JSONL = REPO_ROOT / "corpus" / "incidents.jsonl"
PATCH = REPO_ROOT / "corpus" / "raw" / "manual_label_patch.jsonl"

VALID_TYPES = {"flash-loan", "oracle", "reentrancy", "governance/access",
               "accounting", "precision", "bridge", "token", "rug-pull", "other"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", default=str(JSONL))
    ap.add_argument("--patch", default=str(PATCH))
    ap.add_argument("--dry-run", action="store_true", help="In diff, không ghi file")
    args = ap.parse_args()

    jsonl_path = Path(args.jsonl)
    patch_path = Path(args.patch)

    if not jsonl_path.is_file():
        print(f"[lỗi] không thấy {jsonl_path}")
        sys.exit(1)
    if not patch_path.is_file():
        print(f"[lỗi] không thấy {patch_path} — chạy agent enrich trước")
        sys.exit(1)

    patches = [json.loads(line) for line in patch_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # validate patch
    bad = []
    for p in patches:
        if p.get("attack_type") not in VALID_TYPES:
            bad.append(f"{p.get('id')}: attack_type {p.get('attack_type')!r} ngoài taxonomy")
        if not p.get("sources"):
            bad.append(f"{p.get('id')}: thiếu sources")
    if bad:
        print("PATCH LỖI (dừng — không áp dụng):")
        for b in bad:
            print(f"  ! {b}")
        sys.exit(1)

    records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {str(r.get("id")): r for r in records}

    changed = 0
    not_found = []
    for p in patches:
        rec = by_id.get(str(p.get("id")))
        if rec is None:
            not_found.append(p.get("id"))
            continue
        before = (rec.get("attack_type"), rec.get("gt_factors"))
        rec["attack_type"] = p["attack_type"]
        rec["gt_factors"] = list(p.get("gt_factors") or ["unknown"])
        # nối sources + evidence vào notes
        src_note = " | ".join(p["sources"])
        if src_note:
            rec["notes"] = f"{rec['notes']} [manual: {p['evidence']}] [src: {src_note}]".strip()
        after = (rec.get("attack_type"), rec.get("gt_factors"))
        if before != after:
            changed += 1

    if not_found:
        print(f"WARN: {len(not_found)} id không có trong incidents.jsonl: {not_found}")

    if args.dry_run:
        print(f"==> dry-run: {changed}/{len(patches)} records sẽ đổi → {jsonl_path}")
        return

    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"==> {changed}/{len(patches)} records được cập nhật → {jsonl_path}")


if __name__ == "__main__":
    main()
