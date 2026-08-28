"""
TraceGuard-DeFi corpus — label.py: gán attack_type + gt_factors cho incidents
================================================================================
Pipeline bước 5 (xem corpus/SCHEMA.md §3). Gán nhãn tự động từ notes / tên
protocol / keywords trong tx, sau đó để con người review phần còn thiếu.

Usage:
    python corpus/scripts/label.py                      # in-place update incidents.jsonl
    python corpus/scripts/label.py --auto-only          # chỉ label chắc chắn (không đoán)
    python corpus/scripts/label.py --dry-run            # in stats, không ghi file

Nguyên tắc (SCHEMA.md §1): gt_factors KHÔNG đoán. Nếu notes/postmortem không
khẳng định factor → để ["unknown"] + notes. attack_type thì có thể suy từ cơ chế
(giúp phân bố corpus) nhưng ghi nguồn suy luận vào notes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")  # Windows cp1252 fix

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
INCIDENTS = REPO_ROOT / "corpus" / "incidents.jsonl"

# (regex, attack_type) — thứ tự: keyword đặc trưng trước
TYPE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"flash.?loan|flashloan|flash swap|flash.?mint|flash loan", re.I), "flash-loan"),
    (re.compile(r"price.?manip|oracle manip|oracle", re.I), "oracle"),
    (re.compile(r"reentrancy|re-entrancy|reentrant", re.I), "reentrancy"),
    (re.compile(r"governance|compromised.?key|private.?key|admin.?key|multisig|owner.?key", re.I), "governance/access"),
    (re.compile(r"precision|rounding|integer overflow|underflow", re.I), "precision"),
    (re.compile(r"donate|accounting|inflation attack", re.I), "accounting"),
    (re.compile(r"bridge|cross.?chain", re.I), "bridge"),
    (re.compile(r"approve|permit|signature reuse|phishing|token.?permit", re.I), "token"),
    (re.compile(r"rug.?pull|exit.?scam|honeypot", re.I), "rug-pull"),
]

# Factor keywords → gt_factors (chỉ dùng khi có evidence trong notes/postmortem)
FACTOR_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"flash.?loan|flashloan|flash swap|flash.?mint|flash loan", re.I), "f_fl"),
    (re.compile(r"price.?manip|oracle|pyth|chainlink|twap", re.I), "f_orc"),
    (re.compile(r"swap|am?m|uniswap|curve|balancer|cap|slice|amountIn", re.I), "f_swap"),
    (re.compile(r"key.?compromis|private.?key|admin.?key|owner|governance|multisig|signer|gnosis.?safe", re.I), "f_auth"),
    (re.compile(r"reentrancy|re-entrancy|reentrant", re.I), "f_re"),
]


VALID_TYPES = {"flash-loan", "oracle", "reentrancy", "governance/access",
               "accounting", "precision", "bridge", "token", "rug-pull", "other"}


def label_record(rec: dict) -> None:
    """Gán attack_type + gt_factors (nếu chưa có) cho 1 record. In-place."""
    hay = f"{rec.get('protocol','')} {rec.get('notes','')} {rec.get('source_url','')}".lower()
    # attack_type: chuẩn hoá về taxonomy (SCHEMA.md §1). Nếu attack_type hiện tại
    # là mô tả dài (defihacklabs title suffix) → chạy keyword rules.
    at = (rec.get("attack_type") or "other").strip()
    if not at or at == "other" or at not in VALID_TYPES:
        mapped = None
        for pat, t in TYPE_RULES:
            if pat.search(at + " " + hay):
                mapped = t
                break
        rec["attack_type"] = mapped or "other"
    else:
        rec["attack_type"] = at

    # gt_factors: chỉ khi chưa có (mặc định ["unknown"])
    factors = rec.get("gt_factors") or []
    if factors == ["unknown"]:
        found = []
        for pat, f in FACTOR_RULES:
            if pat.search(hay):
                found.append(f)
        if found:
            rec["gt_factors"] = list(dict.fromkeys(found))  # dedupe, giữ thứ tự
            rec["notes"] = (rec["notes"] + " [auto-label: " + ",".join(found) + "]").strip()
        # else: giữ ["unknown"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(INCIDENTS))
    ap.add_argument("--auto-only", action="store_true", help="Chỉ label keyword chắc chắn, không đoán attack_type")
    ap.add_argument("--dry-run", action="store_true", help="In stats, không ghi file")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.is_file():
        print(f"[lỗi] không thấy {path} — chạy merge.py trước")
        sys.exit(1)

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    labeled = 0
    for rec in records:
        before = (rec.get("attack_type"), tuple(rec.get("gt_factors") or []))
        label_record(rec)
        after = (rec.get("attack_type"), tuple(rec.get("gt_factors") or []))
        if before != after:
            labeled += 1

    if args.dry_run:
        by_type: dict[str, int] = {}
        factor_count: dict[str, int] = {}
        unknown = 0
        for rec in records:
            by_type[rec["attack_type"]] = by_type.get(rec["attack_type"], 0) + 1
            if rec.get("gt_factors") == ["unknown"]:
                unknown += 1
            for f in (rec.get("gt_factors") or []):
                factor_count[f] = factor_count.get(f, 0) + 1
        print(f"{len(records)} incidents, {labeled} được label")
        print("  theo attack_type:", json.dumps(by_type, ensure_ascii=False))
        print("  theo factor:", json.dumps(factor_count, ensure_ascii=False))
        print(f"  gt_factors unknown: {unknown}")
        return

    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"==> {labeled}/{len(records)} records được label → {path}")


if __name__ == "__main__":
    main()
