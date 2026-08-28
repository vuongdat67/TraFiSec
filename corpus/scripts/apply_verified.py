"""
TraceGuard-DeFi corpus — apply_verified.py: cập nhật verified vào incidents.jsonl
====================================================================================
Pipeline bước 4.5 (sau verify_onchain.py): verify_onchain chỉ GHI
corpus/raw/verified_status.jsonl (không sửa file gốc — an toàn). Script này merge
kết quả verify ngược vào incidents.jsonl (theo id).

Usage:
    python corpus/scripts/apply_verified.py [--jsonl corpus/incidents.jsonl]

Lưu ý: `verified:"onchain"` chỉ ghi khi TẤT CẢ hash resolve. Incident không có
trong verified_status (vd chưa verify) giữ nguyên verified hiện có.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JSONL = REPO_ROOT / "corpus" / "incidents.jsonl"
VERIFIED = REPO_ROOT / "corpus" / "raw" / "verified_status.jsonl"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", default=str(JSONL))
    ap.add_argument("--verified", default=str(VERIFIED))
    args = ap.parse_args()

    jsonl_path = Path(args.jsonl)
    ver_path = Path(args.verified)

    if not jsonl_path.is_file():
        print(f"[lỗi] không thấy {jsonl_path} — chạy merge.py trước")
        sys.exit(1)
    if not ver_path.is_file():
        print(f"[lỗi] không thấy {ver_path} — chạy verify_onchain.py trước")
        sys.exit(1)

    # đọc verified status
    status = {}
    for line in ver_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        status[str(rec.get("id"))] = rec

    # đọc + update incidents
    records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    updated = 0
    relabeled = 0
    for rec in records:
        v = status.get(str(rec.get("id")))
        if not v:
            continue
        if rec.get("verified") != v.get("verified") or rec.get("rpc_note") != v.get("rpc_note"):
            rec["verified"] = v.get("verified", "pending")
            rec["rpc_note"] = v.get("rpc_note") or ""
            updated += 1
        # Chain re-label theo ground truth: verify gọi RPC Ethereum mainnet — hash
        # resolve được ⇒ tx đó CHẮC CHẮN là Ethereum (verified_status có kèm
        # results[].ok; chain trong status là chain NGUỒN nên không dùng).
        if v.get("verified") == "onchain":
            resolved_ok = [r for r in (v.get("results") or []) if r.get("ok")]
            if resolved_ok and rec.get("chain") != "ethereum":
                rec["chain"] = "ethereum"
                note = "[relabel: chain→ethereum (on-chain verify)]"
                rec["notes"] = f"{rec['notes']} {note}".strip() if rec.get("notes") else note
                relabeled += 1

    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    from collections import Counter
    counts = Counter(r.get("verified", "(missing)") for r in records)
    print(f"==> {updated}/{len(records)} records được cập nhật verified → {jsonl_path}")
    print(f"    relabel chain: {relabeled} (onchain→ethereum ground truth)")
    print("    theo verified:", json.dumps(counts, ensure_ascii=False))


if __name__ == "__main__":
    main()
