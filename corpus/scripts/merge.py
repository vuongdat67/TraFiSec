"""
TraceGuard-DeFi corpus — merge.py: dedupe nhiều nguồn → corpus/incidents.jsonl
================================================================================
Pipeline bước 3 (xem corpus/SCHEMA.md §3): gộp raw từ các nguồn thành 1 jsonl
chuẩn. Dedupe theo (protocol, date) — nếu 2 nguồn trùng incident thì merge 1 dòng
(ưu tiên dòng có hash verify; ghi cả 2 URL).

Usage:
    python corpus/scripts/merge.py              # chạy từ repo root
    python corpus/scripts/merge.py --raw corpus/raw --out corpus/incidents.jsonl

Input (raw, mỗi file TUỲ CHỌN — thiếu file thì bỏ nguồn đó):
    corpus/raw/rekt_leaderboard.json      [] of {protocol, loss_usd, date, url, chain?, ...}
    corpus/raw/defihacklabs.json          [] of {protocol, date, chain, tx_hashes, src_dir,
                                                 source_url?, loss_usd?, notes?, attack_type?}
    corpus/raw/slowmist.json (optional)   [] of {protocol, date, chain, tx_hashes, ...}
    corpus/raw/bridgetracker.json (opt.)  [] of {protocol, date, chain, tx_hashes, ...}

Output: corpus/incidents.jsonl — 1 JSON/line, schema trong SCHEMA.md §1.
Không gọi RPC (việc của verify_onchain.py). Ghi `verified:"pending"` mặc định.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")  # Windows cp1252 fix

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CHAIN_ALIASES = {
    "ethereum": "ethereum", "eth": "ethereum", "mainnet": "ethereum", "ethereum network": "ethereum",
    "bsc": "bsc", "bnb": "bsc", "binance": "bsc", "bnb chain": "bsc", "binance smart chain": "bsc",
    "arbitrum": "arbitrum", "arb": "arbitrum", "arbitrum one": "arbitrum",
    "polygon": "polygon", "matic": "polygon",
    "avalanche": "avalanche", "avax": "avalanche",
    "optimism": "optimism", "op": "optimism",
    "base": "base",
    "fantom": "fantom", "ftm": "fantom",
    "solana": "solana", "sol": "solana",          # non-EVM — giữ nhưng đánh dấu
    "other": "other", "unknown": "other", "": "other", None: "other",
}


def norm_chain(v: object) -> str:
    if v is None:
        return "other"
    if isinstance(v, (int, float)):
        return "other"
    return CHAIN_ALIASES.get(str(v).strip().lower(), "other")


def slugify(s: str) -> str:
    """Slug đơn giản cho protocol name → dùng trong id."""
    keep = []
    for ch in str(s).strip().lower():
        if ch.isalnum():
            keep.append(ch)
        elif ch in ("-", "_", " "):
            keep.append("-")
    out = "".join(keep)
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "unknown"


def make_id(source: str, protocol: str, date: str) -> str:
    return f"{source}-{slugify(protocol)}-{date}" if date else f"{source}-{slugify(protocol)}"


def _norm_record(r: dict, source: str) -> dict | None:
    """Chuẩn hoá 1 record raw → dict theo schema incidents.jsonl (hoặc None nếu rác)."""
    protocol = (r.get("protocol") or "").strip()
    if not protocol:
        return None
    # Loại entry editorial/non-DeFi (SCHEMA.md §4): 'the-one-that-got-away' là
    # placeholder của rekt.news (Bitcoin mining theft), KHÔNG phải DeFi incident.
    if slugify(protocol) == "the-one-that-got-away":
        return None
    date = str(r.get("date") or "").strip()
    tx_hashes = r.get("tx_hashes") or []
    if isinstance(tx_hashes, str):
        tx_hashes = [tx_hashes] if tx_hashes.strip() else []
    tx_hashes = [h for h in tx_hashes if isinstance(h, str) and h.strip()]
    url = (r.get("source_url") or r.get("url") or "").strip()
    chain = norm_chain(r.get("chain"))
    # Chỉ đánh dấu blocked khi chain XÁC NHẬN non-EVM (solana — RPC mainnet không phủ).
    # EVM/unknown giữ nguyên verified (pending) — verify_onchain.py (tx hash resolve)
    # là nguồn quyết định cuối cùng. "other" ≠ "non-EVM": nhiều Rekt incident chưa
    # có detail page nên chain chưa biết, không được loại vội.
    if chain in ("solana",) or "solana" in str(r.get("chain", "")).lower():
        verified = "blocked"
        rpc_note = (r.get("rpc_note") or "") + "; solana — không replay bằng RPC mainnet"
    else:
        verified = (r.get("verified") or "pending").strip()
        rpc_note = (r.get("rpc_note") or "").strip()
    return {
        "id": make_id(source, protocol, date),
        "source": source,
        "source_url": url,
        "protocol": protocol,
        "date": date,
        "chain": chain,
        "attack_type": (r.get("attack_type") or "other").strip(),
        "loss_usd": r.get("loss_usd"),
        "tx_hashes": tx_hashes,
        "block": r.get("block"),
        "class": "attack",
        "gt_factors": r.get("gt_factors") or ["unknown"],
        "notes": (r.get("notes") or "").strip(),
        "verified": verified,
        "rpc_note": rpc_note.strip(),
    }


def load_raw(path: Path) -> list[dict]:
    if not path.is_file():
        print(f"  [skip] {path.name}: không tồn tại")
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        print(f"  [warn] {path.name}: kỳ vọng JSON array, thấy {type(data).__name__}")
        return []
    print(f"  [{path.name}] {len(data)} raw records")
    return data


def dedupe(records: list[dict]) -> list[dict]:
    """Dedupe theo key (protocol.lower(), date). Merge: nếu trùng, ưu tiên record
    có tx_hashes dài hơn; hợp nhất source_url (comma-separated) + tx_hashes.
    Trả về list theo thứ tự xuất hiện đầu tiên."""
    seen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for rec in records:
        key = (rec["protocol"].strip().lower(), rec["date"].strip())
        if key in seen:
            existing = seen[key]
            # Hợp tx_hashes (đã verify thì giữ nguyên)
            merged = list(dict.fromkeys(existing["tx_hashes"] + rec["tx_hashes"]))
            existing["tx_hashes"] = merged
            # Hợp URLs
            urls = [u for u in (existing.get("source_url") or "", rec.get("source_url") or "") if u]
            existing["source_url"] = ", ".join(dict.fromkeys(urls))
            # Ưu tiên dòng có nhiều thông tin hơn
            for f in ("chain", "attack_type", "loss_usd", "notes", "verified", "rpc_note", "gt_factors"):
                if not existing.get(f) and rec.get(f):
                    existing[f] = rec[f]
            # Ưu tiên nguồn có hash verify (onchain > pending > blocked)
            for src in ("defihacklabs", "rekt", "slowmist", "bridgetracker", "manual"):
                if rec.get("source") == src and src in ("defihacklabs", "manual"):
                    existing["source"] = src
                    break
        else:
            seen[key] = rec
            order.append(key)
    return [seen[k] for k in order]


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge raw corpus sources → incidents.jsonl")
    ap.add_argument("--raw", default=str(REPO_ROOT / "corpus" / "raw"))
    ap.add_argument("--out", default=str(REPO_ROOT / "corpus" / "incidents.jsonl"))
    args = ap.parse_args()

    raw_dir = Path(args.raw)
    out_path = Path(args.out)

    # Enrich rekt: leaderboard không có chain/description — hợp rekt_incidents.json
    # (detail pages, key theo url) để lấy chain + notes (SCHEMA.md §3).
    rekt_detail = {}
    for r in load_raw(raw_dir / "rekt_incidents.json"):
        url = (r.get("url") or "").strip()
        if url:
            rekt_detail[url] = r

    # Nguồn ưu tiên theo SCHEMA.md §2: defihacklabs > rekt > slowmist > bridgetracker
    all_records: list[dict] = []
    for src, fname in [
        ("defihacklabs", "defihacklabs.json"),
        ("rekt", "rekt_leaderboard.json"),
        ("slowmist", "slowmist.json"),
        ("bridgetracker", "bridgetracker.json"),
    ]:
        for r in load_raw(raw_dir / fname):
            if src == "rekt":
                detail = rekt_detail.get((r.get("url") or "").strip())
                if detail:
                    # ưu tiên chain/notes từ detail; loss giữ leaderboard nếu có
                    r = dict(r)
                    if detail.get("chain"):
                        r["chain"] = detail["chain"]
                    notes = (r.get("notes") or "").strip()
                    desc = (detail.get("description_text") or "").strip()
                    r["notes"] = f"{notes} :: {desc[:300]}".strip(" :") if desc else notes
            norm = _norm_record(r, src)
            if norm:
                all_records.append(norm)

    merged = dedupe(all_records)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in merged:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    by_chain: dict[str, int] = {}
    by_verified: dict[str, int] = {}
    for rec in merged:
        by_chain[rec["chain"]] = by_chain.get(rec["chain"], 0) + 1
        by_verified[rec["verified"]] = by_verified.get(rec["verified"], 0) + 1
    print(f"\n==> {len(merged)} incidents → {out_path}")
    print("    theo chain:", json.dumps(by_chain, ensure_ascii=False))
    print("    theo verified:", json.dumps(by_verified, ensure_ascii=False))


if __name__ == "__main__":
    main()
