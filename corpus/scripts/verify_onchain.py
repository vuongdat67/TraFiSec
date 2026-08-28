#!/usr/bin/env python3
"""
TraceGuard-DeFi — verify_onchain.py
====================================
Verify incident attack tx hashes against an archive mainnet RPC
(pipeline step 4 — corpus/SCHEMA.md).

Input:
  - JSONL  corpus/incidents.jsonl               (mỗi dòng 1 incident — schema SCHEMA.md) [mặc định]
  - JSON   corpus/raw/defihacklabs.json         (incident -> tx hash, chain — chạy thử nhanh)

Output (KHÔNG sửa file gốc):
  corpus/raw/verified_status.jsonl  — 1 dòng / incident:
    {id, chain, tx_hashes, verified, rpc_note, results: [{hash, ok, block, from, to, note}]}

  verified:
    - "onchain"  khi TẤT CẢ tx_hashes resolve (có tx object trên RPC)
    - "blocked"  khi có hash không resolve / RPC lỗi / không có tx_hashes

RPC: mặc định resolve từ env (core/env.py auto-load .env; ARCHIVE_RPC). `--rpc` override.
Windows Python 3.12: stdout UTF-8. Import core từ pilot/ (sys.path).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

# Windows Python 3.12: UTF-8 stdout/stderr (in tiếng Việt, mũi tên)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# Import core: package core/ nằm trong pilot/ (pilot/core/*.py)
sys.path.insert(0, str(REPO_ROOT / "pilot"))

from src.core.env import load_dotenv, resolve_rpc  # noqa: E402
from src.core.rpc import RpcClient, RpcError  # noqa: E402


DEFAULT_JSONL = REPO_ROOT / "corpus" / "incidents.jsonl"
DEFAULT_JSON = REPO_ROOT / "corpus" / "raw" / "defihacklabs.json"
OUTPUT = REPO_ROOT / "corpus" / "raw" / "verified_status.jsonl"

HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def _extract_hashes(rec: dict) -> list[str]:
    """Lấy tx_hashes từ incident — chấp các tên field + cả string lẫn list."""
    for key in ("tx_hashes", "tx_hash", "hashes", "hash"):
        if key not in rec:
            continue
        v = rec[key]
        out: list[str] = []
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict) and "hash" in item:
                    out.append(str(item["hash"]))
        elif isinstance(v, dict) and "hash" in v:
            out.append(str(v["hash"]))
        if out:
            return out
    return []


def load_jsonl_incidents(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"Không thấy JSONL: {path}")
    incidents: list[dict] = []
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSONL lỗi dòng {ln}: {e}") from e
        incidents.append(rec)
    return incidents


def load_json_incidents(path: Path) -> list[dict]:
    """defihacklabs.json — chấp list hoặc dict {key: incident} hoặc {incidents: [...]}."""
    if not path.is_file():
        raise FileNotFoundError(f"Không thấy JSON: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        entries = data
    else:
        entries = None
        for key in ("incidents", "data", "hacks", "events"):
            if isinstance(data.get(key), list):
                entries = data[key]
                break
        if entries is None:
            entries = [v for v in data.values() if isinstance(v, dict)]
    incidents: list[dict] = []
    for rec in entries:
        if not isinstance(rec, dict):
            continue
        hashes = _extract_hashes(rec)
        if not hashes:
            continue  # incident không có hash -> không verify được (bỏ qua)
        iid = (rec.get("id") or rec.get("name") or rec.get("protocol")
               or rec.get("slug") or rec.get("title") or "?")
        chain = rec.get("chain") or rec.get("network") or "ethereum"
        incidents.append({"id": str(iid), "chain": chain, "tx_hashes": hashes})
    return incidents


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def resolve_hash(client: RpcClient, h: str, chain: str = "ethereum") -> dict:
    """Verify 1 hash trên RPC. Trả result entry {hash, ok, block, from, to, note}."""
    h = h.strip()
    if not HASH_RE.match(h):
        return {"hash": h, "ok": False, "block": None, "from": None, "to": None,
                "note": f"invalid hash format (không phải 0x+64 hex): {h!r}"}
    try:
        tx = client.eth_get_transaction(h)
    except RpcError as e:
        return {"hash": h, "ok": False, "block": None, "from": None, "to": None,
                "note": f"RPC error: {e}"}
    if tx is None:
        hint = ("mainnet RPC chỉ phủ chain ethereum — tx chain khác cần RPC riêng (vd ARB_ARCHIVE_RPC)"
                if chain.lower() not in ("ethereum", "mainnet") else "")
        note = "tx not found trên RPC"
        if hint:
            note += f"; {hint}"
        return {"hash": h, "ok": False, "block": None, "from": None, "to": None,
                "note": note}
    block = tx.get("blockNumber")
    if isinstance(block, str):
        try:
            block = int(block, 16)
        except ValueError:
            pass
    return {"hash": h, "ok": True, "block": block,
            "from": tx.get("from"), "to": tx.get("to"), "note": None}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Verify incident tx hashes trên archive RPC mainnet (pipeline step 4).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--jsonl", nargs="?", const="", metavar="PATH",
                     help="JSONL incidents (mặc định: corpus/incidents.jsonl)")
    src.add_argument("--json", dest="json_file", nargs="?", const="", metavar="PATH",
                     help="JSON incidents — defihacklabs (mặc định: corpus/raw/defihacklabs.json)")
    ap.add_argument("--rpc", metavar="URL",
                    help="RPC URL override (mặc định: env ARCHIVE_RPC qua core/env.py)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Giới hạn số incident xử lý (0 = tất cả)")
    ap.add_argument("--sleep", type=float, default=0.2,
                    help="Giây giữa các hash (rate limit, mặc định 0.2)")
    args = ap.parse_args()

    # ---- resolve input ----
    try:
        if args.json_file is not None:
            in_path = Path(args.json_file) if args.json_file else DEFAULT_JSON
            incidents = load_json_incidents(in_path)
            in_kind = "json"
        else:
            in_path = Path(args.jsonl) if args.jsonl else DEFAULT_JSONL
            incidents = load_jsonl_incidents(in_path)
            in_kind = "jsonl"
    except (FileNotFoundError, ValueError) as e:
        print(f"LỖI input: {e}", file=sys.stderr)
        print("  Gợi ý: dùng --jsonl <path> cho incidents.jsonl hoặc --json <path> cho defihacklabs.json.",
              file=sys.stderr)
        sys.exit(1)

    if args.limit > 0:
        incidents = incidents[:args.limit]

    # ---- RPC ----
    load_dotenv()
    rpc_url = args.rpc or resolve_rpc("mainnet")
    if not rpc_url:
        print("LỖI: không có RPC. Set ARCHIVE_RPC trong .env hoặc dùng --rpc <url>.", file=sys.stderr)
        sys.exit(1)
    client = RpcClient(rpc_url)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    stats = {"onchain": 0, "blocked": 0, "hashes": 0, "ok_hash": 0, "rpc_errors": 0}
    n_incidents = len(incidents)

    with open(OUTPUT, "w", encoding="utf-8") as out:
        for i, rec in enumerate(incidents, 1):
            iid = rec.get("id") or rec.get("protocol") or f"incident-{i}"
            chain = rec.get("chain", "ethereum")
            hashes = _extract_hashes(rec)

            results = []
            for h in hashes:
                stats["hashes"] += 1
                r = resolve_hash(client, h, chain)
                results.append(r)
                if not r["ok"] and r["note"] and r["note"].startswith("RPC error"):
                    stats["rpc_errors"] += 1
                if r["ok"]:
                    stats["ok_hash"] += 1
                time.sleep(args.sleep)  # rate-limit thân thiện

            all_ok = bool(hashes) and all(r["ok"] for r in results)
            verified = "onchain" if all_ok else "blocked"
            stats["onchain" if all_ok else "blocked"] += 1

            note = None
            if not all_ok:
                failed = [r for r in results if not r["ok"]]
                if failed:
                    note = "; ".join(f"{r['hash'][:18]}...: {r['note']}" for r in failed)
                else:
                    note = "no tx_hashes (incident không có hash để verify)"

            out.write(json.dumps({
                "id": iid,
                "chain": chain,
                "tx_hashes": hashes,
                "verified": verified,
                "rpc_note": note,
                "results": results,
            }, ensure_ascii=False) + "\n")

            n_ok = sum(1 for r in results if r["ok"])
            print(f"[{i}/{n_incidents}] {iid}: verified={verified} "
                  f"({len(results)} hash, {n_ok} resolve)")

    # ---- summary ----
    print("\n=== SUMMARY ===")
    print(f"Input      : {in_path}  ({in_kind})")
    print(f"RPC        : {rpc_url if len(rpc_url) <= 60 else rpc_url[:57] + '...'}")
    print(f"Output     : {OUTPUT}")
    print(f"Incidents  : {n_incidents}  (onchain={stats['onchain']}, blocked={stats['blocked']})")
    print(f"Tx hashes  : {stats['hashes']}  "
          f"(resolve={stats['ok_hash']}, not-resolve={stats['hashes'] - stats['ok_hash']}, "
          f"rpc_errors={stats['rpc_errors']})")


if __name__ == "__main__":
    main()
