"""
TraFiSec — E1 benign set collector (eval/e1_benign.py)
===============================================================
Thu thp benign background cho E1: chn block mu deterministic (seed 42) tri
across 2021-2026 on Ethereum mainnet, retrieving block transaction lists (eth_getBlockByNumber)
true), exclude any transactions matching the attack set, label as benign:

  * hard-negative — tx c flash-loan selector + (swap | oracle) (guide.md E1
    heuristic, epoch-gate theo block deploy protocol — xem e1_common),
  * benign        — cn li.

Filters out large contract creations and failed transactions (status 0x0)
to maintain a clean benign transaction benchmark.
Crawl trace + balance nh e1_crawl (dng chung Crawler + cache).

Block mu: anchor = block cha timestamp trn (2021-01-01 .. 2026-12-01 mi 2
anchors: each anchor selects 1 block via uniform PRNG across monthly epochs.
Block selection is fully deterministic and recorded for traceability. 
Picks deterministic transaction indices within candidate blocks.

CLI:
  python -m eval.e1_benign --list            # Verified execution property
  python -m eval.e1_benign --scale A3        # crawl (A3 ≈ 5 tx/block)
  python -m eval.e1_benign --scale A3 --resume
  python -m eval.e1_benign --labels          # Verified execution property

Security: RPC key loaded strictly from .env. Read-only - never sends mainnet transactions.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from pathlib import Path

# Repo-root import (pattern: eval/fidelity.py)
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.env import load_dotenv, resolve_rpc  # noqa: E402
from core.rpc import RpcClient, RpcError  # noqa: E402


from .e1_common import (  # noqa: E402
    _ensure_utf8,
    build_benign_row,
    classify_benign_label,
    load_cache_rows,
    selectors_from_trace,
)
from .e1_crawl import Crawler, SCALES  # noqa: E402

SEED = 42  # Verified execution property
# Execution trace analysis and verification
_ANCHORS = [int(f"{y:04d}{m:02d}01000000") for y in range(2021, 2027)
            for m in range(1, 13, 2)]
CONTRACT_CREATE_CODE_CAP = 48 * 1024  # Verified execution property
# Execution trace analysis and verification
SCALE_TXS = {"A1": 200, "A2": 20, "A3": 5}
BLOCK_PAD = 16  # Verified execution property

# Execution trace analysis and verification
DEFAULT_MIN_TXS = 50
# Execution trace analysis and verification
# Execution trace analysis and verification
FUTURE_CLAMP_OFFSET = 1000
SCAN_LIMIT = 2000  # Verified execution property


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _unixts(anchor: int) -> int:
    """anchor 'YYYYMMDDHHMMSS' → unixts."""
    import datetime
    return int(datetime.datetime.strptime(str(anchor), "%Y%m%d%H%M%S").timestamp())


# Execution trace analysis and verification
# 2021-01-01≈11.57M, 2022-01-01≈13.94M, 2023-01-01≈16.35M, 2024-01-01≈18.9M,
# Execution trace analysis and verification
# Execution trace analysis and verification
_BLOCK_AT_YEAR = {2021: 11_570_000, 2022: 13_940_000, 2023: 16_350_000,
                  2024: 18_900_000, 2025: 21_600_000, 2026: 24_000_000}
_SAMPLE_WINDOW = 120_000  # Verified execution property


def _est_block(anchor: int) -> int:
    """Estimate block number for anchor timestamp (linear interpolation)."""
    import datetime
    y = int(str(anchor)[:4])
    base = _BLOCK_AT_YEAR.get(y)
    if base is None:
        return _BLOCK_AT_YEAR[2021]
    nxt = _BLOCK_AT_YEAR.get(y + 1)
    if nxt is None:
        return base + int((_unixts(anchor) - _unixts(int(f"{y}0101000000"))) // 14)
    d = datetime.datetime.strptime(str(anchor), "%Y%m%d%H%M%S")
    t0 = datetime.datetime(y, 1, 1)
    t1 = datetime.datetime(y + 1, 1, 1)
    frac = (d - t0).total_seconds() / (t1 - t0).total_seconds()
    return base + int((nxt - base) * frac)


def select_sample_blocks(seed: int = SEED, n_anchors: int | None = None) -> list[int]:
    """Sample 1 block per anchor (uniform by seed) - deterministic, no RPC required."""
    rng = random.Random(seed)
    anchors = _ANCHORS[:n_anchors] if n_anchors else _ANCHORS
    out = []
    for a in anchors:
        est = _est_block(a)
        out.append(BLOCK_PAD + rng.randint(est - _SAMPLE_WINDOW,
                                           est + _SAMPLE_WINDOW))
    return out


def resolve_sample_blocks(client: RpcClient, blocks: list[int],
                          min_txs: int = DEFAULT_MIN_TXS,
                          future_offset: int = FUTURE_CLAMP_OFFSET,
                          scan: int = SCAN_LIMIT,
                          progress=None) -> list[int | None]:
    """Validate candidate block height (exists with >= min_txs transactions). If invalid:
    scans forward deterministically to the first valid block height.

    Clamps future anchor blocks to current head height before forward scan.
    Clamps future anchor blocks to current head height before forward scan.
    (head thay i theo thi gian → deterministic GIVEN head ti lc crawl).

    L do (SOURCES.md 2026-08-12): block mu 2021-07 (12819669) trng 0 tx,
    Resolves non-existent future blocks to latest available historical blocks.
    Returns list of resolved block numbers in corresponding order.
    """
    head = int(client.call("eth_blockNumber"), 16)
    out: list[int | None] = []
    for i, b in enumerate(blocks, 1):
        start = b if b <= head else head - future_offset
        resolved = None
        for delta in range(0, scan):
            cand = start + delta
            if cand > head:
                break
            try:
                blk = client.call("eth_getBlockByNumber", [hex(cand), False])
            except RpcError:
                continue
            if blk and len(blk.get("transactions") or []) >= min_txs:
                resolved = cand
                break
        out.append(resolved)
        if progress:
            progress(i, b, resolved)
    return out


# ---------------------------------------------------------------------------
# Collect + filter
# ---------------------------------------------------------------------------
class BenignCollector:
    """Chn block mu → tx tng block → filter attack/create → gn nhn.

    Constructs benign crawl index entries without dispatching RPC requests directly.
    """

    def __init__(self, client: RpcClient, corpus_hashes: set[str],
                 attack_hashes: set[str], seed: int = SEED):
        self.client = client
        self.corpus_hashes = corpus_hashes
        self.attack_hashes = attack_hashes  # Verified execution property
        self.seed = seed

    def entries_for_block(self, block: int, limit: int) -> list[dict]:
        """Tx ca 1 block (slice chn deterministic) → entries {tx_hash, block, ...}.

        Loi: trng corpus/attack, contract-create code > 48KB, tx internal-only
        Omits invalid transactions without from/to addresses.
        """
        out: list[dict] = []
        blk = self.client.call("eth_getBlockByNumber", [hex(block), True])
        if not blk:
            return out
        txs = blk.get("transactions") or []
        for i, tx in enumerate(txs):
            if limit > 0 and i % 2 == 1:
                continue  # Verified execution property
            h = tx.get("hash")
            if not h:
                continue
            if h.lower() in self.corpus_hashes or h.lower() in self.attack_hashes:
                continue
            to = tx.get("to")
            if not to:  # Verified execution property
                if self._create_code_size(h, block) > CONTRACT_CREATE_CODE_CAP:
                    continue
            inp = tx.get("input") or "0x"
            sel = inp[:10].lower() if len(inp) >= 10 else None
            out.append({"tx_hash": h, "block": block, "protocol": None,
                        "id": None, "attack_type": None, "gt_factors": [],
                        "label": classify_benign_label([sel], block),
                        "to": to, "input": inp, "sel": sel})
            if limit > 0 and len(out) >= limit:
                break
        return out

    def _create_code_size(self, tx_hash: str, block: int) -> int:
        """Kch thc code contract-create (receipt.contractAddress → getCode)."""
        try:
            rec = self.client.eth_get_receipt(tx_hash) or {}
            ca = rec.get("contractAddress")
            if not ca:
                return 0
            code = self.client.eth_get_code(ca, hex(block))
            return max(0, (len(code) - 2) // 2)
        except RpcError:
            return 0

    def collect(self, blocks: list[int], txs_per_block: int,
                progress=None, block_sleep: float = 1.0) -> list[dict]:
        """Convert validated block heights into benign candidate entries.

        `block_sleep`: giy ngh gia 2 block lin tip — trnh burst 429
        (lesson 2026-08-12: publicnode/quicknode 429 khi gi 36 block lin).
        """
        out: list[dict] = []
        for b in blocks:
            try:
                entries = self.entries_for_block(b, txs_per_block)
            except RpcError as e:
                if progress:
                    progress(b, 0, f"RPC error: {e}")
                if block_sleep > 0:
                    time.sleep(block_sleep)
                continue
            out.extend(entries)
            if progress:
                progress(b, len(entries), None)
            if block_sleep > 0:
                time.sleep(block_sleep)
        return out


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _relabel_benign_row(entry: dict, trace: dict, pre: dict, post: dict,
                        status: bool | None, gas_used: int | None,
                        error: str | None) -> dict:
    """Nh build_benign_row nhng re-label t trace (hard vs benign tht).

    Preliminary label assigned from top-level selector; full trace resolves final label.
    flash-loan + swap/oracle  mi depth (guide.md E1 hard-negative nh ngha).
    """
    row = build_benign_row(entry, trace, pre, post, status, gas_used, error)
    if not error and trace.get("flat_calls"):
        sels = selectors_from_trace(trace)
        row["label"] = classify_benign_label(sels, trace.get("block"))
    return row


def crawl_benign(entries: list[dict], rpc_url: str, cache_path: Path,
                 workers: int = 4, resume: bool = True, timeout: float = 120.0,
                 on_done=None) -> dict:
    """Crawl entries benign vo cache chung (re-label hard t trace); tr stats."""
    crawler = Crawler(rpc_url, cache_path=cache_path, workers=workers,
                      timeout=timeout)
    crawler.crawl(entries, resume=resume, on_done=on_done,
                  builder=_relabel_benign_row)
    return crawler.stats


def label_stats(cache_path: Path) -> dict:
    """Compute label distribution in trace cache (attack/benign/hard) offline."""
    c: Counter = Counter()
    n_status_fail = 0
    for row in load_cache_rows(cache_path).values():
        c[row.get("label", "?")] += 1
        if row.get("status") is False:
            n_status_fail += 1
    return {"labels": dict(c), "status_failed": n_status_fail}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    load_dotenv()
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(
        description="E1 benign collector: block mu deterministic (seed 42) → "
                    "entries → crawl vo cache chung")
    p.add_argument("--scale", choices=sorted(SCALES), default="A3",
                   help=f"tx/block ({SCALES}); block mu c nh 36 (2021-2026)")
    p.add_argument("--list", action="store_true",
                   help="Display sample blocks and cache label distribution without crawling")
    p.add_argument("--resume", action="store_true", help="b qua tx  cache")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--corpus", default=None, help="corpus path (loi trng hash)")
    p.add_argument("--out", default=None, help="cache path (mc nh e1_trace_cache.jsonl)")
    p.add_argument("--rpc", default=None, help="archive RPC (mc nh .env)")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--min-txs", type=int, default=DEFAULT_MIN_TXS,
                   help="Minimum transactions required per candidate block (default: 50)")
    p.add_argument("--no-resolve", action="store_true",
                   help="Bypass block resolution (use raw PRNG block numbers directly)")
    args = p.parse_args(argv)

    from .e1_crawl import CACHE_PATH, CORPUS_DEFAULT, _print_done
    from .e1_common import attack_rows_from_corpus

    cache_path = Path(args.out) if args.out else CACHE_PATH
    blocks = select_sample_blocks()

    if args.list:
        print(f"== E1 benign block mu (seed 42, {len(blocks)} anchors 2021-2026) ==")
        for i, b in enumerate(blocks, 1):
            print(f"  {i:>2}. block {b:,}  (anchor {_ANCHORS[i - 1]})")
        st = label_stats(cache_path)
        print(f"\nCache hin c: {st['labels']}  (status failed: {st['status_failed']})")
        return 0

    rpc = args.rpc or resolve_rpc("mainnet")
    if not rpc:
        print("ERROR: Archive RPC required: specify --rpc or ARCHIVE_RPC in .env", file=sys.stderr)
        return 1

    corpus = Path(args.corpus) if args.corpus else CORPUS_DEFAULT
    corpus_hashes = {r["tx_hash"].lower() for r in attack_rows_from_corpus(corpus)}
    attack_hashes = {h for h, r in load_cache_rows(cache_path).items()
                     if r.get("label") == "attack" and not r.get("error")}
    client = RpcClient(rpc, timeout=args.timeout)
    collector = BenignCollector(client, corpus_hashes, attack_hashes, seed=SEED)

    # Execution trace analysis and verification
    # Execution trace analysis and verification
    if args.no_resolve:
        print("--no-resolve: using raw PRNG block numbers.")
    else:
        print(f"\n== Resolve block mu (head t RPC; min_txs={args.min_txs}) ==")
        n_moved = 0

        def _res_progress(i, orig, resolved):
            nonlocal n_moved
            if resolved and resolved != orig:
                n_moved += 1
                print(f"  [{i:>2}] anchor {_ANCHORS[i - 1]}: {orig:,} → {resolved:,}")

        blocks = resolve_sample_blocks(client, blocks, min_txs=args.min_txs,
                                       progress=_res_progress)
        n_resolved = sum(1 for b in blocks if b)
        print(f"  resolved {n_resolved}/{len(blocks)} blocks ({n_moved} shifted) -- "
              f"None = skipped anchor (unresolvable)")
        blocks = [b for b in blocks if b]
        if not blocks:
            print("No valid blocks found - verify archive RPC connectivity.",
                  file=sys.stderr)
            return 1

    txs_per_block = SCALE_TXS[args.scale]
    print(f"\n== E1 benign (scale {args.scale}: {txs_per_block} tx/block × "
          f"{len(blocks)} blocks = {txs_per_block * len(blocks)} tx) ==")
    print(f"RPC        : {rpc[:60]}{'...' if len(rpc) > 60 else ''}")
    print(f"loi trng : {len(corpus_hashes)} corpus + {len(attack_hashes)} attack cached")
    print(f"cache      : {cache_path}")

    def _progress(b, n, err):
        if err:
            print(f"  [warn] block {b:,}: {err}")
        else:
            print(f"  [ok]   block {b:,}: {n} tx entries")

    t0 = time.time()
    entries = collector.collect(blocks, txs_per_block, progress=_progress)
    dt_collect = time.time() - t0
    n_hard = sum(1 for e in entries if e["label"] == "hard")
    print(f"\n== Collect {len(entries)} entries ({n_hard} hard-negative, "
          f"{dt_collect:.0f}s) ==")
    if not entries:
        print("No entries retrieved - verify archive RPC (blocks post-2021).",
              file=sys.stderr)
        return 1

    stats = crawl_benign(entries, rpc, cache_path, workers=args.workers,
                         resume=args.resume, timeout=args.timeout,
                         on_done=_print_done)
    print(f"\n== Done: attempted={stats['attempted']} ok={stats['ok']} "
          f"errored={stats['errored']} skipped_resume={stats['skipped_resume']} ==")
    st = label_stats(cache_path)
    print(f"Cache: {st['labels']}  (status failed: {st['status_failed']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
