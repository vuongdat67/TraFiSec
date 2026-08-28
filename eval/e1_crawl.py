"""
TraFiSec — E1 crawler (eval/e1_crawl.py)
=================================================
Parallel trace crawler for E1 evaluation pipeline:
  (a) debug_traceTransaction callTracer+withLog (QuickNode/Publicnode) — fallback
      fallback to eth_getTransactionByHash + receipt if debug_trace is unsupported,
  (b) balance pre/post qua Multicall3 0xcA11bd... getEthBalance aggregate
  (c) eth_getTransactionByHash + receipt (status/gasUsed/logs).

Output: eval/results/e1_trace_cache.jsonl — 1 dng/tx, ghi INCREMENTAL.
Resume b qua tx  cache thnh cng. Progress CSV: eval/results/e1_crawl_progress.csv.

Lesson 2026-08-12: RpcClient.call  c retry 429/network ngm; Crawler ch cn
rate limiting and concurrency management to prevent RPC throttling.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import threading
import time
from pathlib import Path

# Repo-root import
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.rpc import RpcClient, RpcError  # noqa: E402
from core.trace import TraceFetchError, parse_call_tracer, parse_tx_receipt  # noqa: E402
from .e1_common import (  # noqa: E402
    _ensure_utf8,
    attack_rows_from_corpus,
    build_trace_row,
    eth_get_balance_batched,
    load_cache_rows,
)

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
CACHE_PATH = RESULTS_DIR / "e1_trace_cache.jsonl"
PROGRESS_PATH = RESULTS_DIR / "e1_crawl_progress.csv"
CORPUS_DEFAULT = _REPO_ROOT / "corpus" / "incidents.jsonl"

SCALES = {"A1": 150_000, "A2": 15_000, "A3": 5_000}
SEC_PER_TX_ATTACK = 4.0
SEC_PER_TX_BENIGN = 1.2
_MAX_ACCOUNTS = 50

class Crawler:
    def __init__(self, rpc_url: str, cache_path: Path = CACHE_PATH,
                 trace_rpc_url: str | None = None,
                 rpc_fallback_urls: tuple[str, ...] = (),
                 trace_fallback_urls: tuple[str, ...] = (),
                 progress_path: Path = PROGRESS_PATH, workers: int = 4,
                 timeout: float = 120.0, max_accounts: int = _MAX_ACCOUNTS,
                 throttle: float = 0.1):
        self.rpc_url = rpc_url
        self.trace_rpc_url = trace_rpc_url or rpc_url
        self.rpc_fallback_urls = rpc_fallback_urls
        self.trace_fallback_urls = trace_fallback_urls
        self.cache_path = cache_path
        self.progress_path = progress_path
        self.workers = max(1, workers)
        self.timeout = timeout
        self.max_accounts = max_accounts
        self.throttle = throttle
        self._lock = threading.Lock()
        self._tl = threading.local()
        self._use_debug_trace = True  # Verified execution property
        self.stats = {"attempted": 0, "ok": 0, "errored": 0, "skipped_resume": 0}
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

    def _client(self) -> RpcClient:
        c = getattr(self._tl, "client", None)
        if c is None:
            c = RpcClient(self.rpc_url, timeout=self.timeout,
                          fallback_urls=self.rpc_fallback_urls)
            self._tl.client = c
        return c

    def _trace_client(self) -> RpcClient:
        if self.trace_rpc_url == self.rpc_url:
            return self._client()
        c = getattr(self._tl, "trace_client", None)
        if c is None:
            c = RpcClient(self.trace_rpc_url, timeout=self.timeout,
                          fallback_urls=self.trace_fallback_urls)
            self._tl.trace_client = c
        return c

    def _done_hashes(self) -> set[str]:
        done: set[str] = set()
        if self.cache_path.exists():
            for row in load_cache_rows(self.cache_path).values():
                if not row.get("error"):
                    done.add(row["tx_hash"])
        return done

    def _write_cache_row(self, row: dict) -> None:
        with self._lock:
            with open(self.cache_path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _write_progress(self, row: dict, ms: int) -> None:
        new_file = not self.progress_path.exists()
        with self._lock:
            with open(self.progress_path, "a", encoding="utf-8", newline="", errors="replace") as f:
                w = csv.writer(f)
                if new_file:
                    w.writerow(["ts", "tx_hash", "label", "block", "status", "source", "gas_used", "n_calls", "n_logs", "error", "ms"])
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), row.get("tx_hash"),
                            row.get("label"), row.get("block"), row.get("status"), row.get("source"),
                            row.get("gas_used"),
                            len((row.get("trace") or {}).get("flat_calls", [])),
                            len((row.get("trace") or {}).get("logs", [])),
                            (row.get("error") or "")[:120], ms])

    def crawl_one(self, entry: dict, builder=build_trace_row) -> dict:
        tx_hash = entry["tx_hash"]
        client = self._client()
        tr = None
        pre, post = {}, {}
        status, gas, error = None, None, None

        # Execution trace analysis and verification
        if self.throttle > 0:
            time.sleep(self.throttle * self.workers * (hash(tx_hash) % 10) / 10)

        try:
            # (a) debug_traceTransaction
            if self._use_debug_trace:
                try:
                    # Trace acquisition is deliberately separate from archive
                    # metadata/state reads.  QuickNode is configured for this
                    # path; Alchemy remains the archive source of truth.
                    res = self._trace_client().call("debug_traceTransaction",
                                    [tx_hash, {"tracer": "callTracer",
                                               "tracerConfig": {"withLog": True, "onlyTopCall": False}}])
                    tr = parse_call_tracer(tx_hash, res)
                except RpcError as e:
                    if "400" in str(e) or "method" in str(e).lower():
                        self._use_debug_trace = False  # Verified execution property
                    # Execution trace analysis and verification
                except Exception as e:
                    error = f"Trace parse error: {e}"

            # Fallback (b) tx + receipt
            if tr is None:
                tx = client.eth_get_transaction(tx_hash)
                if not tx:
                    raise TraceFetchError(f"{tx_hash}: tx not found")
                receipt = client.eth_get_receipt(tx_hash) or {}
                tr = parse_tx_receipt(tx_hash, tx, receipt)
                status = receipt.get("status") in ("0x1", 1)
                g = receipt.get("gasUsed")
                gas = int(g, 16) if g else None

            block = tr.get("block")
            if not isinstance(block, int):
                bh = (client.eth_get_transaction(tx_hash) or {}).get("blockNumber")
                block = int(bh, 16) if isinstance(bh, str) else None
            tr["block"] = block

            if status is None or gas is None:
                receipt = client.eth_get_receipt(tx_hash) or {}
                st = receipt.get("status")
                if st is not None:
                    status = st in ("0x1", 1)
                g = receipt.get("gasUsed")
                if g is not None:
                    gas = int(g, 16)

            # (c) Balances
            addrs = sorted(tr.get("addresses") or [])[:self.max_accounts]
            pre_blk = (block - 1) if block is not None else "latest"
            post_blk = block if block is not None else "latest"
            pre = eth_get_balance_batched(client, addrs, pre_blk)
            post = eth_get_balance_batched(client, addrs, post_blk)

        except Exception as e:
            error = str(e)[:500]

        if tr is None:
            tr = {"tx_hash": tx_hash, "block": entry.get("block"), "source": "error", "flat_calls": [], "logs": [], "addresses": set()}
        return builder(entry, tr, pre, post, status, gas, error)

    def crawl(self, entries: list[dict], resume: bool = True, limit: int = 0,
              on_done=None, builder=build_trace_row) -> list[dict]:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        todo = list(entries)
        if resume:
            done = self._done_hashes()
            todo = [e for e in todo if e["tx_hash"] not in done]
            self.stats["skipped_resume"] = len(entries) - len(todo)
        if limit:
            todo = todo[:limit]

        rows: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="e1crawl") as pool:
            fut = {pool.submit(self.crawl_one, e, builder): e for e in todo}
            for f in as_completed(fut):
                t0 = time.time()
                row = f.result()
                ms = int((time.time() - t0) * 1000)
                self._write_cache_row(row)
                self._write_progress(row, ms)
                self.stats["attempted"] += 1
                if row.get("error"):
                    self.stats["errored"] += 1
                else:
                    self.stats["ok"] += 1
                if on_done:
                    on_done(row, ms)
                rows.append(row)
        return rows

def _print_done(row: dict, ms: int) -> None:
    h = row["tx_hash"]
    print(f"  [done] {h[:18]}... block={row.get('block')} label={row.get('label')} src={row.get('source')} status={row.get('status')} ({ms}ms){' ERR: ' + row.get('error')[:80] if row.get('error') else ''}")

def _estimate(entries: list[dict], workers: int) -> str:
    n_attack = sum(1 for e in entries if e.get("label") == "attack")
    sec = (n_attack * SEC_PER_TX_ATTACK + (len(entries) - n_attack) * SEC_PER_TX_BENIGN) / workers
    return f"{len(entries)} tx ≈ {sec/60:.1f}m"

def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    from core.env import (load_dotenv, resolve_rpc_candidates,
                              resolve_trace_rpc_candidates)
    load_dotenv()
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser()
    p.add_argument("--scale", choices=sorted(SCALES), default="A2")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--rpc", default=None)
    p.add_argument("--trace-rpc", default=None,
                   help="trace-only RPC; metadata/balances still use --rpc")
    p.add_argument("--tx", action="append", dest="tx_hashes",
                   help="crawl an explicit transaction hash (repeatable)")
    p.add_argument("--block", type=int, default=None,
                   help="block number for explicit --tx entries")
    p.add_argument("--label", default="attack",
                   help="label for explicit --tx entries")
    p.add_argument("--timeout", type=float, default=120.0)
    args = p.parse_args(argv)
    archive_candidates = ((args.rpc,) if args.rpc else
                          resolve_rpc_candidates("mainnet"))
    rpc = archive_candidates[0] if archive_candidates else None
    if not rpc:
        return 1
    if args.tx_hashes:
        entries = [{"tx_hash": h, "block": args.block, "label": args.label,
                    "source": "explicit", "protocol": "unknown",
                    "attack_id": "explicit", "attack_type": "explicit",
                    "gt_factors": []} for h in args.tx_hashes]
    else:
        entries = attack_rows_from_corpus(CORPUS_DEFAULT)
    trace_candidates = ((args.trace_rpc,) if args.trace_rpc else
                        resolve_trace_rpc_candidates("mainnet"))
    trace_rpc = trace_candidates[0] if trace_candidates else rpc
    crawler = Crawler(rpc, trace_rpc_url=trace_rpc,
                      rpc_fallback_urls=archive_candidates[1:],
                      trace_fallback_urls=trace_candidates[1:],
                      workers=args.workers, timeout=args.timeout)
    print(f"== E1 crawl: {len(entries)} tx | workers={args.workers} | "
          f"archive={rpc[:32]}... | trace={trace_rpc[:32]}... ==")
    crawler.crawl(entries, resume=args.resume, limit=args.limit, on_done=_print_done)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
