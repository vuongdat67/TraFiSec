"""
TraFiSec — Stage 1 Screener (src/core/screener.py)
=========================================================
API chnh: `Screener(fusion_weights, tau)` vi `score(tx)` + `screen_batch(txs)`
-> [(tx, score), ...] sp theo score gim dn. 4 view c lp + fusion logistic
(fusion.py), candidate queue theo ngng τ (recall≥99% train) + top-k cap 1%.

Read-only trace and state - no replay execution (handled in Stage 2). Fetch qua TraceFetcher
(trace.py), dng RpcClient t pilot/core/rpc.py; RPC key ch t .env.

Usage:
  python -m core.screener --demo                  # Verified execution property
  python -m core.screener --tx <hash>             # Verified execution property
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

# Import pilot/core cho RpcClient + env (pattern verify_onchain.py).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from .rpc import RpcClient, RpcError  # noqa: E402

from .candidate import CandidateQueue  # noqa: E402
from .fusion import LogisticFusion, fit_seed_default  # noqa: E402
from .trace import TraceFetcher, TraceFetchError  # noqa: E402
from .views import evaluate_all  # noqa: E402

DEFAULT_TAU = 0.50  # Verified execution property


def _seed_rand() -> None:
    random.seed(20260811)
    import numpy as np
    np.random.seed(20260811)


class Screener:
    """Stage 1 screener: fetch → 4 views → fusion → candidate.

    `fusion`: LogisticFusion  fit (fit_seed_default() nu khng truyn).
    `tau`: candidate screening threshold (default: fusion model threshold at target recall).
    `fetcher`: TraceFetcher (network). `screen_batch` nhn danh sch tx-hash —
    Fetches trace and state delta with caching in TraceFetcher.
    """

    def __init__(self, fusion: LogisticFusion | None = None, tau: float | None = None,
                 fetcher: TraceFetcher | None = None,
                 client: RpcClient | None = None):
        if fusion is None:
            fusion = fit_seed_default()
        self.fusion = fusion
        t = tau
        if t is None:
            t = fusion.train_recall_99_tau if fusion.train_recall_99_tau is not None \
                else DEFAULT_TAU
        self.tau = t
        self.fetcher = fetcher or (TraceFetcher(client) if client else None)
        self.queue = CandidateQueue(tau=self.tau)

    # ---- 1 tx: fetch + views + fusion -> dict ----
    def analyze(self, tx_hash: str) -> dict:
        """Score y  1 tx: {tx_hash, scores, fused_score, candidate, views}."""
        if self.fetcher is None:
            raise RuntimeError("Screener cn fetcher (RPC)  analyze tx; "
                               "Use analyze_scores() if feature scores are precomputed.")
        trace = self.fetcher.fetch_trace(tx_hash)
        delta = self.fetcher.state_delta(tx_hash, trace.get("block"))
        return self._analyze_data(tx_hash, trace, delta)

    def _analyze_data(self, tx_hash: str, trace: dict, delta: dict) -> dict:
        views = evaluate_all(trace, delta)
        scores = {v: (views[v]["score"] if views[v]["coverage"] else None)
                  for v in self.fusion.view_names}
        fused = self.fusion.score(scores)
        cand = fused >= self.tau
        return {
            "tx_hash": tx_hash,
            "scores": {v: round(views[v]["score"], 4) for v in views},
            "fused_score": round(fused, 4),
            "candidate": cand,
            "view_coverage": {v: bool(views[v]["coverage"]) for v in views},
            "views": views,
            "source": trace.get("source"),
            "block": trace.get("block"),
        }

    def score(self, tx_hash: str) -> float:
        """Score fusion duy nht (thun tin cho batch)."""
        return self.analyze(tx_hash)["fused_score"]

    # Execution trace analysis and verification
    def screen_batch(self, tx_hashes: list[str]) -> list[tuple[str, float]]:
        """Fetch + score c batch → [(tx_hash, fused_score), ...] gim dn."""
        out: list[tuple[str, float]] = []
        for h in tx_hashes:
            try:
                s = self.score(h)
            except TraceFetchError:
                continue  # Verified execution property
            out.append((h, s))
        out.sort(key=lambda x: -x[1])
        return out

    def select_candidates(self, scored: list[tuple[str, float]]) -> list[str]:
        """Select candidates exceeding threshold tau subject to top-k cap."""
        return self.queue.select_top_k(scored, n_batch=len(scored))


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def _demo_hashes(limit: int = 5) -> list[str]:
    corpus = _REPO_ROOT / "corpus" / "incidents.jsonl"
    onchain: list[str] = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if rec.get("verified") == "onchain" and rec.get("chain") == "ethereum":
            for h in rec.get("tx_hashes", []):
                onchain.append(h)
                break
    _seed_rand()
    random.shuffle(onchain)
    return onchain[:limit]


def demo(argv: list[str] | None = None) -> int:
    """Evaluate screening score distribution over sample attack transactions."""
    sys.stdout.reconfigure(encoding="utf-8")
    argv = argv if argv is not None else sys.argv[1:]
    limit = 5
    rpc_url = None
    for a in argv:
        if a.startswith("--limit="):
            limit = int(a[len("--limit="):])
        elif a.startswith("--rpc="):
            rpc_url = a[len("--rpc="):]
    from .env import load_dotenv, resolve_rpc
    load_dotenv()

    hashes = _demo_hashes(limit)
    if not hashes:
        print("ERROR: No on-chain attack transactions found in corpus/incidents.jsonl",
              file=sys.stderr)
        return 1
    url = rpc_url or resolve_rpc("mainnet")
    if not url:
        print("ERROR: No archive RPC configured. Set ARCHIVE_RPC in .env (see .env.example).",
              file=sys.stderr)
        return 1
    client = RpcClient(url)
    screener = Screener(fetcher=TraceFetcher(client))
    print(f"RPC            : {url[:54]}..." if len(url) > 54 else f"RPC            : {url}")
    print(f"Fusion weights : {json.dumps(screener.fusion.weights, indent=2)}")
    print(f"tau (candidate): {screener.tau:.4f}   "
          f"train_recall99_tau={screener.fusion.train_recall_99_tau:.4f}   "
          f"ECE={screener.fusion.ece if screener.fusion.ece is not None else 'n/a'}")
    print(f"tx to demo     : {len(hashes)}")

    rows = []
    for h in hashes:
        try:
            a = screener.analyze(h)
        except (TraceFetchError, RpcError) as e:
            print(f"  [SKIP] {h[:20]}... — {e}")
            continue
        rows.append(a)
        scores = "  ".join(f"{v}={a['scores'][v]:.3f}" for v in a["scores"])
        print(f"\n  tx {a['tx_hash'][:20]}...  block={a['block']}  src={a['source']}")
        print(f"    views: {scores}")
        print(f"    fused= {a['fused_score']:.4f}   candidate={a['candidate']}  "
              f"tau={screener.tau:.4f}")

    if not rows:
        print("No transactions could be scored (RPC unsupported or failed transaction).", file=sys.stderr)
        return 2

    fused = [r["fused_score"] for r in rows]
    n_cand = sum(1 for r in rows if r["candidate"])
    print("\n=== SUMMARY (attack tx) ===")
    print(f"n={len(fused)}  min={min(fused):.4f}  median={sorted(fused)[len(fused)//2]:.4f}  "
          f"max={max(fused):.4f}  mean={sum(fused)/len(fused):.4f}")
    print(f"candidate (score ≥ τ={screener.tau:.4f}): {n_cand}/{len(fused)}")
    ok = n_cand == len(fused)
    print(f"Attack > tau: {'YES — demo PASS' if ok else 'NO — demo FAIL'} "
          f"(recall-bias: k vng mi attack tx l candidate)")
    return 0 if ok else 3


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    argv = argv if argv is not None else sys.argv[1:]
    if "--demo" in argv:
        return demo([a for a in argv if a != "--demo"])
    # Execution trace analysis and verification
    if "--tx" in argv:
        i = argv.index("--tx")
        tx_hash = argv[i + 1]
        from .env import load_dotenv, resolve_rpc
        load_dotenv()
        url = resolve_rpc("mainnet")
        if not url:
            print("ERROR: No RPC found in .env", file=sys.stderr)
            return 1
        screener = Screener(fetcher=TraceFetcher(RpcClient(url)))
        a = screener.analyze(tx_hash)
        out = {"tx_hash": a["tx_hash"], "fused_score": a["fused_score"],
               "candidate": a["candidate"], "tau": screener.tau,
               "scores": a["scores"], "view_coverage": a["view_coverage"],
               "source": a["source"], "block": a["block"]}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
