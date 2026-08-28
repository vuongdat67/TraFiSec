"""
TraFiSec — E6 Operational Latency & Cost (C6 trong paper)
================================================================
o chi ph vn hnh 2 tng TraceGuard (proposal §6.3 / guide.md §E6):

  Stage 1 (screener)  — `TraceFetcher.fetch_trace` + `state_delta` + 4 views +
                        logistic fusion (Screener.analyze). Real measurement on benchmark sample
                        attack tx t corpus (seed 42, N=min(200, available)) +
                        benign tx nu c file crawl `eval/results/e1_trace_cache.jsonl`
                        (supports structured cache format "hash<TAB>latency_ms" -
                        missing cache records fallback to estimated latency without blocking).
                        Metric: p50/p95/max latency + tx/s n lung + RPC calls/tx
                        (1 trace + state delta ≈ 1 + 2×# Verified execution property
                        calls/tx = 7 = 1 debug_trace + stateDiff + 5 balance/nonce).
  Stage 2 (replay)    — u tin parse E5 logs tht (eval/results/e5_case_*.log,
                        each log records total wall-clock time for exactly one case -
                        including fork initialization, warmup, execution, and state delta).
                        no → `--measure-stage2` (mc nh OFF — tn anvil + RPC):
                        fork tht ti block−1 (k=0, khng warmup), o fork-time,
                        send-time; state-delta time + # Verified execution property
                        diffMode. Metric: p50/p95 per case.
  Resource projection scenarios: estimated RPC consumption per 1M transactions/day through
                        screener + replay top-K=1% candidate (CandidateQueue
                        top_k_frac=0.01), km $ c (PublicNode free / Alchemy free
                        tier / QuickNode paid — assumption ghi r trong CSV).

Ghi `eval/results/e6_latency.csv` (ct layer, metric, value, unit, method, source)
+ summary ra stdout. Deterministic: seed 42 cho mu attack.

Security: No mainnet transactions - Stage 2 measurement runs only on local Anvil fork
local Anvil fork on port 8550. Archive RPC keys loaded strictly from .env.

Usage:
  python -m eval.e6_latency                         # Verified execution property
  python -m eval.e6_latency --no-stage1             # Verified execution property
  python -m eval.e6_latency --measure-stage2 --n 3  # Verified execution property
  python -m eval.e6_latency --sample 50 --seed 7    # Verified execution property
"""
from __future__ import annotations

import argparse
import json
import math
import random
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Imports (pattern verify_onchain.py / screener.py)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from core.env import load_dotenv, resolve_rpc  # noqa: E402
from core.rpc import RpcClient, RpcError  # noqa: E402


from core.screener import Screener  # noqa: E402
from core.trace import TraceFetcher  # noqa: E402

RESULTS_DIR = _REPO_ROOT / "eval" / "results"
CSV_PATH = RESULTS_DIR / "e6_latency.csv"
CORPUS_PATH = _REPO_ROOT / "corpus" / "incidents.jsonl"
CACHE_PATH = RESULTS_DIR / "e1_trace_cache.jsonl"  # Verified execution property

SEED = 42  # Verified execution property
MAX_SAMPLE_ATTACK = 200  # N = min(200, available)
MAX_SAMPLE_BENIGN = 200

E6_PORT = 8550  # Verified execution property
MAX_STAGE2_CASES = 3  # Verified execution property

# Execution trace analysis and verification
COST_ASSUMPTIONS = {
    "tx_per_day": 1_000_000,          # Verified execution property
    "top_k_frac": 0.01,               # CandidateQueue.top_k_frac — replay top 1%
    "replay_per_case_calls": 200,     # Verified execution property
    "rpc_calls_per_screener_tx": 7,   # 1 debug_trace + 1 stateDiff + 5 balance/nonce
    # Illustrative sensitivity parameter, not a claim about any provider price.
    "illustrative_usd_per_100k_calls": 0.25,
    "day_seconds": 86_400,
}


# ===========================================================================
# Execution trace analysis and verification
# ===========================================================================
def percentile(sorted_vals: list[float], p: float) -> float:
    """Compute percentile p (0..100) using nearest-rank on sorted values.

    p50 ca [1,2,3,4] → nearest-rank ceil(0.5*4)=2 → 2.0; p95 [1..100] → 95.
    """
    if not sorted_vals:
        return 0.0
    rank = max(1, math.ceil(p / 100.0 * len(sorted_vals)))
    return float(sorted_vals[min(rank, len(sorted_vals)) - 1])


@dataclass
class LatencyStats:
    """Summarize latency statistics: p50, p95, max, and throughput.

    `n` = s mu o tht; `method` = "measured" | "estimated"; `unit` ms.
    """

    n: int
    p50_ms: float
    p95_ms: float
    max_ms: float
    method: str
    unit: str = "ms"
    note: str = ""

    @classmethod
    def from_seconds(cls, secs: list[float], method: str, note: str = "") -> "LatencyStats":
        """T list thi gian giy → thng k ms (p50/p95/max)."""
        if not secs:
            return cls(0, 0.0, 0.0, 0.0, method, note=note)
        s = sorted(secs)
        return cls(len(secs), percentile(s, 50) * 1000.0, percentile(s, 95) * 1000.0,
                   max(s) * 1000.0, method, note=note)

    def to_rows(self, layer: str, metric: str, tps: float | None = None) -> list[dict]:
        """→ CSV rows: p50/p95/max (+ tx/s nu tps c truyn)."""
        rows = [
            {"layer": layer, "metric": f"{metric}_p50", "value": round(self.p50_ms, 1),
             "unit": "ms", "method": self.method, "source": f"n={self.n}{'; ' + self.note if self.note else ''}"},
            {"layer": layer, "metric": f"{metric}_p95", "value": round(self.p95_ms, 1),
             "unit": "ms", "method": self.method, "source": f"n={self.n}{'; ' + self.note if self.note else ''}"},
            {"layer": layer, "metric": f"{metric}_max", "value": round(self.max_ms, 1),
             "unit": "ms", "method": self.method, "source": f"n={self.n}{'; ' + self.note if self.note else ''}"},
        ]
        if tps is not None:
            rows.append({"layer": layer, "metric": f"{metric}_tps", "value": round(tps, 3),
                         "unit": "tx/s", "method": self.method,
                         "source": f"n={self.n}; single-thread"})
        return rows


def estimate_screener_calls(n_accounts: int) -> int:
    """Estimate RPC calls for screener processing per transaction: 1 trace + state delta.

    State delta: stateDiffTracer (1 call) if supported by archive node; fallback otherwise
    balance+nonce pre/post cho # Verified execution property
    → 1 + 1 + 2×min(# Verified execution property
    depending on archive node capabilities).
    """
    cap = min(n_accounts, 64)
    diff_path = 2  # debug_trace (trace) + debug_trace (stateDiff)
    balance_path = 1 + 1 + 2 * cap  # trace + balance×2 + nonce×2 per account
    return int(round((diff_path + balance_path) / 2.0))


# ===========================================================================
# Execution trace analysis and verification
# ===========================================================================
def _corpus_attack_hashes(corpus_path: Path, seed: int = SEED,
                          limit: int = MAX_SAMPLE_ATTACK) -> list[str]:
    """Mu deterministic attack tx: verified==onchain, chain==ethereum, seed 42.

    Sample 1 representative transaction per incident to avoid duplicate weighting.
    Returns deterministic shuffled hash list according to seed.
    """
    hashes: list[str] = []
    seen: set[str] = set()
    for line in corpus_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("verified") != "onchain" or rec.get("chain") != "ethereum":
            continue
        tx_hashes = rec.get("tx_hashes") or []
        if not tx_hashes:
            continue  # Verified execution property
        h = tx_hashes[0]
        if h and h not in seen:
            seen.add(h)
            hashes.append(h)
    rng = random.Random(seed)
    rng.shuffle(hashes)
    return hashes[:limit]


def _benign_cache_entries(cache_path: Path, limit: int = MAX_SAMPLE_BENIGN) -> list[tuple[str, float | None]]:
    """c cache benign crawl nu tn ti → [(tx_hash, latency_ms | None)].

    File is optional - E6 executes even if cache is absent (skips benign partition),
    flexible format: each line represents a transaction record
    as a JSON object or tab-separated string.
    Uses cached latency measurements when available to bypass network calls.
    Missing latency entries return None and are skipped during aggregation.
    """
    if not cache_path.is_file():
        return []
    out: list[tuple[str, float | None]] = []
    for line in cache_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        h: str | None = None
        ms: float | None = None
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                h = rec.get("tx_hash") or rec.get("hash")
                raw = rec.get("latency_ms") or rec.get("ms")
                ms = float(raw) if raw is not None else None
            except (json.JSONDecodeError, ValueError):
                h = None
        else:
            parts = line.split("\t")
            h = parts[0].strip()
            if len(parts) >= 2:
                try:
                    ms = float(parts[1])
                except ValueError:
                    ms = None
        if h and h.startswith("0x"):
            out.append((h, ms))
    return out[:limit]


class Stage1Measurer:
    """o Stage 1: fetch trace + state delta + 4 views + fusion cho 1 tx."""

    def __init__(self, client: RpcClient, cache: dict[str, float] | None = None):
        self.screener = Screener(fetcher=TraceFetcher(client))
        self.cache = cache or {}

    def time_one(self, tx_hash: str) -> tuple[float, int]:
        """Latency ms y  1 tx: trace fetch + state_delta + views + fusion.

        Tr (latency_ms, n_rpc_calls_estimate). views/fusion thun (khng I/O)
        Execution latency is primarily dominated by archive RPC round-trips.
        """
        t0 = time.perf_counter()
        trace = self.screener.fetcher.fetch_trace(tx_hash)
        delta = self.screener.fetcher.state_delta(tx_hash, trace.get("block"))
        self.screener._analyze_data(tx_hash, trace, delta)  # views + fusion
        ms = (time.perf_counter() - t0) * 1000.0
        calls = estimate_screener_calls(len(trace.get("addresses", set())))
        return ms, calls

    def run(self, hashes: list[str], label: str) -> dict:
        """o batch (n lung) → LatencyStats + calls/tx trung bnh."""
        lat: list[float] = []
        calls: list[int] = []
        skipped: list[str] = []
        for h in hashes:
            if h in self.cache:
                lat.append(self.cache[h])
                calls.append(estimate_screener_calls(4))
                continue
            try:
                ms, c = self.time_one(h)
            except Exception as e:  # Verified execution property
                skipped.append(f"{h[:16]}.. ({e})")
                continue
            lat.append(ms)
            calls.append(c)
        stats = LatencyStats.from_seconds([v / 1000.0 for v in lat], "measured")
        mean_ms = statistics.mean(lat) if lat else 0.0
        tps = (1000.0 / mean_ms) if mean_ms > 0 else 0.0
        return {
            "stats": stats, "tps": tps,
            "calls_per_tx": statistics.mean(calls) if calls else 0.0,
            "n_calls": len(lat), "skipped": skipped, "label": label,
        }


# ===========================================================================
# Execution trace analysis and verification
# ===========================================================================
@dataclass
class ReplayCase:
    """Replay case representation with block height and transaction index."""

    case_id: str
    tx_hash: str
    block: int
    tx_index: int = 0
    mainnet_gas: int | None = None


def parse_e5_logs(results_dir: Path) -> tuple[list[float], list[dict]]:
    """Parse wall-time per case t eval/results/e5_case_*.log.

    E5 records total execution wall-clock time for one case = fork + warmup + send +
    Parses recorded execution seconds from log files.
    Skips empty or malformed log files.
    """
    secs: list[float] = []
    rows: list[dict] = []
    pat = re.compile(r"trong\s+([\d.]+)\s*s", re.IGNORECASE)
    for p in sorted(results_dir.glob("e5_case_*.log")):
        text = p.read_text(encoding="utf-8", errors="replace")
        m = pat.search(text)
        if not m:
            rows.append({"case": p.stem, "source_log": p.name, "note": "no time line"})
            continue
        secs.append(float(m.group(1)))
        rows.append({"case": p.stem, "source_log": p.name, "note": "1 case wall"})
    return secs, rows


def _pick_replay_cases(corpus_path: Path, n: int = MAX_STAGE2_CASES,
                       seed: int = SEED) -> list[ReplayCase]:
    """Chn n case k=0 n gin (block + tx t corpus — tx_index=0)."""
    out: list[ReplayCase] = []
    for line in corpus_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("verified") != "onchain" or rec.get("chain") != "ethereum":
            continue
        hashes = rec.get("tx_hashes") or []
        if not hashes:
            continue
        # Execution trace analysis and verification
        out.append(ReplayCase(case_id=rec.get("id", "?"), tx_hash=hashes[0],
                              block=rec.get("block") or 0, tx_index=0))
    rng = random.Random(seed)
    rng.shuffle(out)
    return out[:n]


def measure_stage2_replay(cases: list[ReplayCase], rpc: str) -> dict:
    """Measure 3 replay cases at k=0 (local Anvil fork - no mainnet interaction).

    o wall-time tng bc: fork (ForkRunner start + block ready), send
    (Replayer.replay — tx_parts archive + cast send + receipt), state-delta
    (prestateTracer diffMode + snapshot #accounts + 2 snapshot cell reads).
    Warmup prefix is empty for k=0 cases.
    REVERTED do timeout — khng phi latency).
    """
    from eval.fidelity import E5Replayer, _mainnet_gas_price  # Verified execution property
    from core.fork import ForkRunner

    fork_times: list[float] = []
    send_times: list[float] = []
    state_times: list[float] = []
    total_times: list[float] = []
    n_accounts: list[int] = []
    rows: list[dict] = []
    archive = RpcClient(rpc)
    for c in cases:
        row: dict = {"case": c.case_id, "tx": c.tx_hash[:20] + ".."}
        try:
            # Execution trace analysis and verification
            if not c.block:
                tx = archive.eth_get_transaction(c.tx_hash)
                c.block = int(tx.get("blockNumber"), 16) if tx else 0
            state_block = c.block - 1 if c.block else 0
            t_fork0 = time.perf_counter()
            with ForkRunner(rpc, state_block, port=E6_PORT) as fork:
                t_fork1 = time.perf_counter()
                fork_times.append(t_fork1 - t_fork0)
                rp = E5Replayer(fork, archive, timeout=120,
                                gas_price=_mainnet_gas_price(archive, c.tx_hash))
                t_send0 = time.perf_counter()
                res = rp.replay(c.tx_hash, None)
                t_send1 = time.perf_counter()
                send_times.append(t_send1 - t_send0)
                # Execution trace analysis and verification
                t_st0 = time.perf_counter()
                n_acc, ok = _measure_state_snapshot(fork.url, c.tx_hash, archive)
                t_st1 = time.perf_counter()
                if ok:
                    state_times.append(t_st1 - t_st0)
                    n_accounts.append(n_acc)
                row.update({"fork_s": round(t_fork1 - t_fork0, 1),
                            "send_s": round(t_send1 - t_send0, 1),
                            "state_s": round(t_st1 - t_st0, 1) if ok else None,
                            "outcome": res.outcome.value, "accounts": n_acc})
            if res.observed:
                total_times.append(t_fork1 - t_fork0 + t_send1 - t_send0
                                   + ((t_st1 - t_st0) if ok else 0.0))
            else:
                row["latency_excluded"] = "transport outcome unobserved"
            rows.append(row)
        except Exception as e:  # Verified execution property
            row["error"] = str(e)[:120]
            rows.append(row)
    return {"fork": fork_times, "send": send_times, "state": state_times,
            "total": total_times, "accounts": n_accounts, "rows": rows}


def _measure_state_snapshot(fork_url: str, tx_hash: str, archive: RpcClient) -> tuple[int, bool]:
    """Estimate touched accounts via prestateTracer diffMode and measure snapshot cells.

    Returns (n_accounts, ok) - ok is False when prestateTracer is unavailable.
    Reads cell state snapshots using normalized hex representations.
    """
    from eval.fidelity import _snapshot_cells  # lazy

    fc = RpcClient(fork_url, timeout=60)
    try:
        diff = archive.call("debug_traceTransaction",
                            [tx_hash, {"tracer": "prestateTracer",
                                       "tracerConfig": {"diffMode": True}}])
    except RpcError:
        return 0, False
    if not isinstance(diff, dict) or not diff.get("post"):
        return 0, False
    post_map = diff["post"]
    _snapshot_cells(fc, post_map, "latest")
    _snapshot_cells(fc, post_map, "latest")
    return len(post_map), True


# ===========================================================================
# Execution trace analysis and verification
# ===========================================================================
def operational_cost(calls_per_screener_tx: float,
                     replay_calls_per_case: float,
                     assumptions: dict | None = None) -> list[dict]:
    """Project daily RPC call volume and cost based on 1M tx/day throughput.

    - Stage 1: tx_per_day × calls_per_screener_tx (screener ch RPC trace —
      r, khng fork).
    - Stage 2: replay top-K = top_k_frac × tx_per_day case/ngy, mi case
      replay_calls_per_case (anvil lazy-fetch ~ #accounts touched × ~3).
    - USD is a sensitivity scenario at a caller-supplied rate, not a provider
      quote. Provider pricing/compute-unit semantics change over time.
    """
    a = dict(COST_ASSUMPTIONS)
    if assumptions:
        a.update(assumptions)
    tpd = a["tx_per_day"]
    calls_s1 = tpd * calls_per_screener_tx
    n_replay = math.ceil(tpd * a["top_k_frac"])
    calls_s2 = n_replay * replay_calls_per_case
    total = calls_s1 + calls_s2

    rows = [
        {"layer": "stage1", "metric": "calls_per_day", "value": calls_s1,
         "unit": "calls/day", "method": "estimated",
         "source": f"{tpd} tx/day × {calls_per_screener_tx} calls/tx"},
        {"layer": "stage2", "metric": "replay_cases_per_day", "value": n_replay,
         "unit": "cases/day", "method": "estimated",
         "source": f"top-{a['top_k_frac']:.0%} of {tpd} tx/day (top_k_frac={a['top_k_frac']})"},
        {"layer": "stage2", "metric": "calls_per_day", "value": calls_s2,
         "unit": "calls/day", "method": "estimated",
         "source": f"{n_replay} cases/day × {replay_calls_per_case} calls/case "
                   f"(anvil lazy-fetch ~accounts touched)"},
        {"layer": "total", "metric": "calls_per_day", "value": total,
         "unit": "calls/day", "method": "estimated",
         "source": "stage1 + stage2"},
        {"layer": "total", "metric": "usd_per_day_at_scenario_rate",
         "value": total / 100_000.0 * a["illustrative_usd_per_100k_calls"],
         "unit": "USD/day", "method": "estimated",
         "source": ("illustrative sensitivity only; rate="
                    f"{a['illustrative_usd_per_100k_calls']} USD/100k calls; "
                    "not a provider quote")},
    ]
    return rows


def capacity_rows(cases_per_day: int, p50_s: float, p95_s: float,
                  target_utilization: float = 0.70) -> list[dict]:
    """Concurrent replay workers required by Little's-law sensitivity."""
    out = []
    for name, service in (("p50", p50_s), ("p95", p95_s)):
        workers = math.ceil((cases_per_day / 86_400.0) * service / target_utilization)
        out.append({"layer": "capacity", "metric": f"workers_required_at_{name}",
                    "value": workers, "unit": "workers", "method": "estimated",
                    "source": (f"arrival={cases_per_day}/day × service={service}s / "
                               f"target utilization={target_utilization:.0%}")})
    return out


# ===========================================================================
# CSV + summary
# ===========================================================================
CSV_COLUMNS = ["layer", "metric", "value", "unit", "method", "source"]


def write_csv(rows: list[dict], path: Path = CSV_PATH) -> Path:
    """Write latency results to eval/results/e6_latency.csv."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import csv
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in CSV_COLUMNS})
    return path


def _fmt(v: float) -> str:
    if v >= 1000:
        return f"{v:,.0f}"
    return f"{v:.3f}" if v < 1 else f"{v:.2f}"


def print_summary(all_rows: list[dict], stage2_measured: bool) -> None:
    print("\n== E6 Operational Latency & Cost (C6) — summary ==")
    groups: dict[tuple, list[dict]] = {}
    for r in all_rows:
        groups.setdefault((r["layer"], r["metric"]), []).append(r)
    for (layer, metric), rs in sorted(groups.items()):
        if not rs:
            continue
        row = rs[0]
        method = row["method"]
        if metric.endswith("_p50") or metric.endswith("_p95") or metric.endswith("_max"):
            val = row["value"]
            n = row["source"].split(";")[0]
            print(f"  {layer:<10} {metric:<28} {_fmt(float(val)):>10} {row['unit']:<8} "
                  f"[{method}] {n}")
        else:
            print(f"  {layer:<10} {metric:<28} {_fmt(float(row['value'])):>10} "
                  f"{row['unit']:<8} [{method}]")
    measured_logs = any(r.get("layer") == "stage2" and
                        r.get("metric") == "replay_per_case_p50" and
                        r.get("method") == "measured" for r in all_rows)
    source = ("MEASURED live (anvil fork local)" if stage2_measured else
              "MEASURED from E5 run logs" if measured_logs else "UNAVAILABLE/ESTIMATED")
    print(f"\n== Stage 2 replay = {source} — "
          f"khng gi tx mainnet ==")


# ===========================================================================
# CLI
# ===========================================================================
def _ensure_utf8() -> None:
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and "utf" not in sys.stderr.encoding.lower():
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    _ensure_utf8()
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="E6 Operational Latency & Cost -- TraceGuard two-stage benchmarking")
    parser.add_argument("--sample", type=int, default=MAX_SAMPLE_ATTACK,
                        help=f"Maximum attack transactions to sample for Stage 1 (default: {MAX_SAMPLE_ATTACK})")
    parser.add_argument("--seed", type=int, default=SEED, help="Deterministic random seed (default: 42)")
    parser.add_argument("--no-stage1", action="store_true",
                        help="Skip Stage 1 benchmarking")
    parser.add_argument("--measure-stage2", action="store_true",
                        help="Benchmark real replay cases on local Anvil fork")
    parser.add_argument("--stage2-n", type=int, default=MAX_STAGE2_CASES,
                        help=f"Number of replay cases to benchmark (default: {MAX_STAGE2_CASES})")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass reading trace cache")
    parser.add_argument("--rpc", default=None, help="Archive RPC endpoint (default from .env)")
    parser.add_argument("--out", default=None, help="CSV output path (defaults to eval/results/e6_latency.csv)")
    args = parser.parse_args(argv)

    rpc = args.rpc or resolve_rpc()
    if not rpc:
        raise SystemExit("Archive RPC required: specify --rpc or set ARCHIVE_RPC in .env")

    all_rows: list[dict] = []
    stats_s1: dict | None = None
    stage2_measured = False
    stage2_service_s: tuple[float, float] | None = None

    # Execution trace analysis and verification
    if not args.no_stage1:
        print(f"== Stage 1: Screener latency benchmarking (sample={args.sample}, seed={args.seed}) ==")
        client = RpcClient(rpc)
        measurer = Stage1Measurer(client)
        hashes = _corpus_attack_hashes(CORPUS_PATH, seed=args.seed, limit=args.sample)
        print(f"  attack transaction sample: {len(hashes)} (corpus onchain ethereum)")
        if not hashes:
            raise SystemExit("No on-chain attack transactions found in corpus - check corpus/incidents.jsonl")

        res = measurer.run(hashes, label="attack")
        stats_s1 = res
        all_rows.extend(res["stats"].to_rows("stage1", "screener_per_tx", tps=res["tps"]))
        all_rows.append({"layer": "stage1", "metric": "rpc_calls_per_tx",
                         "value": round(res["calls_per_tx"], 2), "unit": "calls/tx",
                         "method": "estimated",
                         "source": "1 trace + stateDiff + balance/nonce pre+post "
                                   "(TraceFetcher.state_delta, cap 64 accounts)"})
        if res["skipped"]:
            print(f"  [SKIP] {len(res['skipped'])} transactions could not be scored: "
                  f"{'; '.join(res['skipped'][:3])}{'...' if len(res['skipped']) > 3 else ''}")

        # Execution trace analysis and verification
        benign_lat: list[float] = []
        benign_hashes: list[str] = []
        if not args.no_cache and CACHE_PATH.is_file():
            for h, ms in _benign_cache_entries(CACHE_PATH):
                if ms is not None:
                    benign_lat.append(ms)
                benign_hashes.append(h)
        if benign_hashes:
            stats_b = LatencyStats.from_seconds([v / 1000.0 for v in benign_lat], "measured")
            all_rows.extend(stats_b.to_rows("stage1", "screener_benign_per_tx"))
            if benign_lat:
                print(f"  benign transactions (cache): {len(benign_hashes)} entries -- "
                      f"{len(benign_lat)} with latency (p50={stats_b.p50_ms:.0f}ms "
                      f"p95={stats_b.p95_ms:.0f}ms)")
            else:
                print(f"  benign transactions (cache): {len(benign_hashes)} entries - no RPC calls needed")
        else:
            all_rows.append({"layer": "stage1", "metric": "screener_benign_per_tx_p50",
                             "value": 0.0, "unit": "ms", "method": "estimated",
                             "source": "no benign crawl cache (e1_trace_cache.jsonl) - skip"})
            print(f"  benign: missing cache {CACHE_PATH.name} - skipped")

    # Execution trace analysis and verification
    print("\n== Stage 2: Replay latency benchmarking ==")
    secs, log_rows = parse_e5_logs(RESULTS_DIR)
    print(f"  e5_case_*.log: {len(log_rows)} logs -- {len(secs)} with recorded wall-time")
    if args.measure_stage2:
        cases = _pick_replay_cases(CORPUS_PATH, n=args.stage2_n, seed=args.seed)
        print(f"  MEASURE: replaying {len(cases)} cases at k=0 on Anvil port {E6_PORT}")
        m = measure_stage2_replay(cases, rpc)
        stage2_measured = True
        all_rows.extend(LatencyStats.from_seconds(m["total"], "measured",
                                                  note="anvil fork local, k=0").to_rows(
            "stage2", "replay_per_case"))
        if m["total"]:
            ordered = sorted(m["total"])
            stage2_service_s = (percentile(ordered, 50), percentile(ordered, 95))
        all_rows.extend(LatencyStats.from_seconds(m["fork"], "measured",
                                                  note="anvil fork block−1").to_rows(
            "stage2", "fork_time"))
        all_rows.extend(LatencyStats.from_seconds(m["send"], "measured",
                                                  note="cast send + receipt").to_rows(
            "stage2", "send_time"))
        if m["state"]:
            all_rows.extend(LatencyStats.from_seconds(m["state"], "measured",
                                                      note="prestateTracer diffMode + 2 snapshots").to_rows(
                "stage2", "state_delta_time"))
        accounts = m["accounts"] or [1]
        all_rows.append({"layer": "stage2", "metric": "rpc_calls_per_case",
                         "value": round(3 * statistics.mean(accounts), 1),
                         "unit": "calls/case", "method": "measured",
                         "source": f"anvil lazy-fetch ~3 calls × #{statistics.mean(accounts):.0f} "
                                   f"accounts touched (trung bnh {len(accounts)} case)"})
        for row in m["rows"]:
            print(f"  [{row['case']}] {row.get('outcome', 'ERROR')} "
                  f"fork={row.get('fork_s')}s send={row.get('send_s')}s "
                  f"state={row.get('state_s')}s accounts={row.get('accounts', '-')}")
    elif secs:
        all_rows.extend(LatencyStats.from_seconds(secs, "measured",
                                                  note="E5 logs wall-time/case").to_rows(
            "stage2", "replay_per_case"))
        ordered = sorted(secs)
        stage2_service_s = (percentile(ordered, 50), percentile(ordered, 95))
        all_rows.append({"layer": "stage2", "metric": "rpc_calls_per_case",
                         "value": COST_ASSUMPTIONS["replay_per_case_calls"],
                         "unit": "calls/case", "method": "estimated",
                         "source": "anvil lazy-fetch ~# Verified execution property
                                   "o tht bng --measure-stage2)"})
    else:
        print("  No E5 logs found with timing - run with --measure-stage2 to measure "
              "(3 case k=0, anvil fork local)")
        all_rows.append({"layer": "stage2", "metric": "replay_per_case_p50",
                         "value": 0.0, "unit": "ms", "method": "estimated",
                         "source": "no E5 timing data — run --measure-stage2"})
        all_rows.append({"layer": "stage2", "metric": "rpc_calls_per_case",
                         "value": COST_ASSUMPTIONS["replay_per_case_calls"],
                         "unit": "calls/case", "method": "estimated",
                         "source": "anvil lazy-fetch assumption (khng o)"})

    # Execution trace analysis and verification
    s1_calls = stats_s1["calls_per_tx"] if stats_s1 else COST_ASSUMPTIONS["rpc_calls_per_screener_tx"]
    replay_calls = COST_ASSUMPTIONS["replay_per_case_calls"]
    all_rows.extend(operational_cost(s1_calls, replay_calls))
    if stage2_service_s:
        cases_per_day = math.ceil(COST_ASSUMPTIONS["tx_per_day"] *
                                  COST_ASSUMPTIONS["top_k_frac"])
        all_rows.extend(capacity_rows(cases_per_day, *stage2_service_s))
    print(f"\n  cost: calls/tx screener={s1_calls:.2f} | replay calls/case={replay_calls} | "
          f"top-K={COST_ASSUMPTIONS['top_k_frac']:.0%} ca 1M tx/ngy "
          f"(assumption: {json.dumps(COST_ASSUMPTIONS, ensure_ascii=False)})")

    out_path = write_csv(all_rows, path=args.out) if args.out else write_csv(all_rows)
    print(f"\n== Done. CSV: {out_path} ({len(all_rows)} rows) ==")
    print_summary(all_rows, stage2_measured)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
