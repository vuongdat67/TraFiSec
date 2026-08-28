"""
TraFiSec -- E4 Counterfactual Necessity Evaluation Runner
=========================================================
Evaluates counterfactual necessity without leaking ground-truth attack factors.
Intervention candidates are inferred purely from execution traces and contract state.
Ground-truth factor labels are unmasked strictly at scoring time after verdicts are frozen.

Protocol per incident:
  1. `build_mutation_plan(case)` -- Blind discovery from trace/state:
       - f_fl: Flash loan suppression (identifies provider from trace selectors).
       - f_orc: Oracle pinning (pins pre-exploit price in storage).
       - f_swap: Calldata parameter slicing (caps slippage/borrow amounts).
       - f_auth: Authority revocation (modifies proxy admin slots).
  2. `run_necessity(case, mutations)` -- Replays baseline and mutated states on local fork.
  3. Outcome Guard & Harm evaluation -- Separates causal factors (CAUSE) from execution reverts (REVERT).
  4. CSV reporting tracks observation validity, harm contracts, verdicts, and provenance.
"""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import time
from pathlib import Path

from core.env import load_dotenv, resolve_rpc
from core.fork import ForkRunner
from core.mutate import (
    EIP1967_ADMIN_SLOT,
    AuthRevoke,
    CompositeMutation,
    FlashLoanDisable,
    HealthCheckGuard,
    _operate_success_runtime,
    Mutation,
    OraclePin,
    ShamStorageWrite,
    SwapSlice,
    start_cap_override,
    _operate_guard_runtime,
)
from core.outcome import Outcome, ReplayResult
from core.replay import Replayer
from core.rpc import RpcClient, RpcError
from eval.fidelity import E5Replayer, _mainnet_gas_price
from eval.b2_adapter import run as run_b2
from eval.e4.models import Case, HarmAssessment, MutationPlan
from eval.e4.harm import (assess_attacker_value_harm, assess_harm,
                          assess_transfer_harm, resolve_attacker_address,
                          attacker_candidates_from_trace,
                          assess_euler_bad_debt_delta)
from eval.e4.verdict import criterion, evaluate_removal_intervention
from eval.e4 import planner as _planner
from eval.e4 import harm as _harm
from eval.e4 import b2_mutation as _b2
from eval.e4 import execution as _execution
from eval.e4 import reporting as _reporting

# Compatibility names for planner/harm helpers moved to E4 modules.
_resolve_trace = _planner._resolve_trace
_walk_calls_generator = _planner._walk_calls_generator
_find_flash_provider = _planner._find_flash_provider
_flash_selector_for_provider = _planner._flash_selector_for_provider
_find_oracle = _planner._find_oracle
_find_proxy = _planner._find_proxy
_pin_oracle_stub = _planner._pin_oracle_stub
_price_hex = _planner._price_hex
build_mutation_plan = _planner.build_mutation_plan
_loss_from_receipt = _harm.loss_from_receipt
_loss_from_receipt_data = _harm._loss_from_receipt_data
_attacker_candidates_from_trace = _harm.attacker_candidates_from_trace
_assess_euler_bad_debt_delta = _harm.assess_euler_bad_debt_delta

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DEFAULT = REPO_ROOT / "corpus" / "incidents.jsonl"
RESULTS_DIR = REPO_ROOT / "eval" / "results"
CSV_PATH = RESULTS_DIR / "e4_necessity.csv"

NECESSITY_PORT = 8547  # Verified execution property
NECESSITY_MAX_DELTA_PCT = 10.0  # fidelity PASS: Δ gas ≤ 10% so mainnet.
REPLAYER_TIMEOUT = 300  # Verified execution property
RPC_SLEEP = 0.3  # Verified execution property

# Execution trace analysis and verification
START_SELECTOR = "641ccd83"  # start(uint256 flash,uint256 amount,uint256 min)
# Execution trace analysis and verification
FLASH_SELECTORS = {
    "ab9c4b5d": "AaveV2.flashLoan",   # 0x7d2768de...
    "42b0b77c": "AaveV3.flashLoan",   # 0x87870bca...
    "5c38449e": "Balancer.flashLoan",  # 0xba122222...
    "8240a3e0": "dYdX.operate",        # 0x1e0447b1...
    "a67a6a45": "dYdX.operate",        # historical dYdX SoloMargin operate
    "30e8d2c6": "UniswapV2.swap",      # pair.swap(uint,uint,address) — callback data
    "022c0d9f": "UniswapV2.swap",      # pair.swap(uint,uint,address,bytes) — flash swap
}
UNISWAP_V2_CALLBACK = "10d1e85c"  # Verified execution property
# Execution trace analysis and verification
SAFE_EXEC_SELECTORS = ("a0e67e2b", "e101f8a4", "f9a5e5d0")
# Execution trace analysis and verification
ORACLE_GETTERS = {
    "feaf968c": "latestRoundData",
    "85bb7d69": "answer",
    "50d25bcd": "latestAnswer",
    "59e02dd7": "peek",
}
# Execution trace analysis and verification
AUTH_SELECTORS = {
    "a0e67e2b": "getOwners",          # GnosisSafe
    "e101f8a4": "getThreshold",       # GnosisSafe
    "8d80ff0a": "executeTransaction",  # GnosisSafe execTransaction
    "f9a5e5d0": "execTransaction",     # GnosisSafe (v1.3.0 selector)
}

# ---- load versioned OracleStub runtime template once (patch immutables in-place) ----
# Do not read Foundry's ignored ``out/`` tree here.  A clean release snapshot must
# contain every execution input explicitly, including compiler-emitted immutable
# offsets.  ``OracleStub.runtime.json`` is that small, checksummed input.
ORACLE_STUB_TEMPLATE = REPO_ROOT / "pilot" / "oraclestub" / "OracleStub.runtime.json"


def _load_oracle_stub_runtime() -> tuple[str | None, tuple[tuple[int, int], ...]]:
    """Load and validate the released runtime plus compiler immutable offsets."""
    try:
        payload = json.loads(ORACLE_STUB_TEMPLATE.read_text(encoding="utf-8"))
        runtime = str(payload["deployed_bytecode"])
        if not runtime.startswith("0x"):
            runtime = "0x" + runtime
        bytes.fromhex(runtime[2:])
        references = tuple(
            (int(item["start"]), int(item["length"]))
            for item in payload["immutable_references"]
        )
        if not references:
            raise ValueError("OracleStub template has no immutable references")
        runtime_bytes = len(runtime[2:]) // 2
        for start, length in references:
            if length != 32 or start < 0 or start + length > runtime_bytes:
                raise ValueError("invalid OracleStub immutable reference")
            begin = 2 + start * 2
            end = begin + length * 2
            if runtime[begin:end] != "0" * (length * 2):
                raise ValueError("OracleStub immutable placeholder is not zeroed")
        return runtime, references
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None, ()


ORACLE_STUB_RUNTIME, ORACLE_STUB_IMMUTABLES = _load_oracle_stub_runtime()

# ---- archive client (module-level, init on demand) ----
_ARCHIVE_CLIENT: RpcClient | None = None


def get_archive(rpc: str | None = None) -> RpcClient:
    global _ARCHIVE_CLIENT
    load_dotenv()
    if _ARCHIVE_CLIENT is None:
        _ARCHIVE_CLIENT = RpcClient(rpc or resolve_rpc() or "", timeout=REPLAYER_TIMEOUT)
    return _ARCHIVE_CLIENT


def _ensure_utf8() -> None:
    import sys
    if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and "utf" not in sys.stderr.encoding.lower():
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 (EVM). Uses pycryptodome with eth_hash fallback."""
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:  # pragma: no cover
        import eth_hash  # type: ignore
        return bytes.fromhex(eth_hash.keccak(data).hex())


def _resolve_prior_hashes(archive: RpcClient, tx_hash: str, block: int,
                          tx_index: int) -> list[str]:
    """Retrieve transaction hashes for indices 0..k-1 in the same block (prefix warmup)."""
    if tx_index <= 0:
        return []
    try:
        blk = archive.call("eth_getBlockByNumber", [hex(block), True])
    except RpcError:
        return []
    txs = blk.get("transactions", []) if isinstance(blk, dict) else []
    if len(txs) <= tx_index:
        return []
    return [t.get("hash") for t in txs[:tx_index] if t.get("hash")]


def _block_tag(block: int | None) -> str:
    """Hex block tag for RPC; defaults to 'latest' if block is None."""
    return hex(block) if block is not None else "latest"


def _retry_rpc(fn, attempts: int = 3, base_sleep: float = 1.5):
    """Short retry loop for RPC network timeouts."""
    for a in range(attempts):
        try:
            return fn()
        except RpcError:
            if a == attempts - 1:
                raise
            time.sleep(base_sleep * (a + 1))


def _safe_hex_int(v: str | None, default: int = 0) -> int:
    """Safely parse hex string to int without raising ValueError on empty strings."""
    if not v or not isinstance(v, str):
        return default
    v = v.strip()
    if v in ("", "0x", "0X"):
        return default
    try:
        return int(v, 16)
    except ValueError:
        return default


def load_corpus(corpus_path=CORPUS_DEFAULT) -> list[dict]:
    """Load JSONL corpus file into list of dict records."""
    rows = []
    with open(corpus_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def mutation_factor(name: str) -> str:
    """Normalize implementation-specific names (e.g. f_auth(A)) to factor id."""
    for factor in ("f_fl", "f_health_check", "f_orc", "f_swap", "f_auth", "f_re"):
        if name.startswith(factor):
            return factor
    return "unknown"


def mutation_kind(mutation: Mutation | str) -> str:
    """Return the causal signature family for an intervention."""
    if isinstance(mutation, Mutation):
        return getattr(mutation, "mutation_kind", "removal")
    return "insertion-blocking" if str(mutation).startswith("f_health_check") else "removal"


def _blocking_signature(mutation: Mutation, payload: dict, *, out_of_gas: bool,
                        call_trace_equal: bool) -> tuple[bool, str]:
    if getattr(mutation, "mutation_kind", "removal") != "insertion-blocking":
        return False, "not_blocking_insertion"
    if out_of_gas:
        return False, "out_of_gas"
    data = str(payload.get("revert_data") or payload.get("error") or "")
    if not data or data in {"0x", "0X"}:
        return False, "missing_revert_data"
    if call_trace_equal:
        return False, "call_trace_unchanged"
    expected = getattr(mutation, "expected_revert_reason", "")
    if expected:
        if expected.encode().hex() not in data.lower():
            return False, "guard_selector_unverified"
        donate_frames = [frame for frame in payload.get("call_trace", [])
                         if frame.get("event") == "enter"
                         and str(frame.get("input") or "")[2:10].lower() == "36f022aa"]
        if not donate_frames:
            return False, "guard_call_frame_missing"
        return True, "checkLiquidity_revert_verified"
    return False, "guard_selector_unverified"


def mutation_factors(mutation: Mutation | str) -> tuple[str, ...]:
    """Semantic factor set for single or composite interventions."""
    if isinstance(mutation, CompositeMutation):
        factors = (mutation_factor(str(item)) for item in mutation.mutations)
    else:
        name = str(mutation)
        if name.startswith("joint[") and name.endswith("]"):
            factors = (mutation_factor(item) for item in name[6:-1].split("+"))
        else:
            factors = (mutation_factor(name),)
    return tuple(sorted({factor for factor in factors if factor != "unknown"}))


def build_joint_mutations(mutations: list[Mutation]) -> list[CompositeMutation]:
    """Blind, deterministic |M|=2 candidates over distinct supported factors."""
    joints = []
    for left, right in itertools.combinations(mutations, 2):
        left_factors, right_factors = mutation_factors(left), mutation_factors(right)
        if not left_factors or not right_factors or set(left_factors) & set(right_factors):
            continue
        joints.append(CompositeMutation((left, right)))
    return joints


def score_joint_match(mutation: Mutation | str, gt_factors: list[str],
                      joint_verdict: str) -> str:
    """Exact-set scoring only; permissive subset/superset matching is forbidden."""
    if joint_verdict != "JOINT_CAUSE":
        return "not_scored_joint"
    predicted = set(mutation_factors(mutation))
    ground_truth = {factor for factor in gt_factors if factor != "unknown"}
    if not ground_truth:
        return "unknown_gt"
    return "joint_exact_match" if predicted == ground_truth else "joint_no_match"


def classify_joint_verdict(mutation: CompositeMutation, pair_verdict: str,
                           prior_rows: list[dict]) -> str:
    """Require both individual components to preserve harm before joint cause."""
    if pair_verdict != "CAUSE":
        return ("NOT_JOINT_CAUSE" if pair_verdict == "NOT_NECESSARY"
                else "JOINT_INCONCLUSIVE-pair")
    component_verdicts = []
    for component in mutation.mutations:
        row = next((item for item in prior_rows
                    if item.get("mutation") == str(component)), None)
        component_verdicts.append(str((row or {}).get("verdict") or ""))
    if any(verdict == "CAUSE" for verdict in component_verdicts):
        return "REDUNDANT_WITH_SINGLE"
    if component_verdicts and all(verdict == "NOT_NECESSARY"
                                  for verdict in component_verdicts):
        return "JOINT_CAUSE"
    return "JOINT_INCONCLUSIVE-components"


def score_factor_match(mutation: str, gt_factors: list[str], verdict: str) -> str:
    """Score a conclusive factor prediction after the blind verdict is fixed.

    Both positive and negative verdicts belong in the accuracy denominator.
    Scoring only ``CAUSE`` rows would hide false negatives and inflate the
    apparent localization quality.
    """
    if verdict not in ("CAUSE", "NOT_NECESSARY"):
        return "not_scored"
    gt = {x for x in gt_factors if x != "unknown"}
    if not gt:
        return "unknown_gt"
    predicted = verdict == "CAUSE"
    actual = mutation_factor(mutation) in gt
    return "match" if predicted == actual else "no_match"


def factor_confusion(mutation: str, gt_factors: list[str], verdict: str) -> str:
    """Return TP/FP/FN/TN for a conclusive intervention verdict."""
    if verdict not in ("CAUSE", "NOT_NECESSARY"):
        return "not_scored"
    gt = {x for x in gt_factors if x != "unknown"}
    if not gt:
        return "unknown_gt"
    predicted = verdict == "CAUSE"
    actual = mutation_factor(mutation) in gt
    return ("TP" if actual else "FP") if predicted else ("FN" if actual else "TN")


def score_rows(rows: list[dict], gt_factors: list[str],
               *, paper_eligible: bool) -> list[dict]:
    """Open adjudicated labels only after every replay verdict is frozen."""
    scored_rows = []
    for source in rows:
        row = dict(source)
        mutation = str(row.get("mutation") or "")
        row["factor_gt"] = (
            ("+".join(gt_factors) or "unknown")
            if paper_eligible else "unknown_not_scored"
        )
        if mutation == "control_sham":
            row["factor_match"] = row["factor_confusion"] = "not_scored_control"
        elif mutation in ("fidelity", "no_mutation", "error", "ineligible"):
            row["factor_match"] = row.get("factor_match") or "not_scored"
            row["factor_confusion"] = row.get("factor_confusion") or "not_scored"
        elif not paper_eligible:
            row["factor_match"] = row["factor_confusion"] = "not_scored_legacy_gt"
        elif mutation.startswith("joint["):
            row["factor_match"] = score_joint_match(
                mutation, gt_factors, str(row.get("joint_verdict") or "")
            )
            row["factor_confusion"] = "not_scored_joint"
        else:
            verdict = str(row.get("verdict") or "")
            row["factor_match"] = score_factor_match(mutation, gt_factors, verdict)
            row["factor_confusion"] = factor_confusion(
                mutation, gt_factors, verdict
            )
        scored_rows.append(row)
    return scored_rows


def receipt_fingerprint(receipt: dict | None) -> str | None:
    """Stable behavior fingerprint; excludes tx/block hashes and gas metadata."""
    if not receipt:
        return None
    payload = {
        "status": receipt.get("status"),
        "logs": [{"address": x.get("address"), "topics": x.get("topics"),
                  "data": x.get("data")} for x in receipt.get("logs") or []],
        "contractAddress": receipt.get("contractAddress"),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def assess_sham_control(*, fidelity_ok: bool, observed: bool,
                        execution_preserving: bool, behavior_changed: bool,
                        baseline_harm: str, mutated_harm: str) -> tuple[str, bool | None]:
    """Evaluate an unrelated-state negative control without causal scoring."""
    if not fidelity_ok:
        return "CONTROL_INCONCLUSIVE-fidelity", None
    if not observed:
        return "CONTROL_INCONCLUSIVE-transport", None
    if not execution_preserving:
        return "CONTROL_INCONCLUSIVE-invalid-execution", None
    if behavior_changed:
        return "CONTROL_FAIL-behavior-changed", False
    if baseline_harm != "HARM" or mutated_harm == "UNKNOWN":
        return "CONTROL_INCONCLUSIVE-harm-unmeasured", None
    if mutated_harm != "HARM":
        return "CONTROL_FAIL-harm-disappeared", False
    return "CONTROL_PASS", True


def _validate_sham_unrelated(trace: dict | None, sham: ShamStorageWrite) -> None:
    """Fail closed unless the sham address is absent from a resolved call trace."""
    if not trace:
        raise ValueError("sham control requires a resolved call trace")
    touched = {
        str(node.get(field) or "").lower()
        for node in _walk_calls_generator(trace)
        for field in ("from", "to")
    }
    if sham.address in touched:
        raise ValueError("sham sentinel unexpectedly appears in the transaction trace")

def _run_necessity_legacy(*args, **kwargs):
    """Backward-compatible name for the extracted execution runner."""
    return _execution.run_necessity(*args, **kwargs)

# Compatibility entry point now goes through the E4 execution boundary.
run_necessity = _execution.run_necessity

# Compatibility names now route reporting through the E4 boundary.
_b2_mutation_args = _b2.mutation_args
_b2_target_payload = _b2.target_payload
_b2_call_trace_diff = _b2.call_trace_diff
_assess_transfer_harm = _harm.assess_transfer_harm
_assess_attacker_value_harm = _harm.assess_attacker_value_harm
_assess_pool_balance_delta = _harm.assess_pool_balance_delta
_fetch_prestate_native_balance_delta = _harm.fetch_prestate_native_balance_delta
_fetch_trace_token_transfer_delta = _harm.fetch_trace_token_transfer_delta
_resolve_attacker_address = _harm.resolve_attacker_address
_aggregate = _reporting.aggregate
write_csv = _reporting.write_csv
load_results = _reporting.load_results
build_evidence_graph = _reporting.build_evidence_graph
