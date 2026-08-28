"""
TraFiSec — Unified Core Package (src/core)
=================================================
Tng 1 (Screener):
- trace.py      — TraceFetcher: fetch trace + state delta t archive RPC.
- views.py      — 4 view extractors (call_structure / token_flow / state_delta / economic).
- fusion.py     — LogisticFusion: score = σ(w₀ + Σ w_v·s_v), calibrate ECE.
- candidate.py  — CandidateQueue: ngng τ + top-k cap cho Stage 2.
- screener.py   — Screener API: score(tx) / screen_batch(txs).

Tng 2 (Replay & Counterfactual Engine):
- env.py        — .env auto-load + resolve_rpc.
- rpc.py        — RpcClient JSON-RPC (anvil + archive, anvil_set* patches).
- fork.py       — ForkRunner: vng i anvil fork.
- replay.py     — Replayer: replay tx ln anvil fork.
- outcome.py    — Outcome + ReplayResult.
- mutate.py     — Mutation ABC + FlashLoanDisable, OraclePin, SwapSlice, AuthRevoke, SignatureRecovery.
- loss.py       — TraceAnalyzer: loss per-party t trace.
- runner.py     — CaseConfig + CaseRunner.
"""
from .candidate import CandidateQueue
from .env import load_dotenv, resolve_rpc
from .fork import ForkRunner
from .fusion import (
    LogisticFusion,
    calibrate_temperature,
    expected_calibration_error,
    fit_logistic_fusion,
    fit_seed_default,
    seed_train_data,
)
from .loss import TraceAnalyzer
from .mutate import (
    AuthRevoke,
    FlashLoanDisable,
    Mutation,
    OraclePin,
    RecoveryResult,
    SignatureRecovery,
    SwapSlice,
)
from .outcome import Outcome, ReplayResult
from .replay import Replayer
from .rpc import RpcClient, RpcError
from .runner import CaseConfig, CaseRunner
from .screener import Screener
from .trace import (
    TOPIC_TRANSFER,
    TraceFetcher,
    TraceFetchError,
    parse_call_tracer,
    parse_tx_receipt,
)
from .views import ALL_VIEWS, evaluate_all

__all__ = [
    "Screener",
    "CandidateQueue",
    "LogisticFusion",
    "fit_logistic_fusion",
    "fit_seed_default",
    "seed_train_data",
    "expected_calibration_error",
    "calibrate_temperature",
    "TraceFetcher",
    "TraceFetchError",
    "parse_call_tracer",
    "parse_tx_receipt",
    "TOPIC_TRANSFER",
    "evaluate_all",
    "ALL_VIEWS",
    # Replay engine
    "load_dotenv",
    "resolve_rpc",
    "RpcClient",
    "RpcError",
    "ForkRunner",
    "Replayer",
    "Outcome",
    "ReplayResult",
    "Mutation",
    "FlashLoanDisable",
    "OraclePin",
    "SwapSlice",
    "AuthRevoke",
    "SignatureRecovery",
    "RecoveryResult",
    "TraceAnalyzer",
    "CaseConfig",
    "CaseRunner",
]
