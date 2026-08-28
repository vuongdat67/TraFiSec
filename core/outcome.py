"""
TraFiSec pilot — Outcome model
======================================
Three-valued verdict taxonomy and execution outcome data structures.
Lesson 2026-08-11: cast send timeout ≠ revert; status 0x1 + gasUsed gn mainnet
= executed; status 0x0 + gasUsed nh ≈ revert sm (precondition).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Outcome(str, Enum):
    # No receipt was obtained. This is transport/infrastructure evidence, not
    # an EVM execution outcome and especially not a revert.
    UNOBSERVED = "UNOBSERVED"
    # Execution succeeded but no harm oracle was evaluated.  This is the safe
    # default for the generic replayer; callers may refine it to *_HARM after
    # evaluating a case-specific, independently specified security objective.
    EXECUTED_UNKNOWN = "EXECUTED_UNKNOWN"
    EXECUTED_NO_HARM = "EXECUTED_NO_HARM"
    EXECUTED_HARM = "EXECUTED_HARM"
    REVERTED = "REVERTED"

    def __str__(self) -> str:
        return self.value


@dataclass
class ReplayResult:
    """Replay execution result across fidelity baseline or counterfactual mutation.

    - `status True/False` — receipt status; `None` = send fail/timeout and must
      use `UNOBSERVED`, never `REVERTED`.
    - `gas_used` vs `mainnet_gas` — Δ ≤ ~10% = fidelity PASS (lesson: gas nh
      Significant gas reduction indicates early revert.
    """
    outcome: Outcome
    status: bool | None = None
    gas_used: int | None = None
    mainnet_gas: int | None = None
    note: str = ""
    details: dict = field(default_factory=dict)
    # Execution trace analysis and verification
    # Execution trace analysis and verification
    receipt: dict | None = None
    # `observed=False` distinguishes RPC/cast/receipt failures from an EVM
    # revert.  A transport failure is not one of the three execution outcomes
    # and must never be used as counterfactual evidence.
    observed: bool = True
    error_kind: str | None = None
    failure_class: str | None = None
    rpc_method: str | None = None
    attempt_count: int | None = None
    elapsed_ms: int | None = None

    @property
    def gas_delta_pct(self) -> float | None:
        if self.gas_used and self.mainnet_gas:
            return (self.gas_used - self.mainnet_gas) / self.mainnet_gas * 100
        return None

    def fidelity_pass(self, max_delta_pct: float = 10.0) -> bool:
        """Fidelity PASS: status True + gas Δ ≤ max_delta_pct (so vi mainnet)."""
        if not self.status or not self.gas_used or not self.mainnet_gas:
            return False
        return abs(self.gas_delta_pct or 0.0) <= max_delta_pct

    def to_csv_row(self, case_mut: str) -> str:
        """Dng outcomes.csv: case,mutation,outcome,loss_S,loss_Sm,Δloss,note"""
        loss_s = self.details.get("loss_S", "")
        loss_sm = self.details.get("loss_Sm", "")
        dloss = self.details.get("dloss", "")
        return f"{case_mut},{self.outcome.value},{loss_s},{loss_sm},{dloss},{self.note}"
