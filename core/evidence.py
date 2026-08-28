"""
TraFiSec — Evidence Graph (src/core/evidence.py)
========================================================
Dataclass + JSON serializer cho evidence graph theo proposal §5.4.

Evidence graph artifact tracking all counterfactual intervention branches and
outcome, viol, Δloss  analyst t verify li bng `traceguard replay --verify`.

Format JSON (proposal §5.4):
    {
      "tx": "0x...",
      "fork_block": 16817994,
      "world_hash": "...",
      "mutations": [
        {
          "id": "f_fl",
          "state_patch": {...},
          "pre_loss": 8700000,
          "post_loss": 0,
          "outcome": "EXECUTED_NO_HARM",
          "viol_baseline": 1,
          "viol_counterfactual": 0,
          "verdict": "CAUSE",
          "note": ""
        },
        ...
      ],
      "verdict": "CAUSE",
      "confidence": 0.95,
      "audit_log": [...]
    }

Outcome taxonomy (RESEARCH_SCOPE.md):
  1. Observed: receipt obtained vs UNOBSERVED (transport failure)
  2. Execution: SUCCESS vs EVM_REVERT
  3. Intervention validity: VALID vs INVALID / NO_OP
  4. Harm observability: HARM_MEASURED vs HARM_UNMEASURED
  5. Causal verdict: CAUSE | NOT_CAUSE | INCONCLUSIVE
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Outcome(str, Enum):
    """Outcome ca 1 replay branch (proposal §5.1)."""
    EXECUTED_NO_HARM = "EXECUTED_NO_HARM"   # Verified execution property
    EXECUTED_HARM = "EXECUTED_HARM"         # Verified execution property
    REVERTED = "REVERTED"                   # Verified execution property
    UNOBSERVED = "UNOBSERVED"               # transport failure, timeout
    UNKNOWN = "UNKNOWN"                     # Verified execution property


class Verdict(str, Enum):
    """Causal verdict ca 1 mutation branch (proposal §5.1–5.2)."""
    CAUSE = "CAUSE"                         # Verified execution property
    NOT_CAUSE = "NOT_CAUSE"                 # necessity not confirmed
    INCONCLUSIVE = "INCONCLUSIVE"           # fidelity fail / unobserved / invalid
    REVERTED_BRANCH = "REVERTED_BRANCH"     # Verified execution property
    JOINT_CAUSE = "JOINT_CAUSE"            # joint-cause pair confirmed
    REDUNDANT_WITH_SINGLE = "REDUNDANT_WITH_SINGLE"  # Verified execution property


class InterventionValidity(str, Enum):
    """Validity ca intervention (RESEARCH_SCOPE.md outcome taxonomy)."""
    VALID = "VALID"               # intervention supported + behavior-preserving
    INVALID = "INVALID"           # unsupported intervention
    NO_OP = "NO_OP"              # mutation applied but no effect on execution
    UNKNOWN = "UNKNOWN"


@dataclass
class MutationBranch:
    """Mt nhnh mutation trong evidence graph.

    Records individual mutation execution attempts under the outcome taxonomy.
    """
    # Identification
    mutation_id: str                       # "f_fl", "f_orc", "f_swap", "f_auth"
    mutation_name: str = ""                # human-readable name

    # Outcome taxonomy (RESEARCH_SCOPE.md)
    observed: bool = True                  # receipt obtained
    execution_success: bool | None = None  # EVM success vs revert
    intervention_validity: InterventionValidity = InterventionValidity.UNKNOWN
    harm_measured: bool = False            # victim ledger available + measured

    # Core data
    outcome: Outcome = Outcome.UNKNOWN
    viol_baseline: int = -1               # viol(S): 1=violation, 0=no-violation
    viol_counterfactual: int = -1         # viol(S-X): 1=violation, 0=no-violation
    pre_loss: float = 0.0                 # loss(S) USD
    post_loss: float = 0.0               # loss(S-X) USD
    delta_loss: float = 0.0              # pre_loss - post_loss

    # Causal verdict
    verdict: Verdict = Verdict.INCONCLUSIVE
    confidence: float = 0.0              # 0-1: how confident in verdict

    # Evidence
    state_patch: dict = field(default_factory=dict)     # state mutations applied
    gas_used_mainnet: int = 0
    gas_used_replay: int = 0
    gas_delta_pct: float = 0.0
    note: str = ""
    inconclusive_reason: str = ""        # REVERTED / UNOBSERVED / INVALID / UNMEASURED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        d["verdict"] = self.verdict.value
        d["intervention_validity"] = self.intervention_validity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MutationBranch":
        d = dict(d)
        d["outcome"] = Outcome(d.get("outcome", "UNKNOWN"))
        d["verdict"] = Verdict(d.get("verdict", "INCONCLUSIVE"))
        d["intervention_validity"] = InterventionValidity(
            d.get("intervention_validity", "UNKNOWN"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def is_cause(self) -> bool:
        return self.verdict in (Verdict.CAUSE, Verdict.JOINT_CAUSE)

    def is_reverted_branch(self) -> bool:
        return self.outcome == Outcome.REVERTED


@dataclass
class EvidenceGraph:
    """Evidence graph hon chnh cho 1 transaction (proposal §5.4).

    Serializes counterfactual evidence trace into JSON.
    1. Audit trail cho reviewer
    2. Reproduce bng `traceguard replay --verify <id>`
    3. Paper claim support (denominator tracking)
    """
    # Transaction identity
    tx: str
    run_id: str = ""
    fork_block: int = 0
    world_hash: str = ""                  # Verified execution property

    # Ground truth (opened AFTER verdict)
    gt_factors: list[str] = field(default_factory=list)
    security_objective: str = ""
    victim_set: list[str] = field(default_factory=list)
    lmin: float = 0.0

    # Fidelity gate (E5)
    fidelity_passed: bool | None = None
    fidelity_cell_match_pct: float = 0.0
    baseline_outcome: Outcome = Outcome.UNKNOWN
    baseline_loss: float = 0.0
    baseline_gas_used: int = 0

    # Mutation branches
    branches: list[MutationBranch] = field(default_factory=list)

    # Sham control (E4 validity)
    sham_outcome: Outcome = Outcome.UNKNOWN
    sham_viol: int = -1
    sham_passed: bool | None = None      # must preserve harm (viol=1)

    # Aggregate verdict
    verdict: Verdict = Verdict.INCONCLUSIVE
    confidence: float = 0.0
    cause_factors: list[str] = field(default_factory=list)
    joint_causes: list[list[str]] = field(default_factory=list)

    # Provenance
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_log: list[str] = field(default_factory=list)

    def add_branch(self, branch: MutationBranch) -> None:
        self.branches.append(branch)
        self.audit_log.append(
            f"[{datetime.now(timezone.utc).isoformat()}] branch {branch.mutation_id}: "
            f"outcome={branch.outcome.value} verdict={branch.verdict.value}"
        )

    def finalize(self) -> None:
        """Compute aggregate verdict t branches.

        Quy tc (proposal §5.2):
        - CAUSE: ≥1 branch vi EXECUTED_NO_HARM (CAUSE verdict)
        - BENIGN: viol_baseline=1 AND mi branch u EXECUTED_HARM hoc REVERTED
        - INCONCLUSIVE: khng  data hoc fidelity fail
        """
        if self.fidelity_passed is False:
            self.verdict = Verdict.INCONCLUSIVE
            self.audit_log.append("INCONCLUSIVE: fidelity gate failed")
            return

        cause_branches = [b for b in self.branches if b.is_cause()]
        if cause_branches:
            self.verdict = Verdict.CAUSE
            self.cause_factors = [b.mutation_id for b in cause_branches]
            self.confidence = max(b.confidence for b in cause_branches)
        elif (self.baseline_outcome == Outcome.EXECUTED_HARM
              and self.branches
              and all(b.outcome in (Outcome.EXECUTED_HARM, Outcome.REVERTED)
                      for b in self.branches)):
            self.verdict = Verdict.NOT_CAUSE
            self.confidence = 0.8
        else:
            self.verdict = Verdict.INCONCLUSIVE
            reasons = [b.inconclusive_reason for b in self.branches
                       if b.inconclusive_reason]
            self.audit_log.append(f"INCONCLUSIVE: {'; '.join(reasons) or 'insufficient data'}")

    def to_dict(self) -> dict:
        d = {
            "tx": self.tx,
            "run_id": self.run_id,
            "fork_block": self.fork_block,
            "world_hash": self.world_hash,
            "gt_factors": self.gt_factors,
            "security_objective": self.security_objective,
            "victim_set": self.victim_set,
            "lmin": self.lmin,
            "fidelity_passed": self.fidelity_passed,
            "fidelity_cell_match_pct": self.fidelity_cell_match_pct,
            "baseline_outcome": self.baseline_outcome.value,
            "baseline_loss": self.baseline_loss,
            "baseline_gas_used": self.baseline_gas_used,
            "branches": [b.to_dict() for b in self.branches],
            "sham_outcome": self.sham_outcome.value,
            "sham_viol": self.sham_viol,
            "sham_passed": self.sham_passed,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "cause_factors": self.cause_factors,
            "joint_causes": self.joint_causes,
            "created_at": self.created_at,
            "audit_log": self.audit_log,
        }
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceGraph":
        branches = [MutationBranch.from_dict(b) for b in d.get("branches", [])]
        g = cls(
            tx=d.get("tx", ""),
            run_id=d.get("run_id", ""),
            fork_block=d.get("fork_block", 0),
            world_hash=d.get("world_hash", ""),
            gt_factors=d.get("gt_factors", []),
            security_objective=d.get("security_objective", ""),
            victim_set=d.get("victim_set", []),
            lmin=d.get("lmin", 0.0),
            fidelity_passed=d.get("fidelity_passed"),
            fidelity_cell_match_pct=d.get("fidelity_cell_match_pct", 0.0),
            baseline_outcome=Outcome(d.get("baseline_outcome", "UNKNOWN")),
            baseline_loss=d.get("baseline_loss", 0.0),
            baseline_gas_used=d.get("baseline_gas_used", 0),
            sham_outcome=Outcome(d.get("sham_outcome", "UNKNOWN")),
            sham_viol=d.get("sham_viol", -1),
            sham_passed=d.get("sham_passed"),
            verdict=Verdict(d.get("verdict", "INCONCLUSIVE")),
            confidence=d.get("confidence", 0.0),
            cause_factors=d.get("cause_factors", []),
            joint_causes=d.get("joint_causes", []),
            created_at=d.get("created_at", ""),
            audit_log=d.get("audit_log", []),
        )
        g.branches = branches
        return g

    @classmethod
    def from_json(cls, s: str) -> "EvidenceGraph":
        return cls.from_dict(json.loads(s))

    def summary(self) -> str:
        """Text summary for CLI display."""
        cause_list = ", ".join(self.cause_factors) if self.cause_factors else "none"
        lines = [
            f"Evidence Graph: {self.tx[:20]}... (block {self.fork_block})",
            f"  Verdict: {self.verdict.value} (confidence={self.confidence:.2f})",
            f"  Cause factors: {cause_list}",
            f"  Branches: {len(self.branches)} | CAUSE:{sum(b.is_cause() for b in self.branches)}"
            f" | REVERTED:{sum(b.is_reverted_branch() for b in self.branches)}",
            f"  Baseline loss: ${self.baseline_loss:,.0f}",
            f"  Fidelity: {self.fidelity_cell_match_pct:.1%} cell match",
        ]
        for b in self.branches:
            lines.append(
                f"    [{b.mutation_id}] outcome={b.outcome.value} "
                f"Δloss={b.delta_loss:,.0f} verdict={b.verdict.value}"
                + (f" [{b.inconclusive_reason}]" if b.inconclusive_reason else "")
            )
        return "\n".join(lines)


def make_branch_from_necessity_row(row: dict) -> MutationBranch:
    """Factory: to MutationBranch t necessity.py output row (backward compat).

    Dng  convert cc necessity result rows hin ti thnh EvidenceGraph branches.
    """
    outcome_str = row.get("outcome", "UNKNOWN").upper()
    try:
        outcome = Outcome(outcome_str)
    except ValueError:
        outcome = Outcome.UNKNOWN

    viol_base = row.get("viol_baseline", -1)
    viol_cf = row.get("viol_counterfactual", -1)
    pre_loss = float(row.get("pre_loss_usd", row.get("pre_loss", 0)) or 0)
    post_loss = float(row.get("post_loss_usd", row.get("post_loss", 0)) or 0)

    # Derive verdict
    if outcome == Outcome.EXECUTED_NO_HARM and viol_base == 1 and viol_cf == 0:
        verdict = Verdict.CAUSE
        confidence = 0.9
    elif outcome == Outcome.REVERTED:
        verdict = Verdict.REVERTED_BRANCH
        confidence = 0.0
    elif outcome == Outcome.UNOBSERVED:
        verdict = Verdict.INCONCLUSIVE
        confidence = 0.0
    elif viol_cf == 1:
        verdict = Verdict.NOT_CAUSE
        confidence = 0.8
    else:
        verdict = Verdict.INCONCLUSIVE
        confidence = 0.0

    return MutationBranch(
        mutation_id=row.get("mutation", row.get("mutation_id", "unknown")),
        mutation_name=row.get("mutation_name", ""),
        observed=outcome not in (Outcome.UNOBSERVED, Outcome.UNKNOWN),
        execution_success=outcome in (Outcome.EXECUTED_NO_HARM, Outcome.EXECUTED_HARM),
        outcome=outcome,
        viol_baseline=viol_base,
        viol_counterfactual=viol_cf,
        pre_loss=pre_loss,
        post_loss=post_loss,
        delta_loss=pre_loss - post_loss,
        verdict=verdict,
        confidence=confidence,
        harm_measured=pre_loss > 0,
        gas_used_mainnet=int(row.get("gas_used_mainnet", 0)),
        gas_used_replay=int(row.get("gas_used_replay", 0)),
        note=row.get("note", ""),
        inconclusive_reason=row.get("inconclusive_reason", ""),
    )
