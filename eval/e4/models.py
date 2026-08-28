"""Pure E4 domain models.

This module contains no archive calls, replay orchestration, or reporting.
The models intentionally retain the current field shapes so the first
refactor step is behavior-preserving.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.mutate import Mutation


@dataclass
class Case:
    """One E4 attack case, independent from corpus mutation."""

    case_id: str
    protocol: str
    attack_type: str
    tx_hash: str
    block: int | None = None
    tx_index: int = 0
    prior_hashes: list[str] = field(default_factory=list)
    gt_factors: list[str] = field(default_factory=list)
    chain: str = "mainnet"
    loss_usd: float | None = None
    notes: str = ""
    source_url: str = ""
    extra: dict = field(default_factory=dict)
    mainnet_gas: int | None = None
    trace: dict | None = field(default=None, repr=False)


@dataclass
class MutationPlan:
    """Blindly discovered intervention candidates for one case."""

    mutations: list[Mutation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, mutation: Mutation, note: str = "") -> None:
        """Add one semantic candidate, deduplicating equivalent paths."""
        key = (
            mutation.name,
            getattr(mutation, "provider", None),
            getattr(mutation, "oracle", None),
            getattr(mutation, "proxy", None),
            getattr(mutation, "start_cap", None),
            getattr(mutation, "ratio", None),
        )
        existing = {
            (
                item.name,
                getattr(item, "provider", None),
                getattr(item, "oracle", None),
                getattr(item, "proxy", None),
                getattr(item, "start_cap", None),
                getattr(item, "ratio", None),
            )
            for item in self.mutations
        }
        if key in existing:
            return
        self.mutations.append(mutation)
        if note:
            self.notes.append(note)


@dataclass(frozen=True)
class HarmAssessment:
    """Result of a case-specific harm oracle."""

    status: str
    loss_usd: float | None = None
    source: str = ""
    reason: str = ""
