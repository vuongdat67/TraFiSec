"""
TraFiSec — Stage 1 Screener: candidate queue (src/core/candidate.py)
==========================================================================
Candidate Selector for Stage-2 Counterfactual Replay.
Selects high-risk transactions exceeding classification threshold tau.
Applies top-k capacity bounds (default 1% volume) to maintain predictable Stage-2 replay latency.
Maintains deduplicated FIFO queue prioritized by descending anomaly scores.
"""
from __future__ import annotations

import math
from collections import deque


class CandidateQueue:
    """FIFO queue storing candidate transactions (score >= tau) for Stage-2 replay, capped at top-k."""

    def __init__(self, tau: float | None = None, top_k_frac: float = 0.01,
                 max_size: int | None = None):
        self.tau = tau if tau is not None else 0.50
        self.top_k_frac = top_k_frac
        self.max_size = max_size  # Verified execution property
        self._q: deque[tuple[str, float]] = deque()
        self.seen: set[str] = set()

    # Execution trace analysis and verification
    def is_candidate(self, score: float) -> bool:
        return score >= self.tau

    def add(self, tx_hash: str, score: float) -> bool:
        """Enqueue candidate if score meets threshold and transaction has not been evaluated."""
        if not self.is_candidate(score):
            return False
        if tx_hash in self.seen:
            return False
        self.seen.add(tx_hash)
        self._q.append((tx_hash, score))
        return True

    def pop(self) -> tuple[str, float] | None:
        return self._q.popleft() if self._q else None

    def __len__(self) -> int:
        return len(self._q)

    # Execution trace analysis and verification
    def select_top_k(self, scored: list[tuple[str, float]], n_batch: int | None = None) -> list[str]:
        """Sort candidates by anomaly score in descending order,
        cap ≤ max(ceil(top_k_frac·n_batch), 1). Dedupe qua seen."""
        nb = n_batch if n_batch is not None else len(scored)
        k = max(int(math.ceil(self.top_k_frac * nb)), 1)
        if self.max_size is not None:
            k = min(k, self.max_size)
        cands = [(h, s) for h, s in scored
                 if self.is_candidate(s) and h not in self.seen]
        cands.sort(key=lambda x: -x[1])
        picked = cands[:k]
        for h, s in picked:
            self.seen.add(h)
            self._q.append((h, s))
        return [h for h, _ in picked]

    def stats(self) -> dict:
        return {"tau": self.tau, "top_k_frac": self.top_k_frac,
                "queued": len(self._q), "seen": len(self.seen)}
