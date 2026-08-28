"""Small dependency-free statistical helpers shared by paper reports."""
from __future__ import annotations

import math
from statistics import NormalDist


def wilson_interval(successes: int, total: int,
                    confidence: float = 0.95) -> dict[str, float | int]:
    """Wilson score interval for a binomial proportion.

    The method behaves sensibly for small samples and boundary counts, unlike
    the normal approximation.  Empty denominators remain explicit instead of
    being presented as a zero-width interval.
    """
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("require 0 <= successes <= total")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between 0 and 1")
    if total == 0:
        return {"successes": successes, "total": total, "confidence": confidence,
                "low": 0.0, "high": 1.0}
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = (z / denominator) * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    )
    return {"successes": successes, "total": total, "confidence": confidence,
            "low": max(0.0, center - margin), "high": min(1.0, center + margin)}
