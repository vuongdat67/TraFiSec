"""Agreement statistics for independently produced categorical review votes."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable


def cohen_kappa(pairs: Iterable[tuple[str, str]]) -> dict[str, float | int | None]:
    """Return raw agreement and Cohen's kappa without hiding degeneracy."""
    values = list(pairs)
    n = len(values)
    if not n:
        return {"n": 0, "raw_agreement": None, "kappa": None}
    agree = sum(left == right for left, right in values)
    raw = agree / n
    left_counts = Counter(left for left, _ in values)
    right_counts = Counter(right for _, right in values)
    labels = set(left_counts) | set(right_counts)
    expected = sum((left_counts[label] / n) * (right_counts[label] / n)
                   for label in labels)
    kappa = None if expected >= 1.0 else (raw - expected) / (1.0 - expected)
    return {"n": n, "raw_agreement": raw, "kappa": kappa}


def first_two_votes(records: Iterable[dict], field: str) -> list[tuple[str, str]]:
    """Extract the first two distinct-reviewer labels from each record."""
    pairs: list[tuple[str, str]] = []
    for record in records:
        votes = record.get("reviewer_votes") or []
        distinct: list[dict] = []
        seen: set[str] = set()
        for vote in votes:
            reviewer = str(vote.get("reviewer") or "")
            if reviewer and reviewer not in seen:
                seen.add(reviewer)
                distinct.append(vote)
        if len(distinct) >= 2:
            left = distinct[0].get(field)
            right = distinct[1].get(field)
            if left is not None and right is not None:
                pairs.append((str(left), str(right)))
    return pairs


def e4_agreement(records: Iterable[dict]) -> dict:
    """Eligibility and exact multi-label root-cause agreement for E4."""
    records = list(records)
    eligibility = cohen_kappa(first_two_votes(records, "eligibility"))
    root_pairs: list[tuple[str, str]] = []
    for record in records:
        votes = record.get("reviewer_votes") or []
        distinct: list[dict] = []
        seen: set[str] = set()
        for vote in votes:
            reviewer = str(vote.get("reviewer") or "")
            if reviewer and reviewer not in seen:
                seen.add(reviewer)
                distinct.append(vote)
        if len(distinct) >= 2:
            left = "+".join(sorted(map(str, distinct[0].get("root_cause") or [])))
            right = "+".join(sorted(map(str, distinct[1].get("root_cause") or [])))
            root_pairs.append((left, right))
    return {"eligibility": eligibility, "root_cause_exact_set": cohen_kappa(root_pairs)}
