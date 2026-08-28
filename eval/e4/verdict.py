"""Pure causal verdict policy for E4.

No RPC, filesystem, subprocess, or replay dependency belongs here.  This
module preserves the current outcome-guard semantics while providing a seam
for later separation of removal and insertion-blocking policies.
"""

from __future__ import annotations

from core.outcome import Outcome


def criterion(
    outcome: str,
    *,
    baseline_harm: str = "UNKNOWN",
    mutated_harm: str = "UNKNOWN",
    observed: bool = True,
    execution_preserving: bool = False,
    behavior_changed: bool = False,
) -> str:
    """Evaluate the current removal-style E4 causal criterion.

    Reverts, transport failures, invalid interventions, and unmeasured harm
    remain inconclusive.  One mutation that fails to remove harm is not proof
    that the transaction is benign.
    """
    if not observed:
        return "INCONCLUSIVE-transport"
    if baseline_harm == "UNKNOWN":
        return "INCONCLUSIVE-harm-unmeasured"
    if baseline_harm != "HARM":
        return "INCONCLUSIVE-baseline-harm"
    if outcome == Outcome.REVERTED.value:
        return "INCONCLUSIVE-revert"
    if not execution_preserving:
        return "INCONCLUSIVE-invalid-intervention"
    if not behavior_changed:
        return "INCONCLUSIVE-no-effect"
    if mutated_harm == "NO_HARM":
        return "CAUSE"
    if mutated_harm == "HARM":
        return "NOT_NECESSARY"
    return "INCONCLUSIVE-harm-unmeasured"


def evaluate_removal_intervention(
    *,
    baseline_harm: bool | None,
    mutation_executed: bool,
    mutation_harm: bool | None,
    intervention_supported: bool,
) -> str:
    """Small typed seam for removal-style policy consumers."""
    if not intervention_supported:
        return "INCONCLUSIVE"
    if baseline_harm is None:
        return "INCONCLUSIVE-harm-unmeasured"
    if not baseline_harm:
        # Necessity is only defined for an actually harmful baseline.  A
        # benign baseline cannot establish that removing the factor was
        # unnecessary; it leaves the causal question untested.
        return "INCONCLUSIVE-baseline-harm"
    if not mutation_executed:
        return "INCONCLUSIVE-revert"
    if mutation_harm is None:
        return "INCONCLUSIVE"
    return "NOT_NECESSARY" if mutation_harm else "CAUSE"


def evaluate_blocking_intervention(
    *,
    baseline_harm: bool,
    reached_check: bool,
    reverted_expected_reason: bool,
    reverted_expected_frame: bool,
    reverted_oog: bool,
) -> str:
    """Typed seam for insertion-blocking mutations such as Euler's guard."""
    if not baseline_harm:
        return "NOT_NECESSARY"
    if not reached_check:
        return "INCONCLUSIVE"
    if reverted_oog:
        return "INCONCLUSIVE-oog"
    if not (reverted_expected_reason and reverted_expected_frame):
        return "INCONCLUSIVE-revert"
    return "CAUSE-NECESSARY-blocking"
