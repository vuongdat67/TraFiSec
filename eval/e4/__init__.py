"""E4 compatibility surface.

The implementation still lives in :mod:`eval.necessity` during the
incremental refactor.  New callers may import the extracted domain models and
verdict policy from this package without changing the legacy entry point.
"""

from eval.e4.models import Case, HarmAssessment, MutationPlan
from eval.e4.verdict import criterion
from eval.e4.harm import (
    HarmOracle,
    ReceiptLedgerOracle,
    TransferDeltaOracle,
    assess_harm,
    assess_attacker_value_harm,
    assess_pool_balance_delta,
    assess_euler_bad_debt_delta,
    parse_prestate_native_balance_delta,
    fetch_prestate_native_balance_delta,
    parse_trace_token_transfer_delta,
    fetch_trace_token_transfer_delta,
    assess_transfer_harm,
    AttackerValueOracle,
    PoolBalanceOracle,
    EulerBadDebtOracle,
    resolve_attacker_address,
    created_addresses_from_trace,
    attacker_candidates_from_trace,
    create_harm_oracle,
    loss_from_receipt,
)
from eval.e4.b2_mutation import call_trace_diff, mutation_args, target_payload
from eval.e4.execution import run_necessity
from eval.e4.reporting import aggregate, build_evidence_graph, load_results, write_csv
from eval.e4.cli import main

# Keep the existing public API available while extraction proceeds in small
# steps.  This import is deliberately last: necessity imports the extracted
# models/policy above.
from eval.necessity import *  # noqa: F401,F403,E402
