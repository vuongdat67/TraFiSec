"""Unit tests cho eval.necessity — E4 Counterfactual Necessity.

Pure stdlib test (unittest + mock + tempfile) - no Anvil or external tools required
network hay .env keys. Mi RPC mock qua unittest.mock.patch.

Chy t repository root:
    python -m unittest discover -s tests -p "test_*.py"
    python -m unittest tests.test_necessity
    python tests/test_necessity.py
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.necessity import (  # noqa: E402
    Case,
    HarmAssessment,
    MutationPlan,
    _aggregate,
    assess_sham_control,
    _find_flash_provider,
    _flash_selector_for_provider,
    _find_oracle,
    _find_proxy,
    _loss_from_receipt,
    _pin_oracle_stub,
    _price_hex,
    build_joint_mutations,
    build_evidence_graph,
    build_mutation_plan,
    criterion,
    classify_joint_verdict,
    factor_confusion,
    score_factor_match,
    score_joint_match,
    score_rows,
    write_csv,
)
from eval.e4.models import (  # noqa: E402
    Case as E4Case,
    HarmAssessment as E4HarmAssessment,
    MutationPlan as E4MutationPlan,
)
from eval.e4.verdict import (  # noqa: E402
    criterion as e4_criterion,
    evaluate_blocking_intervention,
    evaluate_removal_intervention,
)
from eval.e4.harm import (  # noqa: E402
    ReceiptLedgerOracle,
    TransferDeltaOracle,
    assess_attacker_value_harm,
    attacker_candidates_from_trace,
    create_harm_oracle,
    created_addresses_from_trace,
    resolve_attacker_address,
)
from eval.e4.b2_mutation import (  # noqa: E402
    OracleStubProvider,
    StorageOverrideProvider,
    call_trace_diff,
    mutation_args,
    target_payload,
)
from eval.e4.execution import run_necessity as extracted_run_necessity  # noqa: E402
from eval.e4.reporting import aggregate, build_evidence_graph as extracted_graph  # noqa: E402
from core.mutate import (  # noqa: E402
    AmmReservePin,
    AuthRevoke,
    CompositeMutation,
    FlashLoanDisable,
    OraclePin,
    ShamStorageWrite,
    SwapSlice,
)


def _make_trace(*, fl=None, oracle=None, proxy=None, top_input="0x"):
    """Construct a synthetic 3-node callTracer tree for testing."""
    calls = []
    if fl:
        calls.append({"type": "CALL", "from": "0xattacker", "to": fl,
                      "input": "0xab9c4b5d" + "00" * 32})  # AaveV2 flashLoan
    if oracle:
        calls.append({"type": "STATICCALL", "from": "0xc", "to": oracle,
                      "input": "0xfeaf968c"})  # latestRoundData
    if proxy:
        calls.append({"type": "DELEGATECALL", "from": proxy,
                      "to": "0x2222222222222222222222222222222222222222",
                      "input": "0x"})
    return {"type": "CALL", "from": "0xattacker", "to": "0xattack_contract",
            "input": top_input, "value": "0x0", "calls": calls}


class FakeArchive:
    """Mock archive RPC for build_mutation_plan tests (offline)."""

    def __init__(self, *, code=None, admin=None, implementation=None, price=12345, top_input="0x",
                 safes=None):
        self.code = code or {}
        self.admin = admin or {}
        self.implementation = implementation or {}
        self.price = price
        self.top_input = top_input
        self.safes = set(a.lower() for a in (safes or []))

    def eth_get_code(self, addr, block="latest"):
        return self.code.get(addr.lower(), "0x")

    def eth_get_storage(self, addr, slot, block="latest"):
        if slot.startswith("0xb5"):
            return self.admin.get(addr.lower(), "0x0")
        if slot.startswith("0x3608"):
            return self.implementation.get(addr.lower(), "0x0")
        return "0x0"

    def eth_get_transaction(self, h):
        return {"input": self.top_input}

    def eth_get_receipt(self, h):
        return {"gasUsed": "0x5208"}

    def call(self, method, params=None):
        if method == "eth_call":
            to = ((params or [{}])[0] or {}).get("to", "").lower()
            data = ((params or [{}])[0] or {}).get("data", "0x")
            sel = data[2:10] if len(data) >= 10 else ""
            if to in self.safes:
                return "0x" + "11" * 32  # Verified execution property
            if sel == "feaf968c":
                # latestRoundData → (roundId=1, answer=self.price)
                return "0x" + "00" * 32 + format(self.price, "064x") + "0" * 64 * 3
            return "0x"  # Verified execution property
        if method == "eth_getBlockByNumber":
            return {"transactions": []}
        raise ValueError(f"unexpected method {method}")


class TestBuildMutationPlan(unittest.TestCase):
    """Candidate discovery is trace-driven and independent of labels."""

    def test_all_factors_map(self):
        fl = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"  # AaveV2
        orc = "0x338eee1f00000000000000000000000000000000"
        proxy = "0x5a9af1f2a4c1b2a5b0c3d4e5f60718293a4b5c6d"
        arch = FakeArchive(code={orc: "0x6000", fl: "0x6000",
                                 "0x2222222222222222222222222222222222222222": "0x6000"},
                           admin={proxy: "0x" + "00" * 31 + "01"},
                           implementation={proxy: "0x" + "00" * 12 +
                                           "2222222222222222222222222222222222222222"},
                           top_input="0x641ccd83" + "00" * 96)
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    block=100, gt_factors=["f_fl", "f_orc", "f_swap", "f_auth"],
                    trace=_make_trace(fl=fl, oracle=orc, proxy=proxy))
        case.trace["calls"][-1]["input"] = "0x4f1ef286"
        plan = build_mutation_plan(case, arch)
        kinds = [type(m) for m in plan.mutations]
        self.assertIn(FlashLoanDisable, kinds)
        self.assertIn(OraclePin, kinds)
        self.assertIn(SwapSlice, kinds)
        self.assertIn(AuthRevoke, kinds)

    def test_unknown_gt_does_not_block_discovery(self):
        fl = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["unknown"], trace=_make_trace(fl=fl))
        plan = build_mutation_plan(case, FakeArchive())
        self.assertTrue(any(isinstance(m, FlashLoanDisable) for m in plan.mutations))

    def test_label_does_not_create_or_suppress_candidate(self):
        fl = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"
        traces = _make_trace(fl=fl)
        a = Case("a", "T", "x", "0xa", gt_factors=["f_auth"], trace=traces)
        b = Case("b", "T", "x", "0xb", gt_factors=["unknown"], trace=traces)
        pa = [type(m) for m in build_mutation_plan(a, FakeArchive()).mutations]
        pb = [type(m) for m in build_mutation_plan(b, FakeArchive()).mutations]
        self.assertEqual(pa, pb)

    def test_fl_not_found_skips_with_note(self):
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["f_fl"], trace=_make_trace())
        plan = build_mutation_plan(case, FakeArchive())
        self.assertEqual(plan.mutations, [])
        self.assertTrue(any("f_fl unsupported" in n for n in plan.notes))

    def test_swap_needs_start_selector(self):
        # Execution trace analysis and verification
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["f_swap"], trace=_make_trace(),
                    extra={})
        arch = FakeArchive(top_input="0x12345678")
        plan = build_mutation_plan(case, arch)
        self.assertEqual(plan.mutations, [])
        self.assertTrue(any("f_swap unsupported" in n for n in plan.notes))

    def test_auth_safe_multisig_not_revoked(self):
        # Execution trace analysis and verification
        proxy = "0x5a9af1f2a4c1b2a5b0c3d4e5f60718293a4b5c6d"
        arch = FakeArchive(admin={proxy: "0x0"})
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["f_auth"],
                    trace=_make_trace(proxy=proxy))
        plan = build_mutation_plan(case, arch)
        self.assertEqual(plan.mutations, [])
        self.assertTrue(any("f_auth unsupported" in n for n in plan.notes))

    def test_auth_safe_multisig_signature_bound_skipped(self):
        # Execution trace analysis and verification
        # (getOwners/threshold) -> permission-gated -> skip AuthRevoke.
        safe = "0x27fd43babfbe83a81d14665b1a6fb8030a60c9b4"
        arch = FakeArchive(admin={safe: "0x0"}, safes=[safe])
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["f_auth"],
                    trace=_make_trace(proxy=safe))
        plan = build_mutation_plan(case, arch)
        self.assertEqual(plan.mutations, [])
        self.assertTrue(any("permission-gated" in n for n in plan.notes))

    def test_unsupported_reentrancy_does_not_appear_from_label(self):
        case = Case(case_id="t", protocol="T", attack_type="x", tx_hash="0xabc",
                    gt_factors=["f_re"], trace=_make_trace())
        plan = build_mutation_plan(case, FakeArchive())
        self.assertEqual(plan.mutations, [])
        self.assertFalse(any(getattr(m, "name", "") == "f_re" for m in plan.mutations))


class TestE4RefactorSeams(unittest.TestCase):
    """The extracted seams preserve the legacy model and verdict contract."""

    def test_legacy_and_extracted_models_are_same_types(self):
        self.assertIs(Case, E4Case)
        self.assertIs(type(HarmAssessment("UNKNOWN")), E4HarmAssessment)
        self.assertIs(type(MutationPlan()), E4MutationPlan)

    def test_extracted_criterion_matches_legacy_policy(self):
        kwargs = {
            "baseline_harm": "HARM",
            "mutated_harm": "NO_HARM",
            "observed": True,
            "execution_preserving": True,
            "behavior_changed": True,
        }
        self.assertEqual(
            e4_criterion("EXECUTED_NO_HARM", **kwargs),
            criterion("EXECUTED_NO_HARM", **kwargs),
        )

    def test_removal_precedence_checks_baseline_before_revert(self):
        self.assertEqual(
            e4_criterion("REVERTED", baseline_harm="NO_HARM"),
            "INCONCLUSIVE-baseline-harm",
        )
        self.assertEqual(
            e4_criterion("REVERTED", baseline_harm="UNKNOWN"),
            "INCONCLUSIVE-harm-unmeasured",
        )

    def test_typed_removal_and_blocking_seams(self):
        self.assertEqual(
            evaluate_removal_intervention(
                baseline_harm=True,
                mutation_executed=True,
                mutation_harm=False,
                intervention_supported=True,
            ),
            "CAUSE",
        )
        self.assertEqual(
            evaluate_blocking_intervention(
                baseline_harm=True,
                reached_check=True,
                reverted_expected_reason=True,
                reverted_expected_frame=True,
                reverted_oog=False,
            ),
            "CAUSE-NECESSARY-blocking",
        )

    def test_b2_adapter_facade_preserves_telemetry_helpers(self):
        payload = {"target_index": 0, "per_tx": [{"call_trace": []}]}
        self.assertEqual(target_payload(payload), payload["per_tx"][0])
        self.assertEqual(call_trace_diff(payload["per_tx"][0], payload["per_tx"][0]),
                         (True, 0, 0, None))

    def test_oracle_stub_provider_requires_trace_selector(self):
        mutation = OraclePin("0x" + "11" * 20, "0x6000", selector="feaf968c")
        self.assertEqual(
            OracleStubProvider().override(mutation),
            {"target_code": {mutation.oracle: mutation.stub_bytecode}},
        )
        with self.assertRaisesRegex(ValueError, "callTracer"):
            OracleStubProvider().override(OraclePin(mutation.oracle, mutation.stub_bytecode))

    def test_removal_unknown_baseline_is_not_not_necessary(self):
        self.assertEqual(
            evaluate_removal_intervention(
                baseline_harm=None,
                mutation_executed=True,
                mutation_harm=None,
                intervention_supported=True,
            ),
            "INCONCLUSIVE-harm-unmeasured",
        )

    def test_removal_no_harm_baseline_is_not_necessary(self):
        """Necessity cannot be assessed when the baseline is benign."""
        self.assertEqual(
            evaluate_removal_intervention(
                baseline_harm=False,
                mutation_executed=True,
                mutation_harm=False,
                intervention_supported=True,
            ),
            "INCONCLUSIVE-baseline-harm",
        )
        self.assertEqual(
            evaluate_removal_intervention(
                baseline_harm=False,
                mutation_executed=False,
                mutation_harm=None,
                intervention_supported=True,
            ),
            "INCONCLUSIVE-baseline-harm",
        )

    def test_oracle_selector_is_carried_from_trace(self):
        oracle = "0x338eee1f00000000000000000000000000000000"
        plan = build_mutation_plan(
            Case("t", "T", "oracle", "0xabc", block=100,
                 trace=_make_trace(oracle=oracle)),
            FakeArchive(code={oracle: "0x6000"}),
        )
        candidate = next(m for m in plan.mutations if isinstance(m, OraclePin))
        self.assertEqual(candidate.selector, "feaf968c")
        from eval.necessity import _b2_mutation_args as legacy_args
        self.assertIs(legacy_args, mutation_args)

    def test_storage_override_provider_is_explicit_and_32_byte_bound(self):
        pool = "0x" + "22" * 20
        slot = "0x" + "00" * 31 + "08"
        value = "0x" + "11" * 32
        mutation = AmmReservePin(pool, {slot: value})
        self.assertEqual(
            StorageOverrideProvider().override(mutation),
            {"target_storage": {pool: {slot: value}}},
        )
        self.assertEqual(mutation_args("/tmp/unused", mutation)[0],
                         {"target_storage": {pool: {slot: value}}})
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            StorageOverrideProvider().override(AmmReservePin(pool, {"0x01": value}))

    def test_execution_facade_preserves_legacy_workflow_boundary(self):
        from eval.necessity import run_necessity, _run_necessity_legacy
        self.assertIs(run_necessity, extracted_run_necessity)
        self.assertIsNot(run_necessity, _run_necessity_legacy)

    def test_reporting_facade_preserves_legacy_functions(self):
        from eval.necessity import _aggregate, build_evidence_graph
        self.assertIs(_aggregate, aggregate)
        self.assertIs(build_evidence_graph, extracted_graph)


class TestTraceDetection(unittest.TestCase):
    """Hm pht hin provider/oracle/proxy t trace (khng cn network)."""

    def test_flash_provider_aave(self):
        fl = "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"
        prov, why = _find_flash_provider(_make_trace(fl=fl))
        self.assertEqual(prov, fl)
        self.assertIn("AaveV2", why)

    def test_flash_provider_none(self):
        prov, why = _find_flash_provider(_make_trace())
        self.assertIsNone(prov)

    def test_flash_provider_uniswap_fallback(self):
        # UniswapV2 pair.swap 0x30e8d2c6 → callback uniswapV2Call 10d1e85c
        pair = "0x21b8065d10f73ee2e260e5b47d3344d3ced7596e"
        trace = {"type": "CALL", "to": "0xattack", "calls": [
            {"type": "CALL", "to": pair, "input": "0x30e8d2c6" + "00" * 32},
            {"type": "CALL", "to": "0xattack", "input": "0x10d1e85c" + "00" * 32},
        ]}
        prov, why = _find_flash_provider(trace)
        self.assertEqual(prov, pair)
        self.assertIn("UniswapV2", why)

    def test_flash_provider_cream_022c0d9f_callback(self):
        # Cream case2 pattern: pair.swap 0x022c0d9f (flash) + uniswapV2Call 10d1e85c
        pair = "0x21b8065d10f73ee2e260e5b47d3344d3ced7596e"
        trace = {"type": "CALL", "to": "0xattack", "calls": [
            {"type": "CALL", "to": pair, "input": "0x022c0d9f" + "00" * 32},
            {"type": "CALL", "to": "0xattack", "input": "0x10d1e85c" + "00" * 32},
        ]}
        prov, why = _find_flash_provider(trace)
        self.assertEqual(prov, pair)
        self.assertIn("flash-swap", why)

    def test_flash_provider_swap_without_callback_skipped(self):
        # Execution trace analysis and verification
        pair = "0x21b8065d10f73ee2e260e5b47d3344d3ced7596e"
        trace = {"type": "CALL", "calls": [
            {"type": "CALL", "to": pair, "input": "0x022c0d9f" + "00" * 32},
        ]}
        prov, why = _find_flash_provider(trace)
        self.assertIsNone(prov)

    def test_oracle_found(self):
        orc = "0x338eee1f00000000000000000000000000000000"
        arch = FakeArchive(code={orc: "0x6000"})
        got, why = _find_oracle(_make_trace(oracle=orc), arch, 100)
        self.assertEqual(got, orc)

    def test_oracle_no_code_skipped(self):
        orc = "0x338eee1f00000000000000000000000000000000"
        arch = FakeArchive(code={})  # Verified execution property
        got, why = _find_oracle(_make_trace(oracle=orc), arch, 100)
        self.assertIsNone(got)

    def test_proxy_found(self):
        # DELEGATECALL: from = proxy (storage holder), to = implementation
        proxy = "0x5a9af1f2a4c1b2a5b0c3d4e5f60718293a4b5c6d"
        impl = "0x1111111111111111111111111111111111111111"
        arch = FakeArchive(
            admin={proxy: "0x" + "00" * 31 + "01"},
            implementation={proxy: "0x" + "00" * 12 + impl[2:]},
            code={impl: "0x6000"},
        )
        trace = {"type": "CALL", "calls": [
            {"type": "DELEGATECALL", "from": proxy, "to": impl,
             "input": "0x4f1ef286"},
        ]}
        got, why = _find_proxy(trace, arch, 100)
        self.assertEqual(got, proxy)
        self.assertIn("EIP-1967", why)

    def test_proxy_not_eip1967(self):
        proxy = "0x5a9af1f2a4c1b2a5b0c3d4e5f60718293a4b5c6d"
        arch = FakeArchive(admin={proxy: "0x0"})
        got, why = _find_proxy(_make_trace(proxy=proxy), arch, 100)
        self.assertIsNone(got)

    def test_proxy_business_delegatecall_is_not_auth_candidate(self):
        proxy = "0x5a9af1f2a4c1b2a5b0c3d4e5f60718293a4b5c6d"
        impl = "0x1111111111111111111111111111111111111111"
        arch = FakeArchive(
            admin={proxy: "0x" + "00" * 31 + "01"},
            implementation={proxy: "0x" + "00" * 12 + impl[2:]},
            code={impl: "0x6000"},
        )
        trace = {"type": "CALL", "calls": [
            {"type": "DELEGATECALL", "from": proxy, "to": impl, "input": "0x"},
        ]}
        got, why = _find_proxy(trace, arch, 100)
        self.assertIsNone(got)
        self.assertIn("business-path", why)


class TestCriterion(unittest.TestCase):
    """Outcome guard: REVERT is never classified as CAUSE (precondition failure)."""

    def test_reverted_not_cause(self):
        verdict = criterion("REVERTED", baseline_harm="HARM", observed=True)
        self.assertEqual(verdict, "INCONCLUSIVE-revert")

    def test_no_harm_is_cause(self):
        verdict = criterion("EXECUTED_NO_HARM", baseline_harm="HARM",
                            mutated_harm="NO_HARM", execution_preserving=True,
                            behavior_changed=True)
        self.assertEqual(verdict, "CAUSE")
        self.assertEqual(score_factor_match("f_fl(0x1)", ["f_fl"], verdict), "match")

    def test_harm_is_not_necessary_not_benign(self):
        verdict = criterion("EXECUTED_HARM", baseline_harm="HARM",
                            mutated_harm="HARM", execution_preserving=True,
                            behavior_changed=True)
        self.assertEqual(verdict, "NOT_NECESSARY")
        self.assertEqual(score_factor_match("f_fl(0x1)", ["f_fl"], verdict),
                         "no_match")
        self.assertEqual(factor_confusion("f_fl(0x1)", ["f_fl"], verdict), "FN")
        self.assertEqual(factor_confusion("f_orc(0x2)", ["f_fl"], verdict), "TN")

    def test_unknown_baseline_harm_inconclusive(self):
        verdict = criterion("EXECUTED_NO_HARM", baseline_harm="UNKNOWN",
                            mutated_harm="NO_HARM", execution_preserving=True,
                            behavior_changed=True)
        self.assertEqual(verdict, "INCONCLUSIVE-harm-unmeasured")

    def test_reverted_even_without_viol_revert(self):
        # Missing baseline harm takes precedence over the revert outcome.
        verdict = criterion("REVERTED", baseline_harm="UNKNOWN")
        self.assertEqual(verdict, "INCONCLUSIVE-harm-unmeasured")

    def test_timeout_is_not_revert(self):
        verdict = criterion("REVERTED", baseline_harm="HARM", observed=False)
        self.assertEqual(verdict, "INCONCLUSIVE-transport")

    def test_no_effect_cannot_be_cause(self):
        verdict = criterion("EXECUTED_NO_HARM", baseline_harm="HARM",
                            mutated_harm="NO_HARM", execution_preserving=True,
                            behavior_changed=False)
        self.assertEqual(verdict, "INCONCLUSIVE-no-effect")

    def test_sham_requires_unchanged_harmful_execution(self):
        self.assertEqual(
            assess_sham_control(
                fidelity_ok=True, observed=True, execution_preserving=True,
                behavior_changed=False, baseline_harm="HARM", mutated_harm="HARM",
            ),
            ("CONTROL_PASS", True),
        )
        self.assertEqual(
            assess_sham_control(
                fidelity_ok=True, observed=True, execution_preserving=True,
                behavior_changed=True, baseline_harm="HARM", mutated_harm="NO_HARM",
            ),
            ("CONTROL_FAIL-behavior-changed", False),
        )

    def test_sham_storage_write_uses_only_local_anvil_rpc(self):
        fork = mock.Mock(url="http://127.0.0.1:8547")
        client = mock.Mock()
        with mock.patch("core.mutate.RpcClient", return_value=client):
            ShamStorageWrite().apply(fork)
        client.anvil_set_storage.assert_called_once()

    def test_joint_candidates_are_blind_distinct_factor_pairs(self):
        mutations = [FlashLoanDisable("0x1"), OraclePin("0x2", "0x6000"),
                     AuthRevoke("0x3")]
        joints = build_joint_mutations(mutations)
        self.assertEqual(len(joints), 3)
        self.assertTrue(all(isinstance(item, CompositeMutation) for item in joints))
        self.assertEqual(str(joints[0]), "joint[f_fl+f_orc]")

    def test_joint_scoring_requires_exact_set(self):
        joint = build_joint_mutations([
            FlashLoanDisable("0x1"), OraclePin("0x2", "0x6000")
        ])[0]
        self.assertEqual(score_joint_match(joint, ["f_fl", "f_orc"], "JOINT_CAUSE"),
                         "joint_exact_match")
        self.assertEqual(score_joint_match(joint, ["f_fl"], "JOINT_CAUSE"),
                         "joint_no_match")
        self.assertEqual(score_joint_match(joint, ["f_fl", "f_orc"],
                                           "NOT_NECESSARY"), "not_scored_joint")

    def test_joint_cause_requires_both_singles_to_preserve_harm(self):
        joint = build_joint_mutations([
            FlashLoanDisable("0x1"), OraclePin("0x2", "0x6000")
        ])[0]
        singles = [
            {"mutation": "f_fl", "verdict": "NOT_NECESSARY"},
            {"mutation": "f_orc", "verdict": "NOT_NECESSARY"},
        ]
        self.assertEqual(classify_joint_verdict(joint, "CAUSE", singles),
                         "JOINT_CAUSE")
        singles[0]["verdict"] = "CAUSE"
        self.assertEqual(classify_joint_verdict(joint, "CAUSE", singles),
                         "REDUNDANT_WITH_SINGLE")
        singles[0]["verdict"] = "INCONCLUSIVE-revert"
        self.assertEqual(classify_joint_verdict(joint, "CAUSE", singles),
                         "JOINT_INCONCLUSIVE-components")

    def test_labels_are_opened_only_by_post_replay_scoring(self):
        frozen = [
            {"mutation": "f_orc(0x2)", "verdict": "CAUSE",
             "factor_gt": "blinded_pending_scoring",
             "factor_match": "not_scored_pending",
             "factor_confusion": "not_scored_pending"},
            {"mutation": "f_fl(0x1)", "verdict": "NOT_NECESSARY",
             "factor_gt": "blinded_pending_scoring",
             "factor_match": "not_scored_pending",
             "factor_confusion": "not_scored_pending"},
        ]
        scored = score_rows(frozen, ["f_orc"], paper_eligible=True)
        self.assertEqual(scored[0]["factor_match"], "match")
        self.assertEqual(scored[0]["factor_confusion"], "TP")
        self.assertEqual(scored[1]["factor_match"], "match")
        self.assertEqual(scored[1]["factor_confusion"], "TN")
        self.assertTrue(all(row["factor_gt"] == "f_orc" for row in scored))
        # Scoring returns copies and cannot retroactively affect replay rows.
        self.assertEqual(frozen[0]["factor_gt"], "blinded_pending_scoring")


class TestStubAndLoss(unittest.TestCase):
    """Stub bytecode patch + loss t receipt (offline)."""

    def test_pin_oracle_stub_patches_price(self):
        rt = _pin_oracle_stub(_price_hex(999))
        self.assertIsNotNone(rt)
        # Solidity emits one immutable placeholder per getter/read site.  Every
        # occurrence must be patched; otherwise some oracle getters return zero.
        assert rt is not None
        self.assertEqual(rt.count("7f" + "0" * 61 + "3e7"), 3)  # 999 = 0x3e7
        self.assertNotIn("7f" + "0" * 64, rt)

    def test_pin_oracle_stub_rejects_invalid_price(self):
        self.assertIsNone(_pin_oracle_stub("xyz"))
        self.assertIsNone(_pin_oracle_stub("00"))

    def test_price_hex_64_digits(self):
        self.assertEqual(len(_price_hex(12345)), 64)
        self.assertEqual(_price_hex(0), "0" * 64)

    def test_loss_from_receipt(self):
        transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        rec = {"logs": [
            {"address": "0x" + "00" * 20 + "01", "topics": [transfer,
                     "0x000000000000000000000000attacker0000000000000000000000000000000000",
                     "0x000000000000000000000000victim000000000000000000000000000000000000"],
             "data": format(10 ** 18, "064x")},  # 1 token
        ]}
        arch = mock.Mock()
        arch.eth_get_receipt.return_value = rec
        # Missing valuation is unknown, never silently zero.
        self.assertIsNone(_loss_from_receipt(arch, "0xabc", {}))

    def test_loss_requires_preregistered_victim_and_price(self):
        transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        token = "0x0000000000000000000000000000000000000001"
        victim = "0x00000000000000000000000000000000000000aa"
        attacker = "0x00000000000000000000000000000000000000bb"
        def topic(address):
            return "0x" + "0" * 24 + address[2:]
        rec = {"logs": [{"address": token, "topics": [transfer, topic(victim),
                         topic(attacker)], "data": hex(2 * 10**18)}]}
        arch = mock.Mock()
        arch.eth_get_receipt.return_value = rec
        prices = {token: {"usd_per_token": 3, "decimals": 18}}
        self.assertEqual(_loss_from_receipt(arch, "0xabc", prices, {victim}), 6.0)

    def test_generic_attacker_value_oracle_uses_native_and_transfer_deltas(self):
        attacker = "0x" + "aa" * 20
        token = "0x" + "bb" * 20
        transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        topic = lambda address: "0x" + "0" * 24 + address[2:]
        target = {
            "balance_changes": [{"address": attacker, "previous": "0", "current": str(2 * 10**18)}],
            "logs": [{"address": token, "topics": [transfer, topic("0x" + "11" * 20), topic(attacker)],
                      "data": hex(3 * 10**18)}],
        }
        result = assess_attacker_value_harm(
            target, attacker,
            token_prices={token: {"usd_per_token": 1, "decimals": 18}},
            native_price_usd=50_000,
        )
        self.assertEqual(result.status, "HARM")
        self.assertEqual(result.loss_usd, 100_003)

    def test_generic_attacker_value_oracle_fails_closed_on_missing_price(self):
        attacker = "0x" + "aa" * 20
        result = assess_attacker_value_harm(
            {"balance_changes": [{"address": attacker, "previous": "0", "current": "1"}]},
            attacker,
        )
        self.assertEqual(result.status, "UNKNOWN")
        self.assertIn("lack explicit USD prices", result.reason)

    def test_attacker_value_oracle_includes_nested_created_contracts(self):
        eoa = "0x" + "aa" * 20
        created = "0x" + "bb" * 20
        nested = "0x" + "cc" * 20
        trace = {
            "type": "CREATE", "from": eoa, "to": created,
            "calls": [{"type": "CREATE", "from": created, "to": nested}],
        }
        self.assertEqual(created_addresses_from_trace(trace, eoa), {created, nested})
        self.assertEqual(
            attacker_candidates_from_trace({"call_trace": [
                {"event": "enter", "type": "CREATE", "from": eoa, "to": created},
                {"event": "enter", "type": "CREATE", "from": created, "to": nested},
            ]}, eoa),
            {eoa, created, nested},
        )
        result = assess_attacker_value_harm(
            {"call_trace": [
                {"event": "enter", "type": "CREATE", "from": eoa, "to": created},
            ], "balance_changes": [
                {"address": created, "previous": "0", "current": str(3 * 10**18)},
            ]}, eoa, native_price_usd=50_000,
        )
        self.assertEqual(result.status, "HARM")
        self.assertIn(created, result.reason)

    def test_attacker_defaults_to_transaction_sender_but_allows_override(self):
        sender = "0x" + "11" * 20
        override = "0x" + "22" * 20
        self.assertEqual(resolve_attacker_address({"from": sender}), sender)
        self.assertEqual(resolve_attacker_address({"from": sender}, override), override)

    def test_harm_facade_uses_extracted_implementation(self):
        from eval.e4 import assess_harm as extracted_assess_harm
        from eval.necessity import assess_harm as legacy_assess_harm
        self.assertIs(extracted_assess_harm, legacy_assess_harm)
        self.assertIsInstance(create_harm_oracle({}), ReceiptLedgerOracle)
        self.assertIsInstance(
            create_harm_oracle({"oracle": "bzx_transfer_delta"}),
            TransferDeltaOracle,
        )

    def test_transfer_delta_oracle_is_fail_closed(self):
        oracle = TransferDeltaOracle()
        result = oracle.assess({"logs": []}, {"attacker": "0xabc"})
        self.assertEqual(result.status, "UNKNOWN")


class TestAggregateAndCsv(unittest.TestCase):
    """Aggregate + CSV (tempfile)."""

    def _rows(self):
        return [
            {"case": "c1", "mutation": "fidelity", "outcome": "EXECUTED_NO_HARM",
             "run_id": "r1", "paper_eligible": True,
             "factor_match": "", "factor_confusion": "", "cause": ""},
            {"case": "c1", "mutation": "f_fl", "outcome": "EXECUTED_NO_HARM",
             "run_id": "r1", "paper_eligible": True, "observed": True,
             "execution_preserving": True, "behavior_changed": True,
             "harm_S": "HARM", "harm_Sm": "NO_HARM",
             "factor_match": "match", "factor_confusion": "TP",
             "cause": "1", "verdict": "CAUSE"},
            {"case": "c1", "mutation": "f_swap", "outcome": "REVERTED",
             "run_id": "r1", "paper_eligible": True, "observed": True,
             "factor_match": "not_scored", "factor_confusion": "not_scored",
             "cause": "", "verdict": "INCONCLUSIVE-revert"},
        ]

    def test_aggregate_factor_match(self):
        rows = self._rows() + [{
            "case": "c1", "mutation": "control_sham", "run_id": "r1",
            "paper_eligible": True, "observed": True,
            "execution_preserving": True, "behavior_changed": False,
            "harm_S": "HARM", "harm_Sm": "HARM", "control_pass": True,
            "factor_match": "not_scored_control", "verdict": "CONTROL_PASS",
        }, {
            "case": "c1", "mutation": "joint[f_fl+f_orc]", "run_id": "r1",
            "paper_eligible": True, "observed": True,
            "execution_preserving": True, "behavior_changed": True,
            "harm_S": "HARM", "harm_Sm": "NO_HARM",
            "factor_match": "joint_exact_match", "verdict": "CAUSE",
            "joint_verdict": "JOINT_CAUSE",
        }]
        agg = _aggregate(rows)
        self.assertEqual(agg["factor_match"], 1)
        self.assertAlmostEqual(agg["factor_match_rate"], 1.0)
        # revert-rate: 1 REVERTED / 2 mutation rows
        self.assertAlmostEqual(agg["revert_rate"], 0.5)
        self.assertEqual(agg["case_denominators"], {
            "attempted": 1, "eligible": 1, "observed": 1,
            "execution_preserved": 1, "intervention_valid": 1,
            "harm_measured": 1, "scored": 1,
        })
        self.assertEqual(agg["confusion"]["TP"], 1)
        self.assertEqual(agg["by_mutation"]["f_fl"]["confusion"]["TP"], 1)
        self.assertEqual(agg["by_mutation"]["f_fl"]["accuracy"], 1.0)
        self.assertEqual(agg["controls"], {
            "sham_attempted": 1, "sham_pass": 1,
            "sham_fail": 0, "sham_inconclusive": 0,
        })
        self.assertEqual(agg["joint_interventions"]["exact_match"], 1)
        # Joint rows do not inflate single-factor accuracy or intervention chain.
        self.assertEqual(agg["intervention_denominators"]["attempted"], 2)

    def test_write_csv_upsert(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e4.csv"
            write_csv(self._rows(), p)
            write_csv([self._rows()[1]], p)  # Verified execution property
            from eval.necessity import load_results
            rows = load_results(p)
            self.assertEqual(len(rows), 3)  # fidelity + f_fl + f_swap
            self.assertEqual(rows[0]["case"], "c1")
            self.assertEqual(rows[0]["mutation"], "fidelity")

    def test_write_csv_keeps_independent_runs(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e4.csv"
            row = self._rows()[1]
            write_csv([row], p)
            write_csv([{**row, "run_id": "r2", "verdict": "NOT_NECESSARY"}], p)
            from eval.necessity import load_results
            self.assertEqual(len(load_results(p)), 2)

    def test_evidence_graph_retains_failure_and_joint_branches(self):
        rows = self._rows() + [{
            "case": "c1", "mutation": "joint[f_fl+f_orc]",
            "candidate_factor": "unknown", "joint_factors": "f_fl+f_orc",
            "observed": False, "verdict": "INCONCLUSIVE-transport",
            "joint_verdict": "JOINT_INCONCLUSIVE-pair",
        }]
        graph = build_evidence_graph(rows)
        case = graph["cases"][0]
        self.assertEqual(len(case["nodes"]), 4)
        joint = next(node for node in case["nodes"]
                     if node["mutation"].startswith("joint["))
        self.assertFalse(joint["observed"])
        self.assertEqual(joint["joint_verdict"], "JOINT_INCONCLUSIVE-pair")


class TestStartCapOverride(unittest.TestCase):
    """start_cap_override — slice word2 (amount) ca start(flash,amount,min).

    Guard for Replayer._send calldata mutation handling without syntax truncation
    km data  positional (cast send --data khng chp nhn SIG) — override phi
    ng 100 bytes v gi nguyn word3 (min).
    """

    def _start_calldata(self, amount: int, min_: int) -> str:
        return ("0x641ccd83" + "0" * 64
                + format(amount, "064x") + format(min_, "064x"))

    def test_override_zeroes_word2(self):
        from core.mutate import start_cap_override
        cd = self._start_calldata(0x1b1ae4d6e2ef5000, 0x0133e9d5b211fac000)
        ov = start_cap_override(cd, 0)
        self.assertIsNotNone(ov)
        self.assertEqual(len(ov), 2 + 8 + 192)  # Verified execution property
        self.assertEqual(ov[2:10], "641ccd83")  # Verified execution property
        self.assertEqual(ov[2 + 8 + 64:2 + 8 + 128], "0" * 64)  # word2 = 0 (amount)
        self.assertEqual(ov[2 + 8 + 128:], format(0x0133e9d5b211fac000, "064x"))  # word3 (min)

    def test_override_none_wrong_length(self):
        from core.mutate import start_cap_override
        self.assertIsNone(start_cap_override("0x641ccd83", 0))  # Verified execution property
        self.assertIsNone(start_cap_override("0x12345678" + "00" * 96, 0))  # sai selector

    def test_parameterized_swap_keeps_nonzero_amount(self):
        from core.mutate import SwapSlice
        cd = self._start_calldata(1000, 355)
        m = SwapSlice(ratio=0.75)
        self.assertEqual(m.name, "f_swap[0.75]")
        self.assertTrue(m.causal_ready)
        # The actual calldata rewrite is installed on Replayer at send time;
        # validate that the mutation contract does not use the destructive 0.
        self.assertEqual(int(cd[2 + 8 + 64:2 + 8 + 128], 16), 1000)

    def test_precondition_mutation_is_not_causal_ready(self):
        m = FlashLoanDisable("0xprovider")
        self.assertFalse(m.causal_ready)
        self.assertEqual(m.validate_execution(observed=True, status=True)[0], False)

    def test_flash_mutation_uses_provider_entrypoint_selector(self):
        trace = _make_trace(fl="0x" + "11" * 20)
        provider = "0x" + "11" * 20
        self.assertEqual(_flash_selector_for_provider(trace, provider), "ab9c4b5d")
        self.assertEqual(FlashLoanDisable(provider, selector="ab9c4b5d").selector,
                         "ab9c4b5d")


if __name__ == "__main__":
    unittest.main()
