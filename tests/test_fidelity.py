"""Unit tests cho eval.fidelity — E5 Replay Fidelity.

Pure stdlib test (unittest + mock + tempfile) - no Anvil or external tools required
network hay .env keys. Mi RPC mock qua unittest.mock.patch.

Chy t repository root:
    python -m unittest discover -s tests -p "test_*.py"
    python -m unittest tests.test_fidelity
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.fidelity import (  # noqa: E402
    E5Replayer,
    FidelityCase,
    _cell_keys,
    _distribute_round_robin,
    _local_client,
    _match_cells,
    _normalize_diff_post,
    _norm,
    _snapshot_cells,
    run_fidelity,
    run_fidelity_case,
    run_state_delta,
    select_fidelity_set,
    summarize,
    write_csv,
    load_results,
    load_fidelity_set,
)
from core.outcome import Outcome, ReplayResult  # noqa: E402
from core.rpc import RpcError  # noqa: E402


def _synthetic_corpus(n_per_type=4, types=("flash-loan", "oracle", "governance/access")):
    """Corpus nh: n_per_type case/type, tx hash hex(k) bin thin, block tht."""
    rows = []
    i = 0
    for t in types:
        for _ in range(n_per_type):
            i += 1
            rows.append({
                "id": f"syn-{t}-{i}", "protocol": f"P{i}", "date": "2025-01-01",
                "chain": "ethereum", "attack_type": t, "loss_usd": 100000,
                "tx_hashes": [f"0x{i:064x}"], "block": 20000000 + i,
                "class": "attack", "gt_factors": ["f_other"],
                "notes": "syn", "verified": "onchain",
            })
    return rows


def _write_corpus(rows) -> str:
    d = tempfile.mkdtemp(prefix="traceguard_test_")
    p = Path(d) / "corpus.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return str(p)


def _fake_tx(tx_hash: str, index: int) -> dict:
    return {"blockNumber": hex(20000000 + index % 1000),
            "transactionIndex": hex(index % 5),
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "input": "0xdeadbeef", "value": "0x0", "gas": "0x2dc6c0"}


class FakeArchive:
    """Archive gi: map tx_hash → (block, index). Khng cn RPC tht."""

    def __init__(self, tx_by_hash: dict[str, dict]):
        self._m = tx_by_hash

    def eth_get_transaction(self, h):
        return self._m.get(h)

    def eth_get_receipt(self, h):
        return {"gasUsed": "0x5208"} if h in self._m else None


class TestSelectFidelitySet(unittest.TestCase):
    def _run(self, n, seed=42, rows=None):
        rows = rows or _synthetic_corpus()
        with mock.patch("eval.fidelity.get_archive") as ga:
            arch = FakeArchive({r["tx_hashes"][0]: _fake_tx(r["tx_hashes"][0], i)
                                for i, r in enumerate(rows)})
            ga.return_value = arch
            return select_fidelity_set(_write_corpus(rows), n=n, seed=seed)

    def test_selects_n_cases(self):
        cases, meta = self._run(6)
        self.assertEqual(len(cases), 6)
        self.assertEqual(meta["total_onchain"], 12)

    def test_prioritizes_k0_then_low_k(self):
        cases, _ = self._run(4)
        kvals = [c.tx_index for c in cases]
        self.assertEqual(kvals, sorted(kvals), "k must be non-decreasing (k=0 first)")

    def test_deterministic_same_seed(self):
        a, _ = self._run(6, seed=7)
        b, _ = self._run(6, seed=7)
        self.assertEqual([c.tx_hash for c in a], [c.tx_hash for c in b])

    def test_type_coverage(self):
        cases, _ = self._run(6)
        types = {c.attack_type for c in cases}
        self.assertGreaterEqual(len(types), 2, "set must cover multiple attack types")

    def test_skips_non_onchain(self):
        rows = _synthetic_corpus(n_per_type=2)
        rows[0]["verified"] = "pending"
        rows[1]["verified"] = "blocked"
        cases, meta = self._run(4, rows=rows)
        self.assertNotIn("syn-flash-loan-1", [c.case_id for c in cases])
        self.assertEqual(meta["total_onchain"], 4)

    def test_missing_receipt_fails_loudly(self):
        rows = _synthetic_corpus(n_per_type=1, types=("oracle",))
        tx_hash = rows[0]["tx_hashes"][0]

        class MissingReceiptArchive(FakeArchive):
            def eth_get_receipt(self, h):
                return None

        with mock.patch("eval.fidelity.get_archive") as ga:
            ga.return_value = MissingReceiptArchive({tx_hash: _fake_tx(tx_hash, 0)})
            with self.assertRaises(RpcError) as ctx:
                select_fidelity_set(_write_corpus(rows), n=1)
        self.assertIn("receipt unavailable", str(ctx.exception))


class TestDistributeRoundRobin(unittest.TestCase):
    def test_round_robin_spreads_types(self):
        cs = [FidelityCase(case_id=f"c{i}", protocol="p", attack_type=t, tx_hash=f"0x{i}",
                           block=1, tx_index=0) for i, t in enumerate(["a", "b", "c"] * 3)]
        out = _distribute_round_robin(cs, 5)
        self.assertEqual(len(out), 5)
        seq = [c.attack_type for c in out]
        self.assertIn("a", seq) and self.assertIn("b", seq) and self.assertIn("c", seq)


class TestHelpers(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(_norm(None), "0x0")
        self.assertEqual(_norm("0x"), "0x0")
        self.assertEqual(_norm(0), "0")
        self.assertEqual(_norm(5), "5")
        self.assertEqual(_norm("0x0"), "0x0")
        self.assertEqual(_norm("0xABC"), "0xabc")

    def test_cell_keys(self):
        spec = {"balance": "1", "storage": {"0x0": "2", "0x1": "3"}}
        keys = _cell_keys(spec)
        self.assertIn("balance", keys)
        self.assertIn("storage:0x0", keys)
        self.assertIn("storage:0x1", keys)

    def test_match_cells(self):
        pre = {"balance": "0x0"}
        post = {"balance": "0x5"}
        mn = {"balance": "0x5"}
        ok, bad, err = _match_cells(pre, post, mn, ["balance"])
        self.assertEqual((ok, bad, err), (1, 0, 0))
        ok, bad, err = _match_cells(pre, {"balance": "0x6"}, mn, ["balance"])
        self.assertEqual((ok, bad, err), (0, 1, 0))
        ok, bad, err = _match_cells(pre, {"balance": None}, mn, ["balance"])
        self.assertEqual((ok, bad, err), (0, 0, 1))

    def test_normalize_diff_post_quantities_but_not_code(self):
        got = _normalize_diff_post({"0xa": {"balance": "0x05", "nonce": 2,
                                           "code": "0x0060",
                                           "storage": {"0x0": "0x0003"}}})
        self.assertEqual(got["0xa"]["balance"], "0x5")
        self.assertEqual(got["0xa"]["nonce"], "0x2")
        self.assertEqual(got["0xa"]["storage"]["0x0"], "0x3")
        self.assertEqual(got["0xa"]["code"], "0x0060")

    def test_local_fork_client_has_single_bounded_attempt(self):
        client = _local_client("http://127.0.0.1:8546", 480)
        self.assertEqual(client.timeout, 30.0)
        self.assertEqual(client.attempts, 1)

    def test_snapshot_fails_fast_when_any_cell_is_unavailable(self):
        client = mock.Mock()
        client.eth_get_balance.side_effect = RpcError("fork state timeout")
        post_map = {
            "0xaaa": {"balance": "0x1", "code": "0x60"},
            "0xbbb": {"balance": "0x2"},
        }
        self.assertIsNone(_snapshot_cells(client, post_map, "latest"))
        client.eth_get_balance.assert_called_once_with("0xaaa", "latest")
        client.eth_get_code.assert_not_called()

    def test_snapshot_canonicalizes_padded_storage_quantities(self):
        client = mock.Mock()
        client.eth_get_storage.return_value = "0x" + "0" * 62 + "03"
        post_map = {"0xaaa": {"storage": {"0x0": "0x3"}}}
        got = _snapshot_cells(client, post_map, "latest")
        self.assertEqual(got["0xaaa"]["storage"]["0x0"], "0x3")


class TestStateDelta(unittest.TestCase):
    def _case(self):
        return FidelityCase(case_id="c1", protocol="p", attack_type="flash-loan",
                            tx_hash="0xaaaa", block=21000000, tx_index=0, mainnet_gas=50000)

    def test_prestate_diff_matches(self):
        # diff.post is both the CELL SET and the transaction-local ground truth.
        case = self._case()
        diff = {"post": {"0xaaa": {"balance": "0x5", "nonce": "0x1"}}}
        arch = mock.Mock()
        arch.call.side_effect = lambda m, p, **k: (
            diff if m == "debug_traceTransaction" else "0x1")
        arch.eth_get_receipt.return_value = {"gasUsed": "0xc350"}
        arch.eth_get_balance.return_value = 5  # Verified execution property
        arch.call.return_value = "0x1"  # eth_getTransactionCount (hex) + eth_getBlockByNumber
        rp = mock.MagicMock()
        rp.replay_same_block.return_value = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                                                         gas_used=50000, mainnet_gas=50000)
        fake_fk = mock.MagicMock()
        fake_fk.eth_get_balance.return_value = 5  # Verified execution property
        fake_fk.call.return_value = "0x1"
        with mock.patch("eval.fidelity.resolve_trace_rpc", return_value=None), \
             mock.patch("eval.fidelity.ForkRunner") as FR, \
             mock.patch("eval.fidelity.E5Replayer") as RP, \
             mock.patch("eval.fidelity.RpcClient") as RC:
            FR.return_value.__enter__.return_value = fork = mock.MagicMock()
            fork.url = "http://127.0.0.1:8546"
            RP.return_value = rp
            RC.return_value = fake_fk
            arch.eth_get_transaction.return_value = {"blockNumber": "0x1"}  # gas price helper
            out = run_state_delta(case, "rpc", arch)

        self.assertEqual(out["mode"], "prestate-diff")
        self.assertEqual(out["n_cells"], 2)
        self.assertEqual(out["match_rate"], 1.0)
        # End-of-block archive state must never be used as tx-local ground truth.
        arch.eth_get_balance.assert_not_called()

    def test_no_tracer_skips_state(self):
        case = self._case()
        arch = mock.Mock()
        arch.call.side_effect = RpcError("debug_traceTransaction not supported")
        with mock.patch("eval.fidelity.ForkRunner"):
            out = run_state_delta(case, "rpc", arch)
        self.assertEqual(out["mode"], "none")
        self.assertEqual(out["n_cells"], 0)

    def test_incomplete_pre_snapshot_stops_before_second_replay(self):
        case = self._case()
        arch = mock.Mock()
        arch.call.return_value = {"post": {"0xaaa": {"balance": "0x5"}}}
        arch.eth_get_receipt.return_value = {"effectiveGasPrice": "0x1"}
        rp = mock.MagicMock()
        with mock.patch("eval.fidelity.resolve_trace_rpc", return_value=None), \
             mock.patch("eval.fidelity.ForkRunner") as fork_runner, \
             mock.patch("eval.fidelity.E5Replayer", return_value=rp), \
             mock.patch("eval.fidelity._align_fork_block"), \
             mock.patch("eval.fidelity._local_client", return_value=mock.Mock()), \
             mock.patch("eval.fidelity._snapshot_cells", return_value=None):
            fork_runner.return_value.__enter__.return_value.url = "http://127.0.0.1:8546"
            out = run_state_delta(case, "rpc", arch)

        self.assertEqual(out["mode"], "none")
        self.assertEqual(out["state_errors"], 1)
        self.assertIn("incomplete pre-replay", out["note"])
        rp.replay.assert_not_called()


class TestRunFidelity(unittest.TestCase):
    def test_mine_timeout_bypasses_short_rpc_cap(self):
        fork = mock.Mock(url="http://127.0.0.1:8546")
        replayer = E5Replayer(fork, mock.Mock(), timeout=900, mine_timeout=600)
        local = mock.Mock()
        local.eth_block_number.side_effect = [100, 101]
        with mock.patch("eval.fidelity._local_client", return_value=local) as client:
            replayer.mine_pending()

        client.assert_called_once_with(
            fork.url, 600.0, timeout_cap=None)
        local.call.assert_called_once_with("anvil_mine", [])
        self.assertEqual(replayer.mine_telemetry["timeout_s"], 600.0)
        self.assertTrue(replayer.mine_telemetry["completed"])

    def test_k0_skips_warmup(self):
        case = FidelityCase(case_id="c1", protocol="p", attack_type="oracle",
                            tx_hash="0xbbbb", block=21000000, tx_index=0, mainnet_gas=100000)
        arch = mock.Mock()
        arch.eth_get_transaction.return_value = None  # Verified execution property
        rp = mock.MagicMock()
        rp.replay_same_block.return_value = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                                                         gas_used=99000, mainnet_gas=100000)
        with mock.patch("eval.fidelity.ForkRunner") as FR, \
             mock.patch("eval.fidelity.E5Replayer") as RP:
            fork = mock.MagicMock()
            fork.url = "http://127.0.0.1:8546"
            FR.return_value.__enter__.return_value = fork
            RP.return_value = rp
            res = run_fidelity(case, "rpc", arch)
        rp.replay_same_block.assert_called_once_with(
            [], case.tx_hash, case.mainnet_gas, gas_limit_multiplier=1.5)
        self.assertTrue(res.fidelity_pass())

    def test_k1_warmup_called(self):
        case = FidelityCase(case_id="c1", protocol="p", attack_type="oracle",
                            tx_hash="0xbbbb", block=21000000, tx_index=1, mainnet_gas=100000)
        arch = mock.Mock()
        arch.call.side_effect = lambda m, p, **k: {"transactions": [
            {"hash": "0xprior0", "transactionIndex": "0x0"},
            {"hash": "0xbbbb", "transactionIndex": "0x1"}]} if m == "eth_getBlockByNumber" else None
        arch.eth_get_transaction.return_value = None  # Verified execution property
        rp = mock.MagicMock()
        rp.replay_same_block.return_value = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                                                         gas_used=99000, mainnet_gas=100000)
        with mock.patch("eval.fidelity.ForkRunner") as FR, \
             mock.patch("eval.fidelity.E5Replayer") as RP:
            fork = mock.MagicMock()
            fork.url = "http://127.0.0.1:8546"
            FR.return_value.__enter__.return_value = fork
            RP.return_value = rp
            run_fidelity(case, "rpc", arch)
        rp.replay_same_block.assert_called_once_with(
            ["0xprior0"], case.tx_hash, case.mainnet_gas, gas_limit_multiplier=1.5)


class TestRunFidelityCase(unittest.TestCase):
    def _case(self):
        return FidelityCase(case_id="c1", protocol="p", attack_type="oracle",
                            tx_hash="0xbbbb", block=21000000, tx_index=0,
                            mainnet_gas=100000)

    def test_unobserved_execution_skips_redundant_state_replay(self):
        fid = ReplayResult(Outcome.UNOBSERVED, observed=False,
                           error_kind="transport_or_timeout", note="timed out")
        with mock.patch("eval.fidelity.run_fidelity", return_value=fid), \
             mock.patch("eval.fidelity.run_state_delta") as state:
            row = run_fidelity_case(self._case(), "rpc", mock.Mock(), timeout=2)

        state.assert_not_called()
        self.assertFalse(row["observed"])
        self.assertEqual(row["state_mode"], "none")
        self.assertEqual(row["state_errors"], 1)
        self.assertIn("state-delta skipped: execution replay unobserved", row["note"])

    def test_incomplete_state_snapshot_is_not_state_eligible(self):
        fid = ReplayResult(Outcome.EXECUTED_NO_HARM, observed=True, status=True,
                           gas_used=100000, mainnet_gas=100000, note="ok")
        state_result = {
            "n_cells": 100, "match": 99, "match_rate": 0.99,
            "mode": "prestate-diff", "observed": True, "replay_status": True,
            "note": "one missing cell", "state_errors": 1, "per_account": {},
        }
        with mock.patch("eval.fidelity.run_fidelity", return_value=fid), \
             mock.patch("eval.fidelity.run_state_delta", return_value=state_result):
            row = run_fidelity_case(self._case(), "rpc", mock.Mock())

        self.assertFalse(row["state_eligible"])
        self.assertFalse(row["state_pass"])
        self.assertTrue(row["execution_pass"])

    def test_state_transport_error_does_not_erase_valid_execution(self):
        fid = ReplayResult(Outcome.EXECUTED_UNKNOWN, observed=True, status=True,
                           gas_used=100000, mainnet_gas=100000, note="execution ok")
        with mock.patch("eval.fidelity.run_fidelity", return_value=fid), \
             mock.patch("eval.fidelity.run_state_delta",
                        side_effect=RpcError("state transport failure")):
            row = run_fidelity_case(self._case(), "rpc", mock.Mock())

        self.assertTrue(row["observed"])
        self.assertTrue(row["execution_pass"])
        self.assertEqual(row["outcome"], "EXECUTED_UNKNOWN")
        self.assertFalse(row["state_eligible"])
        self.assertEqual(row["state_errors"], 1)
        self.assertIn("state-delta unavailable after valid execution", row["note"])


class TestCsv(unittest.TestCase):
    def test_write_load_roundtrip(self):
        rows = [{"case": "x-1", "protocol": "p", "attack_type": "flash-loan",
                 "tx_hash": "0x1", "block": 1, "tx_index": 0, "mutation": "fidelity",
                 "outcome": "EXECUTED_NO_HARM", "status": True, "gas_used": 1,
                 "mainnet_gas": 1, "gas_delta_pct": 0.0, "pass": True,
                 "state_cells": 2, "state_match": 1.0, "state_errors": 0,
                 "state_mode": "prestate-diff", "reason": "k=0", "note": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e5.csv"
            write_csv(rows, path=p)
            got = load_results(path=p)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["case"], "x-1")
        self.assertEqual(got[0]["pass"], "True")


class TestFrozenSet(unittest.TestCase):
    def test_fixed_set_has_twenty_unique_cases(self):
        cases, meta = load_fidelity_set()
        self.assertEqual(len(cases), 20)
        self.assertEqual(len({case.case_id for case in cases}), 20)
        self.assertEqual(len({case.tx_hash for case in cases}), 20)
        self.assertTrue(all(case.tx_hash.startswith("0x") and len(case.tx_hash) == 66
                            for case in cases))
        self.assertIn("frozen set", meta["reasons"][0])

    def test_fixed_set_rejects_missing_required_ground_truth(self):
        payload = {
            "name": "test fixed set",
            "cases": [{
                "case_id": "case-null-gas", "tx_hash": "0x" + "1" * 64,
                "block": 1, "tx_index": 0, "mainnet_gas": None,
            }],
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fixed.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                load_fidelity_set(path)
        self.assertIn("mainnet_gas", str(ctx.exception))

    def test_cli_fixed_set_list_is_offline(self):
        from eval import fidelity_cli

        with mock.patch.object(fidelity_cli, "resolve_rpc",
                               side_effect=AssertionError("RPC resolution attempted")), \
             mock.patch.object(fidelity_cli, "RpcClient",
                               side_effect=AssertionError("RPC client constructed")), \
             mock.patch("builtins.print") as output:
            self.assertEqual(fidelity_cli.main(["--list"]), 0)
        self.assertTrue(output.called)

    def test_cli_separates_archive_rpc_budget_from_replay_timeout(self):
        from eval import fidelity_cli

        row = {
            "run_id": "rpc-budget-test", "fidelity_schema": "transaction-local-v2",
            "case": "defihacklabs-sashatoken-2024-10-06", "protocol": "SashaToken",
            "attack_type": "token", "tx_hash": "0x1", "block": 1, "tx_index": 0,
            "mutation": "fidelity", "outcome": "EXECUTED_NO_HARM", "observed": True,
            "status": True, "gas_used": 100, "mainnet_gas": 100,
            "gas_delta_pct": 0.0, "execution_pass": True, "state_eligible": False,
            "state_pass": False, "joint_pass": False, "pass": True,
            "state_cells": 0, "state_match": 0.0, "state_errors": 0,
            "state_mode": "disabled", "reason": "test", "note": "ok",
        }
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(fidelity_cli, "resolve_rpc", return_value="https://rpc"), \
             mock.patch.object(fidelity_cli, "RpcClient") as rpc_client, \
             mock.patch.object(fidelity_cli, "run_fidelity_case", return_value=row) as run_case, \
             mock.patch.object(fidelity_cli.time, "sleep"), \
             mock.patch("builtins.print"):
            rc = fidelity_cli.main([
                "--cases", "defihacklabs-sashatoken-2024-10-06",
                "--limit", "1", "--no-state", "--run-id", "rpc-budget-test",
                "--out", str(Path(d) / "e5.csv"), "--timeout", "9",
                "--rpc-timeout", "7.5", "--rpc-attempts", "2",
            ])
        self.assertEqual(rc, 0)
        rpc_client.assert_called_once_with("https://rpc", timeout=7.5, attempts=2)
        self.assertEqual(run_case.call_args.kwargs["timeout"], 9)
        self.assertEqual(run_case.call_args.kwargs["mine_timeout"], 30.0)

    def test_paper_mode_rejects_partial_or_resampled_runs(self):
        from eval import fidelity_cli

        with self.assertRaises(SystemExit):
            fidelity_cli.main(["--paper-fixed20", "--limit", "1"])
        with self.assertRaises(SystemExit):
            fidelity_cli.main(["--paper-fixed20", "--resample"])


class TestSummarize(unittest.TestCase):
    def test_aggregate(self):
        def row(case, passed):
            return {"case": case, "attack_type": "oracle", "pass": passed,
                    "outcome": "EXECUTED_NO_HARM", "gas_delta_pct": 2.0,
                    "state_cells": 5, "state_match": 0.95, "note": ""}
        s = summarize([row("a", True), row("b", True), row("c", False)])
        self.assertEqual(s["n"], 3)
        self.assertEqual(s["pass"], 2)
        self.assertAlmostEqual(s["pass_rate"], 2 / 3)
        self.assertEqual(len(s["fails"]), 1)

    def test_explicit_paper_denominators(self):
        rows = [
            {"case": "a", "attack_type": "oracle", "observed": True,
             "status": True, "outcome": "EXECUTED_UNKNOWN", "execution_pass": True,
             "state_eligible": True, "state_pass": True, "joint_pass": True,
             "state_cells": 2, "state_match": 1.0, "note": ""},
            {"case": "b", "attack_type": "oracle", "observed": True,
             "status": False, "outcome": "REVERTED", "execution_pass": False,
             "state_eligible": False, "state_pass": False, "joint_pass": False,
             "state_cells": 0, "state_match": 0.0, "note": ""},
            {"case": "c", "attack_type": "token", "observed": False,
             "status": "", "outcome": "UNOBSERVED", "execution_pass": False,
             "state_eligible": False, "state_pass": False, "joint_pass": False,
             "state_cells": 0, "state_match": 0.0, "note": ""},
        ]
        s = summarize(rows)
        self.assertEqual(s["attempted"], 3)
        self.assertEqual(s["observed"], 2)
        self.assertEqual(s["transport_errors"], 1)
        self.assertEqual(s["evm_reverts"], 1)
        self.assertEqual(s["execution_pass"], 1)
        self.assertEqual(s["state_eligible"], 1)
        self.assertEqual(s["state_pass"], 1)
        self.assertEqual(s["joint_pass"], 1)
        self.assertEqual(s["intervals"]["joint_pass/attempted"]["total"], 3)


if __name__ == "__main__":
    unittest.main()
