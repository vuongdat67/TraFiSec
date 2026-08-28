"""Unit tests cho TraFiSec pilot core (OOP refactor 2026-08-11).

Pure stdlib test (unittest + mock + tempfile) - no external dependencies required
anvil, cast, network hay .env keys. Tt c mock qua unittest.mock.patch.

Chy t repository root:
    python -m unittest discover -s pilot/core -p "test_*.py"
    python -m unittest core.test_core      (cn pilot/ trong PYTHONPATH)
hoc t pilot/:
    python -m unittest core.test_core
"""
from __future__ import annotations

# The test configures console encoding and import paths before project imports.
# ruff: noqa: E402

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Execution trace analysis and verification
# Execution trace analysis and verification
for _stream in (sys.stdout, sys.stderr):
    if getattr(_stream, "encoding", None) and "utf" not in _stream.encoding.lower():
        _stream.reconfigure(encoding="utf-8", errors="replace")

# Execution trace analysis and verification
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


from core.env import load_dotenv, resolve_rpc
from core.loss import TOPIC_TRANSFER, TraceAnalyzer
from core.mutate import (
    EIP1967_ADMIN_SLOT,
    AuthRevoke,
    FlashLoanDisable,
    Mutation,
    OraclePin,
    SwapSlice,
)
from core.outcome import Outcome, ReplayResult
from core.replay import Replayer
from core.rpc import RpcClient, RpcError
from core.run_case import _parse_mutation
from core.runner import CaseConfig, CaseRunner, summarize



# Execution trace analysis and verification
class FakeFork:
    def __init__(self, url: str = "http://127.0.0.1:8545"):
        self.url = url


class EnvTests(unittest.TestCase):
    """load_dotenv + resolve_rpc — precedence, khng overwrite, restore env."""

    KEYS = ["RPC", "CHAIN_RPC", "ARB_ARCHIVE_RPC", "ARCHIVE_RPC",
            "QUICKNODE_ARB_TRACE_RPC", "QUICKNODE_TRACE_RPC",
            "ALCHEMY_API_KEY", "TG_TEST_KEY"]

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in self.KEYS}
        for k in self.KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_load_dotenv_missing_file_returns_none(self):
        self.assertIsNone(load_dotenv((Path(tempfile.gettempdir()) / "no_such_tg.env",)))

    def test_load_dotenv_sets_values_and_skips_comments(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.env"
            p.write_text(
                "# comment line\n"
                "\n"
                'TG_TEST_KEY = "hello world"\n'   # quoted value + spaces
                "# TG_TEST_COMMENT=skip me\n"
                "TG_TEST_NOEQ\n",                 # line without equal sign
                encoding="utf-8",
            )
            self.assertEqual(load_dotenv((p,)), p)
            self.assertEqual(os.environ["TG_TEST_KEY"], "hello world")
            self.assertNotIn("TG_TEST_COMMENT", os.environ)
            self.assertNotIn("TG_TEST_NOEQ", os.environ)

    def test_load_dotenv_does_not_overwrite_existing_env(self):
        os.environ["TG_TEST_KEY"] = "already-set"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.env"
            p.write_text('TG_TEST_KEY=new-value\nTG_TEST_OTHER=x\n', encoding="utf-8")
            load_dotenv((p,))
            self.assertEqual(os.environ["TG_TEST_KEY"], "already-set")
            self.assertEqual(os.environ["TG_TEST_OTHER"], "x")

    def test_resolve_rpc_precedence(self):
        os.environ["ALCHEMY_API_KEY"] = "key1"
        os.environ["ARCHIVE_RPC"] = "https://archive"
        os.environ["ARB_ARCHIVE_RPC"] = "https://arb"
        os.environ["CHAIN_RPC"] = "https://chain"
        os.environ["RPC"] = "https://rpc"

        self.assertEqual(resolve_rpc("mainnet"), "https://rpc")
        os.environ.pop("RPC")
        self.assertEqual(resolve_rpc("mainnet"), "https://chain")
        os.environ.pop("CHAIN_RPC")
        self.assertEqual(resolve_rpc("mainnet"), "https://archive")
        os.environ.pop("ARCHIVE_RPC")
        # Execution trace analysis and verification
        self.assertEqual(resolve_rpc("arbitrum"), "https://arb")
        os.environ.pop("ARB_ARCHIVE_RPC")
        self.assertEqual(resolve_rpc("mainnet"), "https://eth-mainnet.g.alchemy.com/v2/key1")
        self.assertEqual(resolve_rpc("arbitrum"), "https://eth-mainnet.g.alchemy.com/v2/key1")

    def test_resolve_rpc_none_when_nothing_set(self):
        self.assertIsNone(resolve_rpc("mainnet"))
        self.assertIsNone(resolve_rpc("arbitrum"))

    def test_trace_rpc_is_separate_from_archive_rpc(self):
        from core.env import resolve_trace_rpc
        os.environ["ARCHIVE_RPC"] = "https://alchemy-archive"
        os.environ["ARB_ARCHIVE_RPC"] = "https://alchemy-arb"
        os.environ["QUICKNODE_TRACE_RPC"] = "https://quicknode-trace"
        os.environ["QUICKNODE_ARB_TRACE_RPC"] = "https://quicknode-arb-trace"
        self.assertEqual(resolve_rpc("mainnet"), "https://alchemy-archive")
        self.assertEqual(resolve_rpc("arbitrum"), "https://alchemy-arb")
        self.assertEqual(resolve_trace_rpc("mainnet"), "https://quicknode-trace")
        self.assertEqual(resolve_trace_rpc("arbitrum"), "https://quicknode-arb-trace")


def _make_http_resp(payload: dict, status: int = 200) -> mock.MagicMock:
    """mock response cho urllib.request.urlopen — body l JSON payload."""
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    return resp


class RpcClientTests(unittest.TestCase):
    """RpcClient.call + helpers c + anvil_set* params."""

    def test_call_success(self):
        resp = _make_http_resp({"jsonrpc": "2.0", "id": 1, "result": "0x2"})
        with mock.patch("urllib.request.urlopen", return_value=resp) as uo:
            out = RpcClient("https://rpc").call("eth_blockNumber")
        self.assertEqual(out, "0x2")
        req = uo.call_args[0][0]
        self.assertEqual(req.full_url, "https://rpc")
        self.assertEqual(req.get_method(), "POST")
        body = json.loads(req.data.decode())
        self.assertEqual(body["method"], "eth_blockNumber")
        self.assertEqual(body["params"], [])

    def test_call_error_payload_raises_rpc_error(self):
        resp = _make_http_resp({"jsonrpc": "2.0", "id": 1,
                                "error": {"code": -32000, "message": "oops"}})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(RpcError):
                RpcClient("https://rpc").call("eth_blockNumber")

    def test_call_network_error_raises_rpc_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("no network")):
            with self.assertRaises(RpcError):
                RpcClient("https://rpc").call("eth_blockNumber")

    def test_call_uses_explicit_fallback_after_dns_failure(self):
        resp = _make_http_resp({"result": "0x2"})
        with mock.patch("urllib.request.urlopen", side_effect=[
            OSError("nodename nor servname provided, or not known"), resp,
        ]) as uo:
            client = RpcClient("https://primary", attempts=1,
                               fallback_urls=("https://fallback",))
            self.assertEqual(client.call("eth_blockNumber"), "0x2")
        self.assertEqual(uo.call_count, 2)
        self.assertEqual(client.last_endpoint, "https://fallback")

    def test_retry_budget_is_configurable_and_has_no_terminal_sleep(self):
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")) as uo, \
             mock.patch("time.sleep") as sleep:
            with self.assertRaisesRegex(RpcError, r"after 2 attempt\(s\)"):
                RpcClient("https://rpc", timeout=0.25, attempts=2).call("eth_blockNumber")
        self.assertEqual(uo.call_count, 2)
        sleep.assert_called_once_with(1.0)

    def test_retry_configuration_validation(self):
        with self.assertRaises(ValueError):
            RpcClient("https://rpc", timeout=0)
        with self.assertRaises(ValueError):
            RpcClient("https://rpc", attempts=0)
        with self.assertRaises(ValueError):
            RpcClient("https://rpc", attempts=1.5)
        with self.assertRaises(ValueError):
            RpcClient("https://rpc", backoff_base=-1)

    def test_eth_block_number_hex_string(self):
        resp = _make_http_resp({"result": "0x2"})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(RpcClient("https://rpc").eth_block_number(), 2)

    def test_eth_block_number_int(self):
        """Verify integer return value handling from RPC eth_blockNumber."""
        resp = _make_http_resp({"result": 2})
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(RpcClient("https://rpc").eth_block_number(), 2)

    def test_anvil_set_code_params(self):
        resp = _make_http_resp({"result": True})
        with mock.patch("urllib.request.urlopen", return_value=resp) as uo:
            RpcClient("https://rpc").anvil_set_code("0xabc", "0x6000")
        body = json.loads(uo.call_args[0][0].data.decode())
        self.assertEqual(body["method"], "anvil_setCode")
        self.assertEqual(body["params"], ["0xabc", "0x6000"])


class ReplayerTransportTests(unittest.TestCase):
    """The Python process, not only cast flags, enforces replay wall time."""

    def test_direct_rpc_send_failure_is_unobserved(self):
        archive = mock.Mock()
        archive.eth_get_transaction.return_value = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0x0", "gas": "0x5208", "input": "0x",
        }
        runner = Replayer(FakeFork(), archive, timeout=2)
        with mock.patch.object(Replayer, "_send_via_http", return_value=(None, None, None)):
            result = runner.replay("0xabc", mainnet_gas=21000)

        self.assertFalse(result.observed)
        self.assertEqual(result.outcome, Outcome.UNOBSERVED)
        self.assertEqual(result.error_kind, "transport_or_timeout")
        self.assertIn("send fail/timeout", result.note)

    def test_direct_rpc_send_failure_does_not_report_cast_diagnostic(self):
        archive = mock.Mock()
        archive.eth_get_transaction.return_value = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0x0", "gas": "0x5208", "input": "0x",
        }
        with mock.patch.object(Replayer, "_send_via_http", return_value=(None, None, None)):
            result = Replayer(FakeFork(), archive, timeout=2).replay("0xabc")

        self.assertNotIn("| cast:", result.note)


class OutcomeTests(unittest.TestCase):
    """ReplayResult: gas_delta_pct, fidelity_pass, to_csv_row."""

    def test_gas_delta_pct_exact(self):
        r = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                         gas_used=1_562_994, mainnet_gas=1_531_409)
        self.assertAlmostEqual(r.gas_delta_pct, 2.062479716391898, places=5)

    def test_gas_delta_pct_none_when_missing_gas(self):
        self.assertIsNone(ReplayResult(Outcome.REVERTED).gas_delta_pct)
        self.assertIsNone(ReplayResult(Outcome.REVERTED, status=False,
                                       gas_used=100, mainnet_gas=None).gas_delta_pct)

    def test_replay_note_uses_na_when_mainnet_gas_missing(self):
        """Missing reference must not be rendered as a zero percent delta."""
        replayer = Replayer(FakeFork(), mock.Mock(), timeout=2)
        with mock.patch.object(Replayer, "tx_parts", return_value={
                "from": "0x" + "11" * 20,
                "to": "0x" + "22" * 20,
                "value": "0x0", "gas": "0x5208", "input": "0x",
        }), mock.patch.object(Replayer, "_send", return_value=(True, 189420, {
                "status": "0x1", "gasUsed": hex(189420),
        })):
            result = replayer.replay("0xabc", None)
        self.assertIn("mainnet N/A (ΔN/A)", result.note)

    def test_fidelity_pass_false_when_delta_above_threshold(self):
        # Execution trace analysis and verification
        r = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                         gas_used=1_562_994, mainnet_gas=1_531_409)
        self.assertFalse(r.fidelity_pass(max_delta_pct=2.0))

    def test_fidelity_pass_true_within_threshold(self):
        # Δ ~ 1% ≤ 10% → PASS
        r = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                         gas_used=1_562_994, mainnet_gas=1_547_134)
        self.assertTrue(r.fidelity_pass())

    def test_fidelity_pass_false_when_status_false(self):
        r = ReplayResult(Outcome.REVERTED, status=False,
                         gas_used=1_562_994, mainnet_gas=1_531_409)
        self.assertFalse(r.fidelity_pass(max_delta_pct=10.0))

    def test_fidelity_pass_false_when_mainnet_gas_none(self):
        r = ReplayResult(Outcome.EXECUTED_NO_HARM, status=True, gas_used=1_562_994)
        self.assertFalse(r.fidelity_pass())

    def test_to_csv_row_seven_columns_raw(self):
        r = ReplayResult(Outcome.EXECUTED_HARM, status=True,
                         gas_used=1000, mainnet_gas=2000,
                         note="status 0x1, gas 1000 vs mainnet 2000",
                         details={"loss_S": "1.5", "loss_Sm": "0.5", "dloss": "1.0"})
        row = r.to_csv_row("cream/f_swap")
        parts = row.split(",")
        self.assertEqual(len(parts), 7)
        self.assertEqual(parts[0], "cream/f_swap")
        self.assertEqual(parts[1], "EXECUTED_HARM")
        self.assertEqual(parts[2:5], ["1.5", "0.5", "1.0"])
        self.assertEqual(parts[5], "status 0x1")


class MutationTests(unittest.TestCase):
    """apply() patch anvil state ng param, ng th t, trn ng URL."""

    def test_flash_loan_disable(self):
        m = FlashLoanDisable("0x21b8065d10f73EE2e260e5B47D3344d3Ced7596E")
        self.assertEqual(m.name, "f_fl")
        calls = []
        def fake_call(self, method, params):
            calls.append((method, params))
            if method == "eth_getCode":
                return "0x" if params[0].lower().endswith("f1a1") else "0x6000"
            if method == "eth_sendTransaction":
                return "0xdeployment"
            if method == "eth_getTransactionReceipt":
                return {"status": "0x1", "contractAddress": "0x" + "33" * 20}
            return True

        with mock.patch.object(RpcClient, "call", autospec=True, side_effect=fake_call):
            m.apply(FakeFork("http://127.0.0.1:9999"))
        self.assertEqual([m for m, _ in calls], [
            "eth_getCode", "eth_getCode", "anvil_setCode",
            "eth_sendTransaction", "eth_getTransactionReceipt",
            "eth_getCode", "anvil_setCode",
        ])
        self.assertEqual(calls[-1], ("anvil_setCode", [
            "0x21b8065d10f73EE2e260e5B47D3344d3Ced7596E", "0x6000"
        ]))

    def test_flash_loan_disable_uses_fork_url(self):
        m = FlashLoanDisable("0xprovider")
        urls = []

        def fake_call(self, method, params):
            urls.append(self.url)  # Verified execution property
            if method == "eth_getCode":
                return "0x" if params[0].lower().endswith("f1a1") else "0x6000"
            if method == "eth_sendTransaction":
                return "0xdeployment"
            if method == "eth_getTransactionReceipt":
                return {"status": "0x1", "contractAddress": "0x" + "33" * 20}
            return True

        with mock.patch.object(RpcClient, "call", autospec=True, side_effect=fake_call):
            m.apply(FakeFork("http://127.0.0.1:1234"))
        self.assertTrue(urls)
        self.assertTrue(all(url == "http://127.0.0.1:1234" for url in urls))

    def test_oracle_pin(self):
        m = OraclePin("0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf", "0x60006000")
        self.assertEqual(m.name, "f_orc")
        calls = []
        with mock.patch.object(RpcClient, "call", autospec=True,
                               side_effect=lambda self, method, params: calls.append((method, params))):
            m.apply(FakeFork())
        self.assertEqual(calls, [
            ("anvil_setCode", ["0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf", "0x60006000"]),
        ])

    def test_swap_slice_apply_to_replayer(self):
        m = SwapSlice("0xdeadbeef")
        rp = mock.Mock(spec=Replayer)
        rp.data_override = None
        m.apply_to_replayer(rp)
        self.assertEqual(rp.data_override, "0xdeadbeef")

    def test_swap_slice_none_does_not_touch_replayer(self):
        m = SwapSlice()
        rp = mock.Mock(spec=Replayer)
        rp.data_override = None
        m.apply_to_replayer(rp)
        self.assertIsNone(rp.data_override)

    def test_auth_revoke(self):
        proxy = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        m = AuthRevoke(proxy)
        self.assertEqual(m.name, "f_auth(A)")
        calls = []
        with mock.patch.object(RpcClient, "call", autospec=True,
                               side_effect=lambda self, method, params: calls.append((method, params))):
            m.apply(FakeFork())
        self.assertEqual(calls, [
            ("anvil_setStorageAt",
             [proxy, EIP1967_ADMIN_SLOT, "0x" + "00" * 32]),
        ])
        self.assertEqual(EIP1967_ADMIN_SLOT,
                         "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")

    def test_mutation_base_abstract(self):
        self.assertTrue(hasattr(Mutation, "apply"))  # Verified execution property


class RunnerTests(unittest.TestCase):
    """CaseConfig defaults + CaseRunner.record/load_outcomes + summarize."""

    def test_case_config_default_state_block(self):
        cfg = CaseConfig(name="cream", tx_hash="0xabc", tx_block=13_125_071)
        self.assertEqual(cfg.state_block, 13_125_070)
        # Execution trace analysis and verification
        cfg2 = CaseConfig(name="x", tx_hash="0x1", tx_block=10, state_block=7)
        self.assertEqual(cfg2.state_block, 7)

    def test_record_creates_csv_with_header_and_row(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = CaseConfig(name="t", tx_hash="0xabc", tx_block=100,
                             protocol="cream", prior_txs=["0xprior"])
            runner = CaseRunner(cfg, "https://fake-rpc.invalid", out_dir=Path(td))
            r = ReplayResult(Outcome.EXECUTED_HARM, status=True, gas_used=1000,
                             mainnet_gas=2000, note="status 0x1, gas 1000 vs mainnet 2000",
                             details={"loss_S": "1.5", "loss_Sm": "0.5", "dloss": "1.0"})
            runner.record("f_swap", r)
            text = (Path(td) / "outcomes.csv").read_text(encoding="utf-8")
            lines = text.strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0], "case,mutation,outcome,loss_S,loss_Sm,Δloss,note")
            parsed = next(csv.reader(io.StringIO(lines[1])))
            # Execution trace analysis and verification
            # [case_mut, mutation, outcome, loss_S, loss_Sm, Δloss, note]
            self.assertEqual(parsed, ["cream/f_swap", "f_swap", "EXECUTED_HARM",
                                      "1.5", "0.5", "1.0", r.note])

    def test_load_outcomes_reads_back(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = CaseConfig(name="t", tx_hash="0xabc", tx_block=100, protocol="cream")
            runner = CaseRunner(cfg, "https://fake-rpc.invalid", out_dir=Path(td))
            runner.record("fidelity", ReplayResult(Outcome.EXECUTED_NO_HARM,
                                                   status=True, gas_used=100, mainnet_gas=90,
                                                   note="status 0x1, gas 100 vs mainnet 90"))
            runner.record("f_fl", ReplayResult(Outcome.REVERTED, status=False,
                                               gas_used=100, mainnet_gas=90, note="status 0x0, gas 100"))
            rows = runner.load_outcomes()
            self.assertEqual(len(rows), 2)
            # Execution trace analysis and verification
            self.assertEqual(rows[0]["case"], "cream/fidelity")
            self.assertEqual(rows[0]["mutation"], "fidelity")
            self.assertEqual(rows[0]["outcome"], "EXECUTED_NO_HARM")
            self.assertEqual(rows[0]["note"], "status 0x1, gas 100 vs mainnet 90")
            self.assertEqual(rows[1]["case"], "cream/f_fl")
            self.assertEqual(rows[1]["mutation"], "f_fl")
            self.assertEqual(rows[1]["outcome"], "REVERTED")
            self.assertEqual(rows[1]["note"], "status 0x0, gas 100")

    def test_record_upserts_same_mutation_instead_of_duplicating(self):
        """Verify record() updates existing (case, mutation) row rather than appending duplicates."""
        with tempfile.TemporaryDirectory() as td:
            cfg = CaseConfig(name="t", tx_hash="0xabc", tx_block=100, protocol="cream")
            runner = CaseRunner(cfg, "https://fake-rpc.invalid", out_dir=Path(td))
            runner.record("fidelity", ReplayResult(Outcome.EXECUTED_NO_HARM,
                                                   status=True, gas_used=100, mainnet_gas=90,
                                                   note="v1"))
            runner.record("f_swap", ReplayResult(Outcome.REVERTED, status=False, gas_used=50,
                                                 mainnet_gas=90, note="v1"))
            runner.record("f_swap", ReplayResult(Outcome.REVERTED, status=False, gas_used=60,
                                                 mainnet_gas=90, note="v2"))
            rows = runner.load_outcomes()
            self.assertEqual(len(rows), 2)
            swap = [r for r in rows if r["mutation"] == "f_swap"]
            self.assertEqual(len(swap), 1)
            self.assertEqual(swap[0]["note"], "v2")
            self.assertEqual(rows[0]["note"], "v1")  # Verified execution property

    def test_out_dir_accepts_str(self):
        """Verify CaseRunner accepts string path for out_dir."""
        with tempfile.TemporaryDirectory() as td:
            cfg = CaseConfig(name="t", tx_hash="0xabc", tx_block=100)
            runner = CaseRunner(cfg, "https://fake-rpc.invalid", out_dir=td)  # Verified execution property
            self.assertTrue(runner.outcomes_path.parent.is_dir())
            runner.record("fidelity", ReplayResult(Outcome.EXECUTED_NO_HARM,
                                                   status=True, gas_used=100, mainnet_gas=90))
            self.assertTrue(runner.outcomes_path.exists())

    def test_load_outcomes_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = CaseConfig(name="t", tx_hash="0xabc", tx_block=100)
            runner = CaseRunner(cfg, "https://fake-rpc.invalid", out_dir=Path(td))
            self.assertEqual(runner.load_outcomes(), [])

    def test_summarize_joins_lines(self):
        results = {
            "fidelity": ReplayResult(Outcome.EXECUTED_NO_HARM, status=True,
                                     gas_used=100, mainnet_gas=90,
                                     note="status 0x1, gas 100 vs mainnet 90"),
            "f_fl": ReplayResult(Outcome.REVERTED, status=False,
                                 gas_used=100, mainnet_gas=90, note="status 0x0, gas 100"),
        }
        s = summarize(results)
        lines = s.splitlines()
        self.assertEqual(lines[0], "fidelity EXECUTED_NO_HARM status 0x1, gas 100 vs mainnet 90")
        self.assertEqual(lines[1], "f_fl REVERTED status 0x0, gas 100")


class ParseMutationTests(unittest.TestCase):
    """Verify parsing and validation of mutation command-line strings."""

    def test_f_fl(self):
        m = _parse_mutation("f_fl:0x21b8065d10f73EE2e260e5B47D3344d3Ced7596E")
        self.assertIsInstance(m, FlashLoanDisable)
        self.assertEqual(m.provider, "0x21b8065d10f73EE2e260e5B47D3344d3Ced7596E")

    def test_f_orc(self):
        m = _parse_mutation(
            "f_orc:0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf:0x60006000")
        self.assertIsInstance(m, OraclePin)
        self.assertEqual(m.oracle, "0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf")
        self.assertEqual(m.stub_bytecode, "0x60006000")

    def test_f_swap(self):
        # Execution trace analysis and verification
        m = _parse_mutation("f_swap:0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001")
        self.assertIsInstance(m, SwapSlice)
        self.assertEqual(m.calldata_override, "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001")
        self.assertIsNone(m.start_cap)

    def test_f_swap_cap(self):
        # Execution trace analysis and verification
        m = _parse_mutation("f_swap:0")
        self.assertIsInstance(m, SwapSlice)
        self.assertEqual(m.start_cap, 0)

    def test_start_cap_override_slicing(self):
        """Verify calldata slicing and byte offset rewriting for start_cap_override."""
        from core.mutate import start_cap_override
        orig = "0x641ccd83" + format(500 * 10**18, "064x") + \
            format(int("101d0cea7f08a45f0000", 16), "064x") + format(355 * 10**18, "064x")
        ov = start_cap_override(orig, 0)
        self.assertIsNotNone(ov)
        self.assertEqual(ov[2:10], "641ccd83")
        self.assertEqual(ov[2 + 8 + 64: 2 + 8 + 128], format(0, "064x"))  # word2 = 0
        self.assertEqual(ov[2 + 8 + 128:], format(355 * 10**18, "064x"))  # Verified execution property
        self.assertEqual(ov, "0x641ccd83" + format(500 * 10**18, "064x") + format(0, "064x") + format(355 * 10**18, "064x"))
        # sai selector → None
        self.assertIsNone(start_cap_override("0xaaaaaaaa" + orig[10:], 0))

    def test_f_auth(self):
        m = _parse_mutation("f_auth:0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
        self.assertIsInstance(m, AuthRevoke)
        self.assertEqual(m.proxy, "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")

    def test_f_fl_missing_addr(self):
        with self.assertRaises(SystemExit):
            _parse_mutation("f_fl:")

    def test_f_orc_missing_stub(self):
        with self.assertRaises(SystemExit):
            _parse_mutation("f_orc:0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf")

    def test_f_swap_empty(self):
        with self.assertRaises(SystemExit):
            _parse_mutation("f_swap:")

    def test_f_auth_empty(self):
        with self.assertRaises(SystemExit):
            _parse_mutation("f_auth:")

    def test_unknown_name(self):
        with self.assertRaises(SystemExit):
            _parse_mutation("f_unknown:0xabc")


class LossTests(unittest.TestCase):
    """TraceAnalyzer — flow delta + loss per party USD t trace in-memory."""

    def _sample_trace(self) -> dict:
        return {
            "logs": [
                {
                    "topics": [
                        TOPIC_TRANSFER,
                        "0x" + "00" * 32,  # 32-byte from
                        "0x" + "11" * 32,  # 32-byte to
                    ],
                    "data": "0x0de0b6b3a7640000",  # 1e18 wei
                    "address": "0x000000000000000000000000000000000000dEaD",
                }
            ],
            "calls": [
                {"from": "0x0000000000000000000000000000000000000001",
                 "to": "0x0000000000000000000000000000000000000002",
                 "value": "0x9184e72a000"},  # Verified execution property
            ],
        }

    def test_collect_flows(self):
        a = TraceAnalyzer(self._sample_trace(), {})
        net, native = a.collect_flows()
        token = "0x000000000000000000000000000000000000dead"
        frm = "0x" + "00" * 20          # topics[1][-40:]
        to = "0x" + "11" * 20           # topics[2][-40:]
        self.assertEqual(net[(frm, token)], -10**18)
        self.assertEqual(net[(to, token)], 10**18)
        self.assertEqual(native["0x0000000000000000000000000000000000000001"], -10**13)
        self.assertEqual(native["0x0000000000000000000000000000000000000002"], 10**13)

    def test_compute_loss_exact(self):
        prices = {
            "0x000000000000000000000000000000000000dead": 2.5,
            "ETH": 3000.0,
        }
        a = TraceAnalyzer(self._sample_trace(), prices)
        per_party, loss = a.compute_loss()
        to = "0x" + "11" * 20  # Verified execution property
        # victim 0x00..00: token -1e18 * 2.5 = -2.5e18
        self.assertAlmostEqual(per_party["0x0000000000000000000000000000000000000000"], -2.5e18)
        # victim 0x00..01: native -1e13 * 3000 = -3e16
        self.assertAlmostEqual(per_party["0x0000000000000000000000000000000000000001"], -3e16)
        # Execution trace analysis and verification
        self.assertAlmostEqual(per_party[to], 2.5e18)
        self.assertAlmostEqual(per_party["0x0000000000000000000000000000000000000002"], 3e16)
        self.assertAlmostEqual(loss, 2.53e18)

    def test_compute_loss_zero_price_no_effect(self):
        a = TraceAnalyzer(self._sample_trace(), {})
        per_party, loss = a.compute_loss()
        # Execution trace analysis and verification
        self.assertEqual(sum(per_party.values()), 0.0)
        self.assertEqual(loss, 0.0)

    def test_non_transfer_log_ignored(self):
        trace = {
            "logs": [{"topics": ["0x" + "ab" * 32, "0x" + "00" * 32],
                      "data": "0x01", "address": "0xabc"}],
            "calls": [],
        }
        net, native = TraceAnalyzer(trace, {}).collect_flows()
        self.assertEqual(net, {})
        self.assertEqual(native, {})


class CliTests(unittest.TestCase):
    """python -m core.run_case --help chy c."""

    def test_run_case_help(self):
        env = dict(os.environ)
        env.setdefault("PYTHONIOENCODING", "utf-8")
        r = subprocess.run(
            [sys.executable, "-m", "core.run_case", "--help"],
            cwd=str(_REPO_ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("usage", r.stdout.lower())



if __name__ == "__main__":
    unittest.main()
