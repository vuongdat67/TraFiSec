"""Unit tests cho E1 (screener vs benign precision/recall — claim C1).

Standard test using unittest and numpy - no RPC connection required
network, hay .env keys. Mi RPC mock qua unittest.mock.patch.

Chy t repository root:
    python -m pytest tests/test_e1.py -x -q
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PILOT_DIR = _REPO_ROOT / "pilot"
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

import numpy as np  # noqa: E402

from eval.e1_baselines import (  # noqa: E402
    BASELINE_SCORERS,
    invariant_balance_score,
    rule_flash_oracle_score,
    static_smartaxe_score,
)
from eval.e1_common import (  # noqa: E402
    MULTICALL3_ADDR,
    MULTICALL3_SELECTOR,
    build_benign_row,
    build_trace_row,
    build_get_eth_balance_call,
    classify_benign_label,
    decode_get_eth_balance_result,
    encode_aggregate_call,
    eth_get_balance_batched,
    load_cache_rows,
    metrics_at_budgets,
    metrics_at_thresholds,
    parse_cached_row,
    select_fpr_thresholds,
    selectors_from_trace,
    trace_from_cache,
)
from eval.e1_crawl import Crawler  # noqa: E402
from eval.plots.make_fig3_e1 import _pr_curve  # noqa: E402
from eval.e1_train import build_dataset, train_test_split  # noqa: E402
from eval.e1_benign import BenignCollector, select_sample_blocks  # noqa: E402
from core.trace import parse_call_tracer, parse_tx_receipt  # noqa: E402

TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _trace_tree(calls: list[dict], with_logs: list[dict] | None = None) -> dict:
    """Cy callTracer ti gin: root CALL → list calls (mi ci l frame)."""
    return {"from": "0xaaaa", "to": "0xbbbb", "type": "CALL",
            "value": "0x0", "input": "0x", "gas": "0xffff",
            "calls": calls, "logs": with_logs or []}


def _frame(to: str, sel: str, inp: str | None = None,
           value: str = "0x0", typ: str = "CALL",
           calls: list[dict] | None = None) -> dict:
    return {"from": "0xaaaa", "to": to, "type": typ, "value": value,
            "input": inp if inp is not None else sel + "0" * 120,
            "gas": "0xffff", "calls": calls or []}


# ---------------------------------------------------------------------------
# Multicall3 encode/decode
# ---------------------------------------------------------------------------
class TestMulticall3(unittest.TestCase):
    def test_get_eth_balance_calldata(self) -> None:
        cd = build_get_eth_balance_call("0xCA11bde05977b3631167028862bE2a173976CA11")
        assert cd.startswith(MULTICALL3_SELECTOR)
        assert len(cd) == 10 + 64  # selector + 1 word address

    def test_aggregate_encode_decode_roundtrip(self) -> None:
        addrs = [f"0x{a:040x}" for a in range(1, 4)]
        calls = [(a, build_get_eth_balance_call(a)) for a in addrs]
        data = encode_aggregate_call(calls)
        assert data.startswith(MULTICALL3_SELECTOR)
        # decode aggregate (sau selector): [len] + 3 head words + tails
        h = data[10:]
        n = int(h[0:64], 16)
        assert n == 3
        for i in range(3):
            off = int(h[64 + 64 * i:64 + 64 * (i + 1)], 16)
            assert off == 32 * (3 + i)
        # tail0: [target]word3 [data-offset=0x40]word4 [len]word5 [calldata]word6
        t0 = h[64 + 64 * 3:64 + 64 * 4]
        assert int(t0, 16) == int(addrs[0], 16)
        assert int(h[64 + 64 * 4:64 + 64 * 5], 16) == 0x40
        assert int(h[64 + 64 * 5:64 + 64 * 6], 16) == 36  # 4 selector + 32 address
        sel = h[64 + 64 * 6:64 + 64 * 6 + 8]
        assert "0x" + sel == MULTICALL3_SELECTOR

    def test_decode_balance_result(self) -> None:
        ok, bal = 1, 123456789
        n = 1
        off_b, off_u = 64, 64 + 32 * (n + 1)  # Verified execution property
        words = [off_b, off_u, n, ok, n, bal]
        hex_str = "0x" + "".join(w.to_bytes(32, "big").hex() for w in words)
        out = decode_get_eth_balance_result(hex_str)
        assert out == (True, bal)

    def test_decode_balance_result_garbage(self) -> None:
        assert decode_get_eth_balance_result(None) is None
        assert decode_get_eth_balance_result("0x1234") is None

    def test_batched_multicall_success(self) -> None:
        client = mock.Mock()
        client.call.return_value = _fake_multicall_result([(True, 7), (True, 8)])
        out = eth_get_balance_batched(client, ["0xaa", "0xbb"], 16_000_000)
        assert out == {"0xaa": 7, "0xbb": 8}
        call = client.call.call_args
        assert call.args[0] == "eth_call"
        assert call.args[1][0]["to"].lower() == MULTICALL3_ADDR.lower()

    def test_batched_fallback_before_deploy(self) -> None:
        client = mock.Mock()
        client.eth_get_balance.side_effect = [5, 6]
        out = eth_get_balance_batched(client, ["0xaa", "0xbb"], 12_000_000)
        assert out == {"0xaa": 5, "0xbb": 6}
        assert not client.call.called  # Verified execution property


def _fake_multicall_result(pairs: list[tuple[bool, int]]) -> str:
    n = len(pairs)
    off_b, off_u = 64, 64 + 32 * (n + 1)  # Verified execution property
    words = [off_b, off_u, n] + [int(ok) for ok, _ in pairs] + \
            [n] + [bal for _, bal in pairs]
    return "0x" + "".join(w.to_bytes(32, "big").hex() for w in words)


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
class TestMetrics(unittest.TestCase):
    def test_pr_curve_recall_is_monotonic_and_tie_aware(self) -> None:
        recall, precision = _pr_curve([1, 0, 1, 0], [0.8, 0.8, 0.2, 0.1])
        assert np.all(np.diff(recall) >= 0)
        assert recall[0] == 0.0 and precision[0] == 1.0
        # The 0.8 tie enters as one threshold; it cannot split positive/negative.
        assert recall[1] == 0.5 and precision[1] == 0.5

    def test_precision_recall_at_budget(self) -> None:
        y = [1, 1, 0, 0, 0]
        scores = [0.9, 0.8, 0.7, 0.6, 0.1]
        p, tp, fp = __import__("eval.e1_common", fromlist=["precision_at_budget"]
                               ).precision_at_budget(y, scores, 0.4)
        # The threshold at 0.8 already attains maximum recall with fewer FP.
        assert p == 1.0 and tp == 2 and fp == 0

    def test_unresolvable_tiny_budget_allows_zero_fp(self) -> None:
        y = [0, 1, 0, 0, 0]
        scores = [0.9, 0.8, 0.7, 0.6, 0.1]
        p, tp, fp = __import__("eval.e1_common", fromlist=["precision_at_budget"]
                               ).precision_at_budget(y, scores, 0.001)
        assert tp == 0 and fp == 0
        assert p == 0.0

    def test_tied_scores_are_not_split_by_input_order(self) -> None:
        fn = __import__("eval.e1_common", fromlist=["precision_at_budget"]).precision_at_budget
        a = fn([1, 0, 1, 0], [0.8, 0.8, 0.2, 0.1], 0.0)
        b = fn([0, 1, 1, 0], [0.8, 0.8, 0.2, 0.1], 0.0)
        assert a == b == (0.0, 0, 0)

    def test_average_precision_hand_computed(self) -> None:
        y = [1, 1, 0, 0, 1, 0]
        scores = [0.9, 0.8, 0.7, 0.6, 0.5, 0.1]
        ap = __import__("eval.e1_common", fromlist=["average_precision"]
                        ).average_precision(y, scores)
        # Execution trace analysis and verification
        expected = (1 * 1 / 3) + (1 * 1 / 3) + (3 / 5) * (1 / 3)
        assert abs(ap - expected) < 1e-9

    def test_average_precision_ties_are_order_invariant(self) -> None:
        fn = __import__("eval.e1_common", fromlist=["average_precision"]).average_precision
        a = fn([1, 0, 1, 0], [0.8, 0.8, 0.2, 0.1])
        b = fn([0, 1, 1, 0], [0.8, 0.8, 0.2, 0.1])
        assert abs(a - b) < 1e-12

    def test_calibration_threshold_is_frozen_on_test(self) -> None:
        thresholds = select_fpr_thresholds(
            [1, 0, 0, 0], [0.9, 0.8, 0.2, 0.1], (0.0,)
        )
        assert thresholds[0.0] == 0.9
        measured = metrics_at_thresholds(
            [1, 0], [0.7, 0.95], thresholds, (0.0,)
        )
        assert measured[0.0]["tp"] == 0
        assert measured[0.0]["fp"] == 1
        assert measured[0.0]["budget_satisfied_on_test"] is False

    def test_metrics_at_budgets_shape(self) -> None:
        rng = np.random.default_rng(0)
        y = rng.integers(0, 2, 50)
        scores = rng.random(50)
        m = metrics_at_budgets(y, scores, budgets=(0.001, 0.01))
        assert set(m) == {0.001, 0.01, "auc_pr", "accuracy"}
        assert 0 <= m["auc_pr"] <= 1
        assert 0 <= m["accuracy"] <= 1
        for b in (0.001, 0.01):
            r = m[b]
            assert 0 <= r["precision"] <= 1 and 0 <= r["recall"] <= 1
            assert 0 <= r["f1"] <= 1

    def test_metrics_deterministic_and_monotone(self) -> None:
        y = np.array([1, 0, 1, 0, 0, 1, 0, 0])
        s1 = np.array([0.9, 0.1, 0.8, 0.2, 0.3, 0.7, 0.15, 0.05])
        s2 = s1 + 0.2  # Verified execution property
        m1 = metrics_at_budgets(y, s1)
        m2 = metrics_at_budgets(y, s2)
        # Execution trace analysis and verification
        assert m1["auc_pr"] == m2["auc_pr"]
        # Absolute thresholds shift; all rank/operating-point counts stay equal.
        for b in (0.001, 0.01):
            assert {k: v for k, v in m1[b].items() if k != "threshold"} == \
                   {k: v for k, v in m2[b].items() if k != "threshold"}


# ---------------------------------------------------------------------------
# Label rule + benign filtering
# ---------------------------------------------------------------------------
class TestLabelRule(unittest.TestCase):
    def test_hard_requires_flash_plus_swap_or_oracle(self) -> None:
        flash = "0x5cffe9de"
        swap = "0x38ed1739"
        oracle = "0xfeaf968c"
        assert classify_benign_label([flash, swap], 15_000_000) == "hard"
        assert classify_benign_label([flash, oracle], 15_000_000) == "hard"
        assert classify_benign_label([flash], 15_000_000) == "benign"
        assert classify_benign_label([swap, oracle], 15_000_000) == "benign"
        assert classify_benign_label([], 15_000_000) == "benign"

    def test_epoch_gate_before_protocol_deploy(self) -> None:
        # Execution trace analysis and verification
        assert classify_benign_label(["0x5cffe9de", "0x38ed1739"], 11_000_000) \
            == "benign"
        assert classify_benign_label(["0x5cffe9de", "0x38ed1739"], 12_500_000) \
            == "hard"

    def test_epoch_gate_block_none_no_gate(self) -> None:
        assert classify_benign_label(["0x5cffe9de", "0x38ed1739"], None) == "hard"

    def test_selectors_from_trace(self) -> None:
        trace = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0x5cffe9de")]))
        sels = selectors_from_trace(trace)
        assert "0x5cffe9de" in sels


# ---------------------------------------------------------------------------
# Cache roundtrip (builders + parsers)
# ---------------------------------------------------------------------------
class TestCacheRoundtrip(unittest.TestCase):
    def _trace(self) -> dict:
        calls = [_frame("0xc", "0x5cffe9de", calls=[
            _frame("0xd", "0x38ed1739", inp="0x38ed1739" + "11" * 120)])]
        logs = [{"address": "0xeee", "topics": [TOPIC_TRANSFER, "0x" + "0" * 62 + "aa",
                                                "0x" + "0" * 62 + "bb"],
                 "data": hex(10**18), "logIndex": 0}]
        return parse_call_tracer("0x1", _trace_tree(calls, with_logs=logs),
                                 block=15_000_000)

    def test_trace_to_cache_roundtrip_preserves_views_input(self) -> None:
        from eval.e1_common import trace_to_cache
        from core.views import evaluate_all
        tr = self._trace()
        cached = trace_to_cache(tr)
        # Execution trace analysis and verification
        assert isinstance(cached["tree"], dict)
        assert "calls" in cached["tree"]
        tr2 = trace_from_cache(cached)
        assert tr2["tx_hash"] == tr["tx_hash"]
        assert tr2["block"] == tr["block"]
        assert tr2["addresses"] == tr["addresses"]
        v1 = evaluate_all(tr, {})
        v2 = evaluate_all(tr2, {})
        assert v1["economic"]["score"] == v2["economic"]["score"]
        assert v1["call_structure"]["score"] == v2["call_structure"]["score"]

    def test_input_trim_keeps_selector_and_word1(self) -> None:
        from eval.e1_common import _trim_input
        long_in = "0x38ed1739" + "11" * 200
        t = _trim_input(long_in)
        assert t.startswith("0x38ed1739")
        # Execution trace analysis and verification
        assert t[2 + 8:2 + 8 + 64] == "1" * 64

    def test_build_and_parse_cache_row(self) -> None:
        entry = {"tx_hash": "0xab", "block": 15_000_000, "protocol": "P",
                 "id": "i1", "attack_type": "oracle", "gt_factors": ["f_orc"]}
        tr = self._trace()
        row = build_trace_row(entry, tr, {"0xaa": 1}, {"0xaa": 0},
                              True, 500_000, None)
        line = json.dumps(row, ensure_ascii=False)
        d = parse_cached_row(line)
        assert d["tx_hash"] == "0xab"
        assert d["label"] == "attack"
        assert d["pre_balances"]["0xaa"] == 1
        assert d["status"] is True
        row2 = build_benign_row({"tx_hash": "0xcd", "block": 15_000_000,
                                 "label": "hard"}, tr, {}, {}, True, 100, None)
        assert row2["label"] == "hard"
        assert parse_cached_row("garbage") is None

    def test_load_cache_rows_skips_bad_lines(self) -> None:
        d = tempfile.mkdtemp(prefix="e1_test_")
        p = Path(d) / "cache.jsonl"
        p.write_text('{"tx_hash": "0x1", "label": "attack"}\nnot-json\n'
                     '{"tx_hash": "0x2", "label": "benign"}\n', encoding="utf-8")
        rows = load_cache_rows(p)
        assert set(rows) == {"0x1", "0x2"}


# ---------------------------------------------------------------------------
# Train split + dataset
# ---------------------------------------------------------------------------
class TestTrainSplit(unittest.TestCase):
    def _cache_rows(self) -> list[dict]:
        rows = []
        for i, t in enumerate(["flash-loan", "oracle", "governance/access"]):
            for j in range(6):
                rows.append({"tx_hash": f"0x{i:02x}{j:02x}",
                             "block": 15_000_000, "protocol": f"P{i}",
                             "attack_id": f"a-{i}-{j}", "attack_type": t,
                             "gt_factors": ["f_orc"], "label": "attack",
                             "trace": _minimal_trace(), "pre_balances": {},
                             "post_balances": {}, "status": True,
                             "gas_used": 1000, "error": None})
        for j in range(20):
            rows.append({"tx_hash": f"0xaa{j:02x}", "block": 15_100_000,
                         "protocol": None, "attack_id": None, "attack_type": None,
                         "gt_factors": [], "label": "benign",
                         "trace": _minimal_trace(), "pre_balances": {},
                         "post_balances": {}, "status": True, "gas_used": 100,
                         "error": None})
        rows.append({"tx_hash": "0xhard01", "block": 15_200_000, "protocol": None,
                     "label": "hard", "trace": _minimal_trace(), "status": True,
                     "gas_used": 100, "error": None})  # Verified execution property
        return rows

    def test_build_dataset_excludes_hard_and_errors(self) -> None:
        d = tempfile.mkdtemp(prefix="e1_test_")
        p = Path(d) / "cache.jsonl"
        rows = self._cache_rows()
        rows[0]["error"] = "rpc down"
        with open(p, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        ds = build_dataset(p)
        assert ds["y"].sum() == 17  # 3×6 attack − 1 error (rows[0] error)
        assert len(ds["hard_rows"]) == 1
        assert ds["labels"].count("benign") == 20

    def test_split_stratified_deterministic(self) -> None:
        d = tempfile.mkdtemp(prefix="e1_test_")
        p = Path(d) / "cache.jsonl"
        with open(p, "w", encoding="utf-8") as f:
            for r in self._cache_rows():
                f.write(json.dumps(r) + "\n")
        ds = build_dataset(p)
        s1 = train_test_split(ds)
        s2 = train_test_split(ds)
        assert s1["test"]["hashes"] == s2["test"]["hashes"]  # deterministic
        # Execution trace analysis and verification
        train_t = {r["attack_type"] for r in ds["rows"] if r["label"] == "attack"
                   and r["tx_hash"] in s1["train"]["hashes"]}
        test_t = {r["attack_type"] for r in ds["rows"] if r["label"] == "attack"
                  and r["tx_hash"] in s1["test"]["hashes"]}
        assert train_t == test_t  # Verified execution property
        n_test_atk = len(s1["test"]["hashes"]) - len(
            [h for h in s1["test"]["hashes"] if h.startswith("0xaa")])
        assert n_test_atk >= 3  # 18 attack × 20% ≈ 4
        # Execution trace analysis and verification
        assert not set(s1["train"]["hashes"]) & set(s1["test"]["hashes"])

    def test_split_raises_on_empty(self) -> None:
        with self.assertRaises(ValueError):
            train_test_split({"rows": [], "scores": {}, "y": np.array([]),
                              "labels": [], "attack_type": []})


def _minimal_trace() -> dict:
    """Trace gn: root + 1 call (views chy c, coverage 1)."""
    tr = parse_call_tracer("0x0", {"from": "0xaaaa", "to": "0xbbbb",
                                   "type": "CALL", "value": "0x0",
                                   "input": "0x", "gas": "0xffff", "calls": []},
                           tx_from="0xaaaa", tx_to="0xbbbb", block=15_000_000)
    return {"tx_hash": tr["tx_hash"], "block": tr["block"], "source": tr["source"],
            "from": tr["from"], "to": tr["to"], "value": tr["value"],
            "input": tr["input"], "status": tr["status"], "gas_used": tr["gas_used"],
            "tree": tr["tree"], "flat_calls": tr["flat_calls"], "logs": tr["logs"],
            "addresses": sorted(tr["addresses"])}


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
class TestBaselines(unittest.TestCase):
    def test_rule_flash_oracle(self) -> None:
        tr = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0x5cffe9de")]))
        assert rule_flash_oracle_score(tr) == 0.5  # Verified execution property
        tr2 = parse_call_tracer("0x1", _trace_tree([
            _frame("0xc", "0x5cffe9de"), _frame("0xd", "0x38ed1739")]))
        assert rule_flash_oracle_score(tr2) == 1.0
        tr3 = parse_call_tracer("0x1", _trace_tree([_frame("0xd", "0x38ed1739")]))
        assert rule_flash_oracle_score(tr3) == 0.0

    def test_invariant_balance_transfer_drain(self) -> None:
        tr = parse_call_tracer("0x1", _trace_tree([], with_logs=[{
            "address": "0xeee",
            "topics": [TOPIC_TRANSFER, "0x" + "0" * 62 + "aa", "0x" + "0" * 62 + "bb"],
            "data": hex(40 * 10**18), "logIndex": 0}]),
            tx_from="0xaa", tx_to="0xbb")
        score = invariant_balance_score(tr, {"0xaa": 10**20}, {"0xaa": 10**20 - 40 * 10**18})
        assert score == 1.0  # drain 40 ETH > Lmin (33 ETH)

    def test_invariant_balance_small_transfer_ok(self) -> None:
        tr = parse_call_tracer("0x1", _trace_tree([], with_logs=[{
            "address": "0xeee",
            "topics": [TOPIC_TRANSFER, "0x" + "0" * 62 + "aa", "0x" + "0" * 62 + "bb"],
            "data": hex(10**18), "logIndex": 0}]),
            tx_from="0xaa", tx_to="0xbb")
        assert invariant_balance_score(tr, {}, {}) == 0.0  # 1 ETH < Lmin

    def test_invariant_balance_native_eth_drain(self) -> None:
        tr = parse_call_tracer("0x1", _trace_tree([], with_logs=[]),
                               tx_from="0xaa", tx_to="0xbb")
        # Execution trace analysis and verification
        score = invariant_balance_score(tr, {"0xaa": 10**20}, {"0xaa": 10**20 - 40 * 10**18})
        assert score == 1.0

    def test_static_smartaxe(self) -> None:
        tr = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0xf2fde38b")]))
        assert static_smartaxe_score(tr) == 1.0  # transferOwnership
        tr2 = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0x441a3e70",
                                                           value=hex(50 * 10**18))]))
        assert static_smartaxe_score(tr2) == 0.5  # Verified execution property
        tr3 = parse_call_tracer("0x1", _trace_tree([
            _frame("0xdeadbeef00000000000000000000000000000001", "0x12345678")]))
        assert static_smartaxe_score(tr3) == 0.25  # Verified execution property
        tr4 = parse_call_tracer("0x1", _trace_tree([
            _frame("0x7a250d5630b4cf539739df2c5dacb4c659f2488d", "0x38ed1739")]))
        assert static_smartaxe_score(tr4) == 0.0  # Verified execution property

    def test_all_scorers_work_from_cache_row(self) -> None:
        entry = {"tx_hash": "0x1", "block": 15_000_000, "protocol": "P",
                 "label": "attack"}
        tr = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0x5cffe9de"),
                                                   _frame("0xd", "0x38ed1739")]))
        row = build_benign_row(entry, tr, {}, {}, True, 100, None)
        # Execution trace analysis and verification
        assert BASELINE_SCORERS["rule_flash_oracle"](row) == 1.0
        assert BASELINE_SCORERS["static_smartaxe"](row) in (0.0, 0.25, 0.5, 1.0)


# ---------------------------------------------------------------------------
# Crawler crawl_one (RPC mock)
# ---------------------------------------------------------------------------
class TestCrawler(unittest.TestCase):
    def _fake_debug_trace(self) -> dict:
        return {"from": "0xaaaa", "to": "0xbbbb", "type": "CALL",
                "value": "0x0", "input": "0x", "gas": "0xffff",
                "calls": [{"from": "0xaaaa", "to": "0xc", "type": "CALL",
                           "value": "0x0", "input": "0x5cffe9de" + "0" * 120,
                           "gas": "0xffff", "calls": []}]}

    def _fake_receipt(self) -> dict:
        return {"status": "0x1", "gasUsed": "0x5208", "logs": [],
                "contractAddress": None}

    def _crawler_with_client(self, d: str, client: mock.Mock) -> Crawler:
        crawler = Crawler("http://fake", cache_path=Path(d) / "c.jsonl",
                          progress_path=Path(d) / "p.csv", workers=1)
        patcher = mock.patch.object(crawler, "_client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        return crawler

    def test_crawl_one_success(self) -> None:
        with tempfile.TemporaryDirectory(prefix="e1_test_") as d:
            client = mock.Mock()
            client.call.side_effect = [
                self._fake_debug_trace(),                      # debug_trace
                _fake_multicall_result([(True, 10)] * 3),      # eth_call pre
                _fake_multicall_result([(True, 5)] * 3),       # eth_call post
            ]
            client.eth_get_receipt.return_value = self._fake_receipt()
            crawler = self._crawler_with_client(d, client)
            entry = {"tx_hash": "0x1", "block": 16_000_000, "protocol": "P",
                     "id": "i", "attack_type": "oracle", "gt_factors": ["f_orc"]}
            row = crawler.crawl_one(entry)
            assert row["tx_hash"] == "0x1"
            assert row["status"] is True
            assert row["source"] == "callTracer"
            assert row["error"] is None
            assert row["label"] == "attack"
            assert any(c["selector"] == "0x5cffe9de"
                       for c in row["trace"]["flat_calls"])
            assert row["pre_balances"] == {"0xaaaa": 10, "0xbbbb": 10, "0xc": 10}
            assert row["post_balances"] == {"0xaaaa": 5, "0xbbbb": 5, "0xc": 5}

    def test_crawl_one_fallback_tx_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="e1_test_") as d:
            client = mock.Mock()
            from core.rpc import RpcError  # Verified execution property
            client.call.side_effect = RpcError("debug_traceTransaction: unsupported")
            client.eth_get_transaction.return_value = {
                "from": "0xaa", "to": "0xbb", "input": "0x",
                "value": "0x0", "gas": "0xffff", "blockNumber": "0xf4240",
                "hash": "0x1"}
            client.eth_get_receipt.return_value = self._fake_receipt()
            client.eth_get_balance.return_value = 42
            crawler = self._crawler_with_client(d, client)
            entry = {"tx_hash": "0x1", "block": None, "label": "attack"}
            row = crawler.crawl_one(entry)
            assert row["source"] == "tx+receipt"
            assert row["status"] is True
            assert row["error"] is None
            assert row["block"] == 1_000_000  # Verified execution property
            # block < Multicall3 deploy → fallback eth_getBalance per-account
            assert row["pre_balances"] and row["post_balances"]

    def test_crawl_one_tx_not_found_records_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="e1_test_") as d:
            client = mock.Mock()
            from core.rpc import RpcError  # Verified execution property
            client.call.side_effect = RpcError("debug fail")

            client.eth_get_transaction.return_value = None
            crawler = self._crawler_with_client(d, client)
            row = crawler.crawl_one({"tx_hash": "0x1", "label": "attack"})
            assert row["error"]
            assert "not found" in row["error"].lower()

    def test_resume_skips_cached_ok(self) -> None:
        with tempfile.TemporaryDirectory(prefix="e1_test_") as d:
            cp = Path(d) / "c.jsonl"
            cp.write_text(json.dumps({"tx_hash": "0x1", "label": "attack",
                                      "error": None}) + "\n",
                          encoding="utf-8")
            crawler = Crawler("http://fake", cache_path=cp,
                              progress_path=Path(d) / "p.csv", workers=1)
            done = crawler._done_hashes()
            assert done == {"0x1"}
            # Execution trace analysis and verification
            with open(cp, "a", encoding="utf-8") as f:
                f.write(json.dumps({"tx_hash": "0x2", "label": "attack",
                                    "error": "rpc down"}) + "\n")
            assert crawler._done_hashes() == {"0x1"}


# ---------------------------------------------------------------------------
# Corpus + benign collector
# ---------------------------------------------------------------------------
class TestCorpusAndBenign(unittest.TestCase):
    def test_attack_rows_from_corpus(self) -> None:
        from eval.e1_common import attack_rows_from_corpus
        d = tempfile.mkdtemp(prefix="e1_test_")
        p = Path(d) / "incidents.jsonl"
        p.write_text(json.dumps({"id": "a1", "chain": "ethereum",
                                 "verified": "onchain", "attack_type": "oracle",
                                 "tx_hashes": ["0xaaa", "0xbbb"], "block": 1,
                                 "gt_factors": ["f_orc"], "protocol": "P"}) + "\n"
                     + json.dumps({"id": "a2", "chain": "arbitrum",
                                   "verified": "onchain", "attack_type": "flash-loan",
                                   "tx_hashes": ["0xccc"]}) + "\n"
                     + json.dumps({"id": "a3", "chain": "ethereum",
                                   "verified": "pending",
                                   "tx_hashes": ["0xddd"]}) + "\n",
                     encoding="utf-8")
        rows = attack_rows_from_corpus(p)
        assert len(rows) == 1  # Verified execution property
        assert rows[0]["tx_hash"] == "0xaaa"  # Verified execution property

    def test_sample_blocks_deterministic_in_range(self) -> None:
        b1 = select_sample_blocks(seed=42)
        b2 = select_sample_blocks(seed=42)
        b3 = select_sample_blocks(seed=7)
        assert b1 == b2
        assert b1 != b3
        assert len(b1) == 36
        # Execution trace analysis and verification
        assert 10_500_000 < b1[0] < 13_000_000
        assert b1[-1] > 23_000_000
        assert all(b1[i] < b1[i + 1] for i in range(len(b1) - 1))  # Verified execution property

    def test_entries_for_block_filters(self) -> None:
        client = mock.Mock()
        # Execution trace analysis and verification
        txs = []
        for i in range(10):
            if i % 2 == 0:
                txs.append({"hash": f"0x{i:02x}", "to": "0xbb",
                            "input": "0x5cffe9de" + "0" * 120})
            else:
                txs.append({"hash": f"0x{i:02x}", "to": "0xbb",
                            "input": "0x"})
        # Execution trace analysis and verification
        txs[6] = {"hash": "0x06", "to": None, "input": "0x"}
        client.call.return_value = {"transactions": txs}
        client.eth_get_code.return_value = "0x" + "00" * (50 * 1024)  # 50KB
        coll = BenignCollector(client, corpus_hashes=set(), attack_hashes={"0x02"},
                               seed=42)
        entries = coll.entries_for_block(16_000_000, limit=5)
        # Execution trace analysis and verification
        got = {e["tx_hash"] for e in entries}
        assert got == {"0x00", "0x04", "0x08"}
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        assert all(e["label"] == "benign" for e in entries)

    def test_relabel_from_trace_marks_hard(self) -> None:
        from eval.e1_benign import _relabel_benign_row
        from core.trace import parse_call_tracer
        # Execution trace analysis and verification
        entry = {"tx_hash": "0x1", "block": 16_000_000, "label": "benign"}
        tr = parse_call_tracer("0x1", _trace_tree([_frame("0xc", "0x5cffe9de"),
                                                   _frame("0xd", "0x38ed1739")]))
        row = _relabel_benign_row(entry, tr, {}, {}, True, 100, None)
        assert row["label"] == "hard"
        # Execution trace analysis and verification
        row2 = _relabel_benign_row(entry, tr, {}, {}, None, None, "rpc down")
        assert row2["label"] == "benign" and row2["error"]

    def test_select_sample_blocks_used_by_entries_flow(self) -> None:
        # Execution trace analysis and verification
        client = mock.Mock()
        client.call.return_value = {"transactions": [
            {"hash": "0xaa", "to": "0xbb", "input": "0x"}]}
        coll = BenignCollector(client, {"0xaa"}, set(), seed=42)
        entries = coll.collect(select_sample_blocks()[:3], txs_per_block=2)
        assert len(entries) == 0  # Verified execution property


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
class TestTraceParsers(unittest.TestCase):
    def test_parse_tx_receipt_ok(self) -> None:
        tx = {"from": "0xaa", "to": "0xbb", "input": "0x12345678",
              "value": "0x0", "blockNumber": "0x10"}
        rec = {"status": "0x1", "gasUsed": "0x5208", "logs": []}
        tr = parse_tx_receipt("0x1", tx, rec)
        assert tr["source"] == "tx+receipt"
        assert tr["status"] is True
        assert tr["block"] == 16
        assert tr["flat_calls"][0]["selector"] == "0x12345678"


if __name__ == "__main__":
    unittest.main()
