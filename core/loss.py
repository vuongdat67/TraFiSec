"""
TraFiSec pilot — loss per-party t transaction trace (migrate loss_calc.py)
==================================================================================
K thut (deep-read TracExp): fund-flow delta per account × asset t LOG events
(Transfer/Deposit/Withdrawal) + value-bearing CALL/CREATE/SELFDESTRUCT.

Refactor OOP (feedback 2026-08-11): `TraceAnalyzer` class thay hm ri
(load_trace/collect_flows/compute_loss) — gi nguyn thut ton  verify.

Usage (gi tng thch CLI):
  python -m core.loss <trace.json> [--price-usd ETH=3000 TOKEN=1.0 ...]
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# ERC20 Transfer(address,address,uint256) topic
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@dataclass
class TraceAnalyzer:
    """Phn tch trace → net flow per (addr, token) + loss per party (USD)."""

    trace: dict
    prices: dict[str, float] = field(default_factory=dict)  # token addr → USD

    @classmethod
    def from_file(cls, path: str | Path, prices: dict[str, float] | None = None) -> "TraceAnalyzer":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f), prices or {})

    def collect_flows(self) -> tuple[dict, dict]:
        """(net[addr,token], native[addr]) — signed delta per account×asset."""
        net: dict[tuple[str, str], float] = defaultdict(float)
        native: dict[str, float] = defaultdict(float)

        # LOG3 Transfer events: topics = [Transfer, from, to], data = amount
        for log in self.trace.get("logs", []):
            topics = log.get("topics", [])
            if len(topics) >= 3 and topics[0].lower() == TOPIC_TRANSFER:
                frm = "0x" + topics[1][-40:].lower()
                to = "0x" + topics[2][-40:].lower()
                amount = int(log.get("data", "0x0"), 16)
                token = log.get("address", "").lower()
                net[(frm, token)] -= amount
                net[(to, token)] += amount

        # value-bearing calls: from → to, value in ETH
        for call in self.trace.get("calls", []):
            value = int(call.get("value", "0x0"), 16)
            if value:
                native[call.get("from", "").lower()] -= value
                native[call.get("to", "").lower()] += value
        return dict(net), dict(native)

    def compute_loss(self) -> tuple[dict[str, float], float]:
        """(per_party ΔV USD, loss) — loss = Σ_p max(0, −ΔV_p)."""
        net, native = self.collect_flows()
        per_party: dict[str, float] = defaultdict(float)
        for (addr, token), delta in net.items():
            per_party[addr] += delta * self.prices.get(token, 0.0)
        for addr, delta in native.items():
            per_party[addr] += delta * self.prices.get("ETH", 0.0)
        loss = sum(max(0.0, -v) for v in per_party.values())
        return dict(per_party), loss


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    trace_path = argv[0]
    prices: dict[str, float] = {}
    for kv in argv[1:]:
        if kv.startswith("--price-usd="):
            kv = kv[len("--price-usd="):]
        if "=" in kv:
            k, _, v = kv.partition("=")
            try:
                prices[k] = float(v)
            except ValueError:
                print(f"loss: invalid price entry: {kv!r}", file=sys.stderr)
                return 1
    analyzer = TraceAnalyzer.from_file(trace_path, prices)
    per_party, loss = analyzer.compute_loss()
    out = {
        "parties": {k: round(v, 2) for k, v in sorted(per_party.items(), key=lambda x: -abs(x[1]))},
        "loss_usd": round(loss, 2),
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
