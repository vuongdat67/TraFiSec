#!/usr/bin/env python3
"""TraceGuard pilot — tnh loss per-party t transaction trace trn Anvil fork.

K thut (t deep-read TracExp): fund-flow delta per account × asset t
LOG events (Transfer/Deposit/Withdrawal) + value-bearing CALL/CREATE/SELFDESTRUCT.

u vo: 1 file trace JSON t `cast run --debug` hoc `cast tx` + `cast trace`.
Pilot v1: dng `cast run <hash> --debug` → tm LOG3 (Transfer) events + CALL value.
u ra: stdout — JSON {"parties": {...}, "loss_usd": n, "violations": [...]}

Usage:
  python loss_calc.py <trace.json> [--price-usd ETH=3000 TOKEN=1.0 ...]
"""
import json
import sys
import re
from collections import defaultdict

# ERC20 Transfer(address,address,uint256) topic
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

def load_trace(path):
    with open(path) as f:
        return json.load(f)

def collect_flows(trace):
    """Sum net token flows per (address, token) and native ETH flows."""
    net = defaultdict(float)  # (addr, token) -> signed delta (+ in, - out)
    native = defaultdict(float)  # addr -> signed ETH delta

    # LOG3 Transfer events: topics = [Transfer, from, to], data = amount (token)
    for log in trace.get("logs", []):
        topics = log.get("topics", [])
        if len(topics) >= 3 and topics[0].lower() == TOPIC_TRANSFER:
            frm = "0x" + topics[1][-40:].lower()
            to = "0x" + topics[2][-40:].lower()
            amount = int(log.get("data", "0x0"), 16)
            token = log.get("address", "").lower()
            net[(frm, token)] -= amount
            net[(to, token)] += amount

    # value-bearing calls: from=caller, to=callee, value in eth
    for call in trace.get("calls", []):
        value = int(call.get("value", "0x0"), 16)
        if value:
            native[call.get("from", "").lower()] -= value
            native[call.get("to", "").lower()] += value
    return net, native

def compute_loss(net, native, prices):
    """loss = Σ_p max(0, −ΔV_p); ΔV per party = native_eth*price_eth + Σ tokens*token_price"""
    per_party = defaultdict(float)
    for (addr, token), delta in net.items():
        per_party[addr] += delta * prices.get(token, 0.0)  # tokens to USD
    for addr, delta in native.items():
        per_party[addr] += delta * prices.get("ETH", 0.0)
    # loss = total negative value changes (victim perspective)
    loss = sum(max(0.0, -v) for v in per_party.values())
    return per_party, loss

def main():
    trace_path = sys.argv[1]
    prices = {}
    for i in range(2, len(sys.argv)):
        kv = sys.argv[i].split("=")
        if len(kv) == 2:
            prices[kv[0]] = float(kv[1])
    trace = load_trace(trace_path)
    net, native = collect_flows(trace)
    per_party, loss = compute_loss(net, native, prices)
    out = {
        "parties": {k: round(v, 2) for k, v in sorted(per_party.items(), key=lambda x: -abs(x[1]))},
        "loss_usd": round(loss, 2),
    }
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()