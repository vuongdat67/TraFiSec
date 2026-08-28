"""Deterministic on-chain-only prices from the preregistered manifest."""

from __future__ import annotations

import json
import math
from pathlib import Path

from core.rpc import RpcClient


OBSERVE_SELECTOR = "883bdbfd"


def load_price_manifest(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("status") != "preregistered" or payload.get("policy") != "on-chain-only-two-tier":
        raise ValueError("price manifest is not the preregistered on-chain policy")
    return payload


def _word(value: int) -> str:
    return format(value, "064x")


def _signed_word(word: str) -> int:
    value = int(word, 16)
    return value - (1 << 256) if value >= (1 << 255) else value


def _observe_twap_tick(archive: RpcClient, pool: str, block: int, window: int) -> int:
    # observe(uint32[2]) ABI: dynamic-array offset, length, secondsAgos.
    data = "0x" + OBSERVE_SELECTOR + _word(32) + _word(2) + _word(window) + _word(0)
    result = archive.call("eth_call", [{"to": pool, "data": data}, hex(block)])
    raw = str(result or "").removeprefix("0x")
    if len(raw) < 128:
        raise ValueError(f"Uniswap V3 observe returned short data for {pool}")
    first_offset = int(raw[0:64], 16) * 2
    if first_offset + 64 > len(raw):
        raise ValueError("invalid observe int56 array offset")
    length = int(raw[first_offset:first_offset + 64], 16)
    if length != 2:
        raise ValueError(f"expected two tick cumulatives, got {length}")
    a = _signed_word(raw[first_offset + 64:first_offset + 128])
    b = _signed_word(raw[first_offset + 128:first_offset + 192])
    # Solidity integer division floors for negative values; Python // matches it.
    return (b - a) // window


def _tick_price(tick: int, token0_decimals: int, token1_decimals: int,
                target_is_token0: bool) -> float:
    raw_token1_per_token0 = 1.0001 ** tick
    human_token1_per_token0 = raw_token1_per_token0 * 10 ** (token0_decimals - token1_decimals)
    return human_token1_per_token0 if target_is_token0 else 1.0 / human_token1_per_token0


def resolve_reference_prices(archive: RpcClient, manifest: dict, block: int) -> dict[str, dict[str, float | int]]:
    """Resolve reference token USD prices at ``block`` (normally target-1)."""
    assets = manifest["reference_assets"]
    prices: dict[str, dict[str, float | int]] = {}
    for symbol, spec in assets.items():
        if spec["pricing"] == "fixed_usd_1":
            prices[spec["address"].lower()] = {
                "usd_per_token": 1.0, "decimals": int(spec["decimals"]),
            }
    usdc = assets["USDC"]
    for symbol in ("WETH", "WBTC"):
        spec = assets[symbol]
        tick = _observe_twap_tick(archive, spec["reference_pool"], block,
                                  int(spec["twap_window_seconds"]))
        # Both preregistered pools are USDC/token, with USDC token0.
        token_price = _tick_price(tick, int(usdc["decimals"]), int(spec["decimals"]), False)
        prices[spec["address"].lower()] = {
            "usd_per_token": token_price, "decimals": int(spec["decimals"]),
        }
    return prices


def harm_spec_from_manifest(archive: RpcClient, manifest: dict, block: int,
                            attacker: str | None = None) -> dict:
    prices = resolve_reference_prices(archive, manifest, block)
    return {
        "oracle": "attacker_value_delta",
        "attacker": attacker or "",
        "token_prices": prices,
        "native_price_usd": prices[manifest["reference_assets"]["WETH"]["address"].lower()]["usd_per_token"],
        "lmin_usd": float(manifest["lmin_usd"]),
        "valuation_source": "eval/e4_price_manifest.json:onchain_uniswap_v3_twap",
    }
