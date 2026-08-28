"""
TraFiSec pilot — CaseRunner: chy 1 case (fidelity → mutations)
=======================================================================
Standardized CaseRunner execution engine across test cases:
records consistent outcomes.csv records with full execution telemetry.

Quy trnh (proposal §3):
  0. fidelity — fork state block−1, warm-up prior, replay S, so snh gas mainnet.
  1. mi mutation — fork mi, warm-up prior, apply mutation, replay S → outcome(S−X).
"""
from __future__ import annotations

import csv
import json
from decimal import Decimal
from dataclasses import dataclass, field
from pathlib import Path

from .env import PILOT_DIR
from .fork import ForkRunner
from .mutate import Mutation
from .outcome import ReplayResult
from .replay import Replayer
from .rpc import RpcClient


@dataclass
class CaseConfig:
    """Configuration parameters for a single incident evaluation case."""

    name: str
    tx_hash: str
    tx_block: int
    state_block: int | None = None
    prior_txs: list[str] = field(default_factory=list)  # mid-block idx 0..k−1
    protocol: str = ""
    attack_type: str = ""
    chain: str = "mainnet"
    lmin_usd: int = 100_000
    cache_dir: str | Path | None = None
    offline: bool = False
    victims: list[dict] = field(default_factory=list)
    attacker_address: str | None = None
    profit_holders: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.state_block is None:
            self.state_block = self.tx_block - 1


CSV_HEADER = "case,mutation,outcome,loss_S,loss_Sm,Δloss,note"
CSV_COLUMNS = CSV_HEADER.split(",")


class CaseRunner:
    """Execute single incident pilot: benchmark fidelity and candidate mutations, writing outcomes.csv."""

    def __init__(self, config: CaseConfig, rpc: str, out_dir: str | Path | None = None,
                 cache_dir: str | Path | None = None, offline: bool = False):
        self.config = config
        self.rpc = rpc
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.offline = offline
        self.archive = RpcClient(rpc, cache_dir=self.cache_dir, offline=offline)
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        self.out_dir = Path(out_dir) if out_dir is not None else (PILOT_DIR / f"case_{config.name}")
        self.outcomes_path = self.out_dir / "outcomes.csv"
        self.pre_snapshot: dict | None = None
        self.baseline_loss_eth: Decimal | None = None
        self.pre_attacker_eth: Decimal | None = None
        self.pre_profit_snapshot: dict | None = None

    def _snapshot(self, client: RpcClient, block: str) -> dict:
        """Read configured victim balances while the relevant endpoint lives."""
        out = {"block": block, "balances": {}}
        for victim in self.config.victims:
            label, address = victim["label"], victim["address"]
            assets = {}
            for symbol in victim.get("assets", ["ETH"]):
                if symbol == "ETH":
                    value = Decimal(client.eth_get_balance(address, block)) / Decimal(10**18)
                elif symbol == "WBTC":
                    data = "0x70a08231" + address[2:].lower().rjust(64, "0")
                    raw = client.call("eth_call", [{"to": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
                                                     "data": data}, block])
                    value = Decimal(int(raw, 16)) / Decimal(10**8)
                else:
                    raise ValueError(f"unsupported victim asset: {symbol}")
                assets[symbol] = str(value)
            out["balances"][label] = {"address": address, "assets": assets}
        return out

    @staticmethod
    def _loss_eth(pre: dict, post: dict) -> Decimal:
        total = Decimal(0)
        for label, before in pre.get("balances", {}).items():
            after = post.get("balances", {}).get(label, {}).get("assets", {})
            total += Decimal(before.get("assets", {}).get("ETH", "0")) - Decimal(after.get("ETH", "0"))
        return total

    @staticmethod
    def _balance_eth(client: RpcClient, address: str, block: str) -> Decimal:
        return Decimal(client.eth_get_balance(address, block)) / Decimal(10**18)

    def _snapshot_profit_holders(self, client: RpcClient, block: str) -> dict:
        out = {"block": block, "holders": {}}
        token_addresses = {
            "WETH": ("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 18),
            "WBTC": ("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", 8),
        }
        for holder in self.config.profit_holders:
            label, address = holder["label"], holder["address"]
            assets = {}
            for symbol in holder.get("assets", ["ETH"]):
                if symbol == "ETH":
                    value = self._balance_eth(client, address, block)
                else:
                    token, decimals = token_addresses[symbol]
                    data = "0x70a08231" + address[2:].lower().rjust(64, "0")
                    raw = client.call("eth_call", [{"to": token, "data": data}, block])
                    value = Decimal(int(raw, 16)) / Decimal(10**decimals)
                assets[symbol] = str(value)
            out["holders"][label] = {"address": address, "assets": assets}
        return out

    @staticmethod
    def _profit_delta(pre: dict, post: dict) -> dict:
        result = {}
        totals = {"ETH": Decimal(0), "WETH": Decimal(0), "WBTC": Decimal(0)}
        for label, before in pre.get("holders", {}).items():
            after = post.get("holders", {}).get(label, {}).get("assets", {})
            changes = {}
            for symbol, value in before.get("assets", {}).items():
                delta = Decimal(after.get(symbol, "0")) - Decimal(value)
                changes[symbol] = str(delta)
                totals[symbol] += delta
            result[label] = {"address": before["address"], "delta": changes}
        result["totals"] = {k: str(v) for k, v in totals.items() if v != 0}
        return result

    def _attach_profit(self, result: ReplayResult, client: RpcClient, block: str) -> None:
        if not self.config.profit_holders or self.pre_profit_snapshot is None:
            return
        post = self._snapshot_profit_holders(client, block)
        details = self._profit_delta(self.pre_profit_snapshot, post)
        result.details["attacker_profit_by_holder"] = details
        totals = details.get("totals", {})
        result.note += " | separate profit delta " + json.dumps(totals, sort_keys=True)

    def _attach_attacker_profit(self, result: ReplayResult, client: RpcClient,
                                block: str) -> None:
        if not self.config.attacker_address or self.pre_attacker_eth is None:
            return
        post = self._balance_eth(client, self.config.attacker_address, block)
        profit = post - self.pre_attacker_eth
        result.details["attacker_profit_eth_native"] = str(profit)
        result.note += f" | attacker native ETH Δ={profit}"

    def _attach_loss(self, result: ReplayResult, *, post: dict,
                     baseline_loss: Decimal | None = None) -> None:
        if self.pre_snapshot is None:
            return
        base_loss = self._loss_eth(self.pre_snapshot, post) if baseline_loss is None else baseline_loss
        mutated_loss = self._loss_eth(self.pre_snapshot, post)
        result.details.update({
            "loss_S": str(base_loss),
            "loss_Sm": str(mutated_loss),
            "dloss": str(mutated_loss - base_loss),
            "loss_unit": "ETH_native_only",
        })
        result.note += " | native ETH victim loss only; WBTC not converted"

    @property
    def fork_cache_path(self) -> Path:
        """Foundry's persistent remote code/storage cache for this fork."""
        return (Path.home() / ".foundry" / "cache" / "rpc" /
                self.config.chain / str(self.config.state_block) / "storage.json")

    def ensure_fork_cache(self) -> None:
        """Require Foundry's complete fork cache only in offline mode."""
        if self.offline and not self.fork_cache_path.exists():
            raise RuntimeError(
                f"offline fork cache thiu: {self.fork_cache_path}; "
                "chy mt ln online  Anvil ti  code/storage"
            )

    # ---- fidelity ----
    def run_fidelity(self, verify_gas: bool = True) -> ReplayResult:
        self.ensure_fork_cache()
        mainnet_gas = self.archive.eth_get_receipt(self.config.tx_hash) and self.mainnet_gas()
        if self.config.victims:
            self.pre_snapshot = self._snapshot(self.archive, hex(self.config.state_block))
        if self.config.attacker_address:
            self.pre_attacker_eth = self._balance_eth(
                self.archive, self.config.attacker_address, hex(self.config.state_block))
        if self.config.profit_holders:
            self.pre_profit_snapshot = self._snapshot_profit_holders(
                self.archive, hex(self.config.state_block))
        with ForkRunner(self.rpc, self.config.state_block,
                        offline=self.offline,
                        chain_id=1 if self.config.chain == "mainnet" else None) as fork:
            rp = Replayer(fork, self.archive)
            rp.warmup(self.config.prior_txs)
            result = rp.replay(self.config.tx_hash, mainnet_gas)
            if self.config.victims:
                post = self._snapshot(RpcClient(fork.url, timeout=30), "latest")
                self.baseline_loss_eth = self._loss_eth(self.pre_snapshot, post)
                result.details.update({
                    "loss_S": str(self.baseline_loss_eth),
                    "loss_unit": "ETH_native_only",
                })
                result.note += " | native ETH victim loss only; WBTC not converted"
            self._attach_attacker_profit(result, RpcClient(fork.url, timeout=30), "latest")
            self._attach_profit(result, RpcClient(fork.url, timeout=30), "latest")
        self.record("fidelity", result)
        return result

    def mainnet_gas(self) -> int | None:
        rec = self.archive.eth_get_receipt(self.config.tx_hash)
        return int(rec.get("gasUsed", "0x0"), 16) if rec else None

    # ---- mutations ----
    def run_mutations(self, mutations: list[Mutation]) -> dict[str, ReplayResult]:
        self.ensure_fork_cache()
        out = {}
        for m in mutations:
            with ForkRunner(self.rpc, self.config.state_block,
                            offline=self.offline,
                            chain_id=1 if self.config.chain == "mainnet" else None) as fork:
                rp = Replayer(fork, self.archive)
                rp.warmup(self.config.prior_txs)
                m.apply_to_replayer(rp)
                m.apply(fork)
                result = rp.replay(self.config.tx_hash, None)
                if self.config.victims:
                    post = self._snapshot(RpcClient(fork.url, timeout=30), "latest")
                    mutated_loss = self._loss_eth(self.pre_snapshot, post)
                    base_loss = self.baseline_loss_eth if self.baseline_loss_eth is not None else mutated_loss
                    result.details.update({
                        "loss_S": str(base_loss),
                        "loss_Sm": str(mutated_loss),
                        "dloss": str(mutated_loss - base_loss),
                        "loss_unit": "ETH_native_only",
                    })
                    result.note += " | native ETH victim loss only; WBTC not converted"
                self._attach_attacker_profit(result, RpcClient(fork.url, timeout=30), "latest")
                self._attach_profit(result, RpcClient(fork.url, timeout=30), "latest")
            self.record(m.name, result)
            out[m.name] = result
        return out

    # ---- ghi outcomes.csv ----
    def record(self, mutation: str, r: ReplayResult) -> None:
        """Upsert 1 dng outcomes.csv (key = (case, mutation)) —  7 ct.

        Fixed CSV column alignment.
        Updates matching (case, mutation) row to prevent duplicate entries.
        Updates existing row while preserving other mutation records.

        NOTE: `case` ct = protocol/case-mut ghp (gi prefix "Cream Finance (Aug 2021)/f_fl"
        Maintains backwards-compatible outcomes schema.
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        case_mut = f"{self.config.protocol}/{mutation}"
        row = [case_mut, mutation, r.outcome.value,
               r.details.get("loss_S", ""), r.details.get("loss_Sm", ""),
               r.details.get("dloss", ""), r.note]

        rows: list[list[str]] = []
        if self.outcomes_path.exists():
            with self.outcomes_path.open(newline="", encoding="utf-8") as f:
                rows = [r2 for r2 in csv.reader(f) if r2]  # Verified execution property
        header = rows[0] if rows else CSV_COLUMNS
        if rows and rows[0] != CSV_COLUMNS:
            rows = [CSV_COLUMNS] + rows  # Verified execution property
            body = rows[1:]
        else:
            body = rows[1:] if rows else []

        for i, r2 in enumerate(body):
            if len(r2) >= 2 and r2[1] == mutation:
                body[i] = row
                break
        else:
            body.append(row)

        with self.outcomes_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(body)

    def load_outcomes(self) -> list[dict]:
        """c li outcomes.csv (cho report/check)."""
        if not self.outcomes_path.exists():
            return []
        with self.outcomes_path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))


def summarize(results: dict[str, ReplayResult]) -> str:
    """Summarize execution results: fidelity, per-mutation verdicts, and causal attribution."""
    lines = []
    fid = results.get("fidelity")
    if fid:
        lines.append(f"fidelity {fid.outcome.value} {fid.note}")
    for name, r in results.items():
        if name == "fidelity":
            continue
        lines.append(f"{name} {r.outcome.value} {r.note}")
    return "\n".join(lines)
