"""The six fixed engineering pilot identities used by Phase 1.

This is intentionally separate from the preregistered E5 fixed-20 set.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class PilotCase:
    case_id: str
    protocol: str
    chain: str
    attack_type: str
    tx_hash: str
    block: int
    tx_index: int

    @property
    def state_block(self) -> int:
        return self.block - 1

    def as_dict(self) -> dict:
        value = asdict(self)
        value["state_block"] = self.state_block
        return value


PILOT_CASES = (
    PilotCase("case1_bzx_flashloan", "bZx (Feb 2020)", "mainnet", "flash-loan/oracle",
              "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f170a4bc8cd032f768fc5219838", 9484688, 28),
    PilotCase("case2_cream_oracle", "Cream Finance (Aug 2021)", "mainnet", "flash-loan/accounting",
              "0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e", 13125071, 1),
    PilotCase("case3_euler_reentrancy", "Euler Finance (Mar 2023)", "mainnet", "flash-loan/accounting",
              "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d", 16817996, 0),
    PilotCase("case4_radiant_precision", "Radiant Capital (Jan 2024)", "arbitrum", "flash-loan/precision",
              "0x1ce7e9a9e3b6dd3293c9067221ac3260858ce119ec7bca860eac28b2474c7c9b", 166405687, 2),
    PilotCase("case5_wazirx_governance", "WazirX (Jul 2024)", "mainnet", "governance/access",
              "0x48164d3adbab78c2cb9876f6e17f88e321097fcd14cadd57556866e4ef3e185d", 20331565, 0),
    PilotCase("case6_arbitrage", "Honest arbitrage (Jun 2023)", "mainnet", "hard-negative",
              "0xe5732cc1772af6bf6e7f89af0ba957cc3b5403aa3d30bc73f56a07a59987761c", 17447511, 10),
)


def load_pilot_cases() -> tuple[PilotCase, ...]:
    return PILOT_CASES
