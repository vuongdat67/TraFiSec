// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice TraceGuard-DeFi pilot — f_orc mutation stub.
/// Pinned oracle getter: returns the SNAPSHOT price (pre-attack, block−1) regardless
/// of attacker-influenced state. Replaces the live oracle contract via anvil_setCode.
///
/// Two getter families used by Compound-style oracles:
///   - latestRoundData() (Chainlink)      → selector 0xfeaf968c
///   - price / getUnderlyingPrice(address) → selector 0x... (per protocol)
///
/// The compiled runtime bytecode (with a concrete `pinnedPrice` burned in via
/// constructor arg) is what we anvil_setCode onto the oracle address.
contract OracleStub {
    int256 public immutable pinnedPrice; // raw price units, scaled like the real oracle

    constructor(int256 price) {
        pinnedPrice = price;
    }

    // Chainlink-style: latestRoundData()
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answerValue, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (1, pinnedPrice, 0, block.timestamp, 1);
    }

    // Aggregator-style: answer() — fallback read used by many DeFi oracles
    function answer() external view returns (int256) {
        return pinnedPrice;
    }

    // Generic fallback: any other getter hits this — but callers encode their own
    // selector, so a plain fallback won't catch typed getters. Per-case we add the
    // exact selector below (uncomment as needed).
    // fallback() external { revert("OracleStub: unhandled selector"); }
}
