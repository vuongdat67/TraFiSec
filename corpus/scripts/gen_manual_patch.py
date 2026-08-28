# -*- coding: utf-8 -*-
"""Generate corpus/raw/manual_label_patch.jsonl for the 28 attack_type=='other' incidents."""
import sys
import json
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

patches = [
    {
        "id": "defihacklabs-unistreetlaunchpad-2026-08-06",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "LaunchpadFactoryAuto.launch() forwards attacker-supplied init/modify calldata VERBATIM into Uniswap V4 PositionManager.multicall() as msg.sender with no validation; attacker injected setApprovalForAll(self,true) to gain ApprovalForAll over all custodied LP NFTs, then burned each launch LP position and swept USDC+WETH to itself. Unvalidated calldata forwarding / arbitrary-call from a custody contract.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-08/UnistreetLaunchpad_exp.sol"],
    },
    {
        "id": "defihacklabs-exchangeissuance-index-coop-2026-07-30",
        "attack_type": "accounting",
        "gt_factors": ["f_orc"],
        "evidence": "ExchangeIssuance.issueSetForExactToken trusts arbitrary SetToken state with no lock between quote read and settlement (TOCTOU); attacker inflated positionMultiplier ~93.66x mid-flow via a malicious pre-issue hook/NAV valuer, so BasicIssuanceModule.issue pulled ExchangeIssuance's own component inventory into the attacker SetToken, then redeemed it for profit. NAV/valuation manipulation, no compromised key/signer.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-07/ExchangeIssuance_exp.sol"],
    },
    {
        "id": "defihacklabs-summerfi-2026-07-06",
        "attack_type": "accounting",
        "gt_factors": ["f_orc"],
        "evidence": "FleetCommander NAV is the live sum of each Ark's totalAssets() with no manipulation guard; Silo vgUSDC counts depegged Stream USD (xUSD) collateral at par, so the attacker minted vgUSDC far below its counted value, donated cheap vgUSDC into an empty ark to inflate NAV, then redeemed inflated shares to drain other LPs (~$6M). rekt.news lists it as NAV/accounting bug.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-07/SummerFi_exp.sol", "https://rekt.news/"],
    },
    {
        "id": "defihacklabs-novabox-2026-06-09",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "NovaBox blocks contract ETH deposits via extcodesize(msg.sender)==0 and adds new dual ETH/NOVA depositors to the dividend list without initializing their dividend checkpoints; attacker deposited through a constructor helper, joined the list with zero checkpoints, then immediately withdrew ETH and received stale historical ETH dividends. Dividend/accounting state bug.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-06/NovaBox_exp.sol"],
    },
    {
        "id": "defihacklabs-squidroutermodule-2026-05-25",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "The public Axelar express path (expressExecuteWithToken) accepts a caller-supplied payload and uses the delegate encoded in that payload for Safe permission checks; attacker supplied a payload naming a delegate with wildcard permissions on the victim Safe, then approved Permit2 and swapped the Safe's WBTC/wTAO/WETH into u. Missing caller/access check (same root cause as rekt New Market Trading, labeled governance/access+f_auth).",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-05/SquidRouterModule_exp.sol", "https://rekt.news/newmarkettrading-rekt"],
    },
    {
        "id": "defihacklabs-wusdfi-2026-05-25",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "WUSD.wrap() pays a GLOVE reward via _englove() with eligibility based only on msg.sender's current GLOVE balance and wrap size; no per-address claim ledger, no cooldown, no identity binding, so a fresh zero-GLOVE Sybil identity always qualifies and the attacker minted GLOVE rewards repeatedly across many addresses.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-05/WUSD_exp.sol"],
    },
    {
        "id": "defihacklabs-muredistribution-2026-05-21",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "MureDistribution.distribute() accepts a caller-supplied signer and signature; the attacker deployed a fake ERC1271 signer (MureSignerSource) whose isValidSignature always returns the magic value, forged a distribution from the victim QUEST holder, drained ~4.8M QUEST and sold it for ~5.45 ETH. Signature verification bypass.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-05/MureDistribution_exp.sol"],
    },
    {
        "id": "defihacklabs-rwavault-2026-04-28",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "RWAVault overrides ERC4626 withdraw without the allowance spend required when msg.sender != owner; the attacker withdrew eight depositor balances to an attacker-controlled receiver without any allowance/authorization check.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-04/RWAVault_exp.sol"],
    },
    {
        "id": "defihacklabs-unverified-a152-2026-04-27",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "Attacker routed through an already-authorized spending contract and its helper to reuse victim AllowanceTarget approvals, draining approved funds and consolidating them into USDT. Stale/abused approval on the AllowanceTarget.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-04/unverified_a152_exp.sol"],
    },
    {
        "id": "defihacklabs-giddyvaultv3-2026-04-23",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "GiddyVaultV3 validates EIP-712 compound authorizations using only keccak256(SwapInfo.data); the attacker reused valid signed data while replacing fromToken, toToken, amount and aggregator, so each compound call made a strategy approve the attacker helper uint256.max, which then drained the strategy-held YieldBasis gauge tokens. Incomplete signature coverage.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-04/giddyvaultv3_compound_auth_exp.sol"],
    },
    {
        "id": "defihacklabs-juiceboxrevloans-2026-04-20",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "REVLoans registers the caller-supplied loan source the first time borrowFrom() uses it with no validation; a fake terminal/token inflated totalBorrowedFrom without paying real assets, letting the attacker borrow native ETH from JBMultiTerminal with tiny revnet-token collateral and receive the drained treasury ETH. Unvalidated caller-supplied source.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-04/JuiceboxREVLoans_exp.sol"],
    },
    {
        "id": "defihacklabs-xlootstaking-2026-04-15",
        "attack_type": "accounting",
        "gt_factors": ["f_fl"],
        "evidence": "Staking.redeem(uint256[]) calculates all xLOOT rewards before advancing xLoot.nextRedeem[id] and only checks ownerOf(id), so the same owned NFT can be supplied many times in one redeem call; a 2.1 ETH Balancer flash loan triggered a new epoch via receive(), and seven owned xLOOT IDs repeated 155x each claimed the epoch reward 1,085 times (~6.2 ETH). Reward accounting bug + flash-loan epoch trigger.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-04/XLootStaking_exp.sol"],
    },
    {
        "id": "defihacklabs-mimspell3-2025-10-04",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "Attacker borrowed MIM from six Abracadabra Cauldrons via cook(REPAY,NO_OP) where the cauldrons' borrowLimit exceeded available MIM (insolvency/bad debt), withdrew from BentoBox and swapped MIM to 3crv/USDT/WETH for ~1.7M profit. Bypassed/absent insolvency check allowed borrowing without real collateral.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-10/MIMSpell3_exp.sol"],
    },
    {
        "id": "defihacklabs-whereismydragontreasure-2025-07-25",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "WhereIsMyDragonTreasure pays a fixed _singleReward for each legendary card while the effective cost to mint/acquire a redeemable card through the lower-cost EthItem recipe path was below that fixed redemption price; attacker minted a legendary card wrapper cheaply and redeemed it for the fixed ETH reward.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/WhereIsMyDragonTreasure_exp.sol"],
    },
    {
        "id": "defihacklabs-swappstaking-2025-07-24",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "Exploit = staking.deposit(address(cUsdc), staking_cusdc_balance, 0x0) then emergencyWithdraw(address(cUsdc)): the attacker deposited the staking contract's own cUsdc balance into itself and withdrew, capturing reward/share accounting value. DeFiHackLabs root-cause label: Incorrect reward calculation. No swap involved (overrides prior auto-label f_swap).",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/SWAPPStaking_exp.sol"],
    },
    {
        "id": "defihacklabs-emptysetreserve-2025-07-24",
        "attack_type": "flash-loan",
        "gt_factors": ["f_fl", "f_orc"],
        "evidence": "Attacker used Uniswap v4 flash accounting to source USDC/DSU/ESS, bought COMP from Empty Set Reserve through a stale/favorable fixed maker order (swap()), then sold the COMP through Uniswap liquidity for ETH profit. Root cause: reserve exposed a stale fixed order letting a public caller buy COMP inventory below market and extract the spread.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/EmptySetReserve_exp.sol"],
    },
    {
        "id": "defihacklabs-silofinance-2025-06-25",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "The public Silo leverage helper trusts user-supplied swap targets and Silo-like targets without constraining them to the selected market; attacker used a contract pretending to be flash lender/collateral silo/collateral token, and during the fake flash-loan callback routed a swap callback into the real Silo.borrow against any borrower that had granted the helper debt-receive approval. Arbitrary-call/authorization flaw.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/SiloFinance_exp.sol"],
    },
    {
        "id": "defihacklabs-paraswapdaiapproval-2025-06-25",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth", "f_fl"],
        "evidence": "Attacker flash-borrowed 1000 wei WETH from Balancer, used it as fromToken for a ParaSwap simpleSwap with arbitrary exchangeData that repaid the WETH while moving DAI from an account that had authorized ParaSwap; the DAI.move executed as ParaSwap, so the stale approval let an unprivileged caller drain the approved DAI. Stale approval + arbitrary callee.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/ParaSwapDAIApproval_exp.sol"],
    },
    {
        "id": "defihacklabs-bankrollstackplus-2025-06-18",
        "attack_type": "accounting",
        "gt_factors": ["f_fl", "f_auth"],
        "evidence": "Attacker used flash-sourced LINK to buy Bankroll Stack Plus shares, then called public buyFor(address,uint256) against accounts that had pre-approved the Bankroll contract; forced buys injected more LINK and fee accounting into the pool before the attacker sold and withdrew. buyFor lets any caller spend a third party's allowance and mutate pool accounting (incorrect dividends calc).",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/BankrollStackPlus_exp.sol"],
    },
    {
        "id": "defihacklabs-usualmoney-2025-05-27",
        "attack_type": "accounting",
        "gt_factors": ["unknown"],
        "evidence": "USD0++ / USD0 were swappable internally at a fixed 1:1 rate through the USDS++ Sync Vault even though they traded at different prices externally; attacker exploited the capped unwrap path to convert at par internally and realize the price difference on the open market (~$42.8K). Quadriga Initiative calls it an arbitrage exploit, not flash-loan based, not oracle manipulation. Overrides prior auto-label f_swap.",
        "sources": ["https://www.quadrigainitiative.com/hackfraudscam/usualmoneyusdssyncvaultpricingarbitrageexploit.php", "https://x.com/BlockSecTeam/status/1927601457815040283"],
    },
    {
        "id": "defihacklabs-tcdp-2025-04-28",
        "attack_type": "token",
        "gt_factors": ["f_auth"],
        "evidence": "tCDP.transferFrom subtracts from _allowed[msg.sender][to] after transferring from the supplied from address instead of checking _allowed[from][msg.sender]; attacker self-approved tCDP, pulled all outstanding tCDP from three unrelated holders, then burned the stolen tCDP to redeem Compound ETH collateral. Broken ERC20 transferFrom allowance check.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/tcdp_exp.sol"],
    },
    {
        "id": "defihacklabs-alkimiya-io-2025-03-28",
        "attack_type": "precision",
        "gt_factors": ["f_fl"],
        "evidence": "Attacker used a Morpho flash loan of WBTC, called SilicaPools.collateralizedMint with shares = uint128 max + 2 to trigger an unsafecast uint128(shares) overflow, minted inflated pool positions, then startPool/endPool/redeemShort to extract WBTC (~95.5K). Integer overflow in uint128 cast.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/Alkimiya_io_exp.sol"],
    },
    {
        "id": "defihacklabs-rnspay-2025-03-06",
        "attack_type": "governance/access",
        "gt_factors": ["f_auth"],
        "evidence": "RnsPay lets the caller provide an arbitrary exchange target and calldata; attacker used a fake ERC20 as both pay and receipt token so RnsPay balance checks passed, then made RnsPay call USDC.transferFrom against a victim that had approved RnsPay. Arbitrary external call abusing victim approval.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/RnsPay_exp.sol"],
    },
    {
        "id": "defihacklabs-mcai-2025-01-28",
        "attack_type": "token",
        "gt_factors": ["f_auth", "f_swap"],
        "evidence": "MCAI tax wallet bypassed transferFrom allowance accounting, pulled MCAI from the MCAI/WETH Uniswap V2 pair, synced the pair at a tiny MCAI reserve, then sold the drained MCAI back through the router for WETH/ETH profit. Token allowance bug + pair reserve manipulation.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/MCAI_exp.sol"],
    },
    {
        "id": "defihacklabs-lauratoken-2025-01-01",
        "attack_type": "token",
        "gt_factors": ["f_swap"],
        "evidence": "Attacker swapped and added liquidity on WETH/LAURA via uniV2Router, then called the LAURA contract removeLiquidityWhenKIncreases, which reduced the LAURA balance of the WETH/LAURA pair enough to steal all the WETH from the pair (~12.34 ETH). Token pair-balance manipulation via a privileged token function.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/LAURAToken_exp.sol"],
    },
    {
        "id": "defihacklabs-veth-2024-11-14",
        "attack_type": "token",
        "gt_factors": ["f_fl", "f_swap", "f_auth"],
        "evidence": "vETH takeLoan lets a valid factory lend virtual vETH; a privileged Factory function was externally callable to invoke takeLoan and add liquidity to Uniswap V2 pairs (vETH-BIF/Cowbo/BOVIN), inflating the pool's constant product so the attacker (funded by a 32,560 WETH Balancer flash loan) withdrew more value than deposited on three pairs (~$450-477K). Flawed lending/mint flow enabling AMM pool manipulation.",
        "sources": ["https://blog.verichains.io/p/veth-incident-with-unknown-mechanism", "https://www.quillaudits.com/blog/hack-analysis/veth-token-450k-exploit-analysis"],
    },
    {
        "id": "defihacklabs-firetoken-2024-10-01",
        "attack_type": "token",
        "gt_factors": ["f_fl", "f_swap"],
        "evidence": "Attacker used an Aave 20 WETH flash loan, looped weth.withdraw + deploying AttackerC2 constructors (to bypass the isContract check in FIRE _transfer L258/L274-279) to swap WETH->FIRE and transfer FIRE to the pair, inflating the pair's FIRE balance then pair.swap to extract WETH (~8.45 ETH). Token _transfer() pair-manipulation flaw.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/FireToken_exp.sol"],
    },
    {
        "id": "defihacklabs-onyxdao-2024-09-26",
        "attack_type": "flash-loan",
        "gt_factors": ["f_fl", "f_orc", "f_auth"],
        "evidence": "Attacker flash-loaned 2000 WETH from Balancer, minted/borrowed across all Onyx oTokens, manipulated the oETH exchange rate (repeated redeemUnderlying + donation loop in AttackerC2), then called NFTLiquidation.liquidateWithSingleRepay (L671-678) with fake oTokenCollateral/oTokenRepay/underlying contracts that the function did not validate, draining VUSD/XCN/DAI/WBTC/USDT (~$3.8M). Fake-market + rate manipulation, flash-loan funded.",
        "sources": ["https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/OnyxDAO_exp.sol"],
    },
]

root = Path(__file__).resolve().parents[2]
out = root / "corpus" / "raw" / "manual_label_patch.jsonl"
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", encoding="utf-8", newline="\n") as f:
    for p in patches:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")
print("wrote", len(patches), "patches to", out)

allowed = {"flash-loan", "oracle", "reentrancy", "governance/access", "accounting", "precision", "bridge", "token", "rug-pull"}
bad = [p["id"] for p in patches if p["attack_type"] not in allowed]
print("bad attack_type:", bad)

allowed_f = {"f_fl", "f_orc", "f_swap", "f_auth", "f_re", "unknown", "f_other"}
badf = [(p["id"], p["gt_factors"]) for p in patches if any(x not in allowed_f for x in p["gt_factors"])]
print("bad gt_factors:", badf)
