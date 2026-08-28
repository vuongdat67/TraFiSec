"""
TraFiSec pilot — Mutations (f_fl / f_orc / f_swap / f_auth)
==================================================================
Object-oriented counterfactual mutations: each mutation class applies state patches via `apply(fork)`.
Base class chun ho interface; case script ch khai bo instance.

Intervention primitives specification:
- f_fl  — suppress flash-loan borrowing at provider address (code→0x, balance→0).
- f_orc: Pin oracle prices using constant return runtime bytecode.
- f_swap— cap amountIn / redirect recipient qua calldata override (Replayer.data_override).
         + SwapMultiHop: generic multi-hop π_swap(T) isolation (proposal §5.3.1).
- f_auth— revoke admin (EIP-1967 slot) / Safe owner-map (xem case5 — GS026 positional
           Signature and authority verification bypassing unconstrained state modification.
         + SignatureRecovery: ecrecover sig blob → signer set → KEY_COMPROMISE verdict.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import time
from typing import NamedTuple

from .fork import ForkRunner
from .replay import Replayer
from .rpc import RpcClient

EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SHAM_ADDRESS = "0x00000000000000000000000000000000feedc0de"
SHAM_SLOT = "0x" + "a5" * 32
SHAM_VALUE = "0x" + "5a" * 32

# Cream case 2 (case2_cream_oracle): selector `start(uint256 flash,uint256 amount,uint256 min)`
START_SELECTOR = "641ccd83"

# ERC20 Transfer topic
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# GnosisSafe execTransaction selector
EXEC_TX_SELECTOR = "0x6a761202"


def start_cap_override(calldata: str, amount: int) -> str | None:
    """Rewrite word2 (amount) of `start(flash,amount,min)` for f_swap slice capping.

    Returns exact 100-byte mutated calldata, or None if selector does not match.
    (khc selector / sai  di) — ngi gi t quyt (khng i calldata = no-op).
    """
    if not calldata.startswith("0x") or len(calldata) != 2 + 8 + 192:  # 0x + 8 hex selector + 3 word*64
        return None
    if calldata[2:10].lower() != START_SELECTOR:
        return None
    word3 = calldata[2 + 8 + 128: 2 + 8 + 192]
    return calldata[:2 + 8 + 64] + format(amount, "064x") + word3


class Mutation(ABC):
    """Base class cho mi mutation f_*."""

    name: str = "?"
    # A mutation that removes an execution prerequisite is useful for
    # diagnosis, but must never be counted as causal evidence by E4.
    causal_ready: bool = True
    target: str = ""
    validity_note: str = ""
    mutation_kind: str = "removal"

    @abstractmethod
    def apply(self, fork: ForkRunner) -> None:
        """Patch state on active fork (after warmup, prior to replay)."""

    def apply_to_replayer(self, replayer: Replayer) -> None:
        """Optional hook into replayer (e.g., f_swap calldata override)."""

    def validate_execution(self, *, observed: bool, status: bool | None) -> tuple[bool, str]:
        """Return whether this intervention is eligible for causal scoring.

        A successful receipt is necessary but not sufficient: deliberately
        destructive precondition mutations are kept out of the causal set.
        Case-specific invariant checks can tighten this contract later.
        """
        if not observed:
            return False, "transport_or_timeout"
        if status is not True:
            return False, "transaction_reverted"
        if not self.causal_ready:
            return False, self.validity_note or "precondition_only"
        return True, "execution_preserving"

    def __str__(self) -> str:
        return self.name


class FlashLoanDisable(Mutation):
    """f_fl — block the traced flash entrypoint with a forwarding shim.

    The selector is supplied by the call trace when available; callers that
    construct the primitive directly retain the historical dYdX default.
    Empty code is deliberately not used: CALL to an account without code can
    return success with empty returndata and create a false execution-preserving
    result. The original implementation is copied to a shadow address, while
    this address receives a selector-specific guard runtime.
    """

    name = "f_fl"
    mutation_kind = "removal"
    # The provider guard is execution-preserving, but causal scoring still
    # requires a case-specific loss/invariant oracle.  Keep this fail-closed
    # until that oracle is wired for the bZx victim ledger.
    causal_ready = False
    target = "flash_loan_provider"
    validity_note = "selector-specific provider guard; execution/invariants still require validation"

    OPERATE_SELECTOR = "a67a6a45"
    SHADOW_ADDRESS = "0x000000000000000000000000000000000000f1a1"
    DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    def __init__(self, provider: str, selector: str | None = None):
        self.provider = provider
        # Keep the historical dYdX default for callers that construct this
        # primitive directly.  The necessity planner overrides it from the
        # provider call trace (Aave V2 uses ab9c4b5d).
        self.selector = (selector or self.OPERATE_SELECTOR).lower().removeprefix("0x")

    def apply(self, fork: ForkRunner) -> None:
        c = RpcClient(fork.url, timeout=30)
        original = c.eth_get_code(self.provider)
        if not original or original == "0x":
            raise RuntimeError("f_fl: provider has no runtime code at pre-state")
        shadow = self.SHADOW_ADDRESS
        if shadow.lower() == self.provider.lower():
            raise RuntimeError("f_fl: shadow address equals provider")
        if c.eth_get_code(shadow) not in ("0x", "0x0"):
            raise RuntimeError(f"f_fl: shadow address is not empty: {shadow}")
        c.anvil_set_code(shadow, original)
        runtime = _operate_guard_runtime(shadow, self.selector)
        init = _runtime_init(runtime)
        sent = c.call("eth_sendTransaction", [{"from": self.DEPLOYER, "to": None,
            "gas": hex(1_000_000), "gasPrice": "0x0", "value": "0x0", "data": init}])
        deadline, receipt = time.time() + 30, None
        while time.time() < deadline:
            receipt = c.eth_get_receipt(sent)
            if receipt: break
            time.sleep(0.2)
        if not receipt or receipt.get("status") not in ("0x1", 1):
            raise RuntimeError(f"f_fl: guard deployment failed: {sent}")
        guard_address = receipt.get("contractAddress")
        guard_code = c.eth_get_code(guard_address) if guard_address else "0x"
        if not guard_address or guard_code == "0x":
            raise RuntimeError("f_fl: deployed guard has empty runtime")
        c.anvil_set_code(self.provider, guard_code)
        self.shadow_address, self.guard_address, self.guard_runtime = shadow, guard_address, guard_code

def _push(value: int, width: int) -> bytes:
    return bytes([0x5f + width]) + value.to_bytes(width, "big")


def _operate_guard_runtime(shadow: str, selector: str) -> str:
    """Build a tiny selector guard runtime without Solidity constant folding."""
    shadow_int = int(shadow, 16)
    sel_int = int(selector, 16)
    code = bytearray()
    # msg.sig == selector; jump to an empty revert.
    code += _push(0, 1) + b"\x35" + _push(0xe0, 1) + b"\x1c"
    code += _push(sel_int, 4) + b"\x14"
    blocked_placeholder = len(code)
    code += b"\x61\x00\x00\x57"
    # Forward all other selectors to the original implementation.
    # Copy calldata to memory, then push DELEGATECALL arguments in reverse
    # stack order: retSize, retOffset, inSize, inOffset, address, gas.
    code += b"\x36" + _push(0, 1) + _push(0, 1) + b"\x37"
    code += _push(0, 1) + _push(0, 1) + b"\x36" + _push(0, 1)
    code += _push(shadow_int, 20) + b"\x5a\xf4"
    code += b"\x15"
    failed_placeholder = len(code)
    code += b"\x61\x00\x00\x57"
    # RETURN(offset, size): push size, then offset.
    code += b"\x3d\x60\x00\xf3"
    failed_dest = len(code)
    code += b"\x5b\x3d\x60\x00\x60\x00\x3e\x3d\x60\x00\xfd"
    blocked_dest = len(code)
    code += b"\x5b\x60\x00\x60\x00\xfd"
    code[blocked_placeholder + 1:blocked_placeholder + 3] = blocked_dest.to_bytes(2, "big")
    code[failed_placeholder + 1:failed_placeholder + 3] = failed_dest.to_bytes(2, "big")
    return "0x" + code.hex()


def _runtime_init(runtime: str) -> str:
    body = bytes.fromhex(runtime[2:])
    # 14-byte init prefix: PUSH1/PUSH1/PUSH2/CODECOPY/PUSH1/PUSH2/RETURN.
    offset = 14
    # CODECOPY(dest, offset, size): push size, offset, dest.
    init = _push(len(body), 2) + _push(offset, 1) + _push(0, 1) + b"\x39"
    init += _push(len(body), 2) + _push(0, 1) + b"\xf3"
    return "0x" + (init + body).hex()


class HealthCheckGuard(Mutation):
    """Euler-specific guard-restoration pilot intervention.

    This is not one of the generic blind mutation primitives: the target
    boundary, selector, and expected blocking signature are protocol-specific.
    """

    name = "f_health_check"
    mutation_kind = "insertion-blocking"
    expected_revert_reason = "e/collateral-violation"
    SHADOW_ADDRESS = "0x000000000000000000000000000000000000f1a2"
    DONATE_SELECTOR = "36f022aa"

    def __init__(self, target: str, patched_code_path: str | None = None):
        self.target = target.lower()
        self.patched_code_path = patched_code_path

    def apply(self, fork: ForkRunner) -> None:
        pass


def _operate_success_runtime(shadow: str, selector: str) -> str:
    """Forward selectors except one, which returns Solidity ``true``."""
    shadow_int, sel_int = int(shadow, 16), int(selector, 16)
    code = bytearray()
    code += _push(0, 1) + b"\x35" + _push(0xe0, 1) + b"\x1c"
    code += _push(sel_int, 4) + b"\x14"
    success_placeholder = len(code)
    code += b"\x61\x00\x00\x57"
    code += b"\x36" + _push(0, 1) + _push(0, 1) + b"\x37"
    code += _push(0, 1) + _push(0, 1) + b"\x36" + _push(0, 1)
    code += _push(shadow_int, 20) + b"\x5a\xf4"
    failed_placeholder = len(code)
    code += b"\x61\x00\x00\x57" + b"\x3d\x60\x00\xf3"
    failed_dest = len(code)
    code += b"\x5b\x3d\x60\x00\x60\x00\x3e\x3d\x60\x00\xfd"
    success_dest = len(code)
    code += b"\x5b\x60\x01\x60\x00\x52\x60\x20\x60\x00\xf3"
    code[success_placeholder + 1:success_placeholder + 3] = success_dest.to_bytes(2, "big")
    # The delegatecall result is true on success.  The forwarding branch must
    # therefore jump to the returndata-copy/return block; the old shim had
    # these destinations reversed and turned every successful forwarded call
    # into a revert path (observed as downstream OOG).
    code[failed_placeholder + 1:failed_placeholder + 3] = success_dest.to_bytes(2, "big")
    return "0x" + code.hex()


class OraclePin(Mutation):
    """f_orc — pin one trace-observed oracle getter to a pre-prefix price."""

    name = "f_orc"

    def __init__(self, oracle: str, stub_bytecode: str,
                 selector: str | None = None):
        self.oracle = oracle
        self.stub_bytecode = stub_bytecode
        # Provenance, not a guessed dispatch option. The planner must
        # populate this from the callTracer observation.
        self.selector = selector.lower().removeprefix("0x") if selector else None

    def apply(self, fork: ForkRunner) -> None:
        RpcClient(fork.url, timeout=10).anvil_set_code(self.oracle, self.stub_bytecode)


class AmmReservePin(Mutation):
    """f_orc_amm — apply explicitly observed AMM storage values.

    AMM layouts are protocol-specific (some pools pack both reserves into one
    word), so callers must supply exact slot/value pairs from prestate
    evidence. This primitive never guesses slots from a getter selector.
    """

    name = "f_orc_amm"
    mutation_kind = "removal"

    def __init__(self, pool: str, storage_overrides: dict[str, str]):
        self.pool = pool.lower()
        self.storage_overrides = {
            slot.lower(): value.lower()
            for slot, value in storage_overrides.items()
        }

    def apply(self, fork: ForkRunner) -> None:
        client = RpcClient(fork.url, timeout=30)
        for slot, value in self.storage_overrides.items():
            client.anvil_set_storage(self.pool, slot, value)


class SwapSlice(Mutation):
    """f_swap -- cap amountIn or mutate parameters of swap slices.

    Calldata is modified prior to replaying transaction (via Replayer.data_override).
    """

    name = "f_swap"

    def __init__(self, calldata_override: str | None = None,
                 start_cap: int | None = None, ratio: float | None = None):
        if ratio is not None and not 0 < ratio <= 1:
            raise ValueError("swap ratio must be in (0, 1]")
        self.calldata_override = calldata_override
        self.start_cap = start_cap
        self.ratio = ratio
        self.target = "start(uint256 flash,uint256 amount,uint256 min).amount"
        self.validity_note = "parameterized amount intervention; repayment must be checked after replay"
        if ratio is not None:
            self.name = f"f_swap[{ratio:g}]"

    def apply(self, fork: ForkRunner) -> None:
        # Execution trace analysis and verification
        pass

    def apply_to_replayer(self, replayer: Replayer) -> None:
        if self.calldata_override:
            replayer.data_override = self.calldata_override
        if self.start_cap is not None:
            # Execution trace analysis and verification
            replayer.start_cap = self.start_cap
        if self.ratio is not None:
            replayer.start_cap_ratio = self.ratio


# ===========================================================================
# SwapMultiHop — π_swap generic multi-hop isolation (proposal §5.3.1)
# ===========================================================================

class SwapFrame(NamedTuple):
    """Mt slice swap trong trace: (caller, pool, tokenIn, tokenOut, amtIn, amtOut, recipient)."""
    caller: str
    pool: str
    token_in: str
    token_out: str
    amt_in: int
    amt_out: int
    recipient: str
    call_index: int  # Verified execution property


def _extract_swap_frames(flat_calls: list[dict], logs: list[dict]) -> list[SwapFrame]:
    """Trch xut π_swap(T): tp slice swap t call trace + Transfer events."""
    SWAP_POOL_SELECTORS = {
        "0x022c0d9f", "0x128acb08", "0x38ed1739", "0x8803dbee", "0xc04b8d59",
        "0x414bf389", "0x18cbafe5", "0x4a25d94a", "0x7ff36ab5", "0xd0e30db0", "0x2e1a7d4d",
    }
    transfer_events: list[dict] = [
        log for log in logs
        if len(log.get("topics", [])) >= 3
        and log["topics"][0].lower() == TOPIC_TRANSFER
    ]
    frames: list[SwapFrame] = []
    for i, call in enumerate(flat_calls):
        sel = (call.get("selector") or "")
        if sel not in SWAP_POOL_SELECTORS:
            continue
        pool = (call.get("to") or "").lower()
        caller = (call.get("from") or "").lower()
        if not pool:
            continue
        out_transfers = [t for t in transfer_events if ("0x" + t["topics"][1][-40:]).lower() == pool]
        in_transfers = [t for t in transfer_events if ("0x" + t["topics"][2][-40:]).lower() == pool]
        if not out_transfers and not in_transfers:
            continue
        for out_t in out_transfers[:1]:
            token_out = (out_t.get("address") or "").lower()
            recipient = ("0x" + out_t["topics"][2][-40:]).lower()
            raw_data = out_t.get("data") or "0x0"
            amt_out = int(raw_data, 16) if raw_data not in ("0x", "") else 0
            token_in = ""
            amt_in = 0
            for in_t in in_transfers[:1]:
                token_in = (in_t.get("address") or "").lower()
                raw_in = in_t.get("data") or "0x0"
                amt_in = int(raw_in, 16) if raw_in not in ("0x", "") else 0
            frames.append(SwapFrame(caller, pool, token_in, token_out, amt_in, amt_out, recipient, i))
    return frames


def _build_routes(frames: list[SwapFrame]) -> list[list[SwapFrame]]:
    """Ni cc slice thnh route nu out(token_k) == in(token_k+1)."""
    if not frames:
        return []
    used = [False] * len(frames)
    routes: list[list[SwapFrame]] = []
    for i, f in enumerate(frames):
        if used[i]:
            continue
        route = [f]
        used[i] = True
        current_out = f.token_out
        for _ in range(len(frames)):
            found = False
            for j, g in enumerate(frames):
                if not used[j] and g.token_in == current_out:
                    route.append(g)
                    used[j] = True
                    current_out = g.token_out
                    found = True
                    break
            if not found:
                break
        routes.append(route)
    return routes


class SwapMultiHop(Mutation):
    """f_swap generic multi-hop isolation (proposal §5.3.1)."""

    name = "f_swap_multihop"

    def __init__(self, frames: list[SwapFrame], routes: list[list[SwapFrame]],
                 target_slice_index: int = 0, mode: str = "cap"):
        self.frames = frames
        self.routes = routes
        self.target_slice_index = min(target_slice_index, len(frames) - 1) if frames else 0
        self.mode = mode
        self._target_frame = frames[self.target_slice_index] if frames else None
        if frames:
            self.name = f"f_swap_multihop[slice={self.target_slice_index},mode={mode}]"

    @classmethod
    def from_trace(cls, flat_calls: list[dict], logs: list[dict], slice_index: int = 0, mode: str = "cap") -> "SwapMultiHop":
        frames = _extract_swap_frames(flat_calls, logs)
        routes = _build_routes(frames)
        return cls(frames, routes, slice_index, mode)

    def apply(self, fork: ForkRunner) -> None:
        pass

    def apply_to_replayer(self, replayer: Replayer) -> None:
        if not self._target_frame:
            return
        original = getattr(replayer, "original_calldata", None) or getattr(replayer, "data_override", None)
        if not original:
            return
        frame = self._target_frame
        if self.mode in ("cap", "zero"):
            cap_amount = int(frame.amt_in * 0.01) if self.mode == "cap" else 0
            override = start_cap_override(original, cap_amount)
            if override:
                replayer.data_override = override
                return


# ===========================================================================
# SignatureRecovery — f_auth attribution via ecrecover (proposal §5.3.2)
# ===========================================================================

class SignatureRecovery:
    """Dual-evidence verification channel for governance / key-compromise attacks."""
    def __init__(self, calldata: str, owners: list[str], threshold: int, chain_id: int = 1):
        self.calldata = calldata
        self.owners = [o.lower() for o in owners]
        self.threshold = threshold
        self.chain_id = chain_id

    def _parse_signatures(self) -> list[bytes] | None:
        raw = self.calldata[2:] if self.calldata.startswith(("0x", "0X")) else self.calldata
        if len(raw) < 648 or raw[:8].lower() != EXEC_TX_SELECTOR[2:]:
            return None
        sig_offset = int(raw[8 + 9 * 64: 8 + 10 * 64], 16)
        sig_start = 8 + sig_offset * 2
        sig_len = int(raw[sig_start: sig_start + 64], 16)
        sig_blob = bytes.fromhex(raw[sig_start + 64: sig_start + 64 + sig_len * 2])
        sigs = [sig_blob[i: i + 65] for i in range(0, len(sig_blob) - 64, 65)]
        return sigs if sigs else None

    @staticmethod
    def _ecrecover(msg_hash: bytes, sig: bytes) -> str | None:
        if len(sig) != 65:
            return None
        r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
        if v >= 27:
            v -= 27
        if v not in (0, 1):
            return None
        try:
            from eth_keys.datatypes import Signature as _Sig
            return _Sig(vrs=(v, r, s)).recover_public_key_from_msg_hash(msg_hash).to_checksum_address().lower()
        except ImportError:
            return None

    def recover(self, safe_tx_hash: bytes | None = None) -> RecoveryResult:
        sigs = self._parse_signatures()
        if not sigs:
            return RecoveryResult([], [], self.threshold, "PARSE_ERROR")
        if not safe_tx_hash:
            return RecoveryResult([], [], self.threshold, "HASH_REQUIRED")
        recovered = [a for a in [self._ecrecover(safe_tx_hash, s) for s in sigs] if a]
        matched = [a for a in recovered if a in self.owners]
        verdict = "KEY_COMPROMISE" if len(matched) >= self.threshold else "INSUFFICIENT_SIGS"
        return RecoveryResult(recovered, matched, self.threshold, verdict)



class RecoveryResult:
    def __init__(self, signers: list[str], matched_owners: list[str], threshold: int, verdict: str):
        self.signers = signers
        self.matched_owners = matched_owners
        self.threshold = threshold
        self.verdict = verdict


class AuthRevoke(Mutation):
    """f_auth(A) — revoke admin/owner: zero EIP-1967 admin storage slot (proxy)."""

    name = "f_auth(A)"

    def __init__(self, proxy: str):
        self.proxy = proxy

    def apply(self, fork: ForkRunner) -> None:
        RpcClient(fork.url, timeout=10).anvil_set_storage(
            self.proxy, EIP1967_ADMIN_SLOT,
            "0x" + "00" * 32,
        )


class ShamStorageWrite(Mutation):
    """Negative causal control: write an unrelated sentinel storage slot."""

    name = "control_sham"

    def __init__(self, address: str = SHAM_ADDRESS, slot: str = SHAM_SLOT,
                 value: str = SHAM_VALUE):
        self.address = address.lower()
        self.slot = slot
        self.value = value

    def apply(self, fork: ForkRunner) -> None:
        RpcClient(fork.url, timeout=10).anvil_set_storage(
            self.address, self.slot, self.value,
        )


class CompositeMutation(Mutation):
    """Predeclared joint intervention applied atomically on one fresh fork."""

    def __init__(self, mutations: tuple[Mutation, ...]):
        if len(mutations) < 2:
            raise ValueError("composite mutation requires at least two components")
        self.mutations = mutations
        self.name = "joint[" + "+".join(m.name for m in mutations) + "]"

    def apply_to_replayer(self, replayer: Replayer) -> None:
        for mutation in self.mutations:
            mutation.apply_to_replayer(replayer)

    def apply(self, fork: ForkRunner) -> None:
        for mutation in self.mutations:
            mutation.apply(fork)
