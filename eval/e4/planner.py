"""Tier 1 E4 mutation planning.

Candidate discovery uses only the transaction trace, historical archive data,
and case execution metadata.  It must not read ``gt_factors`` or any verdict.
This module owns the discovery seam; execution and causal scoring remain in
the legacy facade until later extraction steps.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.env import load_dotenv, resolve_rpc
from core.mutate import (
    EIP1967_ADMIN_SLOT,
    AuthRevoke,
    FlashLoanDisable,
    HealthCheckGuard,
    OraclePin,
    SwapSlice,
)
from core.rpc import RpcClient, RpcError
from eval.e4.models import Case, MutationPlan


REPO_ROOT = Path(__file__).resolve().parents[2]
REPLAYER_TIMEOUT = 300
START_SELECTOR = "641ccd83"
FLASH_SELECTORS = {
    "ab9c4b5d": "AaveV2.flashLoan",
    "42b0b77c": "AaveV3.flashLoan",
    "5c38449e": "Balancer.flashLoan",
    "8240a3e0": "dYdX.operate",
    "a67a6a45": "dYdX.operate",
    "30e8d2c6": "UniswapV2.swap",
    "022c0d9f": "UniswapV2.swap",
}
UNISWAP_V2_CALLBACK = "10d1e85c"
SAFE_EXEC_SELECTORS = ("a0e67e2b", "e101f8a4", "f9a5e5d0")
ORACLE_GETTERS = {
    "feaf968c": "latestRoundData",
    "85bb7d69": "answer",
    "50d25bcd": "latestAnswer",
    "59e02dd7": "peek",
}
ORACLE_STUB_TEMPLATE = REPO_ROOT / "pilot" / "oraclestub" / "OracleStub.runtime.json"
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
AUTHORITY_SELECTORS = {
    "4f1ef286",  # upgradeTo(address)
    "3659cfe6",  # upgradeToAndCall(address,bytes)
    "99a88ec4",  # changeAdmin(address)
    "8f283970",  # transferOwnership(address)
    "715018a6",  # renounceOwnership()
}


def _load_oracle_stub_runtime() -> tuple[str | None, tuple[tuple[int, int], ...]]:
    """Load and validate the released OracleStub runtime template."""
    try:
        payload = json.loads(ORACLE_STUB_TEMPLATE.read_text(encoding="utf-8"))
        runtime = str(payload["deployed_bytecode"])
        if not runtime.startswith("0x"):
            runtime = "0x" + runtime
        bytes.fromhex(runtime[2:])
        references = tuple(
            (int(item["start"]), int(item["length"]))
            for item in payload["immutable_references"]
        )
        if not references:
            raise ValueError("OracleStub template has no immutable references")
        runtime_bytes = len(runtime[2:]) // 2
        for start, length in references:
            if length != 32 or start < 0 or start + length > runtime_bytes:
                raise ValueError("invalid OracleStub immutable reference")
            begin = 2 + start * 2
            end = begin + length * 2
            if runtime[begin:end] != "0" * (length * 2):
                raise ValueError("OracleStub immutable placeholder is not zeroed")
        return runtime, references
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None, ()


ORACLE_STUB_RUNTIME, ORACLE_STUB_IMMUTABLES = _load_oracle_stub_runtime()
_ARCHIVE_CLIENT: RpcClient | None = None


def get_archive(rpc: str | None = None) -> RpcClient:
    """Return the planner's archive client; never use it during execution."""
    global _ARCHIVE_CLIENT
    load_dotenv()
    if _ARCHIVE_CLIENT is None:
        _ARCHIVE_CLIENT = RpcClient(rpc or resolve_rpc() or "", timeout=REPLAYER_TIMEOUT)
    return _ARCHIVE_CLIENT


def _block_tag(block: int | None) -> str:
    return hex(block) if block is not None else "latest"


def _retry_rpc(fn, attempts: int = 3, base_sleep: float = 1.5):
    for attempt in range(attempts):
        try:
            return fn()
        except RpcError:
            if attempt == attempts - 1:
                raise
            time.sleep(base_sleep * (attempt + 1))


def _resolve_trace(archive: RpcClient, tx_hash: str,
                   error_out: list[str] | None = None) -> dict | None:
    try:
        return _retry_rpc(lambda: archive.call(
            "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}]))
    except RpcError as exc:
        if error_out is not None:
            error_out.append(str(exc)[:240])
        return None


def _walk_calls_generator(trace: dict | None):
    stack = [trace]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        yield node
        stack.extend(node.get("calls") or [])


def _find_flash_provider(trace: dict | None) -> tuple[str | None, str]:
    if not trace:
        return None, "no trace"
    exact = []
    for node in _walk_calls_generator(trace):
        inp = node.get("input") or ""
        if inp.startswith("0x") and len(inp) >= 10:
            selector = inp[2:10]
            if selector in FLASH_SELECTORS:
                exact.append((FLASH_SELECTORS[selector], node.get("to")))
    if exact:
        for label, target in exact:
            if target and label != "UniswapV2.swap":
                return target.lower(), f"{label} {target[:10]}"
        for node in _walk_calls_generator(trace):
            inp = node.get("input") or ""
            if inp.startswith("0x") and len(inp) >= 10 and inp[2:10] == UNISWAP_V2_CALLBACK:
                target = exact[0][1]
                return target.lower(), f"UniswapV2.flash-swap {target[:10]} (callback 0x10d1e85c)"
        return None, "UniswapV2.swap observed but not flash swap (missing callback 0x10d1e85c)"
    return None, "no flashLoan selectors found in trace"


def _flash_selector_for_provider(trace: dict | None, provider: str | None) -> str | None:
    if not trace or not provider:
        return None
    wanted = provider.lower()
    for node in _walk_calls_generator(trace):
        if str(node.get("to") or "").lower() != wanted:
            continue
        inp = str(node.get("input") or "")
        selector = inp[2:10].lower() if inp.startswith("0x") and len(inp) >= 10 else ""
        if selector in FLASH_SELECTORS and selector not in {"30e8d2c6", "022c0d9f"}:
            return selector
    return None


def _find_oracle_details(
    trace: dict | None, archive: RpcClient, block: int,
) -> tuple[str | None, str | None, str]:
    if not trace:
        return None, None, "no trace"
    seen: set[tuple[str, str]] = set()
    for node in _walk_calls_generator(trace):
        if node.get("type") != "STATICCALL":
            continue
        inp = node.get("input") or ""
        if inp.startswith("0x") and len(inp) >= 10:
            selector = inp[2:10].lower()
            getter = ORACLE_GETTERS.get(selector)
            if getter:
                seen.add(((node.get("to") or "").lower(), getter, selector))
    for address, getter, selector in sorted(seen):
        if not address:
            continue
        try:
            code = archive.eth_get_code(address, _block_tag(block))
            if code and code != "0x":
                return address, selector, f"oracle {address[:10]} ({getter}, 0x{selector}) STATICCALL has code"
        except RpcError:
            continue
    return None, None, "no STATICCALL oracle getters found in trace"


def _find_oracle(trace: dict | None, archive: RpcClient, block: int) -> tuple[str | None, str]:
    """Compatibility facade retaining the historical two-value API."""
    address, _selector, reason = _find_oracle_details(trace, archive, block)
    return address, reason


def _is_safe_multisig(addr: str, archive: RpcClient, block: int) -> bool:
    for selector in SAFE_EXEC_SELECTORS:
        try:
            result = archive.call("eth_call", [{"to": addr, "data": "0x" + selector}, _block_tag(block)])
        except RpcError:
            continue
        if result and result not in ("0x", "0x0", "0x" + "0" * 64):
            return True
    return False


def _find_proxy(trace: dict | None, archive: RpcClient, block: int) -> tuple[str | None, str]:
    if not trace:
        return None, "no trace"
    for node in _walk_calls_generator(trace):
        if node.get("type") != "DELEGATECALL":
            continue
        address = (node.get("from") or "").lower()
        if not address:
            continue
        if _is_safe_multisig(address, archive, block):
            return None, f"GnosisSafe {address[:10]} (permission-gated - skip AuthRevoke)"
        try:
            admin = archive.eth_get_storage(address, EIP1967_ADMIN_SLOT, _block_tag(block))
            implementation = archive.eth_get_storage(
                address, EIP1967_IMPLEMENTATION_SLOT, _block_tag(block)
            )
        except RpcError:
            continue
        target = str(node.get("to") or "").lower()
        implementation_address = "0x" + str(implementation).removeprefix("0x")[-40:]
        implementation_code = archive.eth_get_code(implementation_address, _block_tag(block))
        input_data = str(node.get("input") or "").lower()
        selector = input_data[2:10] if input_data.startswith("0x") else ""
        if (
            admin and admin not in ("0x0", "0x00", "0x" + "0" * 64)
            and implementation_address != "0x" + "0" * 40
            and implementation_address == target
            and implementation_code not in ("", "0x")
            and selector in AUTHORITY_SELECTORS
        ):
            return address, (
                f"EIP-1967 proxy {address[:10]} with matching implementation and "
                f"observed authority selector 0x{selector}"
            )
        if implementation_address == target and implementation_code not in ("", "0x"):
            return None, (
                f"proxy-like DELEGATECALL {address[:10]} is business-path only; "
                "no observed authority selector"
            )
    return None, "no EIP-1967 proxy found in trace"


def _pin_oracle_stub(price_hex: str) -> str | None:
    if not ORACLE_STUB_RUNTIME or not ORACLE_STUB_IMMUTABLES or len(price_hex) != 64:
        return None
    try:
        int(price_hex, 16)
    except ValueError:
        return None
    runtime = ORACLE_STUB_RUNTIME
    for start, length in ORACLE_STUB_IMMUTABLES:
        begin = 2 + start * 2
        end = begin + length * 2
        if runtime[begin:end] != "0" * (length * 2):
            return None
        runtime = runtime[:begin] + price_hex + runtime[end:]
    return runtime


def _price_hex(price: int) -> str:
    return format(price, "064x")


def _mainnet_price(archive: RpcClient, oracle: str, block: int,
                   selector: str) -> int | None:
    """Read the exact getter observed in callTracer at the pre-prefix block."""
    try:
        result = archive.call("eth_call", [{"to": oracle, "data": "0x" + selector}, _block_tag(block)])
        if result and result not in ("0x", "0x0"):
            if selector == "feaf968c" and result.startswith("0x") and len(result) >= 2 + 64 * 2:
                answer = result[2 + 64:2 + 128]
                return int(answer, 16) if answer.strip("0") or answer == "0" * 64 else None
            return int(result, 16) if result != "0x" else None
    except RpcError:
        pass
    return None


def build_mutation_plan(case: Case, archive: RpcClient | None = None,
                        trace_rpc: RpcClient | None = None) -> MutationPlan:
    """Discover supported interventions without consulting ground truth."""
    plan = MutationPlan()
    archive = archive or get_archive()
    block = case.block
    if not block:
        try:
            tx = archive.eth_get_transaction(case.tx_hash)
            block_hex = (tx or {}).get("blockNumber") or "0x0"
            block = int(block_hex, 16) if block_hex != "0x0" else None
        except RpcError:
            block = None
    block = (block - 1) if block else None

    trace_errors: list[str] = []
    trace = case.trace or _resolve_trace(trace_rpc or archive, case.tx_hash, trace_errors)
    if not trace and trace_errors:
        plan.notes.append(f"trace unavailable from RPC: {trace_errors[0]}")

    try:
        tx = archive.eth_get_transaction(case.tx_hash)
        top_input = (tx or {}).get("input") or "0x"
    except RpcError:
        top_input = "0x"

    provider, why_fl = _find_flash_provider(trace)
    if provider:
        selector = _flash_selector_for_provider(trace, provider)
        plan.add(FlashLoanDisable(provider, selector=selector),
                 note=f"blind f_fl candidate: {why_fl}; selector={selector or 'default'}")
    else:
        plan.notes.append(f"blind f_fl unsupported: {why_fl}")

    donate_nodes = [node for node in _walk_calls_generator(trace)
                    if (node.get("input") or "")[2:10].lower() == "36f022aa" and node.get("to")]
    donate_targets = [node.get("to") for node in donate_nodes if node.get("type") == "DELEGATECALL"]
    if not donate_targets:
        donate_targets = [node.get("to") for node in donate_nodes]
    if donate_targets:
        plan.add(HealthCheckGuard(donate_targets[0],
                                  patched_code_path=case.extra.get("euler_patched_runtime")),
                 note=("pilot guard-restoration extension: Euler "
                       f"donateToReserves target {donate_targets[0][:10]}"))
    else:
        plan.notes.append(
            "pilot guard-restoration extension unavailable: "
            "donateToReserves selector 36f022aa absent"
        )

    oracle, oracle_selector, why_oracle = _find_oracle_details(trace, archive, block)
    price = _mainnet_price(archive, oracle, block, oracle_selector) if oracle and oracle_selector else None
    stub = _pin_oracle_stub(_price_hex(price)) if oracle and price is not None else None
    if case.extra.get("oracle_mutation_na") or case.extra.get("skip_optional_mutation"):
        plan.notes.append("f_orc intentionally skipped: case metadata marks oracle manipulation N/A")
    elif oracle and oracle_selector and oracle_selector not in ORACLE_GETTERS:
        plan.notes.append(
            f"blind f_orc unsupported: trace getter selector 0x{oracle_selector} "
            "has no matching OracleStub runtime dispatch"
        )
    elif oracle and price is not None and stub:
        plan.add(OraclePin(oracle, stub, selector=oracle_selector),
                 note=f"blind f_orc candidate: {oracle[:10]} selector=0x{oracle_selector} pinned at block-1")
    else:
        plan.notes.append(
            f"blind f_orc unsupported: oracle={oracle or 'N/A'} why={why_oracle}; "
            f"price={'known' if price is not None else 'missing'}; "
            f"stub={'available' if ORACLE_STUB_RUNTIME else 'missing'}")

    if top_input.startswith("0x") and len(top_input) >= 10 and top_input[2:10].lower() == START_SELECTOR:
        for ratio in (0.90, 0.75, 0.50, 0.25):
            plan.add(SwapSlice(ratio=ratio),
                     note=f"blind f_swap candidate: amount scaled to {ratio:g} of original")
    else:
        plan.notes.append(
            f"blind f_swap unsupported: selector {top_input[:10] if top_input else '0x'}; nested-slice parser absent")

    proxy, why_auth = _find_proxy(trace, archive, block)
    if proxy:
        plan.add(AuthRevoke(proxy), note=f"blind f_auth candidate: {why_auth}")
    else:
        plan.notes.append(f"blind f_auth unsupported: {why_auth}; Safe/key provenance is a separate signature-provenance task")
    return plan
