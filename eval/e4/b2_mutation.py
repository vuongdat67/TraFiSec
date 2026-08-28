"""B2 mutation adapter and telemetry helpers.

This boundary converts E4 mutation objects into prepared-context overrides for
the go-ethereum runner.  It performs local file reads only; archive access and
execution remain outside the adapter.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.mutate import (
    EIP1967_ADMIN_SLOT,
    AuthRevoke,
    AmmReservePin,
    CompositeMutation,
    FlashLoanDisable,
    HealthCheckGuard,
    Mutation,
    OraclePin,
    SwapSlice,
    _operate_guard_runtime,
    _operate_success_runtime,
    start_cap_override,
)


@dataclass(frozen=True)
class OracleStubProvider:
    """Translate ``OraclePin`` into the existing B2 code override."""

    def override(self, mutation: OraclePin) -> dict[str, dict[str, str]]:
        if not mutation.selector:
            raise ValueError("f_orc requires the getter selector observed by callTracer")
        if len(mutation.selector) != 8:
            raise ValueError("f_orc getter selector must be four bytes")
        if not mutation.oracle or not mutation.stub_bytecode.startswith("0x"):
            raise ValueError("f_orc requires oracle address and runtime bytecode")
        return {"target_code": {mutation.oracle: mutation.stub_bytecode}}


@dataclass(frozen=True)
class StorageOverrideProvider:
    """Translate an evidence-bound AMM storage mutation for the B2 runner."""

    def override(self, mutation: AmmReservePin) -> dict[str, dict[str, dict[str, str]]]:
        if not mutation.pool or not mutation.storage_overrides:
            raise ValueError("f_orc_amm requires pool and storage overrides")
        overrides: dict[str, str] = {}
        for slot, value in mutation.storage_overrides.items():
            if not (slot.startswith("0x") and len(slot) == 66):
                raise ValueError("f_orc_amm storage slot must be 32 bytes")
            if not (value.startswith("0x") and len(value) == 66):
                raise ValueError("f_orc_amm storage value must be 32 bytes")
            int(slot[2:], 16)
            int(value[2:], 16)
            overrides[slot] = value
        return {"target_storage": {mutation.pool: overrides}}


def _load_prestate_accounts(context: str | Path) -> dict:
    rows = json.loads((Path(context) / "prestates.json").read_text())
    accounts: dict = {}
    for item in rows:
        trace = item.get("trace", {})
        accounts.update(json.loads(trace) if isinstance(trace, str) else trace)
    return accounts


def mutation_args(context: str | Path, mutation: Mutation) -> tuple[dict, str | None]:
    """Translate one mutation into B2 target overrides, fail-closed."""
    if isinstance(mutation, CompositeMutation):
        merged: dict = {"target_code": {}, "target_storage": {}}
        for child in mutation.mutations:
            args, error = mutation_args(context, child)
            if error:
                return {}, error
            if args.get("target_data"):
                if merged.get("target_data"):
                    return {}, "multiple calldata overrides are ambiguous"
                merged["target_data"] = args["target_data"]
            merged["target_code"].update(args.get("target_code", {}))
            for address, slots in args.get("target_storage", {}).items():
                merged["target_storage"].setdefault(address, {}).update(slots)
        return merged, None

    if isinstance(mutation, OraclePin):
        try:
            return OracleStubProvider().override(mutation), None
        except ValueError as exc:
            return {}, str(exc)

    if isinstance(mutation, AmmReservePin):
        try:
            return StorageOverrideProvider().override(mutation), None
        except ValueError as exc:
            return {}, str(exc)

    if isinstance(mutation, FlashLoanDisable):
        try:
            accounts = _load_prestate_accounts(context)
            original = accounts.get(mutation.provider.lower(), {}).get("code")
            if not original or original in ("0x", "0x0"):
                return {}, "f_fl provider code missing from prepared prestate"
            guard = _operate_guard_runtime(mutation.SHADOW_ADDRESS, mutation.selector)
            return {"target_code": {
                mutation.provider: guard,
                mutation.SHADOW_ADDRESS: original,
            }}, None
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return {}, f"cannot load f_fl provider prestate: {exc}"

    if isinstance(mutation, HealthCheckGuard):
        if mutation.patched_code_path:
            try:
                artifact = json.loads(Path(mutation.patched_code_path).read_text())
                patched = artifact.get("deployedBytecode") or artifact.get("runtime")
                if not patched or patched in ("0x", "0x0"):
                    return {}, "f_health_check patched runtime is empty"
                return {"target_code": {mutation.target: patched}}, None
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                return {}, f"cannot load official f_health_check runtime: {exc}"
        try:
            accounts = _load_prestate_accounts(context)
            original = accounts.get(mutation.target.lower(), {}).get("code")
            if not original or original in ("0x", "0x0"):
                return {}, "f_health_check target code missing from prepared prestate"
            return {"target_code": {
                mutation.target: _operate_success_runtime(
                    mutation.SHADOW_ADDRESS, mutation.DONATE_SELECTOR),
                mutation.SHADOW_ADDRESS: original,
            }}, None
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return {}, f"cannot load f_health_check target prestate: {exc}"

    if isinstance(mutation, AuthRevoke):
        return {"target_storage": {mutation.proxy: {
            EIP1967_ADMIN_SLOT: "0x" + "00" * 32,
        }}}, None

    if isinstance(mutation, SwapSlice):
        try:
            txs = json.loads((Path(context) / "transactions.json").read_text())
            case_meta = json.loads((Path(context) / "case.json").read_text())
            target_index = int(case_meta.get("tx_index", len(txs) - 1))
            original = txs[target_index].get("input") or txs[target_index].get("data") or "0x"
        except (OSError, ValueError, TypeError, IndexError, json.JSONDecodeError) as exc:
            return {}, f"cannot load target calldata: {exc}"
        override = mutation.calldata_override
        if mutation.start_cap is not None:
            override = start_cap_override(original, mutation.start_cap)
        if mutation.ratio is not None and original.startswith("0x") and len(original) >= 2 + 8 + 128:
            amount = int(original[2 + 8 + 64:2 + 8 + 128], 16)
            override = start_cap_override(original, int(amount * mutation.ratio))
        if not override:
            return {}, "calldata override could not be constructed"
        return {"target_data": override}, None

    return {}, f"mutation {mutation} is not supported by B2 adapter"


def target_payload(payload: dict) -> dict:
    """Return target telemetry from a B2 result payload."""
    results = payload.get("per_tx") or []
    index = int(payload.get("target_index", len(results) - 1))
    return results[index] if 0 <= index < len(results) else {}


def call_trace_diff(before: dict, after: dict) -> tuple[bool, int, int, int | None]:
    """Compare target call-entry telemetry and locate the first divergence."""
    def enters(item: dict) -> list[tuple]:
        return [(
            frame.get("depth"), frame.get("type"), frame.get("from"),
            frame.get("to"), frame.get("input"), frame.get("value"),
        ) for frame in item.get("call_trace", []) if frame.get("event") == "enter"]

    left, right = enters(before), enters(after)
    first = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), None)
    if first is None and len(left) != len(right):
        first = min(len(left), len(right))
    return left == right, len(left), len(right), first
