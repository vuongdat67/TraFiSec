"""Python boundary for the local go-ethereum B2 runner.

The boundary is intentionally fail-closed: callers must provide a prepared
context containing receipts, prestates and verified proofs.  It never falls
back to Anvil/Replayer when B2 is requested.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BINARY = REPO_ROOT / "tools" / "geth-replay" / "geth-replay"


@dataclass
class B2Run:
    payload: dict
    observed: bool
    status: bool | None
    gas_used: int | None
    gas_limit: int | None
    error: str = ""

    @property
    def proof_verified(self) -> bool:
        return bool(self.payload.get("prestate_proof_verified"))


def run(context: str | Path, *, timeout: int = 300,
        target_data: str | None = None,
        target_code: dict[str, str] | None = None,
        target_storage: dict[str, dict[str, str]] | None = None,
        target_index: int | None = None) -> B2Run:
    root = Path(context)
    required = (root / "prestates.json", root / "receipts.json",
                root / "prestate_proofs.json")
    if not all(path.is_file() for path in required):
        return B2Run({}, False, None, None, None, "b2_context_incomplete")
    if not BINARY.is_file():
        return B2Run({}, False, None, None, None, "b2_runner_binary_missing")
    # Each invocation gets a unique output path.  Accepting a fixed "last"
    # file would allow a timed-out or failed subprocess to be mistaken for a
    # successful result from the current run.
    output = root / f"b2-run-{uuid.uuid4().hex}.json"
    command = [str(BINARY), "--context", str(root), "--proofs",
               str(root / "prestate_proofs.json"), "--output", str(output)]
    if target_index is not None:
        command.extend(["--target-index", str(target_index)])
    if target_data:
        command.extend(["--target-data", target_data])
    for address, code in (target_code or {}).items():
        command.extend(["--target-code", f"{address}={code}"])
    for address, slots in (target_storage or {}).items():
        for slot, value in slots.items():
            command.extend(["--target-storage", f"{address}:{slot}={value}"])
    try:
        proc = subprocess.run(
            command,
            capture_output=True, text=True, timeout=timeout,
            cwd=REPO_ROOT,
        )
    except subprocess.TimeoutExpired:
        return B2Run({}, False, None, None, None, "b2_runner_timeout")
    if proc.returncode not in (0, 2):
        return B2Run({}, False, None, None, None,
                     f"b2_runner_exit_{proc.returncode}:{proc.stderr[-256:]}")
    if not output.is_file():
        return B2Run({}, False, None, None, None,
                     f"b2_runner_no_output:{proc.stderr[-256:]}")
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return B2Run({}, False, None, None, None, f"b2_runner_invalid_output:{exc}")
    results = payload.get("per_tx") or []
    target_pos = int(payload.get("target_index", len(results) - 1))
    target = results[target_pos] if results and 0 <= target_pos < len(results) else {}
    return B2Run(
        payload=payload,
        observed=bool(results) and not target.get("error"),
        status=(target.get("actual_status") if results else None),
        gas_used=(target.get("actual_gas") if results else None),
        gas_limit=payload.get("chain_rules", {}).get("header_gas_limit"),
        error=("; ".join(x.get("error", "") for x in results if x.get("error"))
               or (proc.stderr[-512:] if proc.returncode not in (0, 2) else "")),
    )
