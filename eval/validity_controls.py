"""Local-only end-to-end positive and sham controls for E4 mutations."""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

from core.mutate import SHAM_ADDRESS, SHAM_SLOT, SHAM_VALUE
from core.rpc import RpcClient, RpcError

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "eval" / "results" / "validity_controls.json"
TARGET = "0x00000000000000000000000000000000ca11ab1e"
SLOT_ZERO = "0x" + "00" * 32
SLOT_ONE = "0x" + "00" * 31 + "01"
ONE = "0x" + "00" * 31 + "01"
ZERO = "0x" + "00" * 32
# Runtime: SLOAD(0), MSTORE(0), RETURN(0,32).
STORAGE_READER_RUNTIME = "0x60005460005260206000f3"
# Runtime: OR(SLOAD(0), SLOAD(1)); each single removal preserves 1, pair gives 0.
JOINT_OR_READER_RUNTIME = "0x6000546001541760005260206000f3"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _read(client: RpcClient) -> int:
    value = client.call("eth_call", [{"to": TARGET, "data": "0x"}, "latest"])
    return int(str(value), 16)


def run(out: Path = OUTPUT) -> dict:
    executable = shutil.which("anvil")
    if not executable:
        raise RuntimeError("anvil is required for the local validity-control fixture")
    port = _free_port()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [executable, "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        creationflags=flags,
    )
    client = RpcClient(f"http://127.0.0.1:{port}", timeout=2, attempts=1)
    try:
        for _ in range(40):
            if process.poll() is not None:
                raise RuntimeError("local anvil exited before readiness")
            try:
                client.eth_block_number()
                break
            except RpcError:
                time.sleep(0.1)
        else:
            raise RuntimeError("local anvil readiness timed out")

        client.anvil_set_code(TARGET, STORAGE_READER_RUNTIME)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ONE)
        baseline = _read(client)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ZERO)
        causal_mutated = _read(client)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ONE)
        client.anvil_set_storage(SHAM_ADDRESS, SHAM_SLOT, SHAM_VALUE)
        sham_mutated = _read(client)
        client.anvil_set_code(TARGET, JOINT_OR_READER_RUNTIME)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ONE)
        client.anvil_set_storage(TARGET, SLOT_ONE, ONE)
        joint_baseline = _read(client)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ZERO)
        joint_left_mutated = _read(client)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ONE)
        client.anvil_set_storage(TARGET, SLOT_ONE, ZERO)
        joint_right_mutated = _read(client)
        client.anvil_set_storage(TARGET, SLOT_ZERO, ZERO)
        joint_pair_mutated = _read(client)
        report = {
            "schema_version": 1,
            "scope": "local Anvil only; deterministic storage-reader fixture",
            "target": TARGET,
            "baseline": baseline,
            "causal_mutated": causal_mutated,
            "sham_mutated": sham_mutated,
            "joint_baseline": joint_baseline,
            "joint_left_mutated": joint_left_mutated,
            "joint_right_mutated": joint_right_mutated,
            "joint_pair_mutated": joint_pair_mutated,
            "positive_control_pass": baseline == 1 and causal_mutated == 0,
            "sham_control_pass": baseline == 1 and sham_mutated == 1,
            "joint_control_pass": (
                joint_baseline == 1 and joint_left_mutated == 1
                and joint_right_mutated == 1 and joint_pair_mutated == 0
            ),
        }
        if not all(report[key] for key in (
                "positive_control_pass", "sham_control_pass", "joint_control_pass")):
            raise RuntimeError(f"validity control failed: {report}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        return report
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
