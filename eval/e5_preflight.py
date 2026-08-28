"""Machine-readable archive/local-fork gate for the preregistered E5 run."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from core.env import load_dotenv, resolve_rpc
from core.rpc import RpcClient

from .fidelity import (FIDELITY_PORT, FROZEN_SET_DEFAULT, REPO_ROOT, RESULTS_DIR,
                       FidelityCase, load_fidelity_set, run_fidelity_case, write_csv)
from .run_manifest import (redact_command_args, sha256_file, utc_run_id,
                           write_manifest)


def endpoint_identity(urls: str) -> str:
    """Return a stable provider/route identity without credential material."""
    identities: list[str] = []
    for url in (value.strip() for value in urls.split("|") if value.strip()):
        parsed = urlsplit(url)
        segments = [segment for segment in parsed.path.split("/") if segment]
        if segments and (len(segments[-1]) >= 12 or segments[-2:-1] == ["v2"]):
            segments[-1] = "<credential>"
        query_names = sorted({name for name, _ in parse_qsl(parsed.query,
                                                             keep_blank_values=True)})
        safe = f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}"
        if parsed.port:
            safe += f":{parsed.port}"
        if segments:
            safe += "/" + "/".join(segments)
        if query_names:
            safe += "?" + "&".join(f"{name}=<redacted>" for name in query_names)
        identities.append(safe)
    return "|".join(identities)


def _probe(callable_) -> dict[str, object]:
    try:
        value = callable_()
        return {"pass": value is not None, "error_kind": "" if value is not None else "empty"}
    except Exception as exc:  # noqa: BLE001 - capability report must retain every stage
        message = str(exc).lower()
        kind = next((token for token in ("429", "408", "503", "timeout", "timed out")
                     if token in message), type(exc).__name__)
        return {"pass": False, "error_kind": kind}


def select_preflight_case(cases: list[FidelityCase]) -> FidelityCase:
    preferred = next((case for case in cases
                      if case.case_id == "defihacklabs-sashatoken-2024-10-06"), None)
    case = preferred or next((item for item in cases if item.tx_index == 0), None)
    if case is None or case.tx_index != 0:
        raise ValueError("E5 preflight requires a frozen k=0 case")
    return case


def run_preflight(case: FidelityCase, archive: RpcClient, fork_rpc: str,
                  fixed_set_path: Path = FROZEN_SET_DEFAULT,
                  port: int = FIDELITY_PORT, timeout: int = 300,
                  run_id: str = "") -> dict:
    capabilities: dict[str, dict[str, object]] = {}
    tx_box: dict[str, object] = {}
    trace_box: dict[str, object] = {}

    def transaction():
        tx_box["value"] = archive.eth_get_transaction(case.tx_hash)
        return tx_box["value"]

    capabilities["historical_transaction"] = _probe(transaction)
    capabilities["historical_receipt"] = _probe(
        lambda: archive.eth_get_receipt(case.tx_hash))

    def tracer():
        trace_box["value"] = archive.call(
            "debug_traceTransaction",
            [case.tx_hash, {"tracer": "prestateTracer",
                            "tracerConfig": {"diffMode": True}}],
        )
        value = trace_box["value"]
        return value if isinstance(value, dict) and isinstance(value.get("post"), dict) else None

    capabilities["prestate_diff_tracer"] = _probe(tracer)
    tx = tx_box.get("value") if isinstance(tx_box.get("value"), dict) else {}
    trace = trace_box.get("value") if isinstance(trace_box.get("value"), dict) else {}
    addresses = list((trace.get("post") or {}).keys()) if isinstance(trace, dict) else []
    target = (tx.get("to") if isinstance(tx, dict) else None) or (
        addresses[0] if addresses else (tx.get("from") if isinstance(tx, dict) else None))
    block_tag = hex(case.block - 1)
    capabilities["historical_code"] = _probe(
        lambda: archive.eth_get_code(str(target), block_tag) if target else None)
    capabilities["historical_storage"] = _probe(
        lambda: archive.eth_get_storage(str(target), "0x0", block_tag) if target else None)

    try:
        replay = run_fidelity_case(case, fork_rpc, archive, port=port,
                                   timeout=timeout, state_delta=True, run_id=run_id)
    except Exception as exc:  # noqa: BLE001 - retain a bounded failure row
        replay = {
            "run_id": run_id, "fidelity_schema": "transaction-local-v2",
            "case": case.case_id, "protocol": case.protocol,
            "attack_type": case.attack_type, "tx_hash": case.tx_hash,
            "block": case.block, "tx_index": case.tx_index, "mutation": "fidelity",
            "outcome": "ERROR", "observed": False, "status": "",
            "gas_used": "", "mainnet_gas": case.mainnet_gas or "",
            "gas_delta_pct": "", "execution_pass": False,
            "state_eligible": False, "state_pass": False, "joint_pass": False,
            "pass": False, "state_cells": 0, "state_match": 0.0,
            "state_errors": 1, "state_mode": "none", "reason": case.reason,
            "note": f"preflight exception: {type(exc).__name__}",
        }
    direct_ready = all(bool(stage["pass"]) for stage in capabilities.values())
    observed = str(replay.get("observed")) == "True"
    return {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "case_id": case.case_id,
        "tx_hash": case.tx_hash,
        "tx_index": case.tx_index,
        "fixed_set_sha256": sha256_file(fixed_set_path),
        "archive_endpoint": endpoint_identity(archive.url),
        "fork_endpoint": endpoint_identity(fork_rpc),
        "capabilities": capabilities,
        "replay_observed": observed,
        "ready_for_fixed20": bool(direct_ready and observed),
        "replay": replay,
    }


def verify_preflight(payload: dict, fixed_set_path: Path, archive_rpc: str,
                     fork_rpc: str, max_age_hours: int = 24,
                     now: datetime | None = None) -> list[str]:
    """Fail-closed validation used by E5 paper mode."""
    errors: list[str] = []
    if not payload.get("ready_for_fixed20"):
        errors.append("preflight_not_ready")
    if payload.get("replay_observed") is not True:
        errors.append("preflight_receipt_unobserved")
    if payload.get("tx_index") != 0:
        errors.append("preflight_case_not_k0")
    if payload.get("fixed_set_sha256") != sha256_file(fixed_set_path):
        errors.append("fixed_set_hash_mismatch")
    if payload.get("archive_endpoint") != endpoint_identity(archive_rpc):
        errors.append("archive_endpoint_mismatch")
    if payload.get("fork_endpoint") != endpoint_identity(fork_rpc):
        errors.append("fork_endpoint_mismatch")
    try:
        created = datetime.fromisoformat(str(payload["created_at_utc"]))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current - created > timedelta(hours=max_age_hours) or created > current:
            errors.append("preflight_expired_or_future")
    except (KeyError, TypeError, ValueError):
        errors.append("preflight_timestamp_invalid")
    return errors


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", default=None)
    parser.add_argument("--fork-rpc", default=None)
    parser.add_argument("--set-file", type=Path, default=FROZEN_SET_DEFAULT)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--port", type=int, default=FIDELITY_PORT)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--rpc-timeout", type=float, default=20.0)
    parser.add_argument("--rpc-attempts", type=int, default=2)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    rpc = args.rpc or resolve_rpc()
    if not rpc:
        raise SystemExit("Cn archive RPC trong .env hoc --rpc")
    fork_rpc = args.fork_rpc or rpc
    cases, _ = load_fidelity_set(args.set_file)
    case = select_preflight_case(cases)
    run_id = args.run_id or utc_run_id("e5-preflight")
    out_dir = args.out_dir or RESULTS_DIR / "runs" / run_id
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"preflight output directory must be empty: {out_dir}")
    archive = RpcClient(rpc, timeout=args.rpc_timeout, attempts=args.rpc_attempts)
    payload = run_preflight(case, archive, fork_rpc, args.set_file,
                            args.port, args.timeout, run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "e5_preflight.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    write_csv([payload["replay"]], out_dir / "e5_fidelity.csv")
    write_manifest(
        out_dir / "manifest.json", run_id=run_id, experiment="E5-capability-preflight",
        repository=REPO_ROOT, inputs={"fixed_set": args.set_file},
        parameters={"case_id": case.case_id, "timeout_s": args.timeout,
                    "rpc_timeout_s": args.rpc_timeout, "rpc_attempts": args.rpc_attempts},
        command=redact_command_args([sys.executable, "-m", "eval.e5_preflight", *argv]),
        extra={"ready_for_fixed20": payload["ready_for_fixed20"],
               "archive_endpoint": payload["archive_endpoint"],
               "fork_endpoint": payload["fork_endpoint"]},
    )
    safe = {key: payload[key] for key in (
        "run_id", "case_id", "capabilities", "replay_observed", "ready_for_fixed20")}
    print(json.dumps(safe, indent=2, ensure_ascii=False))
    return 0 if payload["ready_for_fixed20"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
