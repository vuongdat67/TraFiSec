"""Acquire local Merkle proofs for the B2 transaction-relevant prestate.

Proof acquisition is deliberately resumable. A large mid-block context can
contain thousands of accounts, and a timeout must not discard proofs already
accepted by the archive provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Iterable

from core.env import load_dotenv, resolve_rpc
from core.rpc import RpcClient, RpcError
from eval.replay_context import provider_identity, redacted_diagnostic


DEFAULT_CHUNK_SIZE = 50
DEFAULT_CHUNK_ATTEMPTS = 3
B2_RUNNER = Path(__file__).resolve().parent.parent / "tools" / "geth-replay" / "geth-replay"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")


def _write_atomic(path: Path, value: object) -> None:
    """Publish a complete JSON artifact, never a partially written one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    _write(temporary, value)
    temporary.replace(path)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _accounts_from_traces(traces: list[dict]) -> dict[str, set[str]]:
    accounts: dict[str, set[str]] = {}
    for row in traces:
        trace = row.get("trace") or {}
        for address, raw in trace.items():
            address = address.lower()
            accounts.setdefault(address, set())
            for slot in (raw.get("storage") or {}):
                accounts[address].add(slot.lower())
    return accounts


def _authorization_authorities(context: Path) -> list[str]:
    """Recover EIP-7702 authorities with go-ethereum's canonical signer logic."""
    transactions_path = context / "transactions.json"
    if transactions_path.is_file() and json.loads(
        transactions_path.read_text(encoding="utf-8")
    ) == []:
        return []
    if not B2_RUNNER.is_file():
        raise RuntimeError(f"B2 runner missing: {B2_RUNNER}")
    try:
        result = subprocess.run(
            [str(B2_RUNNER), "--context", str(context), "--list-authorities"],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("authority extraction timed out") from exc
    if result.returncode != 0:
        raise RuntimeError(
            "authority extraction failed: " + result.stderr[-512:]
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("authority extraction returned malformed JSON") from exc
    addresses = payload.get("required_accounts", payload.get("authorities"))
    if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
        raise RuntimeError("authority extraction returned invalid required accounts")
    return [a.lower() for a in addresses]


def _load_reusable_proofs(context: Path, accounts: dict[str, set[str]]) -> dict[str, dict]:
    """Reuse proofs whose requested address/key set is unchanged across context extension."""
    path = context / "prestate_proofs.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    reusable: dict[str, dict] = {}
    for item in payload.get("proofs", []):
        address = str(item.get("address") or "").lower()
        keys = {str(key).lower() for key in item.get("storage_keys", [])}
        if address in accounts and keys == accounts[address]:
            reusable[address] = item
    return reusable


def _authorization_accounts(
    proofs: dict[str, dict], required_accounts: list[str], archive: RpcClient,
    state_block: str,
) -> dict[str, dict]:
    """Bind recovered authorities to authenticated account values for StateDB injection."""
    accounts: dict[str, dict] = {}
    for address in required_accounts:
        item = proofs.get(address)
        if item is None:
            raise RpcError(f"missing proof for EIP-7702 authority {address}")
        proof = item.get("proof") or {}
        code = archive.call("eth_getCode", [address, state_block])
        if not isinstance(code, str):
            raise RpcError(f"eth_getCode returned invalid value for authority {address}")
        accounts[address] = {
            "balance": proof.get("balance", "0x0"),
            "nonce": int(str(proof.get("nonce", "0x0")), 16),
            "code": code,
        }
    return accounts


def _context_fingerprint(block_number: int, state_root: str,
                         accounts: dict[str, set[str]]) -> str:
    canonical = {
        "block": block_number,
        "state_root": state_root,
        "accounts": {address: sorted(keys)
                      for address, keys in sorted(accounts.items())},
    }
    return hashlib.sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


def _chunked(values: list[str], size: int) -> Iterable[tuple[int, list[str]]]:
    for index in range(0, len(values), size):
        yield index // size, values[index:index + size]


def _load_progress(context: Path, fingerprint: str) -> tuple[dict, dict[str, dict]]:
    """Load only chunk artifacts belonging to the current proof request."""
    progress_path = context / "proof_progress.json"
    if not progress_path.is_file():
        return {"context_fingerprint": fingerprint}, {}
    progress = json.loads(progress_path.read_text(encoding="utf-8"))
    if progress.get("context_fingerprint") != fingerprint:
        return {"context_fingerprint": fingerprint}, {}
    chunk_dir = context / "proof_chunks"
    proofs: dict[str, dict] = {}
    for chunk_name in progress.get("chunk_files", []):
        chunk_path = chunk_dir / chunk_name
        if not chunk_path.is_file():
            continue
        chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
        if chunk.get("context_fingerprint") != fingerprint:
            continue
        for item in chunk.get("proofs", []):
            proofs[item["address"]] = item
    return progress, proofs


def _fetch_proof(archive: RpcClient, address: str, keys: list[str],
                 state_block: str, attempts: int,
                 backoff_seconds: float = 1.0) -> dict:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            proof = archive.call("eth_getProof", [address, keys, state_block])
            if not isinstance(proof, dict) or not isinstance(proof.get("accountProof"), list):
                raise RpcError("eth_getProof returned no accountProof")
            return {"address": address, "storage_keys": keys, "proof": proof}
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(backoff_seconds * (attempt + 1))
    assert last_error is not None
    raise last_error


def acquire(context: Path, archive: RpcClient, *,
            chunk_size: int = DEFAULT_CHUNK_SIZE,
            chunk_attempts: int = DEFAULT_CHUNK_ATTEMPTS) -> dict:
    if chunk_size < 1 or chunk_attempts < 1:
        raise ValueError("chunk_size and chunk_attempts must be positive")
    block = json.loads((context / "block.json").read_text())
    block_number = int(block["number"], 16)
    state_block = hex(block_number - 1)
    header = archive.call("eth_getBlockByNumber", [state_block, False])
    if not isinstance(header, dict) or not header.get("stateRoot"):
        raise RpcError("state-block header/stateRoot unavailable")
    traces = json.loads((context / "prestates.json").read_text())
    accounts = _accounts_from_traces(traces)
    authorities = _authorization_authorities(context)
    for address in authorities:
        accounts.setdefault(address, set())
    fingerprint = _context_fingerprint(block_number, header["stateRoot"], accounts)
    progress, known_proofs = _load_progress(context, fingerprint)
    known_proofs.update(_load_reusable_proofs(context, accounts))
    addresses = sorted(accounts)
    chunk_dir = context / "proof_chunks"
    started = time.monotonic()
    failures: list[dict] = []
    chunk_files: list[str] = list(progress.get("chunk_files", []))

    for chunk_index, chunk_addresses in _chunked(addresses, chunk_size):
        chunk_name = f"chunk-{chunk_index:05d}.json"
        chunk_proofs: list[dict] = []
        chunk_failures: list[dict] = []
        for address in chunk_addresses:
            if address in known_proofs:
                chunk_proofs.append(known_proofs[address])
                continue
            keys = sorted(accounts[address])
            try:
                item = _fetch_proof(archive, address, keys, state_block,
                                    chunk_attempts)
                known_proofs[address] = item
                chunk_proofs.append(item)
            except Exception as exc:
                chunk_failures.append({
                    "address": address,
                    "storage_keys": keys,
                    "failure_class": "proof_transport_or_provider",
                    "diagnostic": redacted_diagnostic(exc),
                })
        _write_atomic(chunk_dir / chunk_name, {
            "schema_version": 1,
            "context_fingerprint": fingerprint,
            "chunk_index": chunk_index,
            "addresses": chunk_addresses,
            "proofs": chunk_proofs,
            "failures": chunk_failures,
        })
        if chunk_name not in chunk_files:
            chunk_files.append(chunk_name)
        failures.extend(chunk_failures)
        _write_atomic(context / "proof_progress.json", {
            "schema_version": 2,
            "context_fingerprint": fingerprint,
            "block": block_number,
            "state_block": block_number - 1,
            "chunk_size": chunk_size,
            "chunk_attempts": chunk_attempts,
            "total_account_count": len(addresses),
            "proof_count": len(known_proofs),
            "failure_count": len(failures),
            "chunk_files": sorted(chunk_files),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        })

    proofs = [known_proofs[address] for address in addresses
              if address in known_proofs]
    authorization_accounts = _authorization_accounts(
        known_proofs, authorities, archive, state_block
    )
    _write_atomic(context / "authorization_accounts.json", authorization_accounts)
    payload = {
        "schema_version": 2,
        "block": block_number,
        "state_block": block_number - 1,
        "state_root": header["stateRoot"],
        "account_count": len(accounts),
        "proof_count": len(proofs),
        "failures": failures,
        "chunk_size": chunk_size,
        "chunk_attempts": chunk_attempts,
        "resumed_proof_count": len(proofs),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "provider_identity": provider_identity(archive.url),
        "prestate_proof_complete": not failures and len(proofs) == len(accounts),
        "authorization_count": len(authorities),
        "authorization_accounts_path": "authorization_accounts.json",
        "global_state_root_scope": "out_of_scope: full world-state trie is not reconstructed",
        "note": "Proofs cover transaction-relevant account/storage cells at block-1.",
    }
    _write_atomic(context / "prestate_proofs.json", {"header": header, "proofs": proofs})
    payload["input_hash"] = _sha(context / "prestate_proofs.json")
    _write_atomic(context / "proof_manifest.json", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--rpc", default=None)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--chunk-attempts", type=int, default=DEFAULT_CHUNK_ATTEMPTS)
    args = parser.parse_args()
    load_dotenv()
    rpc = args.rpc or resolve_rpc("mainnet")
    if not rpc:
        parser.error("missing archive RPC")
    result = acquire(args.context, RpcClient(rpc, timeout=60, attempts=2),
                     chunk_size=args.chunk_size, chunk_attempts=args.chunk_attempts)
    print(json.dumps(result, indent=2))
    return 0 if result["prestate_proof_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
