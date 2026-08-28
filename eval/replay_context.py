"""Immutable archive context and manifest helpers for pilot replay.

The context is deliberately boring: archive acquisition writes JSON once and
the local replay consumes only this directory.  A missing or modified input is
an error, never an invitation to query another provider.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_FILES = (
    "case.json", "transaction.json", "receipt.json", "block.json",
    "prior_transactions.json", "mainnet_state_diff.json", "prestate_cells.json",
)
_SECRET = re.compile(r"(?i)(https?://[^/\s]+)(?:/[^\s]*)?")


class CacheMissError(RuntimeError):
    """The immutable archive context is absent or incomplete."""


def trace_cache_path(root: str | Path, chain: str, tx_hash: str) -> Path:
    """Stable path for a raw transaction trace, keyed by chain and tx hash."""
    return Path(root) / chain / f"{tx_hash.lower()}.json"


def write_trace_cache(root: str | Path, *, chain: str, tx_hash: str,
                      block: int, trace: dict[str, Any], provider: str) -> Path:
    """Persist one raw prestate diff locally, without credentials."""
    if not isinstance(trace, dict) or not isinstance(trace.get("post"), dict):
        raise CacheMissError("trace has no prestateTracer.diffMode post map")
    path = trace_cache_path(root, chain, tx_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "tx_hash": tx_hash,
        "block": block,
        "tracer": "prestateTracer",
        "diff_mode": True,
        "provider_identity": provider_identity(provider),
        "trace": trace,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    return path


def load_trace_cache(root: str | Path, *, chain: str, tx_hash: str) -> dict[str, Any]:
    """Load one trace cache entry; missing/corrupt entries fail closed."""
    path = trace_cache_path(root, chain, tx_hash)
    if not path.is_file():
        raise CacheMissError(f"trace cache missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CacheMissError(f"trace cache unreadable: {path}") from exc
    trace = payload.get("trace") if isinstance(payload, dict) else None
    if (payload.get("tx_hash", "").lower() != tx_hash.lower()
            or payload.get("tracer") != "prestateTracer"
            or payload.get("diff_mode") is not True
            or not isinstance(trace, dict)
            or not isinstance(trace.get("post"), dict)):
        raise CacheMissError(f"trace cache invalid: {path}")
    return trace


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provider_identity(endpoint: str) -> str:
    """Stable, credential-free endpoint identity for manifests."""
    if not endpoint:
        return ""
    value = endpoint.split("?", 1)[0].rstrip("/")
    parts = value.split("/")
    if len(parts) > 3:
        parts[-1] = "<credential>"
    return "/".join(parts)


def redacted_diagnostic(value: Any, limit: int = 512) -> str:
    text = str(value or "")
    text = _SECRET.sub(lambda m: m.group(1) + "/<redacted>", text)
    text = re.sub(r"(?i)(api[_-]?key|token|secret|password)=([^\s&]+)",
                  r"\1=<redacted>", text)
    return text[:limit]


def canonical_quantity(value: Any) -> str | None:
    """Canonical lower-case EVM quantity; bytecode is handled separately."""
    if value is None:
        return None
    if isinstance(value, int):
        return hex(value)
    text = str(value).lower()
    try:
        return hex(int(text, 16)) if text.startswith("0x") else hex(int(text))
    except ValueError:
        return text


def normalize_post_diff(diff: dict[str, Any]) -> dict[str, Any]:
    """Keep only and normalize transaction-local ``diff.post`` cells."""
    post = diff.get("post") if isinstance(diff, dict) else None
    if not isinstance(post, dict):
        return {}
    out: dict[str, Any] = {}
    for address, raw in post.items():
        if not isinstance(raw, dict):
            continue
        cell: dict[str, Any] = {}
        for key in ("balance", "nonce"):
            if key in raw:
                cell[key] = canonical_quantity(raw[key])
        if "code" in raw:
            cell["code"] = str(raw["code"] or "0x").lower()
        if isinstance(raw.get("storage"), dict):
            cell["storage"] = {
                str(slot).lower(): canonical_quantity(value)
                for slot, value in raw["storage"].items()
            }
        out[str(address).lower()] = cell
    return out


def cell_count(post: dict[str, Any]) -> int:
    total = 0
    for account in post.values():
        total += sum(key in account for key in ("balance", "nonce", "code"))
        total += len(account.get("storage", {}))
    return total


@dataclass(frozen=True)
class ReplayContext:
    root: Path
    case: dict[str, Any]
    inputs: dict[str, str]
    manifest: dict[str, Any]

    @property
    def transaction(self) -> dict[str, Any]:
        return json.loads((self.root / "transaction.json").read_text())

    @property
    def receipt(self) -> dict[str, Any]:
        return json.loads((self.root / "receipt.json").read_text())

    @property
    def prior_transactions(self) -> list[dict[str, Any]]:
        return json.loads((self.root / "prior_transactions.json").read_text())

    @property
    def state_diff(self) -> dict[str, Any]:
        return json.loads((self.root / "mainnet_state_diff.json").read_text())


def write_context(root: str | Path, *, case: dict[str, Any], transaction: dict[str, Any],
                  receipt: dict[str, Any], block: dict[str, Any],
                  prior_transactions: list[dict[str, Any]], state_diff: dict[str, Any],
                  provider: str, run_id: str, timeout_policy: dict[str, Any]) -> Path:
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    payloads = {
        "case.json": case,
        "transaction.json": transaction,
        "receipt.json": receipt,
        "block.json": block,
        "prior_transactions.json": prior_transactions,
        "mainnet_state_diff.json": state_diff,
        "prestate_cells.json": normalize_post_diff(state_diff),
    }
    for name, payload in payloads.items():
        (path / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8", newline="\n")
    inputs = {name: sha256_file(path / name) for name in REQUIRED_FILES}
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "provider": "alchemy",
        "provider_identity": provider_identity(provider),
        "case": case.get("case_id", case.get("case")),
        "tx_hash": case.get("tx_hash"),
        "block": case.get("block"),
        "tx_index": case.get("tx_index"),
        "state_block": int(case["block"]) - 1,
        "prior_count": len(prior_transactions),
        "state_cells": cell_count(payloads["prestate_cells.json"]),
        "timeout_policy": timeout_policy,
        "inputs": inputs,
    }
    (path / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8", newline="\n")
    return path


def load_context(root: str | Path) -> ReplayContext:
    path = Path(root)
    if not path.is_dir():
        raise CacheMissError(f"replay context missing: {path}")
    missing = [name for name in (*REQUIRED_FILES, "manifest.json") if not (path / name).is_file()]
    if missing:
        raise CacheMissError("replay context incomplete: " + ",".join(missing))
    manifest = json.loads((path / "manifest.json").read_text())
    inputs = manifest.get("inputs", {})
    for name in REQUIRED_FILES:
        expected = inputs.get(name)
        if not expected or expected != sha256_file(path / name):
            raise CacheMissError(f"replay context checksum mismatch: {name}")
    case = json.loads((path / "case.json").read_text())
    return ReplayContext(path, case, inputs, manifest)
