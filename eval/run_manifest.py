"""Small, dependency-free provenance manifests for evaluation artifacts."""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from importlib import metadata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_revision(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True,
            stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=root, text=True,
            stderr=subprocess.DEVNULL).strip())
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def utc_run_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}"


def portable_path(value: str | Path, root: Path) -> str:
    """Use a repository-relative path, or a host-neutral external placeholder."""
    path = Path(value)
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        # Absolute interpreter/input paths otherwise leak usernames and make
        # manifests machine-specific. The content hash still identifies an
        # external input when one is supplied.
        return f"<external>/{path.name or 'root'}"


def _portable_value(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {key: _portable_value(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_portable_value(item, root) for item in value]
    if isinstance(value, Path) or (isinstance(value, str) and Path(value).is_absolute()):
        return portable_path(value, root)
    return value


def redact_command_args(args: list[str],
                        secret_flags: tuple[str, ...] = ("--rpc", "--fork-rpc")) -> list[str]:
    """Redact secret-bearing CLI values before persisting a command line."""
    redacted: list[str] = []
    hide_next = False
    for value in map(str, args):
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        if value in secret_flags:
            redacted.append(value)
            hide_next = True
            continue
        inline = next((flag for flag in secret_flags
                       if value.startswith(flag + "=")), None)
        redacted.append(inline + "=<redacted>" if inline else value)
    return redacted


def _command_version(command: str) -> str | None:
    try:
        output = subprocess.check_output(
            [command, "--version"], text=True, stderr=subprocess.STDOUT,
            timeout=10,
        ).strip()
        return output.splitlines()[0] if output else None
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def runtime_provenance() -> dict[str, Any]:
    """Versions needed to interpret and replicate replay/evaluation runs."""
    packages = {}
    for package in ("numpy", "scipy", "matplotlib", "pycryptodome", "pytest", "ruff"):
        try:
            packages[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "tools": {name: _command_version(name) for name in ("anvil", "cast", "forge")},
        "packages": packages,
    }


def write_manifest(path: str | Path, *, run_id: str, experiment: str,
                   repository: str | Path, inputs: dict[str, str | Path],
                   parameters: dict[str, Any], command: list[str] | None = None,
                   extra: dict[str, Any] | None = None) -> Path:
    path = Path(path)
    root = Path(repository).resolve()
    payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "experiment": experiment,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": git_revision(root),
        "runtime": runtime_provenance(),
        "command": _portable_value(command if command is not None else sys.argv, root),
        "parameters": parameters,
        "inputs": {
            name: {"path": portable_path(value, root), "sha256": sha256_file(value)}
            for name, value in inputs.items()
        },
    }
    if extra:
        payload["extra"] = _portable_value(extra, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8", newline="\n")
    return path
