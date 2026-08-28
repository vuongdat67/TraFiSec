"""Sequential execution adapter for the frozen E4 systematic subset.

The frozen subset is authoritative input. This adapter translates its rows to
the official ``eval.e4_necessity.run_candidate`` input shape without applying
the unrelated external-price-feed filter used by the older selected-candidate
CSV CLI. B2 acceptance, blind planning, execution, harm, and verdict policy
remain owned by existing modules.
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from urllib.parse import urlparse

from eval.e4_stage2_subset import ROOT, sha256_file
from eval.e4_necessity import run_candidate
from core.env import load_dotenv, resolve_rpc_candidates, resolve_trace_rpc_candidates
from core.rpc import RpcClient

DEFAULT_SUBSET = ROOT / "eval" / "results" / "e4_stage2_subset_manifest.json"
DEFAULT_QUEUE = ROOT / "eval" / "e4_fixed_set_v2.json"
DEFAULT_TRACE_CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
DEFAULT_PRICE_MANIFEST = ROOT / "eval" / "e4_price_manifest.json"


def _git_revision() -> dict[str, str | bool | None]:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True,
            stderr=subprocess.DEVNULL,
        ).strip())
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def _provider_id(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return parsed.hostname or "configured-rpc"


def _command_version(command: str) -> str | None:
    try:
        output = subprocess.check_output(
            [command, "--version"], text=True, stderr=subprocess.STDOUT,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return output.strip().splitlines()[0] if output.strip() else None


def _package_versions() -> dict[str, str | None]:
    names = ("numpy", "scipy", "pytest", "ruff")
    return {
        name: _package_version(name)
        for name in names
    }


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def load_protocol(subset_path: Path = DEFAULT_SUBSET,
                  queue_path: Path = DEFAULT_QUEUE) -> tuple[dict, dict[str, dict]]:
    """Load frozen subset and exact source rows; reject drift before RPC."""
    subset = json.loads(subset_path.read_text(encoding="utf-8"))
    if subset.get("status") != "protocol-frozen-before-execution":
        raise ValueError("subset manifest is not execution-frozen")
    if subset.get("source_queue_sha256") != sha256_file(queue_path):
        raise ValueError("fixed queue hash does not match frozen subset manifest")
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    rows = {row["case_id"]: row for row in queue["cases"]}
    selected = subset.get("selected_cases") or []
    if len(selected) != int(subset.get("subset_size", 0)):
        raise ValueError("selected case count does not match frozen subset size")
    selected_rows: dict[str, dict] = {}
    for selected_row in selected:
        case_id = selected_row["case_id"]
        source = rows.get(case_id)
        if source is None:
            raise ValueError(f"selected case missing from fixed queue: {case_id}")
        for key in ("tx_hash", "block", "supported_from_cache"):
            if str(source.get(key)) != str(selected_row.get(key)):
                raise ValueError(f"selected case drift for {case_id}: {key}")
        selected_rows[case_id] = source
    return subset, selected_rows


def candidate_row(source: dict) -> dict[str, str]:
    """Adapt fixed-queue metadata to official run_candidate input shape."""
    return {
        "case_id": source["case_id"],
        "tx_hash": source["tx_hash"],
        "block": str(source["block"]),
        "blind_candidate_factors": source.get("blind_candidate_factors", ""),
        "supported_from_cache": source["supported_from_cache"],
        "protocol_name": source["case_id"],
        "trace_evidence": source.get("trace_evidence", ""),
    }


def _case_failure(case_id: str, error: Exception) -> dict:
    return {
        "case_id": case_id,
        "system_status": "INCONCLUSIVE",
        "technical_failure": type(error).__name__,
        "error": str(error),
        "replacement": False,
    }


def _artifact_hashes(*directories: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for directory in directories:
        if not directory.exists():
            continue
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            hashes[str(path.relative_to(ROOT))] = sha256_file(path)
    return hashes


def execute(subset_path: Path = DEFAULT_SUBSET, queue_path: Path = DEFAULT_QUEUE,
            trace_cache: Path = DEFAULT_TRACE_CACHE,
            price_manifest: Path = DEFAULT_PRICE_MANIFEST,
            run_id: str | None = None, timeout: int = 900,
            acquire: bool = True,
            planner_discovered: bool = False) -> dict:
    """Execute selected rows sequentially; continue after one case failure."""
    load_dotenv()
    subset_path = subset_path.resolve()
    queue_path = queue_path.resolve()
    trace_cache = trace_cache.resolve()
    price_manifest = price_manifest.resolve()
    subset, sources = load_protocol(subset_path, queue_path)
    archive_urls = resolve_rpc_candidates("mainnet")
    trace_urls = resolve_trace_rpc_candidates("mainnet")
    if not archive_urls:
        raise RuntimeError("no archive RPC configured")
    run_id = run_id or datetime.now(timezone.utc).strftime("e4-stage2-%Y%m%dT%H%M%SZ")
    output_dir = ROOT / "eval" / "results" / "runs" / run_id
    output_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = output_dir / "run_metadata.json"
    metadata_payload = {
        "schema_version": 1,
        "run_id": run_id,
        "experiment": "E4-stage2-systematic-subset",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": _git_revision(),
        "inputs": {
            "subset_manifest": {"path": str(subset_path.relative_to(ROOT)),
                                 "sha256": sha256_file(subset_path)},
            "fixed_queue": {"path": str(queue_path.relative_to(ROOT)),
                            "sha256": sha256_file(queue_path)},
            "trace_cache": {"path": str(trace_cache.relative_to(ROOT)),
                             "sha256": sha256_file(trace_cache)},
            "price_manifest": {"path": str(price_manifest.relative_to(ROOT)),
                                "sha256": sha256_file(price_manifest)},
            "adapter": {"path": str(Path(__file__).relative_to(ROOT)),
                        "sha256": sha256_file(Path(__file__))},
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": _package_versions(),
            "go_ethereum_backend": "tools/geth-replay",
            "tools": {
                command: _command_version(command)
                for command in ("go", "anvil", "cast", "forge")
            },
        },
        "providers": {
            "archive": _provider_id(archive_urls[0]),
            "trace": _provider_id(trace_urls[0]) if trace_urls else None,
        },
        "parameters": {
            "selection_rule": subset["selection_rule"],
            "case_order": [row["case_id"] for row in subset["selected_cases"]],
            "timeout_seconds": timeout,
            "replacement_after_runtime_start": False,
            "acquire_context": acquire,
            "planner_discovered_mutations": planner_discovered,
        },
    }
    metadata_path.write_text(json.dumps(metadata_payload, indent=2) + "\n", encoding="utf-8")

    archive = RpcClient(archive_urls[0], timeout=60, attempts=2,
                        fallback_urls=archive_urls[1:])
    trace_rpc = (RpcClient(trace_urls[0], timeout=60, attempts=2,
                           fallback_urls=trace_urls[1:]) if trace_urls else None)
    results: list[dict] = []
    for selected in subset["selected_cases"]:
        case_id = selected["case_id"]
        case_run_id = f"{run_id}-q{selected['queue_index']:02d}-{case_id}"
        case_output = output_dir / f"q{selected['queue_index']:02d}-{case_id}"
        context = case_output / "b2-context"
        case_output.mkdir(parents=True, exist_ok=True)
        try:
            rows = run_candidate(
                candidate_row(sources[case_id]), archive=archive, trace_rpc=trace_rpc,
                context=context, price_manifest=price_manifest,
                trace_cache=trace_cache,
                run_id=case_run_id,
                timeout=timeout, acquire=acquire,
                planner_discovered=planner_discovered,
            )
            summary = {
                "queue_index": selected["queue_index"],
                "case_id": case_id,
                "system_status": "OBSERVED",
                "rows": rows,
                "replacement": False,
                "artifact_hashes": _artifact_hashes(
                    case_output, ROOT / "eval" / "results" / "runs" / case_run_id,
                ),
            }
        except Exception as error:  # noqa: BLE001 — one case must not erase subset denominator
            summary = {
                "queue_index": selected["queue_index"],
                **_case_failure(case_id, error),
                "artifact_hashes": _artifact_hashes(case_output),
            }
        (case_output / "system_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        results.append(summary)

    report = {
        "run_id": run_id,
        "selected": len(subset["selected_cases"]),
        "completed": sum(item["system_status"] == "OBSERVED" for item in results),
        "inconclusive": sum(item["system_status"] == "INCONCLUSIVE" for item in results),
        "results": results,
    }
    (output_dir / "systematic_subset_summary.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subset", type=Path, default=DEFAULT_SUBSET)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--trace-cache", type=Path, default=DEFAULT_TRACE_CACHE)
    parser.add_argument("--price-manifest", type=Path, default=DEFAULT_PRICE_MANIFEST)
    parser.add_argument("--run-id")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--no-acquire", action="store_true")
    parser.add_argument("--planner-discovered-mutations", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(execute(
        subset_path=args.subset, queue_path=args.queue,
        trace_cache=args.trace_cache, price_manifest=args.price_manifest,
        run_id=args.run_id, timeout=args.timeout, acquire=not args.no_acquire,
        planner_discovered=args.planner_discovered_mutations,
    ), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
