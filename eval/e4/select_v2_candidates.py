"""Select a deterministic, cache-aware Phase 4 candidate batch."""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

from eval.e4.planner import ORACLE_GETTERS


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "eval" / "results" / "e4_preregistration_queue.csv"
DEFAULT_OUTPUT = ROOT / "eval" / "results" / "e4_v2_selected_candidates.csv"
DEFAULT_ORDER = ROOT / "eval" / "e4_v2_candidate_order.md"
DEFAULT_EXCLUSIONS = ROOT / "eval" / "e4_v2_exclusions.md"
DEFAULT_TRACE_CACHE = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"

# Known replay limitation already established by B2 acceptance-gate evidence.
KNOWN_REPLAY_LIMITATIONS = {
    "defihacklabs-sizeflashloanlooping-2025-08-15":
        "B2 prefix contains non-EOA senders; acceptance gate previously failed.",
}


class SelectionInputError(ValueError):
    """Raised when the queue is not explicit enough for safe selection."""


def _split_factors(value: str) -> list[str]:
    return [part.strip() for part in value.split("+") if part.strip()]


def protocol_name(case_id: str) -> str:
    """Return the stable protocol slug embedded in a DefiHackLabs case id."""
    match = re.fullmatch(r"defihacklabs-(.+)-\d{4}-\d{2}-\d{2}", case_id)
    return match.group(1) if match else case_id


def load_trace_cache(path: Path) -> dict[str, dict]:
    traces: dict[str, dict] = {}
    if not path.is_file():
        raise SelectionInputError(f"trace cache is missing: {path}")
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SelectionInputError(f"invalid trace cache JSON at line {line_number}") from exc
        tx_hash = str(row.get("tx_hash") or "").lower()
        if tx_hash:
            traces[tx_hash] = (row.get("trace") or {}).get("tree") or row.get("trace") or {}
    return traces


def runtime_oracle_mode(row: dict[str, str], trace: dict | None) -> str:
    """Classify the oracle signal using the planner's actual selector support."""
    if "f_orc" not in row["blind_candidate_factors"]:
        return "not-applicable"
    selectors: set[str] = set()
    stack = [trace or {}]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        input_data = str(node.get("input") or "").lower()
        if input_data.startswith("0x") and len(input_data) >= 10:
            selectors.add(input_data[2:10])
        stack.extend(node.get("calls") or [])
    modes: set[str] = set()
    if any(selector in ORACLE_GETTERS for selector in selectors):
        modes.add("external-price-feed")
    if "0902f1ac" in selectors:
        modes.add("amm-reserve")
    if not modes:
        return "unknown"
    return "+".join(sorted(modes))


def _require_fields(fieldnames: list[str] | None) -> None:
    required = {"case_id", "blind_candidate_factors", "supported_from_cache"}
    missing = sorted(required - set(fieldnames or []))
    if missing:
        raise SelectionInputError(
            "Queue is missing required fields: " + ", ".join(missing)
        )


def classify_cache(row: dict[str, str]) -> str:
    """Classify support without interpreting absent data as support."""
    factors = _split_factors(row["blind_candidate_factors"])
    supported = set(_split_factors(row["supported_from_cache"]))
    if not supported:
        return "none"
    if all(factor in supported for factor in factors) and not any(
        factor.endswith("?") for factor in factors
    ):
        return "full"
    return "partial"


def classify_tier(row: dict[str, str]) -> int:
    factors = _split_factors(row["blind_candidate_factors"])
    if len(factors) == 1 and not factors[0].endswith("?"):
        return 1
    if len(factors) == 2 and not any(factor.endswith("?") for factor in factors):
        return 2
    return 3


def _priority(row: dict[str, str]) -> tuple[int, int, str]:
    cache_rank = {"full": 0, "partial": 1, "none": 2}[row["cache_class"]]
    return cache_rank, row["tier"], row["case_id"]


def _selection_reason(row: dict[str, str]) -> str:
    reason = f"Tier {row['tier']} with {row['cache_class']} cache support."
    if row["cache_class"] == "partial":
        reason += " Missing/uncertain factors must be resolved before replay."
    if row["known_limitation"]:
        reason += " Known replay limitation is recorded."
    return reason


def load_queue(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        _require_fields(reader.fieldnames)
        rows = list(reader)
    if not rows:
        raise SelectionInputError(f"Queue is empty: {path}")
    return rows


def rank_candidates(rows: list[dict[str, str]], traces: dict[str, dict] | None = None,
                    *, oracle_mode: str | None = None,
                    max_tier: int | None = None) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    ranked: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    for source in rows:
        row = dict(source)
        row["cache_class"] = classify_cache(row)
        row["tier"] = classify_tier(row)
        row["protocol_name"] = protocol_name(row["case_id"])
        row["runtime_oracle_mode"] = runtime_oracle_mode(
            row, (traces or {}).get(row.get("tx_hash", "").lower())
        ) if traces is not None else "not-checked"
        row["known_limitation"] = KNOWN_REPLAY_LIMITATIONS.get(row["case_id"], "")
        if row["cache_class"] == "none":
            row["exclusion_reason"] = "supported_from_cache is empty."
            excluded.append(row)
        elif row["known_limitation"]:
            row["exclusion_reason"] = row["known_limitation"]
            excluded.append(row)
        elif traces is not None and row["runtime_oracle_mode"] != "external-price-feed":
            row["exclusion_reason"] = (
                "runtime planner does not support this oracle mode: "
                + row["runtime_oracle_mode"]
            )
            excluded.append(row)
        elif oracle_mode and row["runtime_oracle_mode"] != oracle_mode:
            row["exclusion_reason"] = f"runtime oracle mode is {row['runtime_oracle_mode']}; required {oracle_mode}."
            excluded.append(row)
        elif max_tier is not None and row["tier"] > max_tier:
            row["exclusion_reason"] = f"Tier {row['tier']} exceeds configured maximum Tier {max_tier}."
            excluded.append(row)
        else:
            ranked.append(row)
    ranked.sort(key=_priority)
    return ranked, excluded


def select_candidates(rows: list[dict[str, str]], count: int = 8,
                      traces: dict[str, dict] | None = None,
                      *, oracle_mode: str | None = None,
                      max_tier: int | None = None,
                      minimum: int = 5) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    ranked, excluded = rank_candidates(rows, traces=traces, oracle_mode=oracle_mode,
                                       max_tier=max_tier)
    tier1_or_2 = [row for row in ranked if row["tier"] <= (max_tier or 3)]
    if len(tier1_or_2) < minimum:
        raise SelectionInputError(
            f"Only {len(tier1_or_2)} candidates satisfy the configured runtime "
            f"oracle/tier criteria; fewer than the required {minimum}."
        )
    selected = ranked[:count]
    for row in selected:
        row["selection_reason"] = _selection_reason(row)
    for row in ranked[count:]:
        row["exclusion_reason"] = "Ranked below the selected N=8 buffer."
        excluded.append(row)
    return selected, excluded


def write_selected(path: Path, rows: list[dict[str, str]]) -> None:
    columns = [
        "rank", "case_id", "tx_hash", "block", "blind_candidate_factors",
        "protocol_name", "supported_from_cache", "cache_class", "tier",
        "runtime_oracle_mode", "trace_evidence",
        "selection_reason",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for rank, row in enumerate(rows, start=1):
            writer.writerow({
                "rank": rank,
                **{column: row.get(column, "") for column in columns if column != "rank"},
            })


def write_order(path: Path, rows: list[dict[str, str]]) -> None:
    lines = [
        "# E4 v2 candidate order",
        "",
        "Generated deterministically from `e4_preregistration_queue.csv`; the source queue was not modified.",
        "",
    ]
    for rank, row in enumerate(rows, start=1):
        lines.append(
            f"{rank}. `{row['case_id']}` — `{row['blind_candidate_factors']}`; "
            f"{row['cache_class']} cache; Tier {row['tier']}. {row['selection_reason']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_exclusions(path: Path, rows: list[dict[str, str]]) -> None:
    lines = ["# E4 v2 excluded candidates", "", "| Candidate | Reason |", "|---|---|"]
    for row in sorted(rows, key=lambda item: item["case_id"]):
        reason = row.get("exclusion_reason", "").replace("|", "\\|")
        lines.append(f"| `{row['case_id']}` | {reason} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(input_path: Path = DEFAULT_INPUT, output_path: Path = DEFAULT_OUTPUT,
        order_path: Path = DEFAULT_ORDER, exclusions_path: Path = DEFAULT_EXCLUSIONS,
        count: int = 8, trace_cache_path: Path = DEFAULT_TRACE_CACHE,
        oracle_mode: str = "external-price-feed", max_tier: int = 2,
        minimum: int = 5) -> dict[str, object]:
    rows = load_queue(input_path)
    traces = load_trace_cache(trace_cache_path)
    selected, excluded = select_candidates(
        rows, count=count, traces=traces, oracle_mode=oracle_mode,
        max_tier=max_tier, minimum=minimum,
    )
    write_selected(output_path, selected)
    write_order(order_path, selected)
    write_exclusions(exclusions_path, excluded)
    return {
        "input": str(input_path),
        "queue_columns": list(rows[0].keys()),
        "selected": len(selected),
        "queue_rows": len(rows),
        "selected_by_tier": dict(Counter(row["tier"] for row in selected)),
        "selected_by_cache": dict(Counter(row["cache_class"] for row in selected)),
        "excluded": len(excluded),
        "outputs": [str(output_path), str(order_path), str(exclusions_path)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--order", type=Path, default=DEFAULT_ORDER)
    parser.add_argument("--exclusions", type=Path, default=DEFAULT_EXCLUSIONS)
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--trace-cache", type=Path, default=DEFAULT_TRACE_CACHE)
    parser.add_argument("--oracle-mode", default="external-price-feed")
    parser.add_argument("--max-tier", type=int, default=2)
    parser.add_argument("--minimum", type=int, default=5)
    args = parser.parse_args()
    try:
        summary = run(args.input, args.output, args.order, args.exclusions,
                      args.count, args.trace_cache, args.oracle_mode,
                      args.max_tier, args.minimum)
    except SelectionInputError as exc:
        parser.error(str(exc))
    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
