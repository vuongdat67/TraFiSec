"""
TraFiSec Benchmark Dataset Loader & Verifier
Loads and validates verified DeFi exploit incidents and background transactions.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
INCIDENTS_PATH = CORPUS_DIR / "incidents.jsonl"
VERIFIED_PATH = CORPUS_DIR / "verified_attacks.tsv"


def load_incidents(path: Path | str = INCIDENTS_PATH) -> list[dict]:
    """Load all incident records from JSONL file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Incidents file not found: {path}")
    
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_verified_attacks(path: Path | str = VERIFIED_PATH) -> list[dict]:
    """Load verified attack metadata from TSV file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Verified attacks file not found: {path}")
        
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        return list(reader)


def verify_integrity() -> bool:
    """Verify that incidents and verified attack metadata are consistent."""
    incidents = load_incidents()
    verified = load_verified_attacks()
    
    incident_hashes = set()
    for r in incidents:
        hashes = r.get("tx_hashes") or []
        if isinstance(hashes, list):
            for h in hashes:
                incident_hashes.add(h.lower())
        elif isinstance(hashes, str):
            incident_hashes.add(hashes.lower())
            
    verified_hashes = {r["tx_hash"].lower() for r in verified if r.get("tx_hash")}
    overlap = incident_hashes.intersection(verified_hashes)
    print(f"[INFO] Loaded {len(incidents)} incidents, {len(verified)} verified entries ({len(overlap)} matching).")
    return len(overlap) > 0


if __name__ == "__main__":
    verify_integrity()
