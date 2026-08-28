"""
TraFiSec pilot — .env auto-load (user feedback 2026-08-11)
=================================================================
Environment configuration loader for Ethereum RPC endpoints.
Automatically loads .env from repository root and prioritizes chain-specific archive nodes. (hoc pilot/) mt ln duy nht.

Security: `.env` is gitignored; never commit private RPC keys.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PILOT_DIR = REPO_ROOT / "pilot"


def load_dotenv(paths: tuple[Path, ...] = (
    REPO_ROOT / ".env",
    PILOT_DIR / ".env",
    REPO_ROOT.parent / ".env",
)) -> Path | None:
    """Load .env if present (without overwriting existing environment variables). Returns loaded path or None."""
    for p in paths:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
            return p
    return None


def resolve_rpc(chain: str = "mainnet") -> str | None:
    """RPC resolution — cng th t u tin nh common.sh:
    RPC ( export) → CHAIN_RPC → chain-specific archive → generic archive → Alchemy key.

    The archive resolver intentionally remains unchanged; trace-only providers
    are resolved separately by resolve_trace_rpc().
    """
    if os.environ.get("RPC"):
        return os.environ["RPC"]
    if os.environ.get("CHAIN_RPC"):
        return os.environ["CHAIN_RPC"]
    if chain == "arbitrum" and os.environ.get("ARB_ARCHIVE_RPC"):
        return os.environ["ARB_ARCHIVE_RPC"]
    if os.environ.get("ARCHIVE_RPC"):
        return os.environ["ARCHIVE_RPC"]
    if os.environ.get("ALCHEMY_API_KEY"):
        return f"https://eth-mainnet.g.alchemy.com/v2/{os.environ['ALCHEMY_API_KEY']}"
    return None


def resolve_trace_rpc(chain: str = "mainnet") -> str | None:
    """Resolve an optional trace-only RPC.

    QuickNode endpoints are used only for debug/trace calls. Transaction,
    receipt, block, fork, and state reads continue to use resolve_rpc(). A
    missing trace endpoint returns ``None`` so the caller can reuse its archive
    client without changing provider behavior.
    """
    if chain == "arbitrum" and os.environ.get("QUICKNODE_ARB_TRACE_RPC"):
        return os.environ["QUICKNODE_ARB_TRACE_RPC"]
    if chain != "arbitrum" and os.environ.get("QUICKNODE_TRACE_RPC"):
        return os.environ["QUICKNODE_TRACE_RPC"]
    return None


def _configured_candidates(primary: str | None, env_name: str) -> tuple[str, ...]:
    """Return an explicit primary-plus-fallback route without hidden swaps."""
    values = [primary] if primary else []
    values.extend(value.strip() for value in os.environ.get(env_name, "").split("|")
                  if value.strip())
    return tuple(dict.fromkeys(values))


def resolve_rpc_candidates(chain: str = "mainnet") -> tuple[str, ...]:
    """Archive route candidates; fallbacks require explicit configuration."""
    return _configured_candidates(resolve_rpc(chain), "ARCHIVE_RPC_FALLBACKS")


def resolve_trace_rpc_candidates(chain: str = "mainnet") -> tuple[str, ...]:
    """Trace route candidates; never silently substitutes the archive route."""
    return _configured_candidates(resolve_trace_rpc(chain), "QUICKNODE_TRACE_RPC_FALLBACKS")
