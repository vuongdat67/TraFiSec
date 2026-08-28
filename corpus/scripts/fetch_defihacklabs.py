#!/usr/bin/env python3
"""TraceGuard-DeFi — fetch incident list from SunWeb3Sec/DeFiHackLabs (GitHub API).

Output: corpus/raw/defihacklabs.json  (schema: corpus/SCHEMA.md)

Repo structure (verified 2026-08-11) — KHÁC giả định "1 incident = 1 dir src/ + README*":
  * Incidents are Foundry PoC files: src/test/<YYYY-MM>/<Protocol>_exp.sol
    (latest years) and past/<year>/README.md entries (2021-2025).
  * The metadata (protocol, date, loss, tx hash, attack type) lives in Markdown
    headers — NOT in per-incident READMEs:
      - root README.md   -> "List of DeFi Hacks & POCs" (newest ~110, src/test/)
      - past/YYYY/README.md -> older incidents (~760, also src/test/)
  * Each entry:
        ### <YYYYMMDD> <Protocol> - <Attack Type>
        ### Lost: <amount>
        forge test --contracts ./src/test/<YYYY-MM>/<Protocol>_exp.sol
        #### Contract
        [<Protocol>_exp.sol](../../src/test/<YYYY-MM>/<Protocol>_exp.sol)
        #### Link reference
        <explorer URL, optionally /tx/0x...>

So the script:
  1) Lists src/test/ subdirs via GitHub Contents API (date buckets, newest first).
  2) Fetches READMEs: root README.md + past/{2021..2025}/README.md (5 raw files),
     then pulls each incident's <Protocol>_exp.sol via raw.githubusercontent.com
     to regex-extract tx hash, chain, loss, dates, notes.
  3) Chains inference: explorer domain in README links + token symbol in "Lost"
     + known chain+protocol overrides (BSC = bscscan/WBNB/BNB, etc.).

Rate limit: unauthenticated GitHub API = 60 req/h. Design uses exactly 2 API
calls (contents/src + contents/src/test) and raw.githubusercontent.com for
READMEs + .sol files (NOT counted against API limit). If the API limit is hit,
we log a clear warning and continue with what we have (READMEs from raw CDN
still work); no crash.

Usage:
  python corpus/scripts/fetch_defihacklabs.py [--limit N] [--out PATH]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = "SunWeb3Sec/DeFiHackLabs"
BRANCH = "main"
API_BASE = f"https://api.github.com/repos/{REPO}"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
API_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "TraceGuard-DeFi-corpus"}
RAW_HEADERS = {"Accept": "application/vnd.github.raw+json", "User-Agent": "TraceGuard-DeFi-corpus"}

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT = REPO_ROOT / "corpus" / "raw" / "defihacklabs.json"

TIMEOUT = 30  # seconds per HTTP request
SLEEP = 0.2   # between requests
DEFAULT_LIMIT = 300
MAX_LIMIT = 2000

HX64 = r"0x[0-9a-fA-F]{64}"
RE_HASH = re.compile(HX64)
# Hash tx thật KHÔNG có chuỗi dài ký tự giống nhau lặp lại (regex bắt nhầm
# placeholder/zero-padding trong code Solidity). Ngưỡng 6+: an toàn, tx hash
# ngẫu nhiên thực tế không bao giờ có 6 hex giống nhau liên tiếp.
RE_SUSPICIOUS = re.compile(r"(.)\1{5,}")


def is_plausible_tx_hash(h: str) -> bool:
    """Loại hash phantom: chuỗi 0x.. bắt nhầm từ code (≥6 ký tự lặp liên tiếp)."""
    if not RE_HASH.match(h):
        return False
    return not RE_SUSPICIOUS.search(h[2:].lower())


RE_HDR = re.compile(r"^#{2,4}\s+(\d{8})\s+(.+)$", re.MULTILINE)
RE_LOST = re.compile(r"^#{2,4}\s+Lost\s*:?\s*(.*)$", re.MULTILINE | re.IGNORECASE)
RE_POC = re.compile(r"src/test/(\d{4})-(\d{2})/([A-Za-z0-9_]+)_exp\.sol", re.MULTILINE)
RE_DATE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
RE_DATE_MDY = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b")

# --- chain inference ---------------------------------------------------------

EXPLORER_CHAIN = {
    "etherscan.io": "ethereum",
    "etherscan.com": "ethereum",
    "getetherscan.io": "ethereum",
    "arbiscan.io": "arbitrum",
    "bscscan.com": "bsc",
    "polygonscan.com": "polygon",
    "snowtrace.io": "avalanche",
    "ftmscan.com": "fantom",
    "optimistic.etherscan.io": "optimism",
    "basescan.org": "base",
    "avascan.info": "avalanche",
    "bscscan.io": "bsc",
    "blockscan.com": "ethereum",
}
CHAIN_ALIASES = {
    "ethereum": "ethereum", "eth": "ethereum", "mainnet": "ethereum",
    "arbitrum": "arbitrum", "arbitrumone": "arbitrum", "arb": "arbitrum",
    "bsc": "bsc", "bnb": "bsc", "bnbchain": "bsc", "binance": "bsc",
    "polygon": "polygon", "matic": "polygon",
    "avalanche": "avalanche", "avax": "avalanche",
    "fantom": "fantom", "ftm": "fantom",
    "optimism": "optimism", "op": "optimism",
    "base": "base",
    "gnosis": "gnosis", "xdai": "gnosis",
    "linea": "linea", "scroll": "scroll", "zksync": "zksync",
}
SYMBOL_CHAIN = {
    "BNB": "bsc", "WBNB": "bsc", "Cake": "bsc", "CAKE": "bsc",
    "MATIC": "polygon", "WMATIC": "polygon",
    "AVAX": "avalanche", "WAVAX": "avalanche",
    "FTM": "fantom", "WFTM": "fantom",
    "ETH": "ethereum", "WETH": "ethereum",
}
# BSC or Ethereum-native protocols that routinely host on BSC — used as last resort
CHAIN_FALLBACK = {
    "Pancake": "bsc", "PancakeBunny": "bsc", "PancakeHunny": "bsc",
    "Bunny": "bsc", "AutoShark": "bsc", "Belt": "bsc", "Alpaca": "bsc",
    "Wault": "bsc", "Venus": "bsc", "Pollen": "bsc", "Burger": "bsc",
    "JulSwap": "bsc", "Meerkat": "bsc",
    "Uranium": "bsc", "Spartan": "bsc", "Fortune": "bsc", "Value Defi": "bsc",
    "DODO": "ethereum", "Inverse": "ethereum", "Cream": "ethereum",
    "Trader Joe": "avalanche", "Platypus": "avalanche", "Yeti": "avalanche",
    "Benqi": "avalanche", "Gondola": "avalanche", "Rari": "ethereum",
}


def http_json(url: str, headers: dict[str, str]) -> list | dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def _decode_robust(data: bytes) -> str:
    """Decode bytes: try UTF-8 strict, fall back to cp1252 for mojibake em-dashes."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def http_text(url: str, headers: dict[str, str]) -> str:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return _decode_robust(resp.read())


def parse_loss_usd(text: str) -> float | None:
    """Best-effort USD loss from a 'Lost: ...' value. Returns None if not USD-expressible.

    Recognised (KHÔNG đoán — only when $ or explicit USD is present):
      "$8.2 million"  "$130M"  "$10,000"  "$4.4 million"  "20M USD"  "9M USD"  "~$300k"
    Not converted (None): "900 BNB", "153,037 ETH (~$30M)" -> ETH-denominated primary,
      though parenthetical USD inside is still caught below.
    """
    if not text:
        return None
    t = text.strip()
    # 1) explicit $ with optional suffix: "$8.2 million", "$130M", "$10,000", "~$300k"
    m = re.search(r"\$\s*([0-9][0-9.,]*(?:e[0-9]+)?)\s*(million|m|k|b|usd)?", t, re.IGNORECASE)
    if m:
        num = m.group(1)
        suffix = (m.group(2) or "").lower()
        return _apply_suffix(num, suffix or "usd")

    # 2) explicit "N M/K/B USD": "20M USD", "9M USD"
    m = re.search(r"([0-9][0-9.,]*(?:e[0-9]+)?)\s*(million|m|k|b)\s*usd", t, re.IGNORECASE)
    if m:
        return _apply_suffix(m.group(1), m.group(2).lower())

    # 3) "N million" / "N million USD" without $ sign
    m = re.search(r"([0-9][0-9.,]*(?:e[0-9]+)?)\s*million\b", t, re.IGNORECASE)
    if m:
        return _apply_suffix(m.group(1), "million")

    # 4) USD-pegged stablecoin amounts: "29,984.27 USDC", "573,034.79 USDT",
    #    "5,124,773.63 DAI", "20 BUSD" (1:1 USD; not a guess).
    STABLECOINS = r"(?:\b(?:USDC|USDT|USD|USDe|DAI|BUSD|TUSD|GUSD|FRAX|LUSD)\b)"
    m = re.search(r"([0-9][0-9.,]*(?:e[0-9]+)?)\s*" + STABLECOINS, t, re.IGNORECASE)
    if m:
        return _apply_suffix(m.group(1), "usd")
    return None


def _apply_suffix(num_str: str, suffix: str) -> float | None:
    try:
        n = float(num_str.replace(",", ""))
    except ValueError:
        return None
    if suffix == "k":
        n *= 1e3
    elif suffix == "m" or suffix == "million":
        n *= 1e6
    elif suffix == "b" or suffix == "billion":
        n *= 1e9
    return round(n, 2)


def infer_chain(entry: dict, lost_val: str) -> str | None:
    """Chain inference: README explorer > Lost token symbol > protocol fallback."""
    # 1. explorer domain in the entry's own text
    for url in entry.get("ref_urls", []):
        dom = re.search(r"https?://([a-z0-9.-]+)/", url)
        if dom:
            d = dom.group(1).lower()
            for k, v in EXPLORER_CHAIN.items():
                if d == k or d.endswith("." + k):
                    return v
    # 2. token symbol in Lost
    if lost_val:
        for sym in sorted(SYMBOL_CHAIN, key=len, reverse=True):
            if re.search(r"(?<![A-Za-z])" + re.escape(sym) + r"(?![A-Za-z])", lost_val):
                return SYMBOL_CHAIN[sym]
    # 3. protocol name fallback
    for k, v in CHAIN_FALLBACK.items():
        if k.lower() in entry["protocol"].lower():
            return v
    return None


def extract_dates(text: str) -> list[str]:
    dates = set()
    for m in RE_DATE_ISO.finditer(text):
        y, mo, d = m.groups()
        if 2020 <= int(y) <= 2026:
            dates.add(f"{y}-{mo}-{d}")
    for m in RE_DATE_MDY.finditer(text):
        mo, d, y = m.groups()
        if 2020 <= int(y) <= 2026:
            dates.add(f"{y}-{int(mo):02d}-{int(d):02d}")
    return sorted(dates)


def parse_attack_type(header_title: str) -> str | None:
    t = header_title.strip().lower()
    patterns = [
        (r"flash.?loan", "flash-loan"),
        (r"oracle|price.?manipulation|faulty oracl", "oracle"),
        (r"reentrancy", "reentrancy"),
        (r"governance|access.?control|bad access|missing permission|permission", "governance/access"),
        (r"accounting|business logic|logic flaw|logic.?flaw|math", "accounting"),
        (r"precision|rounding|def.?lationary|deflation", "precision"),
        (r"bridge|metapool|cross.?chain", "bridge"),
        (r"token|mint|burn", "token"),
        (r"private key|rug.?pull|rug", "rug-pull"),
    ]
    for pat, tag in patterns:
        if re.search(pat, t):
            return tag
    return None


def normalize_chain(raw: str | None) -> str:
    if not raw:
        return "other"
    return CHAIN_ALIASES.get(raw.strip().lower(), raw.strip().lower())


# --- README fetching ---------------------------------------------------------

def fetch_readmes() -> dict[str, str]:
    """Fetch root README + past/YYYY READMEs. Returns {path: content}."""
    files = ["README.md"]
    files += [f"past/{y}/README.md" for y in ("2021", "2022", "2023", "2024", "2025")]
    out: dict[str, str] = {}
    for f in files:
        url = f"{RAW_BASE}/{f}"
        try:
            out[f] = http_text(url, RAW_HEADERS)
            print(f"  [readme] fetched {f} ({len(out[f])} bytes)")
        except Exception as e:
            print(f"  [warn] fetch README {f} failed: {e}")
        time.sleep(SLEEP)
    return out


def parse_readme_entries(content: str, path: str) -> list[dict]:
    """Split a README into per-incident blocks, oldest-first within each file."""
    blocks = []
    # capture incident header + following lines up to next incident header
    lines = content.splitlines()
    cur = None
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        m = RE_HDR.match(line.strip())
        if m and len(m.group(1)) == 8:
            if cur:
                blocks.append(cur)
            cur = {"date": m.group(1), "title": m.group(2), "lines": [], "readme": path, "line": i}
        elif cur is not None:
            cur["lines"].append(line)
    if cur:
        blocks.append(cur)
    return blocks


def entry_from_block(b: dict) -> dict | None:
    date_raw = b["date"]
    try:
        date = f"{date_raw[:4]}-{date_raw[4:6]}-{date_raw[6:]}"
    except Exception:
        date = None
    title = b["title"]
    protocol = title.split("-")[0].strip() if "-" in title else title.strip()
    if not protocol:
        return None
    block_text = "\n".join(b["lines"])

    # attack type from title suffix
    attack_type = None
    if "-" in title:
        at = title.split("-", 1)[1].strip()
        if at:
            attack_type = parse_attack_type(at) or at

    # lost value
    lost_val = ""
    m = RE_LOST.search(block_text)
    if m:
        lost_val = m.group(1).strip()
    loss_usd = parse_loss_usd(lost_val)

    # ref urls (for chain + hashes)
    ref_urls = []
    for line in b["lines"]:
        s = line.strip()
        if s.startswith("http"):
            ref_urls.append(s)
        elif "://" in s and not s.startswith("```") and not s.startswith("forge "):
            ref_urls.append(s)

    # tx hashes from ref urls + any raw hash in text (filter phantom/padded hashes)
    hashes = []
    for u in ref_urls:
        m = re.search(HX64, u)
        if m and is_plausible_tx_hash(m.group(0)):
            hashes.append(m.group(0).lower())
    for h in RE_HASH.findall(block_text):
        if h.lower() not in hashes and is_plausible_tx_hash(h):
            hashes.append(h.lower())

    # poc path
    poc = None
    m2 = RE_POC.search(block_text)
    if m2:
        poc = f"src/test/{m2.group(1)}-{m2.group(2)}/{m2.group(3)}_exp.sol"

    chain = normalize_chain(infer_chain({"protocol": protocol, "ref_urls": ref_urls}, lost_val))

    # description: first few non-code, non-header lines (a few hundred chars)
    desc_lines = []
    for line in b["lines"]:
        s = line.strip()
        if not s or s.startswith("```") or s.startswith("#") or s.startswith("["):
            continue
        if "forge " in s or "FOUNDRY_EVM_VERSION" in s or "LOST" in s.upper():
            continue
        desc_lines.append(s)
    description_text = " ".join(desc_lines)[:600]

    source_url = f"https://github.com/{REPO}/blob/{BRANCH}/{b['readme']}#L-{b.get('line', 1)}"
    if poc:
        source_url = f"https://github.com/{REPO}/blob/{BRANCH}/{poc}"
    # dir = YYYY-MM bucket: from PoC path, else from incident date
    dirname = None
    if poc and len(poc.split("/")) > 2:
        dirname = poc.split("/")[2]
    elif date:
        dirname = date[:7]

    return {
        "protocol": protocol,
        "dir": dirname,
        "source": "defihacklabs",
        "source_url": source_url,
        "readme_path": b["readme"],
        "date": date,
        "chain": chain,
        "attack_type": attack_type,
        "loss_usd": loss_usd,
        "tx_hashes": hashes,
        "description_text": description_text,
        "raw_lost": lost_val,
        "poc_path": poc,
    }


# --- GitHub API: list dirs ---------------------------------------------------

def api_list_dir(path: str) -> tuple[list[dict] | None, bool]:
    """List a GitHub dir. Returns (entries, rate_limited)."""
    url = f"{API_BASE}/contents/{path}?per_page=100"
    try:
        d = http_json(url, API_HEADERS)
        if isinstance(d, dict):
            msg = d.get("message", "")
            if "API rate limit" in msg:
                print(f"  [warn] GitHub API rate limit exceeded while listing {path}")
                return None, True
            print(f"  [warn] unexpected response for {path}: {msg[:120]}")
            return None, False
        return d, False
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        if e.code in (403, 429) and ("rate limit" in body.lower() or "rate" in body.lower()):
            print(f"  [warn] GitHub API rate limit (HTTP {e.code}) while listing {path}")
            return None, True
        print(f"  [warn] HTTP {e.code} listing {path}: {body[:120]}")
        return None, False
    except Exception as e:
        print(f"  [warn] error listing {path}: {e}")
        return None, False


def collect_incident_dirs() -> tuple[list[dict], bool]:
    """List src/test/<YYYY-MM> date buckets (newest first). Returns (entries, rate_limited)."""
    src, rl = api_list_dir("src")
    if rl:
        return [], True
    if src is None:
        return [], False
    test_dir = next((e for e in src if e.get("type") == "dir" and e.get("name") == "test"), None)
    if not test_dir:
        print("  [warn] no src/test dir found")
        return [], False
    months, rl2 = api_list_dir("src/test")
    if rl2:
        return [], True
    if months is None:
        return [], False
    # each entry is a date bucket dir 'YYYY-MM'
    buckets = [e for e in months if e.get("type") == "dir"]
    # newest first (repo sorts alphabetically, ascending => newest last)
    buckets.sort(key=lambda e: e.get("name", ""), reverse=True)
    return buckets, False


# --- .sol file extraction ----------------------------------------------------

def fetch_sol_metadata(poc_path: str) -> dict:
    """Fetch a PoC .sol file via raw CDN and regex-extract metadata."""
    out = {"hashes": [], "chain": None, "dates": [], "desc": "", "fetched": False}
    if not poc_path:
        return out
    url = f"{RAW_BASE}/{poc_path}"
    try:
        text = http_text(url, RAW_HEADERS)
        out["fetched"] = True
        out["hashes"] = [h.lower() for h in RE_HASH.findall(text)]
        out["dates"] = extract_dates(text)
        # attack/victim/lender addresses: keep only hashes (0x64) — loại phantom
        out["hashes"] = [h for h in out["hashes"] if is_plausible_tx_hash(h)]
        # chain hints in .sol comments
        for kw in ("BSC", "BNB Chain", "Binance Smart Chain", "bscscan"):
            if kw in text:
                out["chain"] = "bsc"
                break
        for kw in ("Arbitrum", "Arbitrum One", "arbiscan"):
            if kw in text:
                out["chain"] = "arbitrum"
                break
        for kw in ("Polygon", "PolygonScan", "Matic", "polygonscan"):
            if kw in text:
                out["chain"] = "polygon"
                break
        for kw in ("Fantom", "FTM", "ftmscan"):
            if kw in text:
                out["chain"] = "fantom"
                break
        for kw in ("Optimism", "OP Mainnet", "optimistic.etherscan"):
            if kw in text:
                out["chain"] = "optimism"
                break
        for kw in ("Avalanche", "AVAX", "snowtrace"):
            if kw in text:
                out["chain"] = "avalanche"
                break
        # first descriptive comment lines (skip SPDX/pragma/import/forge boilerplate)
        parts = []
        for line in text.splitlines()[:60]:
            s = line.strip()
            if not s.startswith("//"):
                continue
            s = s.lstrip("/").strip()
            low = s.lower()
            if not s or low.startswith("spdx") or "solidity" in low or low.startswith("import ") or "forge-std" in low or low.startswith("pragma"):
                continue
            parts.append(s)
        out["desc"] = " ".join(parts)[:400]
        time.sleep(SLEEP)
    except Exception as e:
        print(f"    [warn] fetch {poc_path}: {e}")
    return out


def merge_sol_meta(entry: dict, sol: dict) -> dict:
    e = dict(entry)
    for h in sol.get("hashes", []):
        if h not in e["tx_hashes"]:
            e["tx_hashes"].append(h)
    if not e.get("chain") or e["chain"] == "other":
        c = sol.get("chain")
        if c:
            e["chain"] = normalize_chain(c)
    # no chain guess from absence of evidence — leave "other" (SCHEMA: KHÔNG đoán)
    if sol.get("dates") and not e.get("date"):
        e["date"] = sol["dates"][0]
    if not e.get("description_text") and sol.get("desc"):
        e["description_text"] = sol["desc"]
    return e


# --- main --------------------------------------------------------------------

def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows Python 3.12

    ap = argparse.ArgumentParser(description="Fetch DeFiHackLabs incident list -> corpus/raw/defihacklabs.json")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"max incidents (default {DEFAULT_LIMIT})")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    ap.add_argument("--no-sol", action="store_true", help="skip fetching .sol files (faster, less hash coverage)")
    args = ap.parse_args()

    limit = max(0, min(args.limit, MAX_LIMIT))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("[1/3] listing incident dirs under src/test (GitHub Contents API)")
    buckets, rate_limited = collect_incident_dirs()
    if rate_limited:
        print("  [warn] API rate limit hit on directory listing — proceeding with READMEs only (raw CDN still works)")
    print(f"  found {len(buckets)} date buckets; top: {[b.get('name') for b in buckets[:5]]}")

    print("[2/3] fetching READMEs (root + past/2021..2025) via raw CDN")
    readmes = fetch_readmes()

    print("[3/3] parsing incidents + fetching PoC .sol metadata")
    all_entries: list[dict] = []
    seen: set[str] = set()

    # Order: root README (newest) then past READMEs oldest-first within file.
    # Overall we keep newest-first as the task asks (recent = front).
    order = ["README.md"] + [f"past/{y}/README.md" for y in ("2025", "2024", "2023", "2022", "2021")]
    for path in order:
        content = readmes.get(path)
        if not content:
            continue
        blocks = parse_readme_entries(content, path)
        for b in blocks:
            e = entry_from_block(b)
            if not e:
                continue
            key = (e["date"] or "") + "|" + e["protocol"].lower()
            if key in seen:
                continue
            seen.add(key)
            all_entries.append(e)

    # dedupe protocol collisions across year-readmes (keep newest entry)
    by_proto: dict[str, dict] = {}
    for e in all_entries:
        k = e["protocol"].lower()
        if k not in by_proto or (e.get("date") or "") > (by_proto[k].get("date") or ""):
            by_proto[k] = e
    all_entries = list(by_proto.values())

    # newest-first overall
    all_entries.sort(key=lambda e: e.get("date") or "", reverse=True)

    # fetch .sol metadata for the first `limit` incidents
    fetched = 0
    if not args.no_sol:
        for i, e in enumerate(all_entries[:limit]):
            poc = e.get("poc_path")
            if not poc:
                continue
            sol = fetch_sol_metadata(poc)
            if sol.get("fetched"):
                all_entries[i] = merge_sol_meta(e, sol)
            fetched += 1
            if fetched % 30 == 0:
                print(f"  ... {fetched} .sol fetched")
            if fetched >= limit:
                break

    results = all_entries[:limit]

    # final chain normalization for the output
    for e in results:
        e["chain"] = normalize_chain(e.get("chain") or "other")
        e["loss_usd"] = e.get("loss_usd")
        e["tx_hashes"] = sorted(set(e.get("tx_hashes", [])))
        # drop internal fields not in schema
        e.pop("raw_lost", None)
        e.pop("poc_path", None)
        e.pop("readme_path", None)
        # alias description -> notes so merge.py (pipeline step 3) picks it up
        if e.get("description_text") and not e.get("notes"):
            e["notes"] = e["description_text"]

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    n_hash = sum(1 for e in results if e["tx_hashes"])
    n_chain = sum(1 for e in results if e["chain"] != "other")
    n_loss = sum(1 for e in results if e["loss_usd"])
    print("=" * 60)
    print(f"written: {out_path}")
    print(f"incidents: {len(results)}")
    print(f"with tx_hashes: {n_hash}")
    print(f"with chain (non-other): {n_chain}")
    print(f"with loss_usd: {n_loss}")
    if rate_limited:
        print("[warn] GitHub API rate limit was hit during this run — consider waiting 1h or using a token")


if __name__ == "__main__":
    main()
