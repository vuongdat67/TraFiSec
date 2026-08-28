#!/usr/bin/env python3
"""Scrape Rekt.news leaderboard + incident detail pages -> corpus/raw JSON.

Phase 1 / source 1 (schema: corpus/SCHEMA.md). Python thuần (stdlib urllib),
chạy được trên Windows + Python 3.12, KHÔNG cần requests/bs4 (tự chọn
HTMLParser để tránh phụ thuộc thêm vào requirements.txt).

Outputs:
  corpus/raw/rekt_leaderboard.json  list[{protocol, loss_usd, date, url}]
  corpus/raw/rekt_incidents.json    list[{slug, url, protocol, description_text,
                                          loss_usd, date}]

Usage:
  python corpus/scripts/scrape_rekt.py                 # fetch <= 120 detail pages
  python corpus/scripts/scrape_rekt.py --limit 20      # quick smoke test
  python corpus/scripts/scrape_rekt.py --limit 0       # leaderboard only
"""

from __future__ import annotations

import argparse
import html
from html.parser import HTMLParser
import json
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

if sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # tránh lỗi cp1252 in Unicode
    except Exception:
        pass
if sys.stderr is not None:
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_URL = "https://rekt.news"
LEADERBOARD_URL = "https://rekt.news/leaderboard"
DEFAULT_LIMIT = 120
REQUEST_TIMEOUT = 30.0
SLEEP_BETWEEN = 0.3
PROGRESS_EVERY = 20

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

RAW_DIR = Path(__file__).resolve().parent.parent / "raw"
LEADERBOARD_OUT = RAW_DIR / "rekt_leaderboard.json"
INCIDENTS_OUT = RAW_DIR / "rekt_incidents.json"

# HTML comment node <!-- --> giữa $ và con số trong leaderboard details
_AMOUNT_RE = re.compile(r"\$\s*(?:<!--.*?-->)*\s*([0-9][0-9,]*(?:\.[0-9]+)?)")
# kèm hậu tố B/M/K (vd "$1.43B", "$250.8M") hay gặp trong nội dung bài
_AMOUNT_SUFFIX_RE = re.compile(r"\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)\s*([BMK]?)\b")
_SUFFIX_MULT = {"": 1.0, "K": 1e3, "M": 1e6, "B": 1e9}
_LEADERBOARD_ROW_RE = re.compile(
    r'<li>\s*<div class="leaderboard-row">.*?'
    r'class="leaderboard-row-title">\s*<a href="([^"]+)"[^>]*>(.*?)</a>.*?'
    r'class="leaderboard-row-details">(.*?)</div>.*?</li>',
    re.S,
)

# Chain tên -> chuẩn hoá theo SCHEMA.md (ethereum|bsc|arbitrum|polygon|avalanche|other)
_CHAIN_ALIASES = {
    "ethereum": "ethereum", "eth": "ethereum", "mainnet": "ethereum",
    "arbitrum": "arbitrum", "arb": "arbitrum",
    "bsc": "bsc", "binance": "bsc", "binance smart chain": "bsc",
    "polygon": "polygon", "matic": "polygon", "avalanche": "avalanche",
    "avax": "avalanche", "solana": "other", "sol": "other", "cosmos": "other",
    "osmosis": "other", "terra": "other", "near": "other", "aptos": "other",
    "sui": "other", "tron": "other", "fantom": "other", "ftm": "other",
    "base": "other", "optimism": "other", "op mainnet": "other",
    "zksync": "other", "ronin": "other", "ronin network": "other",
}


def fetch(url: str) -> str:
    """GET url -> text UTF-8. Raise on non-2xx / network error."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        status = getattr(resp, "status", 200)
        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP {status}")
        raw = resp.read()
    return raw.decode("utf-8")


class TextParser(HTMLParser):
    """Gom text của các thẻ <p> bên trong <section class="post-content">.

    Dùng stdlib HTMLParser (không cần bs4/lxml). Xử lý đúng:
      - <p> lồng thẻ inline (<strong>, <a>...) — text vẫn được giữ
      - bỏ <script>/<style>/<figure>/<img> (không phải body text)
      - entity (&amp;, &#x27;) — unescape ở lúc gom paragraph
    """

    def __init__(self) -> None:
        super().__init__()
        self._p_depth = 0          # depth đang ở trong <p>
        self._skip_depth = 0       # depth đang ở trong script/style/figure/img
        self._texts: list[str] = []
        self.paragraphs: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag in ("script", "style", "figure", "img", "picture", "svg"):
            self._skip_depth += 1
        elif tag == "p":
            self._p_depth += 1

    def handle_endtag(self, tag) -> None:
        if tag in ("script", "style", "figure", "img", "picture", "svg"):
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag == "p":
            self._p_depth = max(0, self._p_depth - 1)
            self._flush_paragraph()

    def handle_data(self, data) -> None:
        if self._p_depth > 0 and self._skip_depth == 0:
            self._texts.append(data)

    def handle_entityref(self, name) -> None:
        if self._p_depth > 0 and self._skip_depth == 0:
            self._texts.append("&%s;" % name)

    def handle_charref(self, name) -> None:
        if self._p_depth > 0 and self._skip_depth == 0:
            self._texts.append("&#%s;" % name)

    def _flush_paragraph(self) -> None:
        text = " ".join(html.unescape("".join(self._texts)).split())
        if text:
            self.paragraphs.append(text)
        self._texts = []


def _clean_title(inner_html: str) -> str:
    # bỏ span .leaderboard-audit (N/A, Unaudited, auditor names) — không phải tên protocol
    inner_html = re.sub(r'<span[^>]*class="leaderboard-audit"[^>]*>.*?</span>', "", inner_html, flags=re.S)
    text = re.sub(r"<[^>]+>", "", inner_html)
    text = html.unescape(text)
    return " ".join(text.split())


def _loss_from_details(details: str) -> float:
    m = _AMOUNT_RE.search(details)
    return float(m.group(1).replace(",", "")) if m else 0.0


def parse_date(day: str, month: str, year: str) -> str:
    return datetime(int(year), int(month), int(day)).strftime("%Y-%m-%d")


def parse_leaderboard(page: str) -> list[dict]:
    """Rekt leaderboard -> list[{protocol, loss_usd, date, url}]."""
    rows = []
    for href, inner, details in _LEADERBOARD_ROW_RE.findall(page):
        # slug từ href (vd '/yearn-rekt' | '/cream-rekt-2' | '/yearn-rekt3')
        slug = href.strip().strip("/")
        title = _clean_title(inner)
        m = re.search(r"(\d{1,2})/(\d{1,2})/(\d{2,4})", details)
        if not m:
            print(f"[warn] leaderboard row missing date: {href} ({title})",
                  file=sys.stderr)
            continue
        year = int(m.group(3))
        if year < 100:
            year += 2000  # '22' -> 2022
        date = parse_date(m.group(2), m.group(1), str(year))
        rows.append({
            "protocol": title,
            "loss_usd": _loss_from_details(details),
            "date": date,
            "url": BASE_URL + "/" + slug,
        })
    return rows


def _chain_of(text: str) -> str:
    low = text.lower()
    hits = [name for name in _CHAIN_ALIASES if re.search(r"\b" + re.escape(name) + r"\b", low)]
    if not hits:
        return "other"
    return _CHAIN_ALIASES[hits[0]]


def _loss_of(text: str) -> float:
    """Số loss ước lượng (lớn nhất, hỗ trợ hậu tố $xB/$xM) nhắc trong text."""
    best = 0.0
    for m in _AMOUNT_SUFFIX_RE.finditer(text):
        try:
            v = float(m.group(1).replace(",", "")) * _SUFFIX_MULT[m.group(2)]
        except (ValueError, KeyError):
            continue
        if v > best:
            best = v
    return best


def fetch_incident(entry: dict, href: str) -> dict:
    slug = href.strip().strip("/")
    page = fetch(BASE_URL + "/" + slug)
    parser = TextParser()
    parser.feed(page)
    body = "\n".join(parser.paragraphs)
    description = body[:800].strip() if body else ""
    return {
        "slug": slug,
        "url": BASE_URL + "/" + slug,
        "protocol": entry["protocol"],
        "description_text": description,
        "loss_usd": entry["loss_usd"] or _loss_of(body),
        "date": entry["date"],
        "chain": _chain_of(description) if description else "other",
    }


def load_cached_incidents() -> list[dict]:
    try:
        with INCIDENTS_OUT.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_json(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scrape Rekt.news leaderboard + incidents.")
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT,
        help="Max incident detail pages to fetch (default %d, 0 = leaderboard only)"
        % DEFAULT_LIMIT,
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-fetch incident pages already cached in the output file",
    )
    args = parser.parse_args()

    limit = args.limit if args.limit is not None and args.limit >= 0 else DEFAULT_LIMIT

    print("[1/2] Fetching leaderboard ...", file=sys.stderr)
    try:
        page = fetch(LEADERBOARD_URL)
    except Exception as exc:
        print(f"[fatal] leaderboard fetch failed: {exc}", file=sys.stderr)
        sys.exit(1)
    entries = parse_leaderboard(page)
    if not entries:
        print("[fatal] no incidents parsed from leaderboard (site layout changed?)",
              file=sys.stderr)
        sys.exit(1)
    print(f"      parsed {len(entries)} incidents from leaderboard", file=sys.stderr)
    save_json(LEADERBOARD_OUT, entries)
    print(f"      wrote {LEADERBOARD_OUT}", file=sys.stderr)

    incidents = []
    todo = entries[:limit] if limit > 0 else []
    if not args.force:
        seen = {inc["slug"] for inc in load_cached_incidents()}
        todo = [e for e in todo if e["url"].split("/")[-1] not in seen]
        incidents = [inc for inc in load_cached_incidents() if inc["url"].split("/")[-1] in seen]

    ok = 0
    fail = 0
    if todo:
        print(f"[2/2] Fetching {len(todo)} incident detail pages ...", file=sys.stderr)
        for i, entry in enumerate(todo, start=1):
            href = entry["url"].split("/")[-1]
            try:
                inc = fetch_incident(entry, href)
                incidents.append(inc)
                ok += 1
            except Exception as exc:
                fail += 1
                print(f"      [err] {entry['url']} -> {exc}", file=sys.stderr)
            if i % PROGRESS_EVERY == 0:
                print(f"      progress {i}/{len(todo)} (ok={ok} fail={fail})",
                      file=sys.stderr)
            time.sleep(SLEEP_BETWEEN)

    save_json(INCIDENTS_OUT, incidents)
    print(f"wrote {INCIDENTS_OUT} with {len(incidents)} incidents", file=sys.stderr)
    print(f"done: leaderboard={len(entries)} incidents, fetched ok={ok} fail={fail} "
          f"(cached={len(incidents) - ok})")


if __name__ == "__main__":
    main()
