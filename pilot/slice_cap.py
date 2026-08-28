#!/usr/bin/env python3
"""TraFiSec pilot -- f_swap mutation: cap amountIn / redirect recipient in calldata.

DeFi exploit transactions frequently execute multi-step swap routes (slices):
initial swaps manipulate pool reserves/prices, while later swaps extract profits.
f_swap mutates candidate swap slices:
  - Manipulation slice: cap amountIn to mitigate price distortion.
  - Routing slice: redirect recipient to intercept extracted value.

Since replay is dispatched as a new transaction, calldata is mutated before broadcast.
This utility decodes candidate calldata, identifies Uniswap V2/V3 interfaces,
and outputs mutated calldata.

Usage:
  python slice_cap.py <calldata_hex> [--cap pct] [--redirect 0xADDR]
  python slice_cap.py --test

  --cap pct       Cap amountIn to pct * original (floor), default 0.99.
  --redirect 0xA  Replace swap recipient with 0xA.
"""
import os
import re
import subprocess
import sys

# Uniswap V2 Router02: swapExactTokensForTokens(uint amountIn,uint amountOutMin,address[] path,address to,uint deadline)
SEL_V2 = "38ed1739"
# Uniswap V3 SwapRouter: exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
SEL_V3 = "414bf389"
# Uniswap V3 SwapRouter: exactInput((bytes,address,uint256,uint256,uint256))
SEL_V3_EXACT = "c04b8d59"

_ADDR_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{40}$")


def _err(msg):
    """Print a clear one-line error to stderr and exit non-zero (no traceback)."""
    print("slice_cap: " + msg, file=sys.stderr)
    sys.exit(1)


def _normalize_calldata(arg):
    """Strip 0x / whitespace, lowercase, and validate hex. Returns bare hex."""
    cd = arg.strip()
    if cd.startswith("0x") or cd.startswith("0X"):
        cd = cd[2:]
    if not cd:
        _err("empty calldata")
    if len(cd) < 8:
        _err(f"calldata too short: only {len(cd)} hex chars (expected >= 8 for selector)")
    if len(cd) % 2 != 0:
        _err(f"calldata has odd hex length ({len(cd)}) - expected byte array")
    if any(c not in "0123456789abcdefABCDEF" for c in cd):
        _err("calldata contains non-hex characters")
    return cd.lower()


def _normalize_addr(arg):
    """Validate and normalize a redirect address to 40 bare hex chars."""
    a = arg.strip()
    if a.startswith("0x") or a.startswith("0X"):
        a = a[2:]
    if not _ADDR_RE.fullmatch(a):
        _err(f"invalid redirect address: {arg!r} (expected 40 hex chars)")
    return a.lower()


def _words_after_selector(calldata):
    """Split bare-hex calldata into (selector, [32-byte words])."""
    sel = calldata[:8]
    body = calldata[8:]
    words = [body[i:i + 64] for i in range(0, len(body), 64)]
    return sel, words


def find_slices(calldata):
    """Scan calldata for known DEX router swap selectors."""
    matches = []
    for sel, name in [
        (SEL_V2, "UniswapV2.swapExactTokensForTokens"),
        (SEL_V3, "UniswapV3.exactInputSingle"),
        (SEL_V3_EXACT, "UniswapV3.exactInput"),
    ]:
        idx = 0
        while True:
            pos = calldata.find(sel, idx)
            if pos == -1:
                break
            matches.append((name, pos))
            idx = pos + len(sel)
    matches.sort(key=lambda x: x[1])
    return matches


def cap_amt_in(calldata, pct=0.99):
    """Cap amountIn of the top-level swap slice to pct of original."""
    sel, words = _words_after_selector(calldata)
    if sel == SEL_V2:
        need, idx = 1, 0
    elif sel == SEL_V3:
        need, idx = 5, 4
    elif sel == SEL_V3_EXACT:
        _err("V3 exactInput (0xc04b8d59) does not support amountIn capping (dynamic bytes path)")
    else:
        _err(f"unsupported selector for amountIn cap: 0x{sel}")
    if len(words) < need:
        _err(f"calldata too short for amountIn cap (selector 0x{sel})")
    amount_in = int(words[idx], 16)
    capped = int(amount_in * pct)
    words[idx] = f"{capped:064x}"
    return calldata[:8] + "".join(words)


def redirect_recipient(calldata, to_addr):
    """Redirect the swap recipient of a routing slice to to_addr."""
    sel, words = _words_after_selector(calldata)
    to_hex = to_addr
    if sel == SEL_V2:
        if len(words) < 4:
            _err("calldata too short for recipient redirect (V2 requires path length at word 3)")
        path_len = int(words[3], 16)
        to_idx = 4 + path_len
        if len(words) <= to_idx:
            _err(f"calldata too short: path length is {path_len} but missing recipient word (index {to_idx})")
    elif sel == SEL_V3:
        to_idx = 3
        if len(words) < 4:
            _err("calldata too short for recipient redirect (V3 exactInputSingle requires word 3)")
    else:
        _err(f"unsupported selector for recipient redirect: 0x{sel}")
    words[to_idx] = to_hex.rjust(64, "0")
    return calldata[:8] + "".join(words)


def main():
    if "--test" in sys.argv:
        sys.exit(run_tests())

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cd = _normalize_calldata(sys.argv[1])
    pct = 0.99
    cap_given = False
    redirect = None

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--cap":
            if i + 1 >= len(args):
                _err("--cap requires percentage value (e.g., --cap 0.99)")
            try:
                pct = float(args[i + 1])
            except ValueError:
                _err(f"invalid --cap value: {args[i + 1]!r} (expected float)")
            if not (0.0 < pct <= 1.0):
                _err(f"--cap value outside range (0, 1]: {pct!r}")
            cap_given = True
            i += 2
        elif a == "--redirect":
            if i + 1 >= len(args):
                _err("--redirect requires target address (e.g., --redirect 0x0000...0000)")
            redirect = _normalize_addr(args[i + 1])
            i += 2
        else:
            _err(f"unknown argument: {a!r}")

    slices = find_slices(cd)
    if not slices:
        _err("no recognized DEX swap slices (V2/V3) found in calldata")
    name, off = slices[0]
    print(f"# slice: {name} (offset {off})", file=sys.stderr)

    out = cd
    if redirect is not None:
        out = redirect_recipient(out, redirect)
        print(f"#   redirect recipient -> 0x{redirect}", file=sys.stderr)
    if cap_given or redirect is None:
        out = cap_amt_in(out, pct)
        print(f"#   cap amountIn -> {pct:.4f}", file=sys.stderr)

    print("0x" + out)


def run_tests():
    """Self-contained test suite."""
    results = []

    def t(name, fn):
        try:
            fn()
            results.append((name, True, None))
        except AssertionError as e:
            results.append((name, False, str(e)))
        except Exception as e:
            results.append((name, False, f"{type(e).__name__}: {e}"))

    def _w(v):
        return f"{v:064x}"

    v2_cd = (
        SEL_V2
        + _w(1000)
        + _w(900)
        + _w(160)
        + _w(2)
        + _w(0x1111)
        + _w(0x2222)
        + _w(0xAAAA)
        + _w(9999999999)
    )

    to_bb = "0x" + ("b" * 40)
    v3_cd = (
        SEL_V3
        + _w(0x1111)
        + _w(0x2222)
        + _w(3000)
        + _w(0xAAAA)
        + _w(1000)
        + _w(900)
        + _w(0)
    )

    script = os.path.abspath(__file__)

    def _cli(*args):
        p = subprocess.run([sys.executable, script] + list(args),
                           capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    def _v2_cap():
        out = cap_amt_in(v2_cd, 0.99)
        sel, words = _words_after_selector(out)
        assert sel == SEL_V2
        assert int(words[0], 16) == 990
        assert words[1:] == _words_after_selector(v2_cd)[1][1:]
    t("V2 cap 99%: amountIn 1000 -> 990, other words untouched", _v2_cap)

    def _v3_cap():
        out = cap_amt_in(v3_cd, 0.50)
        sel, words = _words_after_selector(out)
        assert sel == SEL_V3
        assert int(words[4], 16) == 500
    t("V3 cap 50%: struct amountIn 1000 -> 500", _v3_cap)

    def _v2_redirect():
        out = redirect_recipient(v2_cd, "b" * 40)
        _, words = _words_after_selector(out)
        assert words[6] == "b" * 40
    t("V2 redirect: recipient updated correctly", _v2_redirect)

    def _v3_redirect():
        out = redirect_recipient(v3_cd, "b" * 40)
        _, words = _words_after_selector(out)
        assert words[3] == "b" * 40
    t("V3 redirect: struct recipient updated correctly", _v3_redirect)

    def _bad_selector():
        rc, so, se = _cli("12345678" + ("00" * 64))
        assert rc != 0
        assert "slice_cap:" in se
    t("Bad calldata: unknown selector exits non-zero", _bad_selector)

    def _too_short():
        rc, so, se = _cli(SEL_V2)
        assert rc != 0
        assert "too short" in se
    t("Bad calldata: too short for cap exits non-zero", _too_short)

    def _too_short_redirect():
        rc, so, se = _cli(v3_cd[:8 + 3 * 64], "--redirect", to_bb)
        assert rc != 0
        assert "too short" in se
    t("Bad calldata: too short for V3 redirect exits non-zero", _too_short_redirect)

    def _cap_no_value():
        rc, so, se = _cli(v2_cd, "--cap")
        assert rc != 0
        assert "--cap" in se
    t("CLI guard: --cap with no value exits non-zero", _cap_no_value)

    def _bad_redirect_addr():
        rc, so, se = _cli(v2_cd, "--redirect", "0xzzz")
        assert rc != 0
        assert "invalid" in se
    t("CLI guard: malformed --redirect address exits non-zero", _bad_redirect_addr)

    def _odd_len_errors():
        rc, so, se = _cli(SEL_V2 + "0")
        assert rc != 0
        assert "odd" in se
    t("Guard: odd-length hex calldata exits non-zero", _odd_len_errors)

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, msg in results:
        suffix = f"  ({msg})" if msg else ""
        print(f"{'PASS' if ok else 'FAIL'}  {name}{suffix}")
    print(f"\n{passed}/{len(results)} tests passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    main()
