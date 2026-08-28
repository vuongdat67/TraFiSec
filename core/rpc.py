"""
TraFiSec pilot — JSON-RPC client (anvil + archive)
==========================================================
Unified JSON-RPC client interface with retry handling, structured error propagation,
and Anvil state modification RPC helpers.

Security: URL/key ch n t env/.env — khng hard-code.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import urllib.request
import urllib.error

_TIMEOUT_DEFAULT = 60.0
_ATTEMPTS_DEFAULT = 5
_BACKOFF_DEFAULT = 1.0


class RpcError(RuntimeError):
    """Li RPC: network, timeout, hoc JSON-RPC error payload."""


class RpcClient:
    """JSON-RPC client —  cho anvil + archive (eth_*, anvil_set*)."""

    def __init__(
        self,
        url: str,
        timeout: float = _TIMEOUT_DEFAULT,
        attempts: int = _ATTEMPTS_DEFAULT,
        backoff_base: float = _BACKOFF_DEFAULT,
        fallback_urls: tuple[str, ...] = (),
        cache_dir: str | Path | None = None,
        offline: bool = False,
    ):
        if timeout <= 0:
            raise ValueError("RPC timeout must be positive")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
            raise ValueError("RPC attempts must be an integer >= 1")
        if backoff_base < 0:
            raise ValueError("RPC backoff_base must be non-negative")
        self.url = url
        self.timeout = timeout
        self.attempts = attempts
        self.backoff_base = backoff_base
        if any(not isinstance(value, str) or not value for value in fallback_urls):
            raise ValueError("fallback RPC URLs must be non-empty strings")
        self.fallback_urls = tuple(value for value in fallback_urls if value != url)
        self.last_endpoint = url
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.offline = offline

    _CACHEABLE = {
        "eth_getTransactionByHash", "eth_getTransactionReceipt",
        "eth_getCode", "eth_getBalance", "eth_getStorageAt",
        "eth_getBlockByNumber", "eth_getBlockByHash",
    }

    def _cache_path(self, method: str, params: list) -> Path | None:
        if self.cache_dir is None or method not in self._CACHEABLE:
            return None
        key = hashlib.sha256(json.dumps(
            [method, params], sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        return self.cache_dir / "rpc" / method / f"{key}.json"

    def call(self, method: str, params: list | None = None) -> object:
        import time as _time
        params = params or []
        cache_path = self._cache_path(method, params)
        if cache_path is not None and cache_path.exists():
            return json.loads(cache_path.read_text(encoding="utf-8"))
        if self.offline and method in self._CACHEABLE:
            raise RpcError(f"offline cache miss: {method} {params[:1]}")
        failures: list[str] = []
        for endpoint in (self.url, *self.fallback_urls):
            try:
                result = self._call_endpoint(endpoint, method, params, _time)
                self.last_endpoint = endpoint
                if cache_path is not None:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(result), encoding="utf-8")
                return result
            except RpcError as exc:
                failures.append(f"{endpoint}: {exc}")
                if endpoint == self.fallback_urls[-1] if self.fallback_urls else endpoint == self.url:
                    raise RpcError("; ".join(failures)) from exc
                if not self._is_retryable_provider_failure(str(exc)):
                    raise
        raise RpcError("RPC provider list is empty")

    @staticmethod
    def _is_retryable_provider_failure(message: str) -> bool:
        lowered = message.lower()
        return any(token in lowered for token in (
            "could not resolve", "nodename nor servname", "name or service not known",
            "timed out", "timeout", "429", "503", "502", "connection reset",
            "connection refused", "temporary failure",
        ))

    def _call_endpoint(self, endpoint: str, method: str, params: list, time_module) -> object:
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
        req = urllib.request.Request(
            endpoint, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "TraceGuard/1.0 (fork-replay analysis)"})

        last_error: Exception | None = None
        for attempt in range(self.attempts):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    out = json.loads(resp.read().decode())
                    break
            except urllib.error.HTTPError as e:
                if e.code != 429:
                    raise RpcError(f"RPC {method} failed: {e}") from e
                last_error = e
                delay = self.backoff_base * (2 ** attempt + 0.5)
            except Exception as e:
                message = str(e).lower()
                if not any(token in message for token in ("10054", "10060", "timed out")):
                    raise RpcError(f"RPC {method} failed: {e}") from e
                last_error = e
                delay = self.backoff_base * (1 + attempt)

            # Never sleep after the final failed attempt. This makes the upper
            # bound attempts * timeout + intervening backoff, rather than adding
            # an unnecessary terminal delay.
            if attempt + 1 < self.attempts and delay > 0:
                time_module.sleep(delay)
        else:
            detail = str(last_error) if last_error else "429 or network error"
            raise RpcError(
                f"RPC {method} failed after {self.attempts} attempt(s): {detail}"
            ) from last_error

        if "error" in out:
            raise RpcError(f"RPC {method} error: {out['error']}")
        return out.get("result")

    # Execution trace analysis and verification
    def anvil_set_code(self, addr: str, code: str = "0x") -> object:
        return self.call("anvil_setCode", [addr, code])

    def anvil_set_balance(self, addr: str, wei: str = "0x0") -> object:
        return self.call("anvil_setBalance", [addr, wei])

    def anvil_set_storage(self, addr: str, slot: str, value: str) -> object:
        return self.call("anvil_setStorageAt", [addr, slot, value])

    def call_tracer(self, tx_hash: str) -> dict:
        """Run callTracer without requesting the mutually-exclusive structLogs."""
        result = self.call("debug_traceTransaction", [
            tx_hash, {"tracer": "callTracer"}
        ])
        return result if isinstance(result, dict) else {}

    def anvil_impersonate(self, addr: str, on: bool = True) -> object | None:
        return self.call("anvil_impersonateAccount", [addr]) if on else None

    # ---- reads ----
    def eth_block_number(self) -> int:
        """Return block number as int (handles hex string and integer RPC responses)."""
        v = self.call("eth_blockNumber")
        return int(v, 16) if isinstance(v, str) else int(v)

    def eth_get_balance(self, addr: str, block: str = "latest") -> int:
        return int(self.call("eth_getBalance", [addr, block]), 16)

    def eth_get_transaction(self, tx_hash: str) -> dict | None:
        return self.call("eth_getTransactionByHash", [tx_hash])

    def eth_get_receipt(self, tx_hash: str) -> dict | None:
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def eth_get_code(self, addr: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [addr, block]) or "0x"

    def eth_get_storage(self, addr: str, slot: str, block: str = "latest") -> str:
        return self.call("eth_getStorageAt", [addr, slot, block]) or "0x0"
