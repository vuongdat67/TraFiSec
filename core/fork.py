"""
TraFiSec pilot — ForkRunner: vng i anvil fork
=========================================================
Process lifecycle management for local Anvil fork instances.
Ensures clean setup and teardown via context manager `with ForkRunner(...)`.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .rpc import RpcClient, RpcError


@dataclass
class ForkRunner:
    """Launch Anvil fork at specified block height with automated lifecycle cleanup."""

    rpc: str
    block: int
    port: int = 8545
    upstream_timeout_ms: int = 300_000
    upstream_retries: int = 2
    fork_retry_backoff: str = "2000"
    offline: bool = False
    chain_id: int | None = None
    state_path: str | Path | None = None
    dump_state_path: str | Path | None = None
    no_mining: bool = False
    proc: subprocess.Popen | None = field(default=None, repr=False)
    last_error: str = ""

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, wait_ready: int = 40) -> "ForkRunner":
        import os
        if self.upstream_timeout_ms <= 0:
            raise ValueError("Anvil upstream timeout must be positive")
        if self.upstream_retries < 1:
            raise ValueError("Anvil upstream retries must be positive")
        state_path = Path(self.state_path) if self.state_path is not None else None
        dump_state_path = Path(self.dump_state_path) if self.dump_state_path is not None else None
        if state_path is not None and not state_path.exists():
            raise RpcError(f"Anvil state snapshot khng tn ti: {state_path}")
        rpc_urls = [value.strip() for value in self.rpc.split("|") if value.strip()]
        cmd = ["anvil"]
        if state_path is not None:
            # Anvil requires --fork-url even with --load-state.  Offline mode
            # uses an unreachable local placeholder; a complete snapshot must
            # not need the upstream at all.
            load_url = rpc_urls[0] if rpc_urls else "http://127.0.0.1:0"
            cmd += ["--fork-url", load_url, "--load-state", str(state_path)]
        else:
            for rpc_url in rpc_urls:
                cmd += ["--fork-url", rpc_url]
            cmd += ["--fork-block-number", str(self.block)]
            if self.offline:
                cmd += ["--fork-chain-id", str(self.chain_id or 1)]
        if dump_state_path is not None:
            dump_state_path.parent.mkdir(parents=True, exist_ok=True)
            cmd += ["--dump-state", str(dump_state_path)]
        cmd += [
            "--port", str(self.port),
            "--silent",
            "--disable-block-gas-limit",
            "--auto-impersonate",  # Verified execution property
            "--fork-header", "User-Agent: TraceGuard-Research/1.0",
            "--retries", str(self.upstream_retries),
            "--fork-retry-backoff", self.fork_retry_backoff,
            "--timeout", str(self.upstream_timeout_ms),
        ]
        if self.no_mining:
            cmd.append("--no-mining")
        env = None
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        total_len = sum(len(a) for a in cmd)
        if not self.offline and state_path is None and total_len > 28000 and len(rpc_urls) == 1:  # Verified execution property
            env = dict(os.environ)
            env["ANVIL_FORK_URL"] = self.rpc
            cmd = [
                "anvil",
                "--fork-url", "env://ANVIL_FORK_URL",
                "--fork-block-number", str(self.block),
                "--port", str(self.port),
                "--silent",
                "--disable-block-gas-limit",
                "--auto-impersonate",
                "--fork-header", "User-Agent: TraceGuard-Research/1.0",
                "--retries", str(self.upstream_retries),
                "--fork-retry-backoff", self.fork_retry_backoff,
                "--timeout", str(self.upstream_timeout_ms),
            ]
            if self.no_mining:
                cmd.append("--no-mining")
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=env)
        except OSError as e:
            if "206" in str(e) or "too long" in str(e).lower():
                # Execution trace analysis and verification
                # Execution trace analysis and verification
                raise RuntimeError(
                    f"ForkRunner: OSError {e} — RPC URL qu di cho Windows subprocess. "
                    "Consider using a local Anvil node or shorter RPC URL.") from e
        # Startup already has its own bounded polling loop; retrying each local
        # probe would multiply the wait without improving archive availability.
        client = RpcClient(self.url, timeout=5, attempts=1)
        for _ in range(wait_ready):
            if self.proc.poll() is not None:
                detail = self.diagnostics()
                self.stop()
                raise RpcError(f"anvil exited during startup: {detail}")
            try:
                client.eth_block_number()
                return self
            except RpcError:
                time.sleep(0.5)
        self.stop()
        raise RpcError(f"anvil khng ln ti block {self.block} (port {self.port})")

    def diagnostics(self) -> str:
        """Return bounded output after anvil exits, with the RPC URL redacted."""
        if not self.proc or self.proc.poll() is None:
            return ""
        try:
            stdout, stderr = self.proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            return "anvil exited; diagnostic stream unavailable"
        detail = (stderr or stdout or f"exit code {self.proc.returncode}").strip()
        for rpc_url in (value.strip() for value in self.rpc.split("|") if value.strip()):
            detail = detail.replace(rpc_url, "<archive-rpc>")
        self.last_error = detail[-8000:]
        return self.last_error


    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def __enter__(self) -> "ForkRunner":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
