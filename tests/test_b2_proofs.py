import json
from pathlib import Path

import pytest

from eval.b2_proofs import acquire


class FakeArchive:
    url = "https://archive.example"
    last_endpoint = url

    def __init__(self, interrupt_after=None):
        self.calls = []
        self.interrupt_after = interrupt_after

    def call(self, method, params):
        if method == "eth_getBlockByNumber":
            return {"number": "0x10", "stateRoot": "0xroot"}
        if method != "eth_getProof":
            raise AssertionError(method)
        self.calls.append(params[0])
        if self.interrupt_after is not None and len(self.calls) > self.interrupt_after:
            raise KeyboardInterrupt()
        return {"address": params[0], "accountProof": [], "storageProof": []}


def _context(tmp_path: Path) -> Path:
    context = tmp_path / "context"
    context.mkdir()
    (context / "block.json").write_text(json.dumps({"number": "0x10"}))
    traces = [{"trace": {address: {"storage": {}}}}
              for address in ("0x02", "0x01", "0x03")]
    (context / "prestates.json").write_text(json.dumps(traces))
    (context / "transactions.json").write_text("[]")
    return context


def test_proof_acquisition_resumes_completed_chunk(tmp_path):
    context = _context(tmp_path)
    interrupted = FakeArchive(interrupt_after=2)
    with pytest.raises(KeyboardInterrupt):
        acquire(context, interrupted, chunk_size=2, chunk_attempts=1)

    progress = json.loads((context / "proof_progress.json").read_text())
    assert progress["proof_count"] == 2
    assert (context / "proof_chunks" / "chunk-00000.json").is_file()

    resumed = FakeArchive()
    result = acquire(context, resumed, chunk_size=2, chunk_attempts=1)
    assert result["prestate_proof_complete"] is True
    assert resumed.calls == ["0x03"]
    proofs = json.loads((context / "prestate_proofs.json").read_text())["proofs"]
    assert len(proofs) == 3
