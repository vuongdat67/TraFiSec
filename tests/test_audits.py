"""
TraFiSec Audits & Consistency Test Suite
Validates empirical claims, citations, secrets, and dataset integrity.
"""

from corpus.dataset import verify_integrity
from tools.audit_claims import audit as audit_claims
from tools.audit_citations import audit as audit_citations
from tools.audit_secrets import audit as audit_secrets


def test_empirical_claims_consistency() -> None:
    """Verify that paper numbers match experimental results."""
    res = audit_claims()
    assert res["status"].upper() == "PASS", res["errors"]


def test_citations_validity() -> None:
    """Verify that all paper citations are resolved without dangling keys."""
    res = audit_citations()
    assert res["status"].upper() == "PASS", res["errors"]


def test_no_secret_leaks() -> None:
    """Verify that no private keys or active API tokens are committed."""
    res = audit_secrets()
    assert res["status"].upper() == "PASS", res["errors"]


def test_corpus_integrity() -> None:
    """Verify that benchmark dataset incidents and metadata match."""
    assert verify_integrity() is True
