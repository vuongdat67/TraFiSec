"""E4 CLI composition boundary.

Argument parsing and workflow wiring remain in the characterized legacy CLI
for this incremental step.  The public entry point is moved first so future
extractions do not require changing shell commands.
"""

from __future__ import annotations

from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Run the backward-compatible E4 CLI with unchanged arguments."""
    from eval.necessity_cli import _legacy_main

    return _legacy_main(None if argv is None else list(argv))
