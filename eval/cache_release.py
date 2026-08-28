"""Create a deterministic compressed release of the immutable E1 trace cache."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
from pathlib import Path

from .run_manifest import sha256_file, utc_run_id

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DEFAULT = ROOT / "eval" / "results" / "e1_trace_cache.jsonl"
OUT_DEFAULT = ROOT / "eval" / "artifacts" / "e1_trace_cache.jsonl.gz"
MANIFEST_DEFAULT = OUT_DEFAULT.with_name("cache_release_manifest.json")


def release(source: Path, output: Path) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, output.open("wb") as raw:
        with gzip.GzipFile(filename="e1_trace_cache.jsonl", mode="wb",
                           fileobj=raw, mtime=0, compresslevel=9) as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
    manifest = {
        "schema_version": 1,
        "run_id": utc_run_id("cache-release"),
        "source_name": source.name,
        "source_bytes": source.stat().st_size,
        "source_sha256": sha256_file(source),
        "compressed_name": output.name,
        "compressed_bytes": output.stat().st_size,
        "compressed_sha256": sha256_file(output),
        "compression": "gzip level 9; mtime=0",
    }
    manifest_path = output.with_name("cache_release_manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _gzip_content(output: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with gzip.open(output, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def verify(source: Path = SOURCE_DEFAULT, output: Path = OUT_DEFAULT,
           manifest_path: Path = MANIFEST_DEFAULT) -> list[str]:
    """Verify compressed bytes and the decompressed scientific cache content."""
    errors: list[str] = []
    if not manifest_path.is_file():
        return [f"manifest missing: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]

    if not output.is_file():
        return [f"compressed cache missing: {output}"]
    if output.name != manifest.get("compressed_name"):
        errors.append("compressed_name mismatch")
    if output.stat().st_size != manifest.get("compressed_bytes"):
        errors.append("compressed_bytes mismatch")
    if sha256_file(output) != manifest.get("compressed_sha256"):
        errors.append("compressed_sha256 mismatch")

    try:
        decompressed_bytes, decompressed_sha = _gzip_content(output)
    except (OSError, gzip.BadGzipFile, EOFError) as exc:
        errors.append(f"gzip content unreadable: {exc}")
    else:
        if decompressed_bytes != manifest.get("source_bytes"):
            errors.append("decompressed source_bytes mismatch")
        if decompressed_sha != manifest.get("source_sha256"):
            errors.append("decompressed source_sha256 mismatch")

    # The uncompressed cache is intentionally absent from a clean release. If
    # present in a working tree, verify it as an additional equality witness.
    if source.is_file():
        if source.name != manifest.get("source_name"):
            errors.append("source_name mismatch")
        if source.stat().st_size != manifest.get("source_bytes"):
            errors.append("source_bytes mismatch")
        if sha256_file(source) != manifest.get("source_sha256"):
            errors.append("source_sha256 mismatch")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build deterministic E1 cache release")
    parser.add_argument("--source", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--output", type=Path, default=OUT_DEFAULT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_DEFAULT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        errors = verify(args.source, args.output, args.manifest)
        if errors:
            print("Cache release verification failed:")
            print("\n".join(f"- {error}" for error in errors))
            return 1
        print("Cache release verification passed (compressed and decompressed SHA-256).")
        return 0
    print(json.dumps(release(args.source, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
