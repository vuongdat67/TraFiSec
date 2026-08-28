# Portable evaluation inputs

`e1_trace_cache.jsonl.gz` is a compressed copy of the immutable local E1 cache.
Decompress it to `eval/results/e1_trace_cache.jsonl` before reproducing offline
experiments. Verify both compressed and decompressed SHA-256 values against
`cache_release_manifest.json`.

The cache contains historical public-chain transaction traces only. It does not
contain RPC credentials or live-system write capability.

`release_inventory.json` and `SHA256SUMS` cover the paper, primary results,
schemas, figures, cache release, and reproduction tools. Verify them with
`python tools/build_checksums.py --check` after reproduction.
