# E5 archive-RPC preflight — 2026-08-12 to 2026-08-13

This is an infrastructure diagnosis, not an E5 fidelity result. Every probe
used the same fixed-set SASHAToken case and produced no observed receipt, so no
row is eligible for execution, state, or joint fidelity denominators.

## Initial provider sweep (2026-08-12)

| Fork-state route | Observed failure | Classification |
|---|---|---|
| Default archive route | HTTP 429/503 during Anvil lazy-state access | transport, unobserved |
| PublicNode route | HTTP 403 on historical account/state access | provider capability, unobserved |
| free dRPC route | HTTP 408 during historical state access | transport timeout, unobserved |
| multi-RPC fallback | local request timed out before receipt | transport timeout, unobserved |

## Public endpoint follow-up (2026-08-13)

The endpoint's capability changed, so the earlier 403 is not treated as current
evidence. Read-only probes now pass for `eth_blockNumber`, the fixed transaction,
historical `eth_getCode`, and `debug_traceTransaction` with
`prestateTracer.diff.post`. The same endpoint still cannot serve the workload
required by Anvil's lazy historical-state fetch:

| Run | Bound/result | Interpretation |
|---|---|---|
| `e5-v2-public-preflight2-20260813` | external 484 s cap; manifest only | diagnostic attempt; no E5 observation |
| `e5-v2-public-preflight6-20260813` | one CSV row within the configured 60 s bound, `outcome=UNOBSERVED`, `observed=false`, local request `operation timed out` | bounded transport failure; not an EVM revert; state replay correctly skipped |
| `e5-preflight-20260813-full300s` | all five direct capability probes pass; one k=0 replay reaches the full 300 s bound and 305 s process guard, `outcome=UNOBSERVED`, `observed=false` | valid long-bound preflight; archive lazy-state service remains insufficient; fixed-20 gate stays closed |

Between those attempts, the runner was hardened so archive-request timeout and
attempt count are separate from replay timeout, `cast` has a Python-enforced
wall-clock bound, state replay is skipped after unobserved execution, incomplete
state snapshots cannot be state-eligible, and failed runs leave no Anvil/Python
processes. These are runner-validity fixes, not favorable E5 outcomes.

The historical diagnostic directories remain under `raw_logs/e5_preflight_runs/`;
the machine-readable 300 s run is under `runs/e5-preflight-20260813-full300s/`.
They must never be pooled with a paper E5 run. Since the simplest frozen k=0
case still produced no observed receipt, launching all 20 would only measure the
known transport failure and was not done.

A valid next run requires one stable archive endpoint or a local archive node,
one run ID for all 20 frozen cases, and separate reporting of observed,
execution-pass, state-eligible, state-pass, and joint-pass counts.

All stored command lines are credential-redacted. The current-tree secret audit
is `python tools/audit_secrets.py`.
