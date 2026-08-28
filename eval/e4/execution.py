"""E4 execution orchestration.

The implementation owns baseline and mutation replay orchestration.
Legacy callers remain supported through a thin facade in eval.necessity.
"""

from __future__ import annotations

from typing import Any

NECESSITY_PORT = 8547
REPLAYER_TIMEOUT = 300


def run_necessity(case: Case, mutations: list[Mutation] | None = None,
                          *, rpc: str | None = None,
                          archive: RpcClient | None = None,
                          port: int = NECESSITY_PORT,
                          timeout: int = REPLAYER_TIMEOUT,
                          compute_loss: bool = True,
                          run_id: str = "",
                          include_sham: bool = False,
                          include_joint: bool = False,
                          b2_context: str | Path | None = None) -> list[dict]:
    """Run one case while preserving the pre-refactor public workflow."""
    from eval import necessity as n

    Path = n.Path
    json = n.json
    get_archive = n.get_archive
    RpcError = n.RpcError
    _safe_hex_int = n._safe_hex_int
    _resolve_prior_hashes = n._resolve_prior_hashes
    run_b2 = n.run_b2
    Outcome = n.Outcome
    ReplayResult = n.ReplayResult
    E5Replayer = n.E5Replayer
    ForkRunner = n.ForkRunner
    resolve_rpc = n.resolve_rpc
    _mainnet_gas_price = n._mainnet_gas_price
    NECESSITY_MAX_DELTA_PCT = n.NECESSITY_MAX_DELTA_PCT
    assess_harm = n.assess_harm
    _assess_transfer_harm = n._assess_transfer_harm
    _assess_attacker_value_harm = n._assess_attacker_value_harm
    _assess_pool_balance_delta = n._assess_pool_balance_delta
    _assess_euler_bad_debt_delta = n._assess_euler_bad_debt_delta
    _fetch_prestate_native_balance_delta = n._fetch_prestate_native_balance_delta
    _fetch_trace_token_transfer_delta = n._fetch_trace_token_transfer_delta
    _attacker_candidates_from_trace = n._attacker_candidates_from_trace
    resolve_attacker_address = n._resolve_attacker_address
    _b2_target_payload = n._b2_target_payload
    receipt_fingerprint = n.receipt_fingerprint
    build_joint_mutations = n.build_joint_mutations
    ShamStorageWrite = n.ShamStorageWrite
    _validate_sham_unrelated = n._validate_sham_unrelated
    _b2_mutation_args = n._b2_mutation_args
    mutation_factor = n.mutation_factor
    mutation_kind = n.mutation_kind
    _blocking_signature = n._blocking_signature
    HarmAssessment = n.HarmAssessment
    _b2_call_trace_diff = n._b2_call_trace_diff
    criterion = n.criterion
    evaluate_removal_intervention = n.evaluate_removal_intervention
    assess_sham_control = n.assess_sham_control
    CompositeMutation = n.CompositeMutation
    classify_joint_verdict = n.classify_joint_verdict
    mutation_factors = n.mutation_factors
    Replayer = n.Replayer
    SwapSlice = n.SwapSlice
    RPC_SLEEP = n.RPC_SLEEP
    time = n.time
    archive = archive or get_archive(rpc)

    def _save_b2_payload(payload: dict, filename: str) -> None:
        """Keep baseline/mutation B2 telemetry separate from context ``last``."""
        if not b2_context or not run_id:
            return
        out_dir = n.RESULTS_DIR / "runs" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / filename).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if case.block is None:
        tx = archive.eth_get_transaction(case.tx_hash)
        if not tx:
            raise RpcError(f"tx {case.tx_hash} khng resolve trn RPC")
        case.block = _safe_hex_int(tx.get("blockNumber"), 0) or None
        case.tx_index = _safe_hex_int(tx.get("transactionIndex"), 0)
        rec = archive.eth_get_receipt(case.tx_hash)
        if rec:
            case.mainnet_gas = _safe_hex_int(rec.get("gasUsed"), 0) or None
    if not case.mainnet_gas:
        try:
            rec = archive.eth_get_receipt(case.tx_hash)
            if rec:
                case.mainnet_gas = _safe_hex_int(rec.get("gasUsed"), 0) or None
        except RpcError:
            pass
    if not case.prior_hashes:
        case.prior_hashes = _resolve_prior_hashes(
            archive, case.tx_hash, case.block, case.tx_index)
    state_block = case.block - 1

    if b2_context:
        b2 = run_b2(b2_context, timeout=timeout)
        _save_b2_payload(b2.payload, "b2-baseline.json")
        target_receipt = None
        try:
            receipts = json.loads((Path(b2_context) / "receipts.json").read_text())
            target_receipt = receipts[case.tx_index].get("receipt")
        except (OSError, IndexError, TypeError, json.JSONDecodeError):
            pass
        if b2.observed and b2.status is True:
            outcome = Outcome.EXECUTED_UNKNOWN
        elif b2.observed and b2.status is False:
            outcome = Outcome.REVERTED
        else:
            outcome = Outcome.UNOBSERVED
        fid = ReplayResult(
            outcome=outcome, status=b2.status, gas_used=b2.gas_used,
            mainnet_gas=case.mainnet_gas, receipt=target_receipt,
            observed=b2.observed, error_kind="b2_failure" if not b2.observed else None,
            note=(f"B2 sequential relevant-substate; gas={b2.gas_used}; "
                  f"gas_limit={b2.gas_limit}; proof_verified={b2.proof_verified}; "
                  f"acceptance_gate={b2.payload.get('acceptance_gate', False)}"),
        )
    else:
        with ForkRunner(rpc or resolve_rpc(), state_block, port=port,
                        upstream_timeout_ms=timeout * 1000,
                        no_mining=True) as fork:
            rp = E5Replayer(fork, archive, timeout=timeout,
                            gas_price=_mainnet_gas_price(archive, case.tx_hash))
            fid = rp.replay_same_block(case.prior_hashes, case.tx_hash,
                                       case.mainnet_gas, gas_limit_multiplier=1.5)

    fidelity_ok = fid.fidelity_pass(NECESSITY_MAX_DELTA_PCT)
    harm_spec = case.extra.get("harm_spec") if isinstance(case.extra, dict) else None
    attacker_address = (harm_spec or {}).get("attacker") if isinstance(harm_spec, dict) else None
    if isinstance(harm_spec, dict) and harm_spec.get("oracle") == "attacker_value_delta" and not attacker_address:
        try:
            attacker_address = resolve_attacker_address(archive.eth_get_transaction(case.tx_hash))
        except RpcError:
            attacker_address = None
    lmin_usd = (harm_spec or {}).get("lmin_usd", "")
    valuation_source = (harm_spec or {}).get("valuation_source", "")
    baseline_harm = assess_harm(
        fid.receipt, harm_spec, disclosed_loss_usd=case.loss_usd, baseline=True)
    if b2_context and isinstance(harm_spec, dict):
        if harm_spec.get("oracle", "").endswith("_transfer_delta"):
            baseline_harm = _assess_transfer_harm(_b2_target_payload(b2.payload), harm_spec)
        elif harm_spec.get("oracle") == "attacker_value_delta":
            baseline_harm = _assess_attacker_value_harm(
                _b2_target_payload(b2.payload), attacker_address or "",
                attacker_candidates=_attacker_candidates_from_trace(
                    _b2_target_payload(b2.payload), attacker_address or ""),
                token_prices=harm_spec.get("token_prices"),
                native_price_usd=harm_spec.get("native_price_usd"),
                lmin_usd=float(harm_spec.get("lmin_usd", 100_000.0)),
            )
        elif harm_spec.get("oracle") == "pool_balance_delta":
            if str(harm_spec.get("protected_asset", "")).lower() == "weth":
                archive_delta = _fetch_trace_token_transfer_delta(
                    archive, case.tx_hash, harm_spec.get("protected_owner", ""),
                    harm_spec.get("protected_token", ""))
            else:
                archive_delta = _fetch_prestate_native_balance_delta(
                    archive, case.tx_hash, harm_spec.get("protected_owner", ""))
            baseline_harm = (
                _assess_pool_balance_delta(
                    _b2_target_payload(b2.payload), harm_spec,
                    archive_delta_wei=archive_delta)
                if archive_delta is not None else
                HarmAssessment("UNKNOWN", source="pool_balance_delta",
                               reason="historical prestateTracer diffMode unavailable"))
        elif harm_spec.get("oracle") == "euler_bad_debt_delta":
            baseline_harm = _assess_euler_bad_debt_delta(
                _b2_target_payload(b2.payload), harm_spec)
    baseline_fp = receipt_fingerprint(fid.receipt)
    baseline_outcome = fid.outcome.value
    if fid.status is True and baseline_harm.status == "HARM":
        baseline_outcome = Outcome.EXECUTED_HARM.value
    elif fid.status is True and baseline_harm.status == "NO_HARM":
        baseline_outcome = Outcome.EXECUTED_NO_HARM.value
    rows: list[dict] = []

    # fidelity row
    rows.append({
        "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
        "paper_eligible": bool(case.extra.get("paper_eligible")),
        "label_source": case.extra.get("label_source", "legacy_inventory"),
        "factor_gt": "blinded_pending_scoring",
        "mutation": "fidelity", "candidate_factor": "",
        "outcome": baseline_outcome, "observed": fid.observed,
        "fidelity_pass": fidelity_ok, "execution_preserving": fid.status is True,
        "behavior_changed": "", "harm_S": baseline_harm.status,
        "harm_Sm": "", "positive_candidate_delta_usd": baseline_harm.loss_usd if baseline_harm.loss_usd is not None else "",
        "positive_candidate_delta_usd_mutated": "", "delta_positive_candidate_usd": "",
        "verdict": "", "cause": "",
        "lmin_usd": lmin_usd, "valuation_source": valuation_source,
        "control_type": "", "control_pass": "",
        "factor_match": "not_scored",
        "baseline_gas_used": fid.gas_used or "",
        "mutation_gas_used": "",
        "gas_limit": (b2.gas_limit if b2_context else ""),
        "gas_margin": ((b2.gas_limit - fid.gas_used) if b2_context and
                        b2.gas_limit is not None and fid.gas_used is not None else ""),
        "out_of_gas": "",
        "same_block_context": bool(b2_context),
        "per_tx_gas_match": (b2.payload.get("all_gas_match") if b2_context else ""),
        "prestate_proof_verified": (b2.proof_verified if b2_context else ""),
        "target_status": fid.status,
        "revert_reason": "",
        "execution_diverged_by_mutation_error": False,
        "call_trace_equal": True if b2_context else "",
        "baseline_call_count": (len(_b2_target_payload(b2.payload).get("call_trace", []))
                                if b2_context else ""),
        "mutation_call_count": "",
        "call_trace_first_diff": "",
        "override_applied": False,
        "note": (f"fidelity: {fid.note}; harm={baseline_harm.status} "
                 f"source={baseline_harm.source or 'none'}; {baseline_harm.reason}"),
    })

    # Execution trace analysis and verification
    planned_mutations = list(mutations or [])
    if include_joint:
        planned_mutations.extend(build_joint_mutations(planned_mutations))
    if include_sham:
        sham = ShamStorageWrite()
        _validate_sham_unrelated(case.trace, sham)
        planned_mutations.append(sham)
    for m in planned_mutations:
        if b2_context:
            m_name = str(m) or m.name
            b2_args, unsupported = _b2_mutation_args(b2_context, m)
            if unsupported:
                rows.append({
                    "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
                    "mutation": m_name, "candidate_factor": mutation_factor(m_name),
                    "outcome": "UNOBSERVED", "observed": False,
                    "fidelity_pass": fidelity_ok, "execution_preserving": False,
                    "intervention_valid": False, "validity_reason": unsupported,
                    "behavior_changed": False, "harm_S": baseline_harm.status,
                    "harm_Sm": "UNKNOWN", "verdict": "INCONCLUSIVE-b2-unsupported",
                    "cause": "", "factor_match": "not_scored",
                    "baseline_gas_used": fid.gas_used or "", "mutation_gas_used": "",
                    "gas_limit": b2.gas_limit, "gas_margin": "", "out_of_gas": "",
                    "same_block_context": True,
                    "per_tx_gas_match": b2.payload.get("prefix_gas_match", False),
                    "prestate_proof_verified": b2.proof_verified,
                    "note": f"B2 mutation rejected at adapter boundary: {unsupported}",
                })
                continue
            mutated = run_b2(b2_context, timeout=timeout, target_index=case.tx_index, **b2_args)
            safe_mutation = "".join(
                char if char.isalnum() or char in "-_" else "_" for char in m_name)
            _save_b2_payload(mutated.payload, f"b2-mutation-{safe_mutation}.json")
            mutated_gas = mutated.gas_used
            target_payload = _b2_target_payload(mutated.payload)
            baseline_payload = _b2_target_payload(b2.payload)
            trace_equal, baseline_calls, mutation_calls, first_diff = _b2_call_trace_diff(
                baseline_payload, target_payload)
            revert_reason = target_payload.get("revert_data") or target_payload.get("error") or ""
            trace_errors = [str(frame.get("error") or "")
                            for frame in target_payload.get("call_trace", [])
                            if frame.get("error")]
            if not revert_reason and trace_errors:
                revert_reason = trace_errors[0]
            out_of_gas = "out of gas" in str(revert_reason).lower() or any(
                "out of gas" in error.lower() for error in trace_errors)
            kind = mutation_kind(m)
            blocking_verified, blocking_reason = _blocking_signature(
                m, target_payload, out_of_gas=out_of_gas,
                call_trace_equal=trace_equal)
            execution_preserving = mutated.observed and mutated.status is True
            if isinstance(harm_spec, dict) and harm_spec.get("oracle", "").endswith("_transfer_delta"):
                mutated_harm = _assess_transfer_harm(target_payload, harm_spec)
            elif isinstance(harm_spec, dict) and harm_spec.get("oracle") == "attacker_value_delta":
                mutated_harm = _assess_attacker_value_harm(
                    target_payload, attacker_address or "",
                    attacker_candidates=_attacker_candidates_from_trace(
                        target_payload, attacker_address or ""),
                    token_prices=harm_spec.get("token_prices"),
                    native_price_usd=harm_spec.get("native_price_usd"),
                    lmin_usd=float(harm_spec.get("lmin_usd", 100_000.0)),
                )
            elif isinstance(harm_spec, dict) and harm_spec.get("oracle") == "pool_balance_delta":
                mutated_harm = _assess_pool_balance_delta(target_payload, harm_spec)
            elif isinstance(harm_spec, dict) and harm_spec.get("oracle") == "euler_bad_debt_delta":
                mutated_harm = _assess_euler_bad_debt_delta(target_payload, harm_spec)
            else:
                mutated_harm = HarmAssessment("UNKNOWN", reason="harm oracle unavailable")
            mutated_outcome = (
                Outcome.EXECUTED_UNKNOWN.value if execution_preserving else
                Outcome.REVERTED.value if mutated.observed else Outcome.UNOBSERVED.value)
            gas_margin = (mutated.gas_limit - mutated_gas
                          if mutated.gas_limit is not None and mutated_gas is not None else "")
            verdict = "INCONCLUSIVE"
            baseline_status = baseline_harm.status
            if baseline_status == "UNKNOWN":
                verdict = "INCONCLUSIVE-harm-unmeasured"
            elif baseline_status != "HARM":
                verdict = "INCONCLUSIVE-baseline-harm"
            elif kind == "insertion-blocking" and mutated.observed and mutated.status is False:
                verdict = ("CAUSE-NECESSARY-blocking" if blocking_verified
                           else f"INCONCLUSIVE-blocking-{blocking_reason}")
            elif not mutated.observed:
                verdict = "INCONCLUSIVE-transport"
            elif out_of_gas or mutated.status is False:
                verdict = "INCONCLUSIVE-revert"
            elif not fidelity_ok or not mutated.proof_verified:
                verdict = "INCONCLUSIVE-fidelity"
            else:
                verdict = evaluate_removal_intervention(
                    baseline_harm=(True if baseline_harm.status == "HARM" else
                                   False if baseline_harm.status == "NO_HARM" else None),
                    mutation_executed=mutated.status is True,
                    mutation_harm=(
                        False if mutated_harm.status == "NO_HARM" else
                        True if mutated_harm.status == "HARM" else None
                    ),
                    intervention_supported=execution_preserving,
                )
            rows.append({
                "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
                "mutation": m_name, "candidate_factor": mutation_factor(m_name),
                "mutation_kind": kind, "causal_signature": blocking_reason,
                "outcome": mutated_outcome, "observed": mutated.observed,
                "fidelity_pass": fidelity_ok, "execution_preserving": execution_preserving,
                "intervention_valid": execution_preserving,
                "validity_reason": "execution_preserving" if execution_preserving else mutated.error,
                "behavior_changed": (mutated_gas != fid.gas_used if mutated_gas is not None else False),
                "harm_S": baseline_harm.status, "harm_Sm": mutated_harm.status, "verdict": verdict,
                "cause": "1" if verdict in {"CAUSE", "CAUSE-NECESSARY-blocking"} else "", "factor_match": "not_scored",
                "baseline_gas_used": fid.gas_used or "", "mutation_gas_used": mutated_gas or "",
                "gas_limit": mutated.gas_limit or b2.gas_limit,
                "gas_margin": gas_margin, "out_of_gas": out_of_gas,
                "same_block_context": True,
                "per_tx_gas_match": mutated.payload.get("prefix_gas_match", False),
                "prestate_proof_verified": mutated.proof_verified,
                "target_status": mutated.status,
                "revert_reason": revert_reason,
                "execution_diverged_by_mutation_error": bool(
                    mutated.observed and mutated.status is False),
                "call_trace_equal": trace_equal,
                "baseline_call_count": baseline_calls,
                "mutation_call_count": mutation_calls,
                "call_trace_first_diff": first_diff if first_diff is not None else "",
                "override_applied": bool(mutated.payload.get("mutation")),
                "note": (f"B2 mutation runner; target_index={mutated.payload.get('target_index')}; "
                         f"mutation={mutated.payload.get('mutation')}; call_trace_equal={trace_equal}; "
                         f"harm={mutated_harm.reason}; error={mutated.error or 'none'}"),
            })
            continue
        # Calldata-only interventions can be queued with prefix+target in one
        # block.  State/code patches cannot safely be applied between pending
        # prefix transactions and the target without a custom EVM hook; keep
        # those branches explicitly inconclusive instead of introducing a
        # block-context artifact.
        calldata_only = isinstance(m, SwapSlice)
        if calldata_only:
            with ForkRunner(rpc or resolve_rpc(), state_block, port=port,
                            upstream_timeout_ms=timeout * 1000,
                            no_mining=True) as fork:
                rp = E5Replayer(fork, archive, timeout=timeout,
                                gas_price=_mainnet_gas_price(archive, case.tx_hash))
                m.apply_to_replayer(rp)
                res = rp.replay_same_block(case.prior_hashes, case.tx_hash, None,
                                           gas_limit_multiplier=1.5)
            same_block_context = True
        else:
            with ForkRunner(rpc or resolve_rpc(), state_block, port=port,
                            upstream_timeout_ms=timeout * 1000) as fork:
                rp = Replayer(fork, archive, timeout=timeout)
                if case.prior_hashes:
                    rp.warmup(case.prior_hashes)
                m.apply_to_replayer(rp)
                m.apply(fork)
                res = rp.replay(case.tx_hash, None)
            same_block_context = False
        m_name = str(m) or m.name
        mutated_harm = assess_harm(res.receipt, harm_spec) if compute_loss \
            else HarmAssessment("UNKNOWN", reason="loss disabled")
        mutation_fp = receipt_fingerprint(res.receipt)
        execution_preserving = res.observed and res.status is True
        intervention_valid, validity_reason = m.validate_execution(
            observed=res.observed, status=res.status)
        if not same_block_context:
            intervention_valid = False
            validity_reason = "same_block_context_unverified"
        gas_changed = (fid.gas_used is not None and res.gas_used is not None
                       and abs(fid.gas_used - res.gas_used) > max(100, int(fid.gas_used * 0.001)))
        behavior_changed = bool(execution_preserving and
                                ((baseline_fp and mutation_fp and baseline_fp != mutation_fp)
                                 or gas_changed))
        mutated_outcome = res.outcome.value
        if res.status is True and mutated_harm.status == "HARM":
            mutated_outcome = Outcome.EXECUTED_HARM.value
        elif res.status is True and mutated_harm.status == "NO_HARM":
            mutated_outcome = Outcome.EXECUTED_NO_HARM.value
        is_control = isinstance(m, ShamStorageWrite)
        is_joint = isinstance(m, CompositeMutation)
        control_pass: bool | None = None
        if is_control:
            verdict, control_pass = assess_sham_control(
                fidelity_ok=fidelity_ok,
                observed=res.observed,
                execution_preserving=execution_preserving and intervention_valid,
                behavior_changed=behavior_changed,
                baseline_harm=baseline_harm.status,
                mutated_harm=mutated_harm.status,
            )
        else:
            verdict = criterion(
                mutated_outcome,
                baseline_harm=baseline_harm.status if fidelity_ok else "UNKNOWN",
                mutated_harm=mutated_harm.status,
                observed=res.observed,
                execution_preserving=execution_preserving and intervention_valid,
                behavior_changed=behavior_changed,
            )
        joint_verdict = (classify_joint_verdict(m, verdict, rows)
                         if is_joint else "")
        if is_control:
            match = confusion = "not_scored_control"
        else:
            match = confusion = "not_scored_pending"
        loss_s = baseline_harm.loss_usd
        loss_sm = mutated_harm.loss_usd
        dloss = ""
        if loss_s is not None and loss_sm is not None:
            dloss = round(loss_s - loss_sm, 2)
        note_parts = [res.note, f"outcome(S−{m_name})={mutated_outcome}",
                      f"harm(S)={baseline_harm.status}",
                      f"harm(S−X)={mutated_harm.status}",
                      f"behavior_changed={behavior_changed} → {verdict}",
                      f"validity={validity_reason}"]
        if not same_block_context:
            note_parts.append("same_block_context=False: state/code patch mutation not causal-eligible")
        if not fidelity_ok:
            note_parts.append("fidelity gate failed")
        rows.append({
            "run_id": run_id, "planner": "blind-v2", "case": case.case_id,
            "paper_eligible": bool(case.extra.get("paper_eligible")),
            "label_source": case.extra.get("label_source", "legacy_inventory"),
            "factor_gt": "blinded_pending_scoring",
            "mutation": m_name, "candidate_factor": mutation_factor(m_name),
            "ratio": getattr(m, "ratio", ""),
            "execution_status": mutated_outcome,
            "invariant_status": validity_reason,
            "outcome": mutated_outcome, "observed": res.observed,
            "fidelity_pass": fidelity_ok,
            "execution_preserving": execution_preserving,
            "intervention_valid": intervention_valid,
            "validity_reason": validity_reason,
            "behavior_changed": behavior_changed,
            "harm_S": baseline_harm.status, "harm_Sm": mutated_harm.status,
            "positive_candidate_delta_usd": round(loss_s, 2) if loss_s is not None else "",
            "positive_candidate_delta_usd_mutated": round(loss_sm, 2) if loss_sm is not None else "",
            "delta_positive_candidate_usd": dloss,
            "lmin_usd": lmin_usd, "valuation_source": valuation_source,
            "control_type": "sham_unrelated_storage" if is_control else "",
            "control_pass": (control_pass if control_pass is not None else ""),
            "intervention_order": 2 if is_joint else 1,
            "joint_factors": "+".join(mutation_factors(m)) if is_joint else "",
            "joint_verdict": joint_verdict,
            "verdict": verdict,
            "cause": "1" if verdict == "CAUSE" else "",
            "factor_match": match, "factor_confusion": confusion,
            "note": "; ".join(p for p in note_parts if p),
        })
        time.sleep(RPC_SLEEP)

    return rows
