__all__ = [
    "normalize_r3_run",
    "load_r3_study",
    "R3_REP_LABELS",
]

import json
from . import (
    ContractStatus,
    ControlStatus,
    EffectiveState,
    ExperimentConfig,
    GroundingCounts,
    InfraStatus,
    ModelDecision,
    Prematurity,
    ProviderStatus,
    RunKey,
    TokenUsage,
    Truth,
)
from .classify import classify_run, normalize_stop

R3_REP_LABELS = {
    ("credential_compromise", "medium", 3): "A",
    ("recon_heavy", "medium", 13): "B",
    ("data_access_anomaly", "easy", 21): "C",
    ("credential_compromise", "easy", 1): "D",
}

_DECISION_BY_OUTCOME = {
    "SUCCESS": ModelDecision.SUCCESS,
    "WRONG_PRINCIPAL": ModelDecision.WRONG_PRINCIPAL,
    "PREMATURE_BENIGN": ModelDecision.PREMATURE_BENIGN,
    "NO_FINAL": ModelDecision.NO_VALID_FINAL,
    "MALFORMED_FINAL": ModelDecision.NO_VALID_FINAL,
    "WRONG_ACTION": ModelDecision.WRONG_ACTION,
    "TYPE_CONFUSION": ModelDecision.TYPE_CONFUSION,
    "OTHER_MODEL_FAILURE": ModelDecision.OTHER_MODEL_FAILURE,
}


def normalize_r3_run(record, config, benchmark_version="m7d-v1") -> object:
    record = dict(record)
    key = RunKey(
        benchmark_version=benchmark_version,
        scenario_id=record.get("scenario_id", ""),
        repetition_index=int(str(record.get("rep", "R0"))[1:]
                             if str(record.get("rep", "")[:1]) in "ABCD"
                             else 0),
        config_digest=config.identity())
    malicious = record.get("family") != "benign"
    truth = Truth.MALICIOUS if malicious else Truth.BENIGN
    cls = record.get("classification", "")
    if cls == "INFRASTRUCTURE_FAILURE":
        infra = InfraStatus.CONTROL_FAILURE
    elif cls == "EXPERIMENT_INPUT_DRIFT":
        infra = InfraStatus.GENERATION_FAILURE
    else:
        infra = InfraStatus.VALID
    provider, contract = normalize_stop(record.get("stop_reason"))
    if record.get("primary_outcome") in ("PROVIDER_FAILURE",
                                         "RESPONSE_CONTRACT_FAILURE"):
        provider = ProviderStatus.OTHER_PROVIDER_ERROR
        contract = ContractStatus.NOT_EVALUABLE
    outcome = record.get("primary_outcome", "")
    if outcome == "SUCCESS":
        decision = ModelDecision.SUCCESS
    elif provider != ProviderStatus.COMPLETED:
        decision = ModelDecision.NOT_EVALUABLE
    else:
        decision = _DECISION_BY_OUTCOME.get(
            outcome, ModelDecision.OTHER_MODEL_FAILURE)
    bridge = record.get("bridge")
    if bridge == "confirmed":
        control, approved = (ControlStatus.EXECUTION_CONFIRMED, True)
    elif isinstance(bridge, str) and bridge.startswith("rejected"):
        control, approved = (ControlStatus.PREPARE_REJECTED, False)
    elif record.get("action") is not None:
        control, approved = (ControlStatus.PREPARE_ACCEPTED, False)
    else:
        control, approved = (ControlStatus.NOT_PROPOSED, False)
    if approved and record.get("approval_id"):
        control = ControlStatus.APPROVED \
            if control != ControlStatus.EXECUTION_CONFIRMED else control
    delta = record.get("mutation_delta")
    if delta == 1:
        effective = EffectiveState.TARGET_INACTIVE
    elif malicious and delta == 0 and decision == ModelDecision.SUCCESS:
        effective = EffectiveState.TARGET_ACTIVE
    elif not malicious:
        effective = EffectiveState.BENIGN_UNCHANGED
    else:
        effective = EffectiveState.UNKNOWN
    counts = record.get("grounding_counts", {}) or {}
    labels = record.get("secondary_labels", {}) or {}
    grounding = GroundingCounts(
        observed_typed=int(counts.get("OBSERVED_TYPED", 0)),
        literal_only=int(counts.get("LITERAL_ONLY", 0)),
        ungrounded=int(counts.get("UNGROUNDED", 0)),
        actor_reused_as_username=bool(
            labels.get("actor_type_confusion", False)),
        recovered_after_confusion=bool(
            labels.get("actor_type_confusion", False) and
            decision == ModelDecision.SUCCESS),
        correct_username_observed=bool(record.get("principal_ok", False)),
        correct_key_observed=bool(record.get("key_ok", False)))
    calls = record.get("calls", []) or []
    tool_ids = [c.get("tool_id") for c in calls]
    prematurity = Prematurity(
        material_path_remaining=bool(decision not in (
            ModelDecision.SUCCESS, ModelDecision.NOT_EVALUABLE)),
        iam_discovery_attempted="iam_list_users" in tool_ids,
        key_discovery_attempted="iam_list_access_keys" in tool_ids,
        logs_path_attempted="logs_get_log_events" in tool_ids,
        final_turn=int(record.get("model_turns", 0) or 0))
    usage = record.get("token_usage", []) or []
    tokens = TokenUsage(
        input_tokens=sum(t.get("input_tokens", 0) for t in usage),
        output_tokens=sum(t.get("output_tokens", 0) for t in usage))
    return classify_run(
        key, truth, infra=infra, provider=provider, contract=contract,
        decision=decision, control=control, effective=effective,
        turns=int(record.get("model_turns", 0) or 0),
        tool_calls=int(record.get("tool_calls", 0) or 0),
        ordered_tools=tuple(tool_ids),
        broker_denials=sum(1 for c in calls if not c.get("ok", True)),
        unexpected_denials=len(record.get("unexpected_denials", []) or []),
        grounding=grounding, prematurity=prematurity,
        sufficiency=str(record.get("sufficiency", "")),
        confidence=float(record.get("confidence", 0.0) or 0.0),
        tokens=tokens,
        latency_s=float(record.get("model_latency_s", 0.0) or 0.0),
        input_digest="",
        unexpected_rejection=bool(
            record.get("unexpected_containment_rejection", False)),
        investigator_failed=not record.get("investigator_active", True)
        if decision == ModelDecision.SUCCESS else False,
        provenance=("RECORDED_RUNTIME",))


def load_r3_study(path, config, benchmark_version="m7d-v1"):
    with open(path, encoding="utf-8") as handle:
        study = json.load(handle)
    return [normalize_r3_run(run, config,
                             benchmark_version=benchmark_version)
            for run in study.get("runs", [])]
