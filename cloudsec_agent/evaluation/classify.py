__all__ = [
    "normalize_stop",
    "classify_run",
    "aggregate_scenario",
    "aggregate_benchmark",
    "evaluation_input_digest",
    "median_of",
]

import hashlib
import json
from . import (
    BenchmarkAggregate,
    ContractStatus,
    ControlStatus,
    EffectiveState,
    InfraStatus,
    ModelDecision,
    ProviderStatus,
    RunOutcome,
    ScenarioAggregate,
    Stability,
    TokenUsage,
    TopLevel,
    Truth,
)

PROVIDER_MARKERS = {
    ProviderStatus.TIMEOUT: ("timeout", "timed out", "timedout"),
    ProviderStatus.RATE_LIMIT: ("429", "rate_limit", "rate-limit",
                                "rate_limited"),
    ProviderStatus.SERVICE_UNAVAILABLE: ("503", "service_unavailable",
                                         "unavailable", "overloaded"),
    ProviderStatus.TRANSPORT_ERROR: ("transport", "connection", "500",
                                     "502", "504"),
}


def normalize_stop(stop_reason) -> tuple:
    text = str(stop_reason or "").lower()
    for status, markers in PROVIDER_MARKERS.items():
        if any(m in text for m in markers):
            return status, ContractStatus.NOT_EVALUABLE
    if "provider_error" in text or "providererror" in text:
        return (ProviderStatus.OTHER_PROVIDER_ERROR,
                ContractStatus.NOT_EVALUABLE)
    if "final_not_json" in text:
        return ProviderStatus.COMPLETED, ContractStatus.FINAL_NOT_JSON
    if "invalid_final_schema" in text or "schema" in text:
        return (ProviderStatus.COMPLETED,
                ContractStatus.INVALID_FINAL_SCHEMA)
    if "invalid_arguments" in text or "invalid_tool" in text:
        return ProviderStatus.COMPLETED, ContractStatus.INVALID_TOOL_ARGS
    if "no_actionable_finding" in text or "final_answer_accepted" in text:
        return ProviderStatus.COMPLETED, ContractStatus.VALID
    if "truncated" in text:
        return (ProviderStatus.COMPLETED,
                ContractStatus.OTHER_CONTRACT_FAILURE)
    if "no_final" in text:
        return ProviderStatus.COMPLETED, ContractStatus.NO_FINAL
    return ProviderStatus.COMPLETED, ContractStatus.VALID


def classify_run(key, truth, *, infra, provider, contract, decision,
                 control, effective, **metrics) -> RunOutcome:
    if not isinstance(decision, ModelDecision):
        decision = ModelDecision(decision)
    if infra != InfraStatus.VALID:
        top = TopLevel.INFRASTRUCTURE_INVALID
    elif provider != ProviderStatus.COMPLETED:
        top = TopLevel.PROVIDER_INTERRUPTED
        decision = ModelDecision.NOT_EVALUABLE
    elif contract != ContractStatus.VALID:
        top = TopLevel.RESPONSE_CONTRACT_FAILURE
    elif decision == ModelDecision.SUCCESS:
        top = TopLevel.VALID_MODEL_SUCCESS
    else:
        top = TopLevel.VALID_MODEL_FAILURE
    return RunOutcome(
        key=key, truth=truth, infra=infra, provider=provider,
        contract=contract, decision=decision, control=control,
        effective=effective, top_level=top, **metrics)


def evaluation_input_digest(payload) -> str:
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, default=str).encode()).hexdigest()


def median_of(values):
    ordered = sorted(values)
    if not ordered:
        return 0
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _mean(values):
    if not values:
        return 0
    return sum(values) / len(values)


def aggregate_scenario(scenario_id, family, difficulty, outcomes,
                       min_evaluable=2) -> ScenarioAggregate:
    attempted = len(outcomes)
    interrupted = sum(1 for o in outcomes
                      if o.top_level == TopLevel.PROVIDER_INTERRUPTED)
    invalid = sum(1 for o in outcomes
                  if o.top_level == TopLevel.INFRASTRUCTURE_INVALID)
    evaluable = attempted - interrupted - invalid
    successes = sum(1 for o in outcomes
                    if o.top_level == TopLevel.VALID_MODEL_SUCCESS)
    failures = sum(1 for o in outcomes
                   if o.top_level == TopLevel.VALID_MODEL_FAILURE)
    contract = sum(1 for o in outcomes
                   if o.top_level == TopLevel.RESPONSE_CONTRACT_FAILURE)
    actor = sum(1 for o in outcomes if o.grounding.actor_reused_as_username)
    premature = sum(1 for o in outcomes
                    if o.prematurity.material_path_remaining and
                    o.top_level in (TopLevel.VALID_MODEL_FAILURE,
                                    TopLevel.RESPONSE_CONTRACT_FAILURE))
    no_final = sum(1 for o in outcomes
                   if o.contract in (ContractStatus.NO_FINAL,
                                     ContractStatus.FINAL_NOT_JSON))
    turns = tuple(o.turns for o in outcomes)
    calls = tuple(o.tool_calls for o in outcomes)
    toks = tuple(o.tokens.total for o in outcomes)
    if evaluable < min_evaluable:
        stability = Stability.INSUFFICIENT_EVALUABLE_RUNS
    elif evaluable and successes == evaluable:
        stability = Stability.CONSISTENT_SUCCESS
    elif evaluable and successes == 0:
        stability = Stability.CONSISTENT_FAILURE
    else:
        stability = Stability.MIXED
    return ScenarioAggregate(
        scenario_id=scenario_id, family=family, difficulty=difficulty,
        attempted_runs=attempted, evaluable_runs=evaluable,
        provider_interrupted=interrupted, infrastructure_invalid=invalid,
        successes=successes, model_failures=failures,
        contract_failures=contract, actor_confusion_count=actor,
        premature_final_count=premature, no_final_count=no_final,
        turns=turns, tool_calls=calls, tokens=toks, stability=stability)


def aggregate_benchmark(version, scenario_aggs, outcomes) -> BenchmarkAggregate:
    mal = [o for o in outcomes if o.truth == Truth.MALICIOUS]
    ben = [o for o in outcomes if o.truth == Truth.BENIGN]
    ben_ok = [o for o in ben
              if o.top_level == TopLevel.VALID_MODEL_SUCCESS]
    ben_fp = [o for o in ben if o.decision != ModelDecision.SUCCESS and
              o.top_level == TopLevel.VALID_MODEL_FAILURE]
    return BenchmarkAggregate(
        version=version, scenarios=len(scenario_aggs),
        attempted_runs=sum(a.attempted_runs for a in scenario_aggs),
        evaluable_runs=sum(a.evaluable_runs for a in scenario_aggs),
        successful_runs=sum(a.successes for a in scenario_aggs),
        model_failure_runs=sum(a.model_failures for a in scenario_aggs),
        provider_interrupted_runs=sum(
            a.provider_interrupted for a in scenario_aggs),
        infrastructure_invalid_runs=sum(
            a.infrastructure_invalid for a in scenario_aggs),
        benign_attempted=len(ben), benign_evaluable=sum(
            1 for o in ben if o.top_level in (
                TopLevel.VALID_MODEL_SUCCESS, TopLevel.VALID_MODEL_FAILURE,
                TopLevel.RESPONSE_CONTRACT_FAILURE)),
        benign_correct=len(ben_ok), benign_false_positives=len(ben_fp),
        benign_interruptions=sum(
            1 for o in ben
            if o.top_level == TopLevel.PROVIDER_INTERRUPTED),
        proposals=sum(1 for o in mal if o.control not in (
            ControlStatus.NOT_PROPOSED, ControlStatus.NOT_APPLICABLE)),
        prepare_accepted=sum(1 for o in mal if o.control in (
            ControlStatus.PREPARE_ACCEPTED, ControlStatus.APPROVED,
            ControlStatus.EXECUTION_CONFIRMED,
            ControlStatus.ALREADY_EFFECTIVE)),
        prepare_rejected=sum(1 for o in mal if o.control in (
            ControlStatus.PREPARE_REJECTED, ControlStatus.EXECUTION_FAILED)),
        approvals=sum(1 for o in mal if o.control in (
            ControlStatus.APPROVED, ControlStatus.EXECUTION_CONFIRMED,
            ControlStatus.ALREADY_EFFECTIVE)),
        confirmed_mutations=sum(
            1 for o in mal
            if o.control == ControlStatus.EXECUTION_CONFIRMED),
        already_effective=sum(
            1 for o in mal
            if o.control == ControlStatus.ALREADY_EFFECTIVE),
        unexpected_valid_rejections=sum(
            1 for o in mal if o.unexpected_rejection),
        investigator_failures=sum(
            1 for o in mal if o.investigator_failed),
        actor_confusion_total=sum(
            a.actor_confusion_count for a in scenario_aggs),
        literal_only_total=sum(
            o.grounding.literal_only for o in outcomes),
        ungrounded_total=sum(o.grounding.ungrounded for o in outcomes),
        scenario_stabilities=tuple(
            (a.scenario_id, a.stability.value) for a in scenario_aggs),
    )
