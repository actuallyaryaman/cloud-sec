"""M7D evaluation core tests (E1-E19). Pure, no provider, no Docker."""

import json

import pytest

from cloudsec_agent.evaluation import (
    BenchmarkSpec,
    ContractStatus,
    ControlStatus,
    EffectiveState,
    ExperimentConfig,
    InfraStatus,
    ModelDecision,
    ProviderStatus,
    RunKey,
    RunOutcome,
    ScenarioCase,
    Stability,
    TopLevel,
    Truth,
)
from cloudsec_agent.evaluation.classify import (
    aggregate_benchmark,
    aggregate_scenario,
    classify_run,
    evaluation_input_digest,
    normalize_stop,
)
from cloudsec_agent.evaluation.spec import (
    build_default_spec,
    held_out_seeds,
    run_order,
    spec_from_dict,
    spec_to_dict,
)


def _config(**over):
    base = {"provider": "kilo", "model": "stealth/glyph-cluster",
            "adapter_version": "m6g-kilo-v1",
            "prompt_version": "m6p-kilo-sys-v1", "temperature": 0.0,
            "max_output_tokens": 2048, "retries": 0,
            "generator_version": "m7a-v1"}
    base.update(over)
    return ExperimentConfig(**base)


def _key(version="m7d-v1", scenario="s", rep=1):
    return RunKey(benchmark_version=version, scenario_id=scenario,
                  repetition_index=rep, config_digest="c" * 64)


def _outcome(top=None, decision=ModelDecision.SUCCESS,
             provider=ProviderStatus.COMPLETED,
             contract=ContractStatus.VALID,
             infra=InfraStatus.VALID, truth=Truth.MALICIOUS, **over):
    if top is None:
        out = classify_run(
            _key(), truth, infra=infra, provider=provider,
            contract=contract, decision=decision,
            control=ControlStatus.NOT_PROPOSED,
            effective=EffectiveState.UNKNOWN)
        return out
    params = {"key": _key(), "truth": truth, "infra": infra,
              "provider": provider, "contract": contract,
              "decision": decision, "control": ControlStatus.NOT_PROPOSED,
              "effective": EffectiveState.UNKNOWN, "top_level": top}
    params.update(over)
    return RunOutcome(**params)


def test_e1_runkey_deterministic_unique():
    left = RunKey("m7d-v1", "s", 1, "c" * 64)
    assert left.key() == RunKey("m7d-v1", "s", 1, "c" * 64).key()
    assert left.key() != RunKey("m7d-v1", "s", 2, "c" * 64).key()
    assert left.key() != RunKey("m7d-v1", "s", 1, "d" * 64).key()


def test_e2_input_digest_stable():
    payload = {"model": "m", "scope": "abc", "temperature": 0.0}
    assert evaluation_input_digest(payload) == \
        evaluation_input_digest(dict(payload))


def test_e3_input_digest_sensitive():
    base = {"model": "m", "prompt": "p", "tools": "t", "generator": "g",
            "scope": "s"}
    for field in base:
        mutated = dict(base)
        mutated[field] = base[field] + "-changed"
        assert evaluation_input_digest(mutated) != \
            evaluation_input_digest(base)


def test_e4_unknown_version_rejected():
    with pytest.raises(ValueError):
        spec_from_dict({"version": "m7d-v99", "cases": [],
                        "config": _config().__dict__})


def test_e5_serialization_round_trip_deterministic():
    spec = build_default_spec(_config())
    first = json.dumps(spec_to_dict(spec), sort_keys=True)
    second = json.dumps(spec_to_dict(spec_from_dict(
        json.loads(first))), sort_keys=True)
    assert first == second
    assert isinstance(spec_from_dict(json.loads(first)), BenchmarkSpec)


def test_e6_malicious_success():
    out = _outcome(decision=ModelDecision.SUCCESS)
    assert out.top_level == TopLevel.VALID_MODEL_SUCCESS


def test_e7_wrong_principal_is_model_failure():
    out = _outcome(decision=ModelDecision.WRONG_PRINCIPAL)
    assert out.top_level == TopLevel.VALID_MODEL_FAILURE


def test_e8_timeout_interrupted_not_evaluable():
    provider, contract = normalize_stop("kilo_timeout after 30s")
    out = _outcome(provider=provider, contract=contract,
                   decision=ModelDecision.NOT_EVALUABLE)
    assert provider == ProviderStatus.TIMEOUT
    assert out.top_level == TopLevel.PROVIDER_INTERRUPTED
    assert out.decision == ModelDecision.NOT_EVALUABLE


def test_e9_infra_failure_invalidates():
    out = _outcome(infra=InfraStatus.SEED_FAILURE,
                   decision=ModelDecision.SUCCESS)
    assert out.top_level == TopLevel.INFRASTRUCTURE_INVALID


def test_e10_benign_abstention_success():
    out = _outcome(decision=ModelDecision.SUCCESS, truth=Truth.BENIGN)
    assert out.top_level == TopLevel.VALID_MODEL_SUCCESS


def test_e11_benign_fp_despite_blocked_mutation():
    out = classify_run(
        _key(), Truth.BENIGN, infra=InfraStatus.VALID,
        provider=ProviderStatus.COMPLETED, contract=ContractStatus.VALID,
        decision=ModelDecision.WRONG_ACTION,
        control=ControlStatus.PREPARE_REJECTED,
        effective=EffectiveState.BENIGN_UNCHANGED)
    assert out.top_level == TopLevel.VALID_MODEL_FAILURE


def test_e12_valid_target_control_rejection_is_infra():
    out = _outcome(infra=InfraStatus.CONTROL_FAILURE,
                   decision=ModelDecision.SUCCESS,
                   control=ControlStatus.PREPARE_REJECTED)
    assert out.top_level == TopLevel.INFRASTRUCTURE_INVALID


def _scenario(decisions, min_evaluable=2):
    outcomes = []
    for index, decision in enumerate(decisions):
        if decision == "INTERRUPTED":
            outcomes.append(_outcome(
                top=TopLevel.PROVIDER_INTERRUPTED,
                decision=ModelDecision.NOT_EVALUABLE,
                provider=ProviderStatus.SERVICE_UNAVAILABLE,
                contract=ContractStatus.NOT_EVALUABLE))
        elif decision == "INVALID":
            outcomes.append(_outcome(
                top=TopLevel.INFRASTRUCTURE_INVALID,
                infra=InfraStatus.SEED_FAILURE))
        elif decision == "SUCCESS":
            outcomes.append(_outcome(decision=ModelDecision.SUCCESS))
        else:
            outcomes.append(_outcome(decision=ModelDecision.WRONG_PRINCIPAL))
    return aggregate_scenario("s", "f", "easy", outcomes,
                              min_evaluable=min_evaluable)


def test_e13_three_successes_full_rate():
    agg = _scenario(["SUCCESS"] * 3)
    assert agg.success_fraction_evaluable() == 1.0
    assert agg.stability == Stability.CONSISTENT_SUCCESS


def test_e14_mixed_with_interruption_denominators():
    agg = _scenario(["SUCCESS", "FAIL", "INTERRUPTED"])
    assert agg.evaluable_runs == 2
    assert agg.attempted_runs == 3
    assert agg.success_fraction_evaluable() == 0.5
    assert agg.success_fraction_attempted() == pytest.approx(1 / 3)
    assert agg.provider_interrupted == 1
    assert agg.stability == Stability.MIXED


def test_e15_zero_evaluable_insufficient():
    agg = _scenario(["INTERRUPTED"] * 3)
    assert agg.evaluable_runs == 0
    assert agg.success_fraction_evaluable() is None
    assert agg.stability == Stability.INSUFFICIENT_EVALUABLE_RUNS


def test_e16_single_evaluable_not_consistent():
    agg = _scenario(["SUCCESS", "INTERRUPTED", "INTERRUPTED"])
    assert agg.stability == Stability.INSUFFICIENT_EVALUABLE_RUNS


def test_e17_two_failures_plus_interruption_consistent():
    agg = _scenario(["FAIL", "FAIL", "INTERRUPTED"])
    assert agg.evaluable_runs == 2
    assert agg.stability == Stability.CONSISTENT_FAILURE


def test_e18_success_failure_interruption_mixed():
    agg = _scenario(["SUCCESS", "FAIL", "INTERRUPTED"])
    assert agg.stability == Stability.MIXED


def test_e19_benign_fp_rate_excludes_interruptions():
    outcomes = [
        _outcome(decision=ModelDecision.SUCCESS, truth=Truth.BENIGN),
        _outcome(decision=ModelDecision.WRONG_ACTION, truth=Truth.BENIGN),
        _outcome(top=TopLevel.PROVIDER_INTERRUPTED,
                 decision=ModelDecision.NOT_EVALUABLE,
                 provider=ProviderStatus.TIMEOUT,
                 contract=ContractStatus.NOT_EVALUABLE,
                 truth=Truth.BENIGN),
    ]
    agg = aggregate_benchmark(
        "m7d-v1",
        [aggregate_scenario("b", "benign", "easy", outcomes)],
        outcomes)
    assert agg.benign_attempted == 3
    assert agg.benign_evaluable == 2
    assert agg.benign_correct == 1
    assert agg.benign_false_positives == 1
    assert agg.benign_interruptions == 1


def test_seed_rule_skips_known_seeds_and_is_deterministic():
    first = held_out_seeds(2)
    assert held_out_seeds(2) == first
    assert held_out_seeds(3) != first
    used = {1, 3, 11, 13, 21, 23, 31, 33}
    assert not (set(s for seeds in first.values() for s in seeds) & used)


def test_run_order_spreads_repetitions_and_cells():
    spec = build_default_spec(_config())
    order = run_order(spec)
    assert len(order) == 48
    reps = [rep for _, rep in order]
    assert reps == sorted(reps)
    first_rep_cells = [(c.family, c.difficulty) for c, r in order if r == 1]
    assert len(set(first_rep_cells)) == 8
