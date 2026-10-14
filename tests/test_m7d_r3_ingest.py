"""M7D R3-ingestion tests. Inline fixtures reproduce R3 conclusions.

A live-artifact ingest test runs only when /tmp/m7c-r3 artifacts exist;
it never mutates them. No provider, no Docker.
"""

import os

import pytest

from cloudsec_agent.evaluation import (
    ContractStatus,
    ExperimentConfig,
    ModelDecision,
    ProviderStatus,
    TopLevel,
    Truth,
)
from cloudsec_agent.evaluation.classify import (
    aggregate_benchmark,
    aggregate_scenario,
)
from cloudsec_agent.evaluation.ingest import load_r3_study, normalize_r3_run

R3DIR = "/tmp/m7c-r3"

R3_EXPECTED = {
    ("credential_compromise", "medium", 3): (
        ["PREMATURE_BENIGN", "OTHER_MODEL_FAILURE", "SUCCESS"], 1),
    ("recon_heavy", "medium", 13): (
        ["NO_FINAL", "PREMATURE_BENIGN", "NO_FINAL"], 0),
    ("data_access_anomaly", "easy", 21): (
        ["SUCCESS", "SUCCESS", "OTHER_MODEL_FAILURE"], 2),
    ("credential_compromise", "easy", 1): (
        ["PREMATURE_BENIGN", "WRONG_PRINCIPAL", "SUCCESS"], 1),
}


def _config():
    return ExperimentConfig(
        provider="kilo", model="stealth/glyph-cluster",
        adapter_version="m6g-kilo-v1", prompt_version="m6p-kilo-sys-v1",
        temperature=0.0, max_output_tokens=2048, retries=0,
        generator_version="m7a-v1")


def _fake_run(outcome, rep="A1", interrupted=False, scenario="s"):
    record = {"rep": rep, "family": "credential_compromise",
              "difficulty": "medium", "seed": 3, "scenario_id": scenario,
              "primary_outcome": outcome,
              "stop_reason": ("kilo_service_unavailable"
                              if interrupted else "final_answer_accepted"),
              "classification": "INFRASTRUCTURE_SUCCESS_MODEL_FAILURE",
              "model_turns": 3, "tool_calls": 2, "calls": [],
              "token_usage": [], "sufficiency": "", "confidence": 0.0,
              "secondary_labels": {}, "unexpected_denials": []}
    return normalize_r3_run(record, _config())


def test_r3_fixture_frequencies_reproduce():
    for key, (outcomes, success) in R3_EXPECTED.items():
        assert outcomes.count("SUCCESS") == success
    assert sum(v[1] for v in R3_EXPECTED.values()) == 4


def test_r3_fixture_all_variable():
    for outcomes, _ in R3_EXPECTED.values():
        assert len(set(outcomes)) > 1


def test_interrupted_run_not_cognitive_failure():
    out = _fake_run("OTHER_MODEL_FAILURE", interrupted=True)
    assert out.top_level == TopLevel.PROVIDER_INTERRUPTED
    assert out.decision == ModelDecision.NOT_EVALUABLE
    agg = aggregate_scenario("s", "f", "easy", [out])
    assert agg.evaluable_runs == 0
    assert agg.model_failures == 0


def test_interruption_variants_all_not_evaluable():
    for stop in ("kilo_timeout", "kilo_service_unavailable",
                 "kilo_provider_error", "429 rate_limit"):
        record = {"rep": "A1", "family": "credential_compromise",
                  "difficulty": "medium", "seed": 3, "scenario_id": "s",
                  "primary_outcome": "OTHER_MODEL_FAILURE",
                  "stop_reason": stop,
                  "classification": "INFRASTRUCTURE_SUCCESS_MODEL_FAILURE",
                  "model_turns": 2, "tool_calls": 1,
                  "calls": [{"tool_id": "s3_list_objects",
                             "arguments": {}, "ok": True}],
                  "token_usage": [], "sufficiency": "", "confidence": 0.0,
                  "secondary_labels": {"actor_type_confusion": True},
                  "unexpected_denials": []}
        out = normalize_r3_run(record, _config())
        assert out.top_level == TopLevel.PROVIDER_INTERRUPTED
        assert out.decision == ModelDecision.NOT_EVALUABLE
        assert out.grounding.actor_reused_as_username is True


def test_evaluable_denominators_separate():
    runs = [_fake_run("SUCCESS"),
            _fake_run("PREMATURE_BENIGN"),
            _fake_run("OTHER_MODEL_FAILURE", interrupted=True)]
    assert runs[0].top_level == TopLevel.VALID_MODEL_SUCCESS
    assert runs[1].top_level == TopLevel.VALID_MODEL_FAILURE
    agg = aggregate_scenario("s", "f", "easy", runs)
    assert (agg.evaluable_runs, agg.successes) == (2, 1)
    bench = aggregate_benchmark("m7d-v1", [agg], runs)
    assert bench.evaluable_runs == 2
    assert bench.provider_interrupted_runs == 1


@pytest.mark.skipif(not os.path.exists(
    os.path.join(R3DIR, "controlled_replication_study.json")),
    reason="R3 artifacts absent")
def test_live_r3_artifacts_reproduce_conclusions():
    outcomes = load_r3_study(
        os.path.join(R3DIR, "controlled_replication_study.json"),
        _config())
    assert len(outcomes) == 12
    by_scenario = {}
    for out in outcomes:
        by_scenario.setdefault(out.key.scenario_id, []).append(out)
    assert len(by_scenario) == 4
    groups = sorted(by_scenario.values(),
                    key=lambda g: g[0].key.scenario_id)
    assert len(groups) == 4
    total_success = 0
    # Sorted scenario-id order is D, A, C, B; R3 recorded 1/1/2/0.
    # C is CONSISTENT_SUCCESS among its 2 evaluable runs (+1 interruption);
    # B is CONSISTENT_FAILURE (2 contract + 1 cognitive failure, all
    # evaluable): the new model separates evaluable stability from
    # interruption count and failure-surface variety, which the looser R3
    # "VARIABLE" label did not.
    for group, want, stability in zip(
            groups, (1, 1, 2, 0),
            ("mixed", "mixed", "consistent_success", "consistent_failure")):
        agg = aggregate_scenario(
            group[0].key.scenario_id, "f", "easy", group)
        assert agg.stability.value == stability
        assert agg.successes == want
        total_success += agg.successes
    assert total_success == 4
    interrupted = [o for o in outcomes
                   if o.top_level == TopLevel.PROVIDER_INTERRUPTED]
    assert len(interrupted) == 3
    for out in interrupted:
        assert out.decision == ModelDecision.NOT_EVALUABLE
