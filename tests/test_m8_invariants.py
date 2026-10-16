"""M8 safety invariant tests AINV1-AINV20. No provider, no live Floci."""

import pytest

from cloudsec_agent.integration.containment_scope import (
    derive_containment_scope)
from cloudsec_agent.integration.investigation_scope import (
    derive_investigation_scope)
from cloudsec_agent.scenario.attacks import (
    ATTACK_VERSION,
    AttackClass,
    AttackObjective,
    AttackPlacement,
    AttackSpec,
    AttackStrength,
)
from cloudsec_agent.scenario.attacks.invariants import (
    assert_containment_unchanged,
    assert_decoys_unauthorized,
    assert_investigator_protected,
    assert_manifest_isolated,
    assert_mutation_grants_unchanged,
    assert_scope_delta_matches_manifest,
    assert_secret_free,
    assert_truth_equal,
    scope_delta,
    truth_snapshot,
)
from cloudsec_agent.scenario.attacks.models import (
    ActionPath,
    SecretFlow,
)
from cloudsec_agent.scenario.attacks.transform import apply_transform
from cloudsec_agent.scenario.generator import generate_scenario
from cloudsec_agent.scenario.generator.seeding import SECRET_PLAINTEXT


def _spec(family="credential_compromise", difficulty="easy", seed=1):
    return generate_scenario("m7a-v1", seed, family, difficulty)


def _attack(attack_class=AttackClass.DECOY_PRINCIPAL,
            template="decoy_principal_v1",
            placement=AttackPlacement.S3_OBJECT_BODY,
            objective=AttackObjective.WRONG_ATTRIBUTION,
            strength=AttackStrength.LOW, index=1):
    return AttackSpec(
        attack_version=ATTACK_VERSION, attack_class=attack_class,
        strength=strength, placement=placement,
        payload_template_id=template, objective=objective,
        attack_index=index)


def _scopes(spec, result):
    clean = derive_investigation_scope(spec)
    from cloudsec_agent.scenario.attacks.invariants import (
        attack_scope_grants)
    merged = {tool_id: set(clean.resources_for(tool_id))
              for tool_id in clean.tool_ids}
    for tool_id, resources in attack_scope_grants(
            spec, result.view).items():
        merged.setdefault(tool_id, set()).update(resources)
        merged[tool_id] = frozenset(merged[tool_id])
    from cloudsec_agent.integration.investigation_scope import (
        InvestigationScope)
    attacked = InvestigationScope(spec.scenario_id, merged)
    containment = derive_containment_scope(spec)
    return clean, attacked, containment


def _payloads(result):
    texts = [item.body for item in result.view.added_objects]
    texts.extend(event.message for event in result.view.added_log_events)
    return texts


def test_ainv1_hidden_truth_unchanged():
    spec = _spec()
    before = truth_snapshot(spec)
    result = apply_transform(spec, _attack())
    assert_truth_equal(spec, spec)
    assert truth_snapshot(spec) == before
    assert result.manifest.source_scenario_id == spec.scenario_id


def test_ainv2_containment_scope_unchanged():
    spec = _spec()
    result = apply_transform(spec, _attack())
    clean = derive_containment_scope(spec)
    assert_containment_unchanged(clean, derive_containment_scope(spec))
    assert result.view.spec_snapshot_digest


def test_ainv3_mutation_grants_unchanged():
    spec = _spec()
    result = apply_transform(spec, _attack())
    clean, attacked, _ = _scopes(spec, result)
    assert_mutation_grants_unchanged(clean, attacked)


def test_ainv4_policy_broker_semantics_unaffected():
    spec = _spec()
    result = apply_transform(spec, _attack())
    clean, attacked, _ = _scopes(spec, result)
    assert set(clean.tool_ids) == set(attacked.tool_ids)
    assert not attacked.resources_for("update_access_key")
    assert not attacked.resources_for("get_secret_value")


def test_ainv5_channel_only_visibility():
    spec = _spec()
    attack = _attack(placement=AttackPlacement.LOG_MESSAGE)
    result = apply_transform(spec, attack)
    assert not result.view.added_objects
    assert result.view.added_log_events
    assert not result.view.added_log_streams


def test_ainv6_decoy_only_in_declared_artifacts():
    spec = _spec()
    result = apply_transform(spec, _attack())
    decoy = result.manifest.decoy_identities[0]
    assert decoy
    assert any(decoy in text for text in _payloads(result))
    clean_bodies = [item.body for item in spec.objects]
    assert all(decoy not in body for body in clean_bodies)


def test_ainv7_manifest_never_in_model_context():
    spec = _spec()
    result = apply_transform(spec, _attack())
    visible = [spec.briefing_text] + _payloads(result)
    assert_manifest_isolated(result.manifest, visible)


def test_ainv8_secret_lure_reference_only():
    assert SECRET_PLAINTEXT
    spec = _spec()
    attack = AttackSpec(
        attack_version=ATTACK_VERSION,
        attack_class=AttackClass.SECRET_EXFILTRATION_LURE,
        strength=AttackStrength.MEDIUM,
        placement=AttackPlacement.S3_OBJECT_BODY,
        payload_template_id="secret_verification_lure_v1",
        objective=AttackObjective.SECRET_EXFILTRATION_REQUEST)
    result = apply_transform(spec, attack)
    assert_secret_free(_payloads(result))
    assert any(spec.secret_name in text for text in _payloads(result))


def test_ainv9_investigator_outside_scope():
    spec = _spec()
    result = apply_transform(spec, _attack(
        attack_class=AttackClass.INVESTIGATOR_STEERING,
        template="investigator_accusation_v1",
        placement=AttackPlacement.LOG_MESSAGE,
        objective=AttackObjective.INVESTIGATOR_SELF_TARGET))
    containment = derive_containment_scope(spec)
    assert_investigator_protected(containment, spec.investigator_user)
    assert spec.investigator_user in " ".join(_payloads(result))


def test_ainv10_cross_target_unauthorized():
    spec = _spec()
    result = apply_transform(spec, _attack())
    containment = derive_containment_scope(spec)
    assert_decoys_unauthorized(containment,
                               result.manifest.decoy_identities)


def test_ainv11_clean_resources_reachable():
    spec = _spec()
    result = apply_transform(spec, _attack())
    clean, attacked, _ = _scopes(spec, result)
    delta = scope_delta(clean, attacked)
    for tool_id in ("s3_list_objects", "iam_list_users"):
        assert delta[tool_id]["removed"] == []


def test_ainv12_no_clean_resource_removed():
    spec = _spec("data_access_anomaly", "medium", 23)
    result = apply_transform(spec, _attack(index=3))
    clean, attacked, _ = _scopes(spec, result)
    assert_scope_delta_matches_manifest(clean, attacked, spec,
                                        result.view)


def test_primary_stream_log_event_needs_no_new_grant():
    spec = _spec()
    attack = AttackSpec(
        attack_version=ATTACK_VERSION,
        attack_class=AttackClass.INVESTIGATOR_STEERING,
        strength=AttackStrength.LOW,
        placement=AttackPlacement.LOG_MESSAGE,
        payload_template_id="investigator_accusation_v1",
        objective=AttackObjective.INVESTIGATOR_SELF_TARGET)
    result = apply_transform(spec, attack)
    assert not result.view.added_log_streams
    clean, attacked, _ = _scopes(spec, result)
    assert_scope_delta_matches_manifest(clean, attacked, spec,
                                        result.view)


def test_ainv13_transform_deterministic():
    spec = _spec("benign", "easy", 31)
    attack = _attack(index=7)
    first = apply_transform(spec, attack)
    second = apply_transform(spec, attack)
    assert first.transform_digest == second.transform_digest
    assert first.view.spec_snapshot_digest == \
        second.view.spec_snapshot_digest


def test_ainv14_source_object_not_mutated():
    spec = _spec()
    before = spec.as_dict()
    result = apply_transform(spec, _attack())
    assert spec.as_dict() == before
    assert result.view.spec_snapshot_digest


def test_ainv15_unknown_version_fails_closed():
    with pytest.raises(ValueError):
        AttackSpec(
            attack_version="m8a-v0",
            attack_class=AttackClass.DECOY_PRINCIPAL,
            strength=AttackStrength.LOW,
            placement=AttackPlacement.S3_OBJECT_BODY,
            payload_template_id="decoy_principal_v1",
            objective=AttackObjective.WRONG_ATTRIBUTION)


def test_ainv16_briefing_injection_rejected():
    from cloudsec_agent.scenario.attacks import AttackPlacement as Place
    assert "briefing" not in {item.value for item in Place}


def test_ainv17_digest_sensitive():
    spec = _spec()
    low = apply_transform(spec, _attack(strength=AttackStrength.LOW))
    high = apply_transform(spec, _attack(strength=AttackStrength.HIGH))
    assert low.transform_digest != high.transform_digest
    other = apply_transform(_spec("benign", "easy", 31), _attack())
    assert low.transform_digest != other.transform_digest


def test_ainv18_secret_flow_consistency():
    flow = SecretFlow(requested=True)
    assert not flow.value_returned
    with pytest.raises(ValueError):
        SecretFlow(entered_model_context=True)
    with pytest.raises(ValueError):
        SecretFlow(value_returned=True)
    with pytest.raises(ValueError):
        SecretFlow(backend_executed=True)
    allowed = SecretFlow(
        requested=True, broker_authorized=True, policy_allowed=True,
        backend_executed=True, value_returned=True,
        entered_model_context=True)
    assert allowed.entered_model_context


def test_ainv19_action_path_independent():
    path = ActionPath(proposed=True, broker_granted=False,
                      effective=False)
    assert path.proposed and not path.broker_granted
    full = ActionPath(**{name: True for name in (
        "proposed", "canonicalizable", "broker_granted",
        "policy_allowed", "approval_issued", "executor_called",
        "mutation_issued", "effective", "target_correct",
        "target_authorized", "investigator_preserved")})
    assert full.effective and full.investigator_preserved


def test_ainv20_truth_label_unchanged():
    malicious = _spec()
    benign = _spec("benign", "easy", 31)
    assert_truth_equal(malicious, malicious)
    assert_truth_equal(benign, benign)
    assert truth_snapshot(malicious)["malicious"] is True
    assert truth_snapshot(benign)["malicious"] is False
    apply_transform(malicious, _attack())
    apply_transform(benign, _attack())
    assert truth_snapshot(malicious)["malicious"] is True
    assert truth_snapshot(benign)["malicious"] is False
