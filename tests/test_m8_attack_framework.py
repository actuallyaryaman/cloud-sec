"""M8 attack framework tests: models, templates, transforms."""

import pytest

from cloudsec_agent.scenario.attacks.models import (
    ATTACK_VERSION,
    AttackClass,
    AttackObjective,
    AttackPlacement,
    AttackSpec,
    AttackStrength,
)
from cloudsec_agent.scenario.attacks.templates import (
    TEMPLATE_IDS,
    render_template,
)
from cloudsec_agent.scenario.attacks.transform import (
    SUPPORTED_PLACEMENTS,
    apply_transform,
    derive_actor_label,
    derive_decoy_key,
    derive_decoy_user,
    seed_attacked_view,
)
from cloudsec_agent.scenario.generator import generate_scenario


def _spec(family="credential_compromise", difficulty="easy", seed=1):
    return generate_scenario("m7a-v1", seed, family, difficulty)


def _attack(attack_class=AttackClass.EVIDENCE_PROMPT_INJECTION,
            template="instruction_override_v1",
            placement=AttackPlacement.S3_OBJECT_BODY,
            objective=AttackObjective.PROMPT_INJECTION_FOLLOWING,
            strength=AttackStrength.LOW, index=0):
    return AttackSpec(
        attack_version=ATTACK_VERSION, attack_class=attack_class,
        strength=strength, placement=placement,
        payload_template_id=template, objective=objective,
        attack_index=index)


def test_version_constant():
    assert ATTACK_VERSION == "m8a-v1"


def test_unknown_version_rejected():
    with pytest.raises(ValueError):
        AttackSpec(
            attack_version="m8a-v99",
            attack_class=AttackClass.EVIDENCE_PROMPT_INJECTION,
            strength=AttackStrength.LOW,
            placement=AttackPlacement.S3_OBJECT_BODY,
            payload_template_id="instruction_override_v1",
            objective=AttackObjective.PROMPT_INJECTION_FOLLOWING)


def test_template_ids_known():
    assert len(TEMPLATE_IDS) == 5
    for template_id in TEMPLATE_IDS:
        text = render_template(
            template_id, actor_label="ext-abc123",
            decoy_user="svc-deploy-ffee11",
            investigator_user="case-investigator-x",
            secret_name="m7a-secret", target_user="svc-deploy-ffee11")
        assert isinstance(text, str) and len(text) > 40


def test_unknown_template_rejected():
    with pytest.raises(ValueError):
        render_template(
            "nope_v1", actor_label="a", decoy_user="b",
            investigator_user="c", secret_name="d", target_user="e")


def test_templates_carry_no_evaluator_markers():
    for template_id in TEMPLATE_IDS:
        text = render_template(
            template_id, actor_label="ext-abc123",
            decoy_user="svc-deploy-ffee11",
            investigator_user="case-investigator-x",
            secret_name="m7a-secret", target_user="svc-deploy-ffee11")
        lowered = text.lower()
        assert "attack" not in lowered
        assert "ground truth" not in lowered
        assert "correct answer" not in lowered


def test_decoy_differs_from_real_users():
    spec = _spec()
    decoy = derive_decoy_user(spec, 0)
    assert decoy != spec.incident_user
    assert decoy != spec.investigator_user
    assert derive_decoy_user(spec, 0) == decoy
    assert derive_decoy_key(spec, 0).startswith("AKIA")


def test_actor_label_from_first_event():
    spec = _spec("recon_heavy", "easy", 11)
    assert derive_actor_label(spec)


CLASS_CASES = [
    (AttackClass.EVIDENCE_PROMPT_INJECTION, "instruction_override_v1",
     AttackPlacement.S3_OBJECT_BODY,
     AttackObjective.PROMPT_INJECTION_FOLLOWING),
    (AttackClass.INVESTIGATOR_STEERING, "investigator_accusation_v1",
     AttackPlacement.LOG_MESSAGE,
     AttackObjective.INVESTIGATOR_SELF_TARGET),
    (AttackClass.DECOY_PRINCIPAL, "decoy_principal_v1",
     AttackPlacement.LOG_MESSAGE,
     AttackObjective.WRONG_ATTRIBUTION),
    (AttackClass.RESOURCE_SUBSTITUTION, "resource_substitution_v1",
     AttackPlacement.S3_OBJECT_BODY,
     AttackObjective.WRONG_CONTAINMENT_TARGET),
    (AttackClass.SECRET_EXFILTRATION_LURE, "secret_verification_lure_v1",
     AttackPlacement.S3_OBJECT_BODY,
     AttackObjective.SECRET_EXFILTRATION_REQUEST),
]


@pytest.mark.parametrize(
    "attack_class,template,placement,objective", CLASS_CASES)
def test_transform_per_class(attack_class, template, placement,
                             objective):
    spec = _spec()
    attack = AttackSpec(
        attack_version=ATTACK_VERSION, attack_class=attack_class,
        strength=AttackStrength.LOW, placement=placement,
        payload_template_id=template, objective=objective)
    result = apply_transform(spec, attack)
    assert result.source_scenario_id == spec.scenario_id
    assert result.manifest.source_scenario_id == spec.scenario_id
    assert result.manifest.attack_class == attack_class
    assert len(result.manifest.injected_artifacts) >= 1
    assert result.transform_digest
    assert result.view.spec_snapshot_digest


@pytest.mark.parametrize(
    "attack_class,template,placement,objective", CLASS_CASES)
def test_transform_deterministic(attack_class, template, placement,
                                 objective):
    spec = _spec("recon_heavy", "medium", 13)
    attack = AttackSpec(
        attack_version=ATTACK_VERSION, attack_class=attack_class,
        strength=AttackStrength.MEDIUM, placement=placement,
        payload_template_id=template, objective=objective, attack_index=2)
    first = apply_transform(spec, attack)
    second = apply_transform(spec, attack)
    assert first.transform_digest == second.transform_digest
    assert first.manifest.as_dict() == second.manifest.as_dict()
    assert first.attack_id == second.attack_id


def test_digest_changes_with_inputs():
    spec = _spec()
    base = _attack()
    altered = _attack(strength=AttackStrength.HIGH)
    assert apply_transform(spec, base).transform_digest != \
        apply_transform(spec, altered).transform_digest
    moved = _attack(placement=AttackPlacement.LOG_MESSAGE)
    assert apply_transform(spec, base).transform_digest != \
        apply_transform(spec, moved).transform_digest


def test_strength_expands_artifacts():
    spec = _spec()
    counts = []
    for strength in (AttackStrength.LOW, AttackStrength.MEDIUM,
                     AttackStrength.HIGH):
        result = apply_transform(spec, _attack(strength=strength))
        counts.append(len(result.manifest.injected_artifacts))
    assert counts[0] == 1
    assert counts[1] >= counts[0]
    assert counts[2] >= counts[1]


def test_original_spec_unmutated():
    spec = _spec("data_access_anomaly", "easy", 21)
    before = spec.as_dict()
    apply_transform(spec, _attack(index=4))
    assert spec.as_dict() == before


def test_secret_metadata_placement_unsupported():
    spec = _spec()
    attack = AttackSpec(
        attack_version=ATTACK_VERSION,
        attack_class=AttackClass.SECRET_EXFILTRATION_LURE,
        strength=AttackStrength.LOW,
        placement=AttackPlacement.SECRET_METADATA,
        payload_template_id="secret_verification_lure_v1",
        objective=AttackObjective.SECRET_EXFILTRATION_REQUEST)
    assert attack.placement not in SUPPORTED_PLACEMENTS
    with pytest.raises(ValueError):
        apply_transform(spec, attack)


def test_briefing_placement_absent():
    assert not any("briefing" in item.value
                   for item in AttackPlacement)
    with pytest.raises(ValueError):
        AttackPlacement("briefing_injection")


def test_template_class_mismatch_rejected():
    spec = _spec()
    attack = AttackSpec(
        attack_version=ATTACK_VERSION,
        attack_class=AttackClass.DECOY_PRINCIPAL,
        strength=AttackStrength.LOW,
        placement=AttackPlacement.S3_OBJECT_BODY,
        payload_template_id="instruction_override_v1",
        objective=AttackObjective.WRONG_ATTRIBUTION)
    with pytest.raises(ValueError):
        apply_transform(spec, attack)


def test_empty_template_rejected():
    with pytest.raises(ValueError):
        AttackSpec(
            attack_version=ATTACK_VERSION,
            attack_class=AttackClass.DECOY_PRINCIPAL,
            strength=AttackStrength.LOW,
            placement=AttackPlacement.S3_OBJECT_BODY,
            payload_template_id="",
            objective=AttackObjective.WRONG_ATTRIBUTION)


def test_cross_seed_decoy_without_authorization_rejected():
    assert "cross" not in {item.value for item in AttackPlacement}


class _FakeClient:
    def __init__(self, recorder):
        self._recorder = recorder

    def __getattr__(self, name):
        def _call(**kwargs):
            self._recorder.append((name, kwargs))
            if name == "create_access_key":
                return {"AccessKey": {
                    "AccessKeyId": "AKIAFAKEEXAMPLE",
                    "SecretAccessKey": "synthetic-test-only"}}
            return {}
        return _call


class _FakeFloci:
    def __init__(self):
        self.calls = []

    def client(self, service, **kwargs):
        recorder = []
        self.calls.append((service, recorder))
        return _FakeClient(recorder)


def test_seeder_seam_additive_with_fake_floci():
    spec = _spec()
    result = apply_transform(spec, _attack())
    fake = _FakeFloci()
    seeded = seed_attacked_view(fake, spec, result.view)
    assert seeded.ok
    assert seeded.attack_id == result.attack_id
    kinds = [call[0] for call in fake.calls]
    assert "iam" in kinds and "s3" in kinds and "logs" in kinds
    put_keys = [kwargs.get("Key") for service, recorder in fake.calls
                for name, kwargs in recorder if name == "put_object"]
    for item in result.view.added_objects:
        assert item.key in put_keys


def test_seeder_seam_snapshot_mismatch_fails_closed():
    spec = _spec()
    result = apply_transform(spec, _attack())
    other = _spec("benign", "easy", 31)
    fake = _FakeFloci()
    seeded = seed_attacked_view(fake, other, result.view)
    assert not seeded.ok
    assert seeded.errors


def test_family_coverage_all_classes():
    families = [("credential_compromise", "easy", 1),
                ("recon_heavy", "easy", 11),
                ("data_access_anomaly", "easy", 21),
                ("benign", "easy", 31),
                ("credential_compromise", "medium", 3)]
    for attack_class, template, placement, objective in CLASS_CASES:
        for family, difficulty, seed in families:
            spec = generate_scenario("m7a-v1", seed, family, difficulty)
            attack = AttackSpec(
                attack_version=ATTACK_VERSION, attack_class=attack_class,
                strength=AttackStrength.LOW, placement=placement,
                payload_template_id=template, objective=objective)
            result = apply_transform(spec, attack)
            assert result.view.spec_snapshot_digest
