"""M7A generator determinism/family tests. Pure, no network."""

import random
import re

import pytest

from cloudsec_agent.scenario.generator import (
    DIFFICULTIES, FAMILIES, GENERATOR_VERSION, generate_scenario)


def _scenario(family, seed, difficulty="easy"):
    return generate_scenario(GENERATOR_VERSION, seed, family, difficulty)


class TestReproducibility:
    def test_g1_same_seed_identical(self):
        first = _scenario("credential_compromise", 1)
        second = _scenario("credential_compromise", 1)
        assert first.as_dict(include_truth=True) == \
            second.as_dict(include_truth=True)
        assert first.scenario_id == second.scenario_id

    def test_g2_different_seeds_vary(self):
        first = _scenario("credential_compromise", 1)
        second = _scenario("credential_compromise", 2)
        assert (first.incident_user, first.bucket) != \
            (second.incident_user, second.bucket)

    def test_g3_global_random_isolated(self):
        before = random.getstate()
        _scenario("recon_heavy", 11, "medium")
        assert random.getstate() == before

    def test_g4_version_metadata_and_validation(self):
        scenario = _scenario("benign", 31)
        assert scenario.generator_version == GENERATOR_VERSION
        assert scenario.manifest.generator_version == GENERATOR_VERSION
        with pytest.raises(ValueError):
            generate_scenario("m7a-v2", 1, "benign")
        with pytest.raises(ValueError):
            generate_scenario(GENERATOR_VERSION, 1, "unknown-family")
        with pytest.raises(ValueError):
            generate_scenario(GENERATOR_VERSION, 1, "benign", "hard")

    def test_scenario_id_deterministic(self):
        scenario = _scenario("data_access_anomaly", 21)
        assert scenario.scenario_id == \
            f"{GENERATOR_VERSION}:data_access_anomaly:easy:seed-0021"


class TestDifficulty:
    def test_medium_has_more_noise(self):
        easy = _scenario("credential_compromise", 1, "easy")
        medium = _scenario("credential_compromise", 1, "medium")
        assert len(medium.objects) > len(easy.objects)
        assert len(medium.log_events) > len(easy.log_events)
        assert easy.scenario_id != medium.scenario_id


class TestFamilyInvariants:
    @pytest.mark.parametrize("seed", [1, 2, 3])
    def test_g5_credential_compromise(self, seed):
        scenario = _scenario("credential_compromise", seed)
        truth = scenario.ground_truth
        assert truth.malicious is True
        assert truth.principal == scenario.incident_user
        assert truth.key_owner == scenario.incident_user
        assert truth.action_tool_id == "update_access_key"
        assert truth.action_arguments["Status"] == "Inactive"
        assert truth.action_arguments["UserName"] == scenario.incident_user
        assert scenario.investigator_user != scenario.incident_user
        assert scenario.expected.incident_key_active_count == 1

    @pytest.mark.parametrize("seed", [11, 12, 13])
    def test_g6_recon_heavy(self, seed):
        scenario = _scenario("recon_heavy", seed)
        truth = scenario.ground_truth
        assert truth.malicious is True
        assert truth.principal == scenario.incident_user
        assert truth.action_tool_id == "update_access_key"
        kinds = {event.operation for event in scenario.log_events}
        assert len(kinds) >= 2

    @pytest.mark.parametrize("seed", [21, 22, 23])
    def test_g7_data_access_anomaly(self, seed):
        scenario = _scenario("data_access_anomaly", seed)
        truth = scenario.ground_truth
        assert truth.malicious is True
        assert truth.action_tool_id == "update_access_key"
        targets = [event.target for event in scenario.log_events]
        assert any("unusual" in target or "extern" in target
                   for target in targets)

    @pytest.mark.parametrize("seed", [31, 32, 33])
    def test_g8_benign(self, seed):
        scenario = _scenario("benign", seed)
        truth = scenario.ground_truth
        assert truth.malicious is False
        assert truth.action_tool_id is None
        assert truth.principal is None
        assert len(scenario.objects) >= 2
        assert len(scenario.log_events) >= 2


class TestHiddenBoundary:
    def test_g9_public_has_no_manifest(self):
        scenario = _scenario("credential_compromise", 1)
        public = scenario.public_briefing().as_dict()
        blob = str(public)
        assert "ground_truth" not in blob
        assert "manifest" not in blob
        assert scenario.ground_truth.principal not in str(
            public["text"])
        assert "update_access_key" not in blob

    def test_g10_agent_context_cannot_reach_truth(self):
        from cloudsec_agent.agent.models import ToolObservation
        from cloudsec_agent.providers.kilo import build_investigation_text
        from cloudsec_agent.agent.model_port import ModelContext
        scenario = _scenario("credential_compromise", 2)
        public = scenario.public_briefing()
        obs = ToolObservation(
            call_id="c0", request_id="r0", tool_id="s3_list_objects",
            ok=True, classification="success",
            data={"bucket": public.bucket,
                  "keys": [item.key for item in scenario.objects]})
        text = build_investigation_text(ModelContext(
            run_id="r", turn_number=1, observations=(obs,)))
        assert scenario.ground_truth.principal not in text
        assert "update_access_key" not in text

    def test_g11_briefing_hides_key_and_label(self):
        scenario = _scenario("credential_compromise", 3)
        text = scenario.briefing_text
        assert not re.search(r"AKIA[0-9A-Z]+", text)
        assert "malicious" not in text.lower()
        assert "benign" not in text.lower()
        assert "update_access_key" not in text


class TestIdentifiers:
    @pytest.mark.parametrize("family,seed", [
        ("credential_compromise", 1), ("recon_heavy", 11),
        ("data_access_anomaly", 21)])
    def test_g12_actor_need_not_resemble_user(self, family, seed):
        scenario = _scenario(family, seed)
        actors = {event.actor for event in scenario.log_events}
        user = scenario.incident_user
        assert user not in actors
        for actor in actors:
            assert actor != user

    def test_g13_key_fields_explicit(self):
        scenario = _scenario("credential_compromise", 1)
        keyed = [event for event in scenario.log_events
                 if event.actor_access_key_id is not None
                 or event.key_ref == "incident"]
        assert keyed
        for event in keyed:
            assert "actor_access_key_id" in event.as_dict()

    def test_g14_no_stripping_invariant(self):
        scenario = _scenario("credential_compromise", 2)
        mapping = scenario.ground_truth.actor_to_principal
        assert isinstance(mapping, dict) and mapping
        for actor, user in mapping.items():
            assert user == scenario.incident_user

    def test_g15_mapping_not_cosmetic(self):
        scenario = _scenario("recon_heavy", 11)
        mapping = scenario.ground_truth.actor_to_principal
        assert set(mapping.values()) == {scenario.incident_user}


class TestBenign:
    def test_g16_null_remediation(self):
        scenario = _scenario("benign", 31)
        assert scenario.ground_truth.action_tool_id is None
        assert scenario.ground_truth.action_arguments is None

    def test_g17_realistic_activity(self):
        scenario = _scenario("benign", 32)
        assert len(scenario.objects) >= 2
        assert len(scenario.log_events) >= 2
        assert all(event.result == "success"
                   for event in scenario.log_events)
