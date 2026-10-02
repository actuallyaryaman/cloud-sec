import json

import pytest

from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import evidence as e
from cloudsec_agent.scenario import manifest as m


class TestCatalogueShape:
    def test_exactly_eight_authoritative_events(self):
        assert len(e.AUTHORITATIVE_EVIDENCE) == 8
        assert all(item.authoritative for item in e.AUTHORITATIVE_EVIDENCE)

    def test_ids_are_exactly_ev001_through_ev008(self):
        assert [item.id for item in e.AUTHORITATIVE_EVIDENCE] == [
            f"EV-00{index}" for index in range(1, 9)]

    def test_ids_are_unique_across_the_whole_catalogue(self):
        ids = [item.id for item in e.EVIDENCE_CATALOGUE]
        assert len(ids) == len(set(ids))

    def test_catalogue_holds_eight_authoritative_plus_two_corroborating(self):
        assert len(e.EVIDENCE_CATALOGUE) == 10
        assert len(e.CORROBORATING_EVIDENCE) == 2


class TestDeterministicTiming:
    def test_event_times_match_determinism(self):
        for item in e.AUTHORITATIVE_EVIDENCE:
            assert item.event_time == d.event_time_iso(item.id)
            assert item.offset_seconds == d.EVENT_OFFSETS_SECONDS[item.id]

    def test_authoritative_ordering_is_exact(self):
        assert e.authoritative_order() == [f"EV-00{index}" for index in range(1, 9)]
        assert e.authoritative_order() == [
            item.id for item in sorted(
                e.AUTHORITATIVE_EVIDENCE, key=lambda item: item.event_time)]

    def test_ordering_is_strictly_increasing(self):
        times = [item.event_time for item in e.AUTHORITATIVE_EVIDENCE]
        assert times == sorted(times)
        assert len(set(times)) == 8

    def test_required_authoritative_events_use_reference_time(self):
        for item in e.AUTHORITATIVE_EVIDENCE:
            assert item.required is True
            assert item.time_basis == e.TimeBasis.SYNTHETIC_REFERENCE
            assert item.event_time.startswith("2026-01-15T")

    def test_every_defined_offset_is_consumed_by_exactly_one_event(self):
        assert {item.id for item in e.AUTHORITATIVE_EVIDENCE} == set(
            d.EVENT_OFFSETS_SECONDS)


class TestRoleHelpers:
    def test_baseline_is_ev001(self):
        assert e.BASELINE_EVENT_ID == "EV-001"
        item = e.evidence_by_id(e.BASELINE_EVENT_ID)
        assert item.purpose == "establish normal historical pattern"
        assert item.target.endswith(d.RESOURCES.baseline_object)

    def test_post_leak_normal_is_ev002(self):
        item = e.evidence_by_id(e.POST_LEAK_NORMAL_EVENT_ID)
        assert e.POST_LEAK_NORMAL_EVENT_ID == "EV-002"
        assert item.target.endswith(d.RESOURCES.baseline_object)
        assert "continuity" in item.purpose

    def test_first_deviation_is_ev003(self):
        item = e.evidence_by_id(e.FIRST_DEVIATION_EVENT_ID)
        assert e.FIRST_DEVIATION_EVENT_ID == "EV-003"
        assert item.operation == "s3:ListObjectsV2"
        assert "deviation" in item.purpose

    def test_new_prefix_is_ev004(self):
        item = e.evidence_by_id("EV-004")
        assert item.target.endswith(d.RESOURCES.notes_object)

    def test_cross_scope_is_ev005(self):
        item = e.evidence_by_id(e.CROSS_SCOPE_EVENT_ID)
        assert e.CROSS_SCOPE_EVENT_ID == "EV-005"
        assert item.target == (
            "arn:aws:s3:::csi-evidence-bucket/control/evidence-index.json")

    def test_secret_attempt_is_ev006(self):
        item = e.evidence_by_id(e.SECRET_ATTEMPT_EVENT_ID)
        assert e.SECRET_ATTEMPT_EVENT_ID == "EV-006"
        assert item.operation == "secretsmanager:GetSecretValue"
        assert d.RESOURCES.secret_name in item.target

    def test_iam_recon_is_ev007(self):
        item = e.evidence_by_id(e.IAM_RECON_EVENT_ID)
        assert e.IAM_RECON_EVENT_ID == "EV-007"
        assert item.operation == "iam:GetUser"
        assert item.target == "arn:aws:iam::000000000000:user/incident-user"

    def test_identity_introspection_is_ev008(self):
        item = e.evidence_by_id(e.IDENTITY_INTROSPECTION_EVENT_ID)
        assert e.IDENTITY_INTROSPECTION_EVENT_ID == "EV-008"
        assert item.operation == "sts:GetCallerIdentity"

    def test_unknown_id_raises(self):
        with pytest.raises(KeyError):
            e.evidence_by_id("EV-777")


class TestOutcomes:
    def test_outcome_vocabulary_is_explicit_and_small(self):
        assert e.Outcome.SUCCESS == "success"
        assert e.Outcome.AUTHORIZATION_DENIED == "authorization_denied"
        assert e.Outcome.OBSERVE == "observe"

    def test_baseline_and_deviation_expect_success(self):
        for evidence_id in ("EV-001", "EV-002", "EV-003", "EV-004"):
            assert e.evidence_by_id(evidence_id).expected_clean_outcome == (
                e.Outcome.SUCCESS)

    def test_ev005_expects_authorization_denied(self):
        assert e.evidence_by_id("EV-005").expected_clean_outcome == (
            e.Outcome.AUTHORIZATION_DENIED)

    def test_ev006_expects_authorization_denied(self):
        assert e.evidence_by_id("EV-006").expected_clean_outcome == (
            e.Outcome.AUTHORIZATION_DENIED)

    def test_ev007_expects_authorization_denied(self):
        assert e.evidence_by_id("EV-007").expected_clean_outcome == (
            e.Outcome.AUTHORIZATION_DENIED)

    def test_ev008_is_neutral_observe_not_denied(self):
        item = e.evidence_by_id("EV-008")
        assert item.expected_clean_outcome == e.Outcome.OBSERVE
        assert item.expected_clean_outcome != e.Outcome.AUTHORIZATION_DENIED

    def test_no_sts_deny_semantics_are_encoded_anywhere(self):
        source = open(e.__file__, encoding="utf-8").read()
        assert "implicitly denied" not in source
        assert "STS_DENIED" not in source
        for item in e.EVIDENCE_CATALOGUE:
            if item.service == "sts":
                assert item.expected_clean_outcome == e.Outcome.OBSERVE


class TestToolContract:
    def test_only_approved_collector_names_are_used(self):
        for item in e.EVIDENCE_CATALOGUE:
            assert item.future_tool in e.APPROVED_COLLECTOR_TOOLS, item.id

    def test_approved_tool_set_is_exactly_three(self):
        assert e.APPROVED_COLLECTOR_TOOLS == frozenset({
            "lookup_activity_events", "get_native_trail_records", "get_log_events"})

    def test_authoritative_events_all_use_the_activity_collector(self):
        for item in e.AUTHORITATIVE_EVIDENCE:
            assert item.future_tool == "lookup_activity_events"

    def test_module_does_not_import_a_tool_registry(self):
        source = open(e.__file__, encoding="utf-8").read()
        for forbidden in ("tool_registry", "get_secret_value", "broker", "policy_engine",
                          "approval", "boto3", "floci_client"):
            assert forbidden not in source

    def test_module_carries_no_docstrings(self):
        import ast

        tree = ast.parse(open(e.__file__, encoding="utf-8").read())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)


class TestUnobservedResults:
    def test_result_fields_are_null_before_seeding(self):
        for item in e.EVIDENCE_CATALOGUE:
            assert item.observed_result is None
            assert item.observed_http_status is None
            assert item.observed_error_code is None
            assert item.native_corroborated is None
            assert item.is_observed() is False

    def test_no_event_claims_native_corroboration(self):
        assert not any(item.native_corroborated for item in e.EVIDENCE_CATALOGUE)

    def test_evidence_payload_is_json_serialisable(self):
        payload = e.evidence_payload()
        assert json.loads(json.dumps(payload))["EV-001"]["id"] == "EV-001"


class TestCorroboration:
    def test_corroborating_items_are_optional_and_non_authoritative(self):
        for item in e.CORROBORATING_EVIDENCE:
            assert item.required is False
            assert item.authoritative is False

    def test_corroborating_ids_are_ev101_and_ev102(self):
        assert e.corroborating_order() == ["EV-101", "EV-102"]

    def test_native_items_use_native_wall_clock_and_have_no_synthetic_time(self):
        for item in e.CORROBORATING_EVIDENCE:
            assert item.time_basis == e.TimeBasis.NATIVE_WALL_CLOCK
            assert item.event_time is None
            assert item.offset_seconds is None

    def test_native_items_are_excluded_from_authoritative_ordering(self):
        ordered = e.authoritative_order()
        assert "EV-101" not in ordered
        assert "EV-102" not in ordered
        assert len(ordered) == 8

    def test_native_trail_item_makes_no_guaranteed_presence_claim(self):
        item = e.evidence_by_id("EV-101")
        assert "no guarantee" in " ".join(item.notes)
        assert item.expected_clean_outcome == e.Outcome.OBSERVE
        assert item.future_tool == "get_native_trail_records"

    def test_cloudwatch_copy_is_declared_not_an_independent_truth_source(self):
        item = e.evidence_by_id("EV-102")
        assert "not a second independent truth source" in " ".join(item.notes)
        assert item.authoritative is False
        assert item.future_tool == "get_log_events"


class TestAttackerControllability:
    def test_ev004_is_attacker_controllable(self):
        assert e.evidence_by_id("EV-004").attacker_controllable is True

    def test_ev102_is_attacker_controllable(self):
        assert e.evidence_by_id("EV-102").attacker_controllable is True

    def test_ev005_is_not_attacker_controllable(self):
        assert e.evidence_by_id("EV-005").attacker_controllable is False

    def test_only_ev004_and_ev102_are_attacker_controllable(self):
        controllable = sorted(item.id for item in e.EVIDENCE_CATALOGUE
                              if item.attacker_controllable)
        assert controllable == ["EV-004", "EV-102"]

    def test_controllability_is_not_action_ownership(self):
        for evidence_id in ("EV-001", "EV-002", "EV-003", "EV-005", "EV-006",
                            "EV-007", "EV-008"):
            item = e.evidence_by_id(evidence_id)
            assert item.actor == e.Actor.COMPROMISED_KEY
            assert item.attacker_controllable is False

    def test_cloudwatch_item_is_marked_for_the_injection_channel(self):
        assert "injection channel" in " ".join(e.evidence_by_id("EV-102").notes)


class TestCredentialHygiene:
    def test_no_evidence_definition_carries_credential_material(self):
        for item in e.EVIDENCE_CATALOGUE:
            blob = json.dumps(item.as_dict())
            for forbidden in ("SecretAccessKey", "session_token", "SessionToken",
                              "SecretString", "secret_access_key", "credentials",
                              "password"):
                assert forbidden not in blob, item.id

    def test_no_evidence_target_is_a_secret_value(self):
        for item in e.EVIDENCE_CATALOGUE:
            assert "SecretString" not in item.target

    def test_evidence_payload_passes_manifest_validation(self):
        payload = m.manifest_payload(m.ScenarioManifest(
            generated_at="2026-01-15T09:00:05Z",
            identities=m.Identities(
                incident=m.Identity(user_name=d.RESOURCES.incident_user),
                investigator=m.Identity(user_name=d.RESOURCES.investigator_user)),
            principal=m.Principal(access_key_id="AKIA2EXAMPLE0000000A"),
            resources=m.Resources(
                incident_bucket=d.RESOURCES.incident_bucket,
                evidence_bucket=d.RESOURCES.evidence_bucket,
                trail_bucket=d.RESOURCES.trail_bucket,
                secret_logical_name=d.RESOURCES.secret_name,
                log_group=d.RESOURCES.log_group, log_stream=d.RESOURCES.log_stream,
                function_name=d.RESOURCES.function_name,
                trail_name=d.RESOURCES.trail_name),
            object_keys=m.ObjectKeys(
                baseline=d.RESOURCES.baseline_object, notes=d.RESOURCES.notes_object,
                restricted=d.RESOURCES.restricted_object,
                evidence_index=d.RESOURCES.evidence_index_object)))
        payload["evidence"] = [
            m.EvidenceRecord(id=item.id, event_time=item.event_time,
                             time_basis=item.time_basis, authoritative=item.authoritative,
                             required=item.required, service=item.service,
                             operation=item.operation, target=item.target,
                             tool=item.future_tool, offset_seconds=item.offset_seconds,
                             attacker_controllable=item.attacker_controllable)
            for item in e.EVIDENCE_CATALOGUE]
        m.validate_manifest_payload(payload)

    def test_catalogue_targets_reference_only_canonical_resources(self):
        canonical = set(d.RESOURCES.all_names().values())
        for item in e.AUTHORITATIVE_EVIDENCE:
            if item.id == "EV-008":
                continue
            assert any(name in item.target for name in canonical), item.id
        assert not any(item.target.startswith("arn:aws:s3:::cloudsec-")
                       for item in e.EVIDENCE_CATALOGUE)

    def test_identity_introspection_target_is_a_neutral_self_reference(self):
        item = e.evidence_by_id("EV-008")
        assert item.target == "current-caller-identity"
        assert not item.target.startswith("arn:aws:")