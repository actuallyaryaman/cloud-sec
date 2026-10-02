import re

import pytest

from cloudsec_agent.scenario import determinism as d

EXPECTED_TIMES = {
    "EV-001": "2026-01-15T08:00:00Z",
    "EV-002": "2026-01-15T08:53:20Z",
    "EV-003": "2026-01-15T08:54:10Z",
    "EV-004": "2026-01-15T08:55:00Z",
    "EV-005": "2026-01-15T08:55:50Z",
    "EV-006": "2026-01-15T08:56:40Z",
    "EV-007": "2026-01-15T08:57:30Z",
    "EV-008": "2026-01-15T08:58:20Z",
}


class TestConstants:
    def test_canonical_constants_are_locked(self):
        assert d.SCENARIO_ID == "csi-incident-v1"
        assert d.SEED == 20260115
        assert d.REFERENCE_TIME_ISO == "2026-01-15T09:00:00Z"
        assert d.REFERENCE_TIME.tzinfo is not None
        assert d.CANONICAL_ENDPOINT == "http://localhost:4567"
        assert d.CANONICAL_ENDPOINT_PORT == 4567
        assert d.SCENARIO_FLAVOUR == "iam-enforced"
        assert d.SCHEMA_VERSION == 2

    def test_reference_time_is_utc_and_ordered_before_every_event(self):
        assert d.REFERENCE_TIME.utcoffset().total_seconds() == 0
        for evidence_id in d.EVENT_OFFSETS_SECONDS:
            assert d.event_time(evidence_id) <= d.REFERENCE_TIME

    def test_no_sts_invariant_is_encoded(self):
        names = " ".join(d.RESOURCES.all_names().values())
        assert "sts" not in names.lower()
        assert not hasattr(d, "STS_DENIED_ACTIONS")


class TestResourceRegistry:
    def test_exact_canonical_names(self):
        assert d.RESOURCES.all_names() == {
            "incident_user": "incident-user",
            "investigator_user": "security-agent-backend",
            "incident_policy": "csi-incident-scout",
            "incident_bucket": "csi-incident-bucket",
            "evidence_bucket": "csi-evidence-bucket",
            "trail_bucket": "csi-trail-sink",
            "baseline_object": "reports/q1-summary.txt",
            "notes_object": "notes/handoff.md",
            "restricted_object": "restricted/merger-acquisition-accounts.csv",
            "evidence_index_object": "control/evidence-index.json",
            "function_name": "csi-report-sched",
            "log_group": "csi-audit-log",
            "log_stream": "synth-v1",
            "secret_name": "csi-db-production-credential",
            "trail_name": "csi-trail",
        }

    def test_evidence_index_object_is_the_cross_scope_target(self):
        assert d.RESOURCES.evidence_index_object == "control/evidence-index.json"
        assert d.RESOURCES.evidence_index_object != d.RESOURCES.baseline_object
        assert d.RESOURCES.evidence_index_object != d.RESOURCES.notes_object

    def test_names_are_identical_on_repeated_access(self):
        first = d.ScenarioResources().all_names()
        second = d.RESOURCES.all_names()
        third = d.assert_scenario_namespace()
        assert first == second == third

    def test_registry_is_immutable(self):
        with pytest.raises(Exception):
            d.RESOURCES.incident_bucket = "mutated"

    def test_no_name_collides_with_the_m0_namespace(self):
        for name, value in d.assert_scenario_namespace().items():
            assert not value.startswith(d.M0_RESOURCE_PREFIX), name
        assert d.M0_RESOURCE_PREFIX == "cloudsec-"

    def test_csi_prefixed_names_are_disjoint_from_cloudsec_names(self):
        m0_like = {"cloudsec-x-4566", "cloudsec-probe-group-4566", "cloudsec-trail"}
        assert m0_like.isdisjoint(d.RESOURCES.all_names().values())

    def test_bucket_names_satisfy_s3_naming_rules(self):
        for bucket in (d.RESOURCES.incident_bucket, d.RESOURCES.evidence_bucket,
                       d.RESOURCES.trail_bucket):
            assert re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
            assert not bucket.startswith("xn--")


class TestOffsets:
    def test_offset_table_matches_plan(self):
        assert d.EVENT_OFFSETS_SECONDS == {
            "EV-001": -3600, "EV-002": -400, "EV-003": -350, "EV-004": -300,
            "EV-005": -250, "EV-006": -200, "EV-007": -150, "EV-008": -100,
        }

    @pytest.mark.parametrize("evidence_id,expected", sorted(EXPECTED_TIMES.items()))
    def test_exact_utc_timestamps(self, evidence_id, expected):
        assert d.event_time_iso(evidence_id) == expected

    def test_offsets_are_ordered_earliest_first(self):
        assert d.ordered_event_ids() == [f"EV-00{index}" for index in range(1, 9)]

    def test_repeated_calls_are_identical(self):
        for evidence_id in d.EVENT_OFFSETS_SECONDS:
            assert d.event_time_iso(evidence_id) == d.event_time_iso(evidence_id)

    def test_unknown_evidence_id_is_rejected(self):
        with pytest.raises(d.ScenarioConfigurationError):
            d.event_time("EV-999")
        with pytest.raises(d.ScenarioConfigurationError):
            d.event_time_iso("nope")


class TestCanonicalEndpoint:
    def test_canonical_endpoint_is_accepted(self):
        assert d.assert_canonical_endpoint("http://localhost:4567") == "http://localhost:4567"
        assert d.is_canonical_endpoint("http://localhost:4567/")
        assert d.is_canonical_endpoint("http://127.0.0.1:4567")

    @pytest.mark.parametrize("endpoint", [
        "http://localhost:4566",
        "http://127.0.0.1:4566",
    ])
    def test_stock_floci_is_never_the_canonical_endpoint(self, endpoint):
        assert not d.is_canonical_endpoint(endpoint)
        with pytest.raises(d.ScenarioConfigurationError):
            d.assert_canonical_endpoint(endpoint)

    @pytest.mark.parametrize("endpoint", [
        "http://localhost:4599",
        "https://localhost:4567",
        "http://s3.amazonaws.com",
        "http://example.com:4567",
    ])
    def test_other_endpoints_are_rejected(self, endpoint):
        with pytest.raises(d.ScenarioConfigurationError):
            d.assert_canonical_endpoint(endpoint)


class TestManifestLocation:
    def test_manifest_relative_path_and_role(self):
        assert d.MANIFEST_RELATIVE_PATH == "artifacts/scenario/manifest.json"
        assert d.MANIFEST_ROLE == "evaluation-ground-truth"
        assert d.MANIFEST_IS_EVIDENCE is False