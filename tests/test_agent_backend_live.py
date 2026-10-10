"""Bounded M5B live proof: scripted model, real orchestrator, real
backend port, live Floci reads as the investigator identity. No
manifest reads, no containment, no secret retrieval."""

import pytest

from m1_scripted_model import CanonicalScriptedModel
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError,
                                         assert_local_endpoint)
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FlociReadPort
from cloudsec_agent.result import CallOutcome
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import reset as r
from cloudsec_agent.scenario import seed as s

CANONICAL = "http://localhost:4567"
RUN_ID = "run-m5b-live-1"

READ_METHODS = {"s3_list_objects", "s3_get_object", "iam_get_user",
                "iam_list_access_keys", "iam_get_user_policy",
                "iam_list_user_policies", "secrets_describe_secret",
                "logs_get_log_events",
                "lambda_get_function_configuration"}


def _executed_tools(live):
    return {record.tool_id for record in live["audits"]}

FORBIDDEN = ("SecretString", "SecretBinary", "SecretAccessKey",
             "SessionToken", "secret_access_key", "session_token",
             "password")


def _reachable():
    try:
        assert_local_endpoint(CANONICAL)
        Floci(CANONICAL).health()
        return True
    except (EndpointUnavailable, UnsafeEndpointError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(),
    reason="Floci IAM-enforced is not reachable at http://localhost:4567")


def _capture(floci, service, operation, func):
    return CallOutcome.capture(service, operation, func,
                               floci.client(service))


def _active_key_ids(floci, user):
    listed = _capture(floci, "iam", "ListAccessKeys",
                      lambda c: c.list_access_keys(UserName=user))
    assert listed.ok, listed.error_code
    return sorted(item["AccessKeyId"]
                  for item in listed.raw.get("AccessKeyMetadata", [])
                  if item.get("Status") == "Active")


@pytest.fixture(scope="module")
def live():
    floci = Floci(CANONICAL)
    floci.health()
    floci.describe_identity()

    users = _capture(floci, "iam", "ListUsers", lambda c: c.list_users())
    buckets = _capture(floci, "s3", "ListBuckets", lambda c: c.list_buckets())
    names = {item["UserName"] for item in users.raw.get("Users", [])}
    bucket_names = {item["Name"] for item in buckets.raw.get("Buckets", [])}
    if d.RESOURCES.incident_user in names or \
            d.RESOURCES.incident_bucket in bucket_names:
        report = r.reset_canonical_scenario(floci, d.SCENARIO_ID)
        assert not report.fatal_errors, report.as_dict()

    seed_result = s.seed_canonical_scenario(floci, d.SCENARIO_ID)
    assert not seed_result.fatal_errors, seed_result.fatal_errors

    expected_key = _active_key_ids(floci, d.RESOURCES.incident_user)
    assert len(expected_key) == 1
    expected_key = expected_key[0]
    investigator_keys = _active_key_ids(floci, d.RESOURCES.investigator_user)
    assert len(investigator_keys) == 1

    made = _capture(floci, "iam", "CreateAccessKey", lambda c: (
        c.create_access_key(UserName=d.RESOURCES.investigator_user)))
    assert made.ok, made.error_code
    tmp_akid = made.raw["AccessKey"]["AccessKeyId"]
    tmp_secret = made.raw["AccessKey"]["SecretAccessKey"]

    def factory(service):
        return floci.client(service, akid=tmp_akid, secret=tmp_secret)

    probe = {}
    try:
        factory("iam").get_user(UserName=d.RESOURCES.incident_user)
        probe["get_user_ok"] = True
    except Exception as exc:
        response = getattr(exc, "response", None) or {}
        probe["get_user_ok"] = (response.get("Error") or {}).get(
            "Code", type(exc).__name__)
    try:
        factory("iam").list_access_keys(
            UserName=d.RESOURCES.incident_user)
        probe["list_keys_ok"] = True
    except Exception as exc:
        response = getattr(exc, "response", None) or {}
        probe["list_keys_ok"] = (response.get("Error") or {}).get(
            "Code", type(exc).__name__)

    reads = FlociReadPort(factory)
    port = RealBackendToolPort(reads, run_scope=RUN_ID,
                               actor="m5b-live-agent",
                               scenario_id=d.SCENARIO_ID)
    model = CanonicalScriptedModel(
        bucket=d.RESOURCES.incident_bucket, user=d.RESOURCES.incident_user,
        secret=d.RESOURCES.secret_name, function=d.RESOURCES.function_name,
        log_group=d.RESOURCES.log_group, log_stream=d.RESOURCES.log_stream)
    orch = AgentOrchestrator(model, port, actor="m5b-live-agent",
                             scenario_id=d.SCENARIO_ID)
    result, events = orch.run(RUN_ID)

    post_incident = _active_key_ids(floci, d.RESOURCES.incident_user)
    post_investigator = _active_key_ids(floci, d.RESOURCES.investigator_user)
    described = _capture(floci, "secretsmanager", "DescribeSecret",
                         lambda c: c.describe_secret(
                             SecretId=d.RESOURCES.secret_name))

    data = {"floci": floci, "result": result, "events": events,
            "audits": port.audits, "reads": reads,
            "probe_summary": dict(probe),
            "expected_key": expected_key,
            "investigator_key": investigator_keys[0],
            "post_incident": post_incident,
            "post_investigator": post_investigator,
            "secret_describable": described.ok,
            "tmp_akid": tmp_akid}
    yield data

    cleanup = _capture(floci, "iam", "DeleteAccessKey", lambda c: (
        c.delete_access_key(UserName=d.RESOURCES.investigator_user,
                            AccessKeyId=tmp_akid)))
    assert cleanup.ok, cleanup.error_code


class TestPreconditions:
    def test_probe_characterization_recorded(self, live):
        assert live["probe_summary"], "no investigator probe ran"

    def test_seed_produced_expected_identity(self, live):
        assert live["expected_key"].startswith("AKIA")
        assert live["investigator_key"].startswith("AKIA")
        assert live["expected_key"] != live["investigator_key"]


class TestAgentRun:
    def test_investigation_completes(self, live):
        assert live["probe_summary"] == {"get_user_ok": True,
                                         "list_keys_ok": True}, \
            live["probe_summary"]
        assert live["result"].status is InvestigationStatus.COMPLETE

    def test_principal_and_key_discovered(self, live):
        result = live["result"]
        assert result.compromised_principal == d.RESOURCES.incident_user
        assert result.compromised_access_key_id == live["expected_key"]

    def test_containment_proposed_not_executed(self, live):
        result = live["result"]
        assert result.recommended_action.tool_id == "update_access_key"
        assert dict(result.recommended_action.arguments) == {
            "UserName": d.RESOURCES.incident_user,
            "AccessKeyId": live["expected_key"], "Status": "Inactive"}
        assert _executed_tools(live) <= READ_METHODS
        assert live["post_incident"] == [live["expected_key"]]

    def test_investigator_identity_intact(self, live):
        assert live["investigator_key"] in live["post_investigator"]

    def test_secret_never_retrieved(self, live):
        assert live["secret_describable"] is True
        assert _executed_tools(live) <= READ_METHODS
        tools = {record.tool_id for record in live["audits"]}
        assert "get_secret_value" not in tools
        assert "update_access_key" not in tools


class TestEventsAndReplay:
    def test_event_sequence(self, live):
        kinds = [event.kind for event in live["events"]]
        assert kinds[0] is AgentEventKind.RUN_STARTED
        assert kinds[-1] is AgentEventKind.RUN_COMPLETED
        assert AgentEventKind.ACTION_PROPOSED in kinds
        assert AgentEventKind.FINDING_UPDATED in kinds
        assert kinds.count(AgentEventKind.TOOL_REQUESTED) == \
            kinds.count(AgentEventKind.TOOL_RESULT) == 9

    def test_live_audit_join_is_exact(self, live):
        requested = [event for event in live["events"]
                     if event.kind is AgentEventKind.TOOL_REQUESTED]
        by_request = {}
        for record in live["audits"]:
            by_request.setdefault(record.request_id, []).append(record)
        assert set(by_request) == {event.payload["request_id"]
                                   for event in requested}
        for request_id, records in by_request.items():
            assert [record.stage.value for record in records] == [
                "canonicalized", "broker_decided", "verification_decided"]
            assert all(record.run_id == RUN_ID for record in records)

    def test_no_secret_material_in_agent_stream(self, live):
        blob = repr(live["result"])
        blob += repr([event.as_dict() for event in live["events"]])
        for token in FORBIDDEN:
            assert token not in blob
