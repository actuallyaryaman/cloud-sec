"""Bounded M5C live proof: scripted investigation, bridge-driven
containment through the real M2 path, idempotent second submit. No
manifest reads, no secret retrieval, no LLM."""

from datetime import datetime, timedelta, timezone

import pytest

from m1_scripted_model import CanonicalScriptedModel
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.backend.approval import (ApprovalRecord,
                                             FakeApprovalProvider)
from cloudsec_agent.backend.audit import AuditStage
from cloudsec_agent.backend.broker import (BROAD_CAPABILITY, grant_for)
from cloudsec_agent.backend.executor import ContainmentExecutor
from cloudsec_agent.backend.live_executor import LiveExecutionPort
from cloudsec_agent.backend.m2_identity import (cleanup_executor_identity,
                                                 executor_identity_absent,
                                                 setup_executor_identity)
from cloudsec_agent.backend.policy import ScenarioPolicyContext
from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError,
                                         assert_local_endpoint)
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.containment_bridge import ContainmentBridge
from cloudsec_agent.integration.read_port import FlociReadPort
from cloudsec_agent.result import CallOutcome
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import seed as s

CANONICAL = "http://localhost:4567"
RUN = "run-m5c-live-1"
SCOPE = "run-m5c-live-1:contain"

READ_TOOL_IDS = {"s3_list_objects", "s3_get_object", "iam_get_user",
                 "iam_list_access_keys", "iam_get_user_policy",
                 "iam_list_user_policies", "secrets_describe_secret",
                 "logs_get_log_events",
                 "lambda_get_function_configuration"}

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


def _active_keys(floci, user):
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
    names = {item["UserName"] for item in users.raw.get("Users", [])}
    if d.RESOURCES.incident_user not in names:
        seeded = s.seed_canonical_scenario(floci, d.SCENARIO_ID)
        assert not seeded.fatal_errors, seeded.fatal_errors

    expected_key = _active_keys(floci, d.RESOURCES.incident_user)
    assert len(expected_key) == 1
    expected_key = expected_key[0]
    investigator_keys = _active_keys(floci, d.RESOURCES.investigator_user)
    assert len(investigator_keys) == 1

    assert executor_identity_absent(floci.client("iam"))
    _, exec_credential = setup_executor_identity(floci.client("iam"))

    made = _capture(floci, "iam", "CreateAccessKey", lambda c: (
        c.create_access_key(UserName=d.RESOURCES.investigator_user)))
    assert made.ok, made.error_code
    tmp_akid = made.raw["AccessKey"]["AccessKeyId"]
    tmp_secret = made.raw["AccessKey"]["SecretAccessKey"]

    def read_factory(service):
        return floci.client(service, akid=tmp_akid, secret=tmp_secret)

    reads = FlociReadPort(read_factory)
    read_port = RealBackendToolPort(reads, run_scope=RUN,
                                    actor="m5c-live-agent",
                                    scenario_id=d.SCENARIO_ID)
    model = CanonicalScriptedModel(
        bucket=d.RESOURCES.incident_bucket, user=d.RESOURCES.incident_user,
        secret=d.RESOURCES.secret_name, function=d.RESOURCES.function_name,
        log_group=d.RESOURCES.log_group, log_stream=d.RESOURCES.log_stream)
    orch = AgentOrchestrator(model, read_port, actor="m5c-live-agent",
                             scenario_id=d.SCENARIO_ID)
    result, events = orch.run(RUN)

    bridge = ContainmentBridge(run_id=RUN, actor="m5c-live-agent",
                               scenario_id=d.SCENARIO_ID, run_scope=SCOPE)
    prepared = bridge.prepare("a-live-1", result.recommended_action,
                              result.compromised_principal,
                              result.compromised_access_key_id)
    now = datetime.now(timezone.utc)
    provider = FakeApprovalProvider([ApprovalRecord(
        action_digest=prepared.digest, approved_by="m5c-live-human",
        approved_at=now, expires_at=now + timedelta(seconds=600),
        single_use=True, approval_id="appr-m5c-live-1")])
    exec_iam = floci.client(
        "iam", akid=exec_credential.access_key_id,
        secret=exec_credential.secret_access_key)
    context = ScenarioPolicyContext(
        scenario_id=d.SCENARIO_ID,
        incident_user=result.compromised_principal,
        compromised_access_key_id=result.compromised_access_key_id)
    outcome = bridge.submit(
        prepared, grant=grant_for(BROAD_CAPABILITY, SCOPE),
        policy_context=context, approval_provider=provider,
        executor=ContainmentExecutor(LiveExecutionPort(exec_iam)),
        protected_user=d.RESOURCES.investigator_user,
        protected_key_id=investigator_keys[0],
        approval_ref="appr-m5c-live-1", current_time=now)

    prepared2 = bridge.prepare("a-live-2", result.recommended_action,
                               result.compromised_principal,
                               result.compromised_access_key_id)
    provider2 = FakeApprovalProvider([ApprovalRecord(
        action_digest=prepared2.digest, approved_by="m5c-live-human",
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=600),
        single_use=True, approval_id="appr-m5c-live-2")])
    outcome2 = bridge.submit(
        prepared2, grant=grant_for(BROAD_CAPABILITY, SCOPE),
        policy_context=context, approval_provider=provider2,
        executor=ContainmentExecutor(LiveExecutionPort(exec_iam)),
        protected_user=d.RESOURCES.investigator_user,
        protected_key_id=investigator_keys[0],
        approval_ref="appr-m5c-live-2",
        current_time=datetime.now(timezone.utc))

    post_incident = _active_keys(floci, d.RESOURCES.incident_user)
    post_investigator = _active_keys(floci, d.RESOURCES.investigator_user)
    listed = _capture(floci, "iam", "ListAccessKeys", lambda c: (
        c.list_access_keys(UserName=d.RESOURCES.incident_user)))
    states = {item["AccessKeyId"]: item.get("Status")
              for item in listed.raw.get("AccessKeyMetadata", [])}

    data = {"result": result, "events": events, "bridge": bridge,
            "audits": bridge.audits, "read_audits": read_port.audits,
            "outcome": outcome,
            "outcome2": outcome2, "expected_key": expected_key,
            "investigator_key": investigator_keys[0],
            "post_incident": post_incident,
            "post_investigator": post_investigator, "states": states,
            "tmp_akid": tmp_akid}
    yield data

    floci.client("iam").delete_access_key(
        UserName=d.RESOURCES.investigator_user, AccessKeyId=tmp_akid)
    cleanup = cleanup_executor_identity(floci.client("iam"))
    assert not cleanup.fatal_errors, cleanup.as_dict()


class TestLiveContainment:
    def test_investigation_completes_with_discovery(self, live):
        assert live["result"].status is InvestigationStatus.COMPLETE
        assert live["result"].compromised_principal == \
            d.RESOURCES.incident_user
        assert live["result"].compromised_access_key_id == \
            live["expected_key"]

    def test_first_containment_confirmed(self, live):
        outcome = live["outcome"]
        assert outcome.classification == "confirmed"
        assert outcome.executed is True
        assert outcome.effective is True
        assert outcome.backend_request_id == f"{RUN}:contain:a-live-1"
        assert live["states"][live["expected_key"]] == "Inactive"

    def test_second_containment_already_effective(self, live):
        outcome2 = live["outcome2"]
        assert outcome2.classification == "already_effective"
        assert outcome2.executed is False
        assert outcome2.effective is True
        assert live["states"][live["expected_key"]] == "Inactive"

    def test_independent_readback(self, live):
        assert live["post_incident"] == []
        assert live["investigator_key"] in live["post_investigator"]

    def test_full_correlation(self, live):
        requested = [event for event in live["events"]
                     if event.kind is AgentEventKind.TOOL_REQUESTED]
        assert len(requested) == 9
        read_join = {}
        for record in live["read_audits"]:
            read_join.setdefault(record.request_id, []).append(record)
        assert set(read_join) == {event.payload["request_id"]
                                  for event in requested}
        for records in read_join.values():
            assert [record.stage for record in records] == [
                AuditStage.CANONICALIZED, AuditStage.BROKER_DECIDED,
                AuditStage.VERIFICATION_DECIDED]
        bridge_ids = [f"{RUN}:contain:a-live-1", f"{RUN}:contain:a-live-2"]
        by_request = {}
        for record in live["audits"]:
            by_request.setdefault(record.request_id, []).append(record)
        assert set(by_request) == set(bridge_ids)
        for request_id in bridge_ids:
            assert [record.stage for record in by_request[request_id]] == [
                AuditStage.CANONICALIZED, AuditStage.BROKER_DECIDED,
                AuditStage.POLICY_DECIDED, AuditStage.APPROVAL_DECIDED,
                AuditStage.EXECUTION_DECIDED,
                AuditStage.VERIFICATION_DECIDED]
        kinds = [event.kind for event in live["bridge"].events]
        assert kinds == [AgentEventKind.CONTAINMENT_SUBMITTED,
                         AgentEventKind.CONTAINMENT_APPROVED,
                         AgentEventKind.CONTAINMENT_RESULT,
                         AgentEventKind.CONTAINMENT_SUBMITTED,
                         AgentEventKind.CONTAINMENT_APPROVED,
                         AgentEventKind.CONTAINMENT_RESULT]

    def test_no_secret_retrieval(self, live):
        tools = {record.tool_id for record in live["audits"]}
        assert tools == {"update_access_key"}
        blob = repr(live["outcome"]) + repr(live["bridge"].events)
        for token in FORBIDDEN:
            assert token not in blob
