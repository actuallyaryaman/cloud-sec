"""Composed M5C seam: scripted model discovers synthetic key through
reads, proposes containment, bridge drives real broker/policy/approval
and a fake executor. No live backend, no model intelligence."""

import pytest

from m1_scripted_model import CanonicalScriptedModel
from test_agent_containment_integration import (FakeExecutionPort, _approval,
                                                _context)
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.backend.approval import FakeApprovalProvider
from cloudsec_agent.backend.broker import (BROAD_CAPABILITY, grant_for)
from cloudsec_agent.backend.executor import ContainmentExecutor
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.containment_bridge import ContainmentBridge
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.scenario import determinism as d

USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
SECRET = d.RESOURCES.secret_name
FUNCTION = d.RESOURCES.function_name
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
KEY = "AKIA-SYNTH-SEAM-C9"
GUARD_USER = "case-guard"
GUARD_KEY = "GUARDKEY01"
RUN = "run-seam-contain-1"
SCOPE = "run-seam-contain-1:contain"


def _responses():
    return {
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.notes_object],
                         "count": 1, "truncated": False},
        "get_object": {"bucket": BUCKET,
                       "key": d.RESOURCES.notes_object,
                       "body": "notes", "size": 5, "truncated": False},
        "get_user": {"user_name": USER, "truncated": False},
        "list_access_keys": {"user_name": USER,
                             "access_keys": [{"access_key_id": KEY,
                                              "status": "Active"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": USER,
                               "policy_names": ["case-scout"],
                               "count": 1, "truncated": False},
        "get_user_policy": {"user_name": USER, "policy_name": "case-scout",
                            "policy_document": "{}", "truncated": False},
        "describe_secret": {"name": SECRET, "truncated": False},
        "get_function_configuration": {"function_name": FUNCTION,
                                       "truncated": False},
        "get_log_events": {"events": [], "count": 0, "truncated": False},
    }


def _investigate(run_id=RUN):
    responses = _responses()
    reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="test-agent",
                               scenario_id="test-scenario")
    model = CanonicalScriptedModel(
        bucket=BUCKET, user=USER, secret=SECRET, function=FUNCTION,
        log_group=GROUP, log_stream=STREAM)
    orch = AgentOrchestrator(model, port, actor="test-agent",
                             scenario_id="test-scenario",
                             clock=lambda: 1.0)
    return orch.run(run_id)


def _bridge():
    clock = {"now": 0.0}

    def tick():
        clock["now"] += 1.0
        return clock["now"]

    return ContainmentBridge(run_id=RUN, actor="test-agent",
                             scenario_id="test-scenario", run_scope=SCOPE,
                             clock=tick)


class TestComposedContainment:
    def test_full_path_confirmed(self):
        result, events = _investigate()
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_access_key_id == KEY
        proposal = result.recommended_action
        assert proposal.arguments["AccessKeyId"] == KEY

        bridge = _bridge()
        port = FakeExecutionPort({USER: {KEY: "Active"},
                                  GUARD_USER: {GUARD_KEY: "Active"}})
        prepared = bridge.prepare("a1", proposal, USER, KEY)
        provider = FakeApprovalProvider([_approval(prepared.digest)])
        outcome = bridge.submit(
            prepared, grant=grant_for(BROAD_CAPABILITY, SCOPE),
            policy_context=_context(KEY), approval_provider=provider,
            executor=ContainmentExecutor(port), protected_user=GUARD_USER,
            protected_key_id=GUARD_KEY, approval_ref="appr-1",
            current_time=1)
        assert outcome.classification == "confirmed"
        assert outcome.executed is True
        assert outcome.effective is True
        assert port.mutations == [(USER, KEY, "Inactive")]
        assert port.list_access_keys(USER) == [
            {"AccessKeyId": KEY, "Status": "Inactive"}]

        kinds = [event.kind for event in events]
        assert AgentEventKind.ACTION_PROPOSED in kinds
        bridge_kinds = [event.kind for event in bridge.events]
        assert bridge_kinds == [AgentEventKind.CONTAINMENT_SUBMITTED,
                                AgentEventKind.CONTAINMENT_APPROVED,
                                AgentEventKind.CONTAINMENT_RESULT]
        assert outcome.backend_request_id == f"{RUN}:contain:a1"
        assert {record.request_id for record in bridge.audits} == \
            {f"{RUN}:contain:a1"}
        stages = [record.stage.value for record in bridge.audits]
        assert stages == ["canonicalized", "broker_decided",
                          "policy_decided", "approval_decided",
                          "execution_decided", "verification_decided"]
        blob = repr(outcome) + repr(bridge.events)
        for token in ("SecretString", "SecretBinary", "SecretAccessKey",
                      "SessionToken"):
            assert token not in blob

    def test_second_submit_already_effective(self):
        result, _ = _investigate()
        bridge = _bridge()
        port = FakeExecutionPort({USER: {KEY: "Active"},
                                  GUARD_USER: {GUARD_KEY: "Active"}})
        first = bridge.prepare("a1", result.recommended_action, USER, KEY)
        bridge.submit(first, grant=grant_for(BROAD_CAPABILITY, SCOPE),
                      policy_context=_context(KEY),
                      approval_provider=FakeApprovalProvider(
                          [_approval(first.digest)]),
                      executor=ContainmentExecutor(port),
                      protected_user=GUARD_USER, protected_key_id=GUARD_KEY,
                      current_time=1)
        second = bridge.prepare("a2", result.recommended_action, USER, KEY)
        outcome = bridge.submit(
            second, grant=grant_for(BROAD_CAPABILITY, SCOPE),
            policy_context=_context(KEY),
            approval_provider=FakeApprovalProvider(
                [_approval(second.digest, "appr-2")]),
            executor=ContainmentExecutor(port), protected_user=GUARD_USER,
            protected_key_id=GUARD_KEY, approval_ref="appr-2",
            current_time=1)
        assert outcome.classification == "already_effective"
        assert outcome.executed is False
        assert outcome.effective is True
        assert len(port.mutations) == 1
