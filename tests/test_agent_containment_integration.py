"""Pure bridge tests: validation, denials, digest binding, safe
failure. Backend path is real; execution port and approval are fake."""

import pytest

from cloudsec_agent.backend.approval import (ApprovalRecord,
                                             FakeApprovalProvider)
from cloudsec_agent.backend.audit import AuditStage
from cloudsec_agent.backend.broker import (BROAD_CAPABILITY, grant_for)
from cloudsec_agent.backend.executor import (ContainmentExecutor,
                                             ExecutionPort)
from cloudsec_agent.backend.policy import ScenarioPolicyContext
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import RecommendedAction
from cloudsec_agent.integration.containment_bridge import (
    ContainmentBridge, ContainmentBridgeError)
from cloudsec_agent.scenario import determinism as d

USER = d.RESOURCES.incident_user
KEY = "AKIA-SYNTH-M5C-01"
GUARD_USER = "case-guard"
GUARD_KEY = "GUARDKEY01"
RUN = "run-bridge-1"
SCOPE = "run-bridge-1:contain"


class FakeExecutionPort(ExecutionPort):
    def __init__(self, states):
        self.states = {user: dict(keys) for user, keys in states.items()}
        self.mutations = []

    def list_access_keys(self, user_name):
        return [{"AccessKeyId": key, "Status": status}
                for key, status in self.states.get(user_name, {}).items()]

    def update_access_key_status(self, user_name, access_key_id, status):
        self.mutations.append((user_name, access_key_id, status))
        current = self.states.get(user_name, {}).get(access_key_id)
        if current is None:
            return {"http_status": 404, "error_code": "NoSuchEntity",
                    "detail": "absent"}
        self.states[user_name][access_key_id] = status
        return {"http_status": 200, "error_code": None, "detail": ""}


def _states(key_status="Active"):
    return {USER: {KEY: key_status}, GUARD_USER: {GUARD_KEY: "Active"}}


def _bridge(**kwargs):
    params = {"run_id": RUN, "actor": "test-agent",
              "scenario_id": "test-scenario", "run_scope": SCOPE,
              "clock": lambda: 1.0}
    params.update(kwargs)
    return ContainmentBridge(**params)


def _proposal(**overrides):
    arguments = {"UserName": USER, "AccessKeyId": KEY, "Status": "Inactive"}
    arguments.update(overrides.pop("arguments", {}))
    fields = {"tool_id": "update_access_key", "arguments": arguments,
              "reason": "disable the observed key"}
    fields.update(overrides)
    return RecommendedAction(**fields)


def _approval(digest, approval_id="appr-1"):
    return ApprovalRecord(action_digest=digest, approved_by="test-human",
                          approved_at=1, expires_at=9999, single_use=True,
                          approval_id=approval_id)


def _context(key_id=KEY):
    return ScenarioPolicyContext(scenario_id="test-scenario",
                                 incident_user=USER,
                                 compromised_access_key_id=key_id)


def _submit(bridge, prepared, provider, port, approval_ref="appr-1",
            context=None):
    return bridge.submit(
        prepared, grant=grant_for(BROAD_CAPABILITY, SCOPE),
        policy_context=context or _context(),
        approval_provider=provider,
        executor=ContainmentExecutor(port), protected_user=GUARD_USER,
        protected_key_id=GUARD_KEY, approval_ref=approval_ref,
        current_time=1)


class TestPrepare:
    def test_valid_proposal_prepares_with_stable_ids(self):
        bridge = _bridge()
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        assert prepared.request.request_id == f"{RUN}:contain:a1"
        assert prepared.request.tool_id == "update_access_key"
        assert prepared.digest
        again = bridge.prepare("a2", _proposal(), USER, KEY)
        assert again.digest == prepared.digest

    @pytest.mark.parametrize("mutate,code", [
        ({"tool_id": "iam_get_user"}, "unsupported_action"),
        ({"arguments": {"Status": "Active"}}, "invalid_arguments"),
        ({"arguments": {"Status": "oops"}}, "invalid_arguments"),
        ({"arguments": {"Extra": "x"}}, "invalid_arguments"),
        ({"arguments": {"UserName": "someone-else"}},
         "discovery_mismatch"),
    ])
    def test_rejects_bad_proposals(self, mutate, code):
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError) as exc:
            bridge.prepare("a1", _proposal(**mutate), USER, KEY)
        assert exc.value.code == code

    def test_rejects_missing_status(self):
        arguments = {"UserName": USER, "AccessKeyId": KEY}
        proposal = RecommendedAction(tool_id="update_access_key",
                                     arguments=arguments, reason="x")
        with pytest.raises(ContainmentBridgeError):
            _bridge().prepare("a1", proposal, USER, KEY)

    def test_rejects_duplicate_call_id(self):
        bridge = _bridge()
        bridge.prepare("a1", _proposal(), USER, KEY)
        with pytest.raises(ContainmentBridgeError) as exc:
            bridge.prepare("a1", _proposal(), USER, KEY)
        assert exc.value.code == "duplicate_call_id"

    def test_rejects_non_recommendation(self):
        with pytest.raises(ContainmentBridgeError):
            _bridge().prepare("a1", {"tool_id": "update_access_key"},
                              USER, KEY)


class TestConfirmedPath:
    def test_submit_confirmed_with_one_mutation(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        provider = FakeApprovalProvider([_approval(prepared.digest)])
        outcome = _submit(bridge, prepared, provider, port)
        assert outcome.classification == "confirmed"
        assert outcome.executed is True
        assert outcome.effective is True
        assert outcome.backend_request_id == f"{RUN}:contain:a1"
        assert outcome.approval_ref == "appr-1"
        assert port.mutations == [(USER, KEY, "Inactive")]
        assert port.list_access_keys(USER) == [
            {"AccessKeyId": KEY, "Status": "Inactive"}]
        stages = [record.stage for record in bridge.audits]
        assert stages == [AuditStage.CANONICALIZED,
                          AuditStage.BROKER_DECIDED,
                          AuditStage.POLICY_DECIDED,
                          AuditStage.APPROVAL_DECIDED,
                          AuditStage.EXECUTION_DECIDED,
                          AuditStage.VERIFICATION_DECIDED]
        assert all(record.request_id == f"{RUN}:contain:a1"
                   for record in bridge.audits)
        kinds = [event.kind for event in bridge.events]
        assert kinds == [AgentEventKind.CONTAINMENT_SUBMITTED,
                         AgentEventKind.CONTAINMENT_APPROVED,
                         AgentEventKind.CONTAINMENT_RESULT]

    def test_second_submit_is_already_effective(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        first = bridge.prepare("a1", _proposal(), USER, KEY)
        _submit(bridge, first, FakeApprovalProvider([_approval(first.digest)]),
                port)
        second = bridge.prepare("a2", _proposal(), USER, KEY)
        outcome = _submit(bridge, second,
                          FakeApprovalProvider([_approval(second.digest,
                                                          "appr-2")]),
                          port, approval_ref="appr-2")
        assert outcome.classification == "already_effective"
        assert outcome.executed is False
        assert outcome.effective is True
        assert len(port.mutations) == 1
        states = [record.state.as_dict() for record in bridge.audits
                  if record.request_id == f"{RUN}:contain:a2"]
        assert states[-2]["executed"] is False
        assert states[-1]["effective"] is True


class TestDenials:
    def test_approval_denial_blocks_mutation(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        outcome = _submit(bridge, prepared, FakeApprovalProvider([]), port,
                          approval_ref="")
        assert outcome.classification == "approval_required"
        assert outcome.effective is False
        assert port.mutations == []
        kinds = [event.kind for event in bridge.events]
        assert AgentEventKind.CONTAINMENT_APPROVAL_REQUIRED in kinds
        assert AgentEventKind.CONTAINMENT_APPROVED not in kinds

    def test_policy_denial_consumes_no_approval(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        provider = FakeApprovalProvider([_approval(prepared.digest)])
        outcome = _submit(bridge, prepared, provider, port,
                          context=_context("AKIA-CASE-FILE-09"))
        assert outcome.classification == "policy_denied"
        assert outcome.reason_code == "wrong_access_key"
        assert provider.calls == 0
        assert provider.consumed_approval_ids == frozenset()
        assert port.mutations == []

    def test_broker_denial_without_grant(self):
        from cloudsec_agent.backend.broker import TASK_SCOPED_CAPABILITY
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        outcome = bridge.submit(
            prepared, grant=grant_for(TASK_SCOPED_CAPABILITY, SCOPE),
            policy_context=_context(),
            approval_provider=FakeApprovalProvider(
                [_approval(prepared.digest)]),
            executor=ContainmentExecutor(port), protected_user=GUARD_USER,
            protected_key_id=GUARD_KEY, current_time=1)
        assert outcome.classification == "broker_denied"
        assert outcome.effective is False
        assert port.mutations == []

    def test_digest_mismatch_denies(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        first = bridge.prepare("a1", _proposal(), USER, KEY)
        other = bridge.prepare("a2", _proposal(
            arguments={"AccessKeyId": "AKIA-SYNTH-OTHER-03"}),
            USER, "AKIA-SYNTH-OTHER-03")
        provider = FakeApprovalProvider([_approval(first.digest)])
        outcome = _submit(bridge, other, provider, port,
                          context=_context("AKIA-SYNTH-OTHER-03"))
        assert outcome.classification == "approval_required"
        assert port.mutations == []

    def test_raw_port_failure_is_safe(self):
        class ExplodingPort(FakeExecutionPort):
            def update_access_key_status(self, *args):
                raise RuntimeError("boom CANARY")

        bridge = _bridge()
        port = ExplodingPort(_states())
        prepared = bridge.prepare("a1", _proposal(), USER, KEY)
        outcome = _submit(bridge, prepared,
                          FakeApprovalProvider([_approval(prepared.digest)]),
                          port)
        assert outcome.classification == "bridge_error"
        assert outcome.executed is False
        assert "CANARY" not in repr(outcome) + repr(bridge.events)


class TestCorrelation:
    def test_ids_join_bridge_events_and_audits(self):
        bridge = _bridge()
        port = FakeExecutionPort(_states())
        prepared = bridge.prepare("a-call-9", _proposal(), USER, KEY)
        _submit(bridge, prepared,
                FakeApprovalProvider([_approval(prepared.digest)]), port)
        for event in bridge.events:
            assert event.payload["action_call_id"] == "a-call-9"
            assert event.payload["backend_request_id"] == f"{RUN}:contain:a-call-9"
        assert {record.request_id for record in bridge.audits} == \
            {f"{RUN}:contain:a-call-9"}
