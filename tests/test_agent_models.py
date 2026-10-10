"""Unit tests for Agent V1 models, ports, and events."""

import pytest

from cloudsec_agent.agent import events as ev
from cloudsec_agent.agent import model_port as mp
from cloudsec_agent.agent import models as mm
from cloudsec_agent.agent import tool_port as tp
from cloudsec_agent.agent.orchestrator import sanitize_data


def _answer(**overrides):
    fields = {
        "compromised_principal": "analytics-worker",
        "compromised_access_key_id": "AKIA-TEST-ANALYTICS-01",
        "confidence": 0.8,
        "findings": ("odd archive enumeration",),
        "evidence_refs": ("evidence:log-1",),
        "recommended_action": mm.RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": "analytics-worker",
                       "AccessKeyId": "AKIA-TEST-ANALYTICS-01",
                       "Status": "Inactive"},
            reason="disable the key seen in anomalous calls"),
        "rationale_summary": "anomalous access then denied sensitive read",
    }
    fields.update(overrides)
    return mm.AgentFinalAnswer(**fields)


class TestAgentLimits:
    def test_conservative_defaults(self):
        limits = mm.AgentLimits()
        assert limits.max_turns == 20
        assert limits.max_tool_calls == 30
        assert limits.max_identical_request_repeats == 2

    def test_rejects_non_positive_bounds(self):
        with pytest.raises(ValueError):
            mm.AgentLimits(max_turns=0)
        with pytest.raises(ValueError):
            mm.AgentLimits(max_tool_calls=-1)


class TestModelTurn:
    def test_tool_calls_or_final_answer_only(self):
        call = mm.AgentToolCall(call_id="c1", tool_id="iam_get_user",
                                arguments={"UserName": "analytics-worker"})
        assert mp.ModelTurn(tool_calls=[call]).is_final is False
        assert mp.ModelTurn(final_answer=_answer()).is_final is True

    def test_both_or_neither_rejected(self):
        call = mm.AgentToolCall(call_id="c1", tool_id="iam_get_user",
                                arguments={})
        with pytest.raises(ValueError):
            mp.ModelTurn(tool_calls=[call], final_answer=_answer())
        with pytest.raises(ValueError):
            mp.ModelTurn()

    def test_non_call_items_rejected(self):
        with pytest.raises(TypeError):
            mp.ModelTurn(tool_calls=["not-a-call"])


class TestFinalAnswerStructure:
    def test_confidence_range_enforced(self):
        with pytest.raises(ValueError):
            _answer(confidence=1.5)
        with pytest.raises(ValueError):
            _answer(confidence=-0.1)
        assert _answer(confidence=0.0).confidence == 0.0
        assert _answer(confidence=1.0).confidence == 1.0

    def test_empty_principal_or_key_rejected(self):
        with pytest.raises(ValueError):
            _answer(compromised_principal="  ")
        with pytest.raises(ValueError):
            _answer(compromised_access_key_id="")


class TestInvestigationStatus:
    def test_four_stable_statuses(self):
        assert {item.value for item in mm.InvestigationStatus} == {
            "COMPLETE", "INCOMPLETE", "FAILED", "LIMIT_REACHED"}


class TestToolContracts:
    def test_known_tools_cover_reads_sensitive_and_containment(self):
        assert "iam_get_user" in tp.KNOWN_TOOL_IDS
        assert "get_secret_value" in tp.KNOWN_TOOL_IDS
        assert "update_access_key" in tp.KNOWN_TOOL_IDS

    def test_backend_request_shape_is_toolrequest_compatible(self):
        request = tp.BackendToolRequest(
            request_id="r1", tool_id="iam_get_user",
            arguments={"UserName": "analytics-worker"},
            actor="agent", scenario_id="local",
            justification="triage")
        for name in ("request_id", "tool_id", "arguments", "actor",
                     "scenario_id", "justification"):
            assert hasattr(request, name)


class TestAgentEvents:
    def test_replay_kinds_exist(self):
        assert {item.value for item in ev.AgentEventKind} == {
            "RUN_STARTED", "MODEL_TURN_STARTED", "TOOL_REQUESTED",
            "TOOL_RESULT", "FINDING_UPDATED", "ACTION_PROPOSED",
            "CONTAINMENT_SUBMITTED", "CONTAINMENT_APPROVAL_REQUIRED",
            "CONTAINMENT_APPROVED", "CONTAINMENT_RESULT",
            "RUN_COMPLETED", "RUN_STOPPED"}

    def test_event_carries_safe_payload_only(self):
        event = ev.AgentEvent(event_id="e1", run_id="r1", sequence=0,
                              kind=ev.AgentEventKind.RUN_STARTED,
                              timestamp=0.0,
                              payload={"actor": "agent"})
        assert event.as_dict()["payload"] == {"actor": "agent"}

    def test_agent_event_is_not_backend_audit_record(self):
        from cloudsec_agent.backend.audit import AuditRecord
        assert ev.AgentEvent is not AuditRecord


class TestSanitizeData:
    def test_strips_secret_payload_fields(self):
        data = {"UserName": "analytics-worker",
                "SecretString": "CANARY",
                "SecretBinary": b"CANARY",
                "SecretAccessKey": "CANARY",
                "SessionToken": "CANARY",
                "credentials": {"x": 1},
                "password": "CANARY"}
        assert sanitize_data(data, 2000) == {
            "UserName": "analytics-worker"}

    def test_bounds_long_strings(self):
        assert sanitize_data({"k": "x" * 5000}, 2000) == {"k": "x" * 2000}

    def test_non_dict_data_becomes_empty(self):
        assert sanitize_data("oops", 2000) == {}
        assert sanitize_data(None, 2000) == {}
