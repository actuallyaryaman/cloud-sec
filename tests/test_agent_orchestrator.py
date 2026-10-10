"""Pure orchestration tests for Agent V1. Synthetic fixtures only."""

import pytest

from agent_fakes import FakeModelPort, FakeToolPort, denied_result, ok_result
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.model_port import ModelPortError, ModelTurn
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentLimits,
                                          AgentToolCall,
                                          InvestigationStatus,
                                          RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.agent.tool_port import ToolPortError

PRINCIPAL = "analytics-worker"
KEY_ID = "AKIA-TEST-ANALYTICS-01"
RUN = "run-happy-001"


def _call(call_id, tool_id, arguments, justification="triage"):
    return AgentToolCall(call_id=call_id, tool_id=tool_id,
                         arguments=arguments, justification=justification)


def _final(**overrides):
    fields = {
        "compromised_principal": PRINCIPAL,
        "compromised_access_key_id": KEY_ID,
        "confidence": 0.8,
        "findings": ("anomalous archive enumeration",
                     "denied sensitive-resource request"),
        "evidence_refs": ("evidence:report-access",
                          "evidence:archive-enumeration",
                          "evidence:denied-read"),
        "recommended_action": RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": PRINCIPAL, "AccessKeyId": KEY_ID,
                       "Status": "Inactive"},
            reason="disable the key seen in anomalous calls"),
        "rationale_summary":
            "repeated anomalous access then denied sensitive read",
    }
    fields.update(overrides)
    return AgentFinalAnswer(**fields)


def _happy_script():
    return [
        ModelTurn(tool_calls=[_call("c1", "s3_list_objects",
                                    {"Bucket": "analytics-reports"})]),
        ModelTurn(tool_calls=[_call("c2", "iam_get_user",
                                    {"UserName": PRINCIPAL})]),
        ModelTurn(tool_calls=[_call("c3", "iam_list_access_keys",
                                    {"UserName": PRINCIPAL})]),
        ModelTurn(tool_calls=[_call("c4", "iam_get_user_policy",
                                    {"UserName": PRINCIPAL,
                                     "PolicyName": "analytics-read"})]),
        ModelTurn(final_answer=_final()),
    ]


def _happy_handler(invocation):
    table = {
        "s3_list_objects": {"Bucket": "analytics-reports",
                            "Keys": ["report-1", "archive-9"]},
        "iam_get_user": {"UserName": PRINCIPAL},
        "iam_list_access_keys": {"UserName": PRINCIPAL,
                                 "Keys": [KEY_ID]},
        "iam_get_user_policy": {"UserName": PRINCIPAL,
                                "PolicyName": "analytics-read",
                                "Denied": ["archive-9"]},
    }
    return ok_result(table.get(invocation.tool_id, {}))


def _clock():
    state = {"now": 1000.0}

    def tick():
        state["now"] += 1.0
        return state["now"]

    return tick


def _run(script, handler, run_id=RUN, **kwargs):
    orch = AgentOrchestrator(FakeModelPort(script), FakeToolPort(handler),
                             actor="test-actor",
                             scenario_id="test-scenario",
                             clock=_clock(), **kwargs)
    result, events = orch.run(run_id)
    return orch, result, events


def _kinds(events):
    return [event.kind for event in events]


class TestHappyPath:
    def test_completes_with_discovered_principal_and_key(self):
        _, result, events = _run(_happy_script(), _happy_handler)
        assert result.status is InvestigationStatus.COMPLETE
        assert result.stop_reason == "final_answer_accepted"
        assert result.compromised_principal == PRINCIPAL
        assert result.compromised_access_key_id == KEY_ID
        assert result.confidence == 0.8
        assert result.tool_call_count == 4
        assert result.model_turn_count == 5
        assert result.recommended_action.tool_id == "update_access_key"
        assert dict(result.recommended_action.arguments) == {
            "UserName": PRINCIPAL, "AccessKeyId": KEY_ID,
            "Status": "Inactive"}

    def test_exact_tool_calls_recorded(self):
        orch = AgentOrchestrator(
            FakeModelPort(_happy_script()),
            FakeToolPort(_happy_handler), actor="test-actor",
            scenario_id="test-scenario", clock=_clock())
        port = orch._tools
        result, _ = orch.run(RUN)
        assert result.status is InvestigationStatus.COMPLETE
        assert [(inv.tool_id, dict(inv.arguments))
                for inv in port.invocations] == [
            ("s3_list_objects", {"Bucket": "analytics-reports"}),
            ("iam_get_user", {"UserName": PRINCIPAL}),
            ("iam_list_access_keys", {"UserName": PRINCIPAL}),
            ("iam_get_user_policy",
             {"UserName": PRINCIPAL, "PolicyName": "analytics-read"}),
        ]
        for inv in port.invocations:
            assert inv.actor == "test-actor"
            assert inv.scenario_id == "test-scenario"

    def test_proposal_does_not_execute_containment(self):
        orch = AgentOrchestrator(
            FakeModelPort(_happy_script()),
            FakeToolPort(_happy_handler), actor="test-actor",
            scenario_id="test-scenario", clock=_clock())
        result, _ = orch.run(RUN)
        assert result.status is InvestigationStatus.COMPLETE
        assert all(inv.tool_id != "update_access_key"
                   for inv in orch._tools.invocations)

    def test_exact_event_sequence(self):
        _, _, events = _run(_happy_script(), _happy_handler)
        assert _kinds(events) == [
            AgentEventKind.RUN_STARTED,
            AgentEventKind.MODEL_TURN_STARTED,
            AgentEventKind.TOOL_REQUESTED,
            AgentEventKind.TOOL_RESULT,
            AgentEventKind.MODEL_TURN_STARTED,
            AgentEventKind.TOOL_REQUESTED,
            AgentEventKind.TOOL_RESULT,
            AgentEventKind.MODEL_TURN_STARTED,
            AgentEventKind.TOOL_REQUESTED,
            AgentEventKind.TOOL_RESULT,
            AgentEventKind.MODEL_TURN_STARTED,
            AgentEventKind.TOOL_REQUESTED,
            AgentEventKind.TOOL_RESULT,
            AgentEventKind.MODEL_TURN_STARTED,
            AgentEventKind.FINDING_UPDATED,
            AgentEventKind.ACTION_PROPOSED,
            AgentEventKind.RUN_COMPLETED,
        ]

    def test_correlation_ids_line_up(self):
        _, _, events = _run(_happy_script(), _happy_handler)
        requested = [e for e in events
                     if e.kind is AgentEventKind.TOOL_REQUESTED]
        answered = [e for e in events
                    if e.kind is AgentEventKind.TOOL_RESULT]
        assert [e.payload["request_id"] for e in requested] == [
            f"{RUN}:req:{index:04d}" for index in range(4)]
        assert [e.payload["call_id"] for e in requested] == [
            "c1", "c2", "c3", "c4"]
        assert [(e.payload["call_id"], e.payload["request_id"])
                for e in answered] == [
            (e.payload["call_id"], e.payload["request_id"])
            for e in requested]
        assert [e.sequence for e in events] == list(range(len(events)))
        assert all(e.run_id == RUN for e in events)

    def test_deterministic_under_injected_factories(self):
        first = _run(_happy_script(), _happy_handler)[1:]
        second = _run(_happy_script(), _happy_handler)[1:]
        assert [e.as_dict() for e in first[1]] == [
            e.as_dict() for e in second[1]]
        assert first[0] == second[0]

    def test_no_credential_material_anywhere(self):
        _, result, events = _run(_happy_script(), _happy_handler)
        blob = repr(result) + repr([e.as_dict() for e in events])
        for token in ("SecretString", "SecretBinary", "SecretAccessKey",
                      "SessionToken", "secret_access_key", "session_token",
                      "credential", "password"):
            assert token not in blob


class TestSensitiveDenial:
    def test_denied_secret_read_is_safe_and_recoverable(self):
        script = [
            ModelTurn(tool_calls=[_call("c1", "get_secret_value",
                                        {"SecretId": "analytics-vault"})]),
            ModelTurn(tool_calls=[_call("c2", "iam_get_user",
                                        {"UserName": PRINCIPAL})]),
            ModelTurn(final_answer=_final()),
        ]

        def handler(invocation):
            if invocation.tool_id == "get_secret_value":
                return denied_result()
            return ok_result({"UserName": PRINCIPAL})

        _, result, events = _run(script, handler, run_id="run-deny-1")
        assert result.status is InvestigationStatus.COMPLETE
        denials = [e for e in events
                   if e.kind is AgentEventKind.TOOL_RESULT
                   and e.payload["call_id"] == "c1"]
        assert len(denials) == 1
        assert denials[0].payload["ok"] is False
        assert denials[0].payload["classification"] == "policy_denied"
        blob = repr(result) + repr([e.as_dict() for e in events])
        assert "SecretString" not in blob
        assert "SecretBinary" not in blob


class TestMalformedRequests:
    def test_unknown_tool_rejected_before_port(self):
        script = [
            ModelTurn(tool_calls=[_call("c1", "wipe_everything", {})]),
            ModelTurn(final_answer=_final()),
        ]
        orch = AgentOrchestrator(
            FakeModelPort(script), FakeToolPort(_happy_handler),
            actor="test-actor", scenario_id="test-scenario",
            clock=_clock())
        result, events = orch.run("run-malformed-1")
        assert result.status is InvestigationStatus.COMPLETE
        assert orch._tools.invocations == []
        bad = [e for e in events
               if e.kind is AgentEventKind.TOOL_RESULT]
        assert bad and bad[0].payload["classification"] == \
            "validation_error"

    def test_non_mapping_arguments_rejected(self):
        from types import SimpleNamespace
        orch = AgentOrchestrator(
            FakeModelPort([]), FakeToolPort(_happy_handler),
            clock=_clock())
        probe = SimpleNamespace(tool_id="iam_get_user",
                                arguments=["not", "a", "mapping"])
        assert orch._check_call_shape(probe) == \
            "arguments must be a mapping"
        assert orch._check_call_shape(SimpleNamespace(
            tool_id="nope", arguments={})) == "unknown tool_id"

    def test_raw_port_exception_never_reaches_model(self):
        script = [
            ModelTurn(tool_calls=[_call("c1", "iam_get_user",
                                        {"UserName": PRINCIPAL})]),
            ModelTurn(final_answer=_final()),
        ]

        def handler(invocation):
            raise RuntimeError("boom SECRET=CANARY")

        model = FakeModelPort(script)
        orch = AgentOrchestrator(model, FakeToolPort(handler),
                                 actor="t", scenario_id="s",
                                 clock=_clock())
        result, events = orch.run("run-exc-1")
        assert result.status is InvestigationStatus.COMPLETE
        seen = model.contexts[-1].observations[0]
        assert seen.ok is False
        assert seen.safe_error == "tool port failure"
        assert "boom" not in repr(events) + repr(result)

    def test_controlled_port_error_is_safe(self):
        def handler(invocation):
            raise ToolPortError("backend is down")

        _, result, _ = _run(
            [ModelTurn(tool_calls=[_call("c1", "iam_get_user",
                                         {"UserName": PRINCIPAL})]),
             ModelTurn(final_answer=_final())],
            handler, run_id="run-toolport-err-1")
        assert result.status is InvestigationStatus.COMPLETE


class TestLoopLimits:
    def _repeater(self, tool_id, arguments, times):
        return [ModelTurn(tool_calls=[_call(f"c{i}", tool_id, arguments)])
                for i in range(times)]

    def test_identical_repeat_limit(self):
        script = self._repeater("iam_get_user", {"UserName": PRINCIPAL},
                                3) + [ModelTurn(final_answer=_final())]
        _, result, _ = _run(script, _happy_handler,
                            run_id="run-repeat-1")
        assert result.status is InvestigationStatus.LIMIT_REACHED
        assert result.stop_reason == "identical_request_repeat_limit"
        assert result.tool_call_count == 2

    def test_max_tool_calls(self):
        script = [
            ModelTurn(tool_calls=[_call("c1", "iam_get_user",
                                        {"UserName": "w1"})]),
            ModelTurn(tool_calls=[_call("c2", "iam_get_user",
                                        {"UserName": "w2"})]),
            ModelTurn(tool_calls=[_call("c3", "iam_get_user",
                                        {"UserName": "w3"})]),
            ModelTurn(final_answer=_final()),
        ]
        _, result, _ = _run(
            script, _happy_handler, run_id="run-budget-1",
            limits=AgentLimits(max_tool_calls=2))
        assert result.status is InvestigationStatus.LIMIT_REACHED
        assert result.stop_reason == "max_tool_calls_exceeded"
        assert result.tool_call_count == 2

    def test_max_turns(self):
        script = [ModelTurn(tool_calls=[_call(f"c{i}", "s3_list_objects",
                                               {"Bucket": f"b{i}"})])
                  for i in range(50)]
        _, result, _ = _run(script, _happy_handler, run_id="run-turns-1",
                            limits=AgentLimits(max_turns=3))
        assert result.status is InvestigationStatus.LIMIT_REACHED
        assert result.stop_reason == "max_turns_exceeded"
        assert result.model_turn_count == 3

    def test_missing_final_answer_terminates(self):
        script = [ModelTurn(tool_calls=[_call(f"c{i}", "iam_get_user",
                                               {"UserName": f"w{i}"})])
                  for i in range(50)]
        _, result, events = _run(script, _happy_handler,
                                 run_id="run-nofinal-1")
        assert result.status is InvestigationStatus.LIMIT_REACHED
        assert events[-1].kind is AgentEventKind.RUN_STOPPED

    def test_exhausted_script_is_incomplete_not_failed(self):
        _, result, events = _run(
            [ModelTurn(tool_calls=[_call("c1", "iam_get_user",
                                         {"UserName": PRINCIPAL})])],
            _happy_handler, run_id="run-exhaust-1")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert events[-1].kind is AgentEventKind.RUN_STOPPED

    def test_unexpected_model_error_is_failed(self):
        model = FakeModelPort([RuntimeError("provider exploded")])
        orch = AgentOrchestrator(model, FakeToolPort(_happy_handler),
                                 clock=_clock())
        result, events = orch.run("run-modelerr-1")
        assert result.status is InvestigationStatus.FAILED
        assert result.stop_reason == "model_error"


class TestFinalAnswerValidation:
    @pytest.mark.parametrize("mutate,code", [
        ({"findings": tuple(f"f{i}" for i in range(21))},
         "too_many_findings"),
        ({"evidence_refs": tuple(f"e{i}" for i in range(21))},
         "too_many_evidence_refs"),
        ({"rationale_summary": "x" * 501}, "oversized_rationale"),
        ({"recommended_action": None}, "missing_recommended_action"),
        ({"recommended_action": RecommendedAction(
            tool_id="wipe_everything", arguments={},
            reason="bad")}, "unknown_action_tool"),
        ({"recommended_action": RecommendedAction(
            tool_id="update_access_key", arguments={},
            reason="x" * 501)}, "oversized_action_reason"),
    ])
    def test_structural_rejection_only(self, mutate, code):
        answer = _final(**mutate)
        _, result, _ = _run([ModelTurn(final_answer=answer)],
                            _happy_handler,
                            run_id=f"run-final-{code}")
        assert result.status is InvestigationStatus.FAILED
        assert result.stop_reason == f"invalid_final_answer:{code}"
