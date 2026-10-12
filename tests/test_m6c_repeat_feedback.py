"""M6C Track B: deterministic repetition feedback. Pure tests, no provider."""

import json

import pytest

from cloudsec_agent.agent.model_port import ModelPort, ModelTurn
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentLimits,
                                         AgentToolCall, InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.providers import gemini as adapter
from tests.agent_fakes import FakeModelPort, FakeToolPort, ok_result
from tests.m6c_fakes import (SYNTH_GROUP, SYNTH_STREAM, SYNTH_KEY,
                             block_genai_client, neutral_briefing,
                             synthetic_responses)


@pytest.fixture(autouse=True)
def _no_provider_clients(monkeypatch):
    block_genai_client(monkeypatch)


LOGS = {"logGroupName": SYNTH_GROUP, "logStreamName": SYNTH_STREAM}


def _logs_call(call_id):
    return AgentToolCall(call_id=call_id, tool_id="logs_get_log_events",
                         arguments=dict(LOGS))


def _run(script, run_id="run-m6c-b", limits=None):
    model = FakeModelPort(script)
    tools = FakeToolPort(lambda invocation: ok_result({"echo": True}))
    orch = AgentOrchestrator(model, tools, limits=limits or AgentLimits())
    result, events = orch.run(run_id)
    return result, events, model, tools


class TestRepeatMetadata:
    def test_first_call_metadata(self):
        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[_logs_call("c1")])]
        result, _, model, _ = _run(script, run_id="run-b1")
        assert result.tool_call_count == 2
        (obs,) = model.contexts[1].observations
        assert obs.repeat_count == 1
        assert obs.next_identical_request_will_stop is False

    def test_second_call_metadata(self):
        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[_logs_call("c1")]),
                  ModelTurn(tool_calls=[_logs_call("c2")])]
        _, _, model, _ = _run(script, run_id="run-b2")
        second = model.contexts[2].observations[1]
        assert second.repeat_count == 2
        assert second.next_identical_request_will_stop is True

    def test_third_call_terminates_without_execution(self):
        script = [ModelTurn(tool_calls=[_logs_call(f"c{i}")])
                  for i in range(3)]
        result, events, _, tools = _run(script, run_id="run-b3")
        assert result.status is InvestigationStatus.LIMIT_REACHED
        assert result.stop_reason == "identical_request_repeat_limit"
        assert result.tool_call_count == 2
        assert len(tools.invocations) == 2
        requested = [event for event in events
                     if event.kind.value == "TOOL_REQUESTED"]
        assert len(requested) == 2

    def test_tool_port_count_matches_old_semantics(self):
        script = [ModelTurn(tool_calls=[_logs_call(f"c{i}")])
                  for i in range(3)]
        result, _, _, tools = _run(script, run_id="run-b4")
        assert len(tools.invocations) == result.tool_call_count == 2

    def test_different_arguments_tracked_separately(self):
        other = dict(LOGS, logStreamName="other-stream")
        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[AgentToolCall(
                      call_id="c1", tool_id="logs_get_log_events",
                      arguments=other)]),
                  ModelTurn(tool_calls=[_logs_call("c2")])]
        result, _, model, _ = _run(script, run_id="run-b5")
        assert result.tool_call_count == 3
        counts = [obs.repeat_count
                  for obs in model.contexts[3].observations]
        assert counts == [1, 1, 2]

    def test_call_id_does_not_change_identity(self):
        script = [ModelTurn(tool_calls=[_logs_call("same")]),
                  ModelTurn(tool_calls=[_logs_call("different")]),
                  ModelTurn(tool_calls=[_logs_call("third")])]
        _, _, model, _ = _run(script, run_id="run-b6")
        assert model.contexts[2].observations[1].repeat_count == 2

    def test_tool_id_distinguishes_keys(self):
        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[AgentToolCall(
                      call_id="c1", tool_id="s3_list_objects",
                      arguments=dict(LOGS))]),
                  ModelTurn(tool_calls=[_logs_call("c2")])]
        result, _, model, _ = _run(script, run_id="run-b7")
        assert result.tool_call_count == 3
        assert model.contexts[2].observations[1].repeat_count == 1


class TestAuditAndAuthNonImpact:
    def test_backend_audits_carry_no_repeat_state(self):
        from cloudsec_agent.scenario import determinism as d
        responses = synthetic_responses()
        reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
        port = RealBackendToolPort(reads, run_scope="run-b8",
                                   actor="m6c-b",
                                   scenario_id="test-scenario")
        granted = AgentToolCall(
            call_id="g", tool_id="logs_get_log_events",
            arguments={"logGroupName": d.RESOURCES.log_group,
                       "logStreamName": d.RESOURCES.log_stream})
        script = [ModelTurn(tool_calls=[AgentToolCall(
            call_id="g0", tool_id="logs_get_log_events",
            arguments=dict(granted.arguments))]),
            ModelTurn(tool_calls=[AgentToolCall(
                call_id="g1", tool_id="logs_get_log_events",
                arguments=dict(granted.arguments))])]
        orch = AgentOrchestrator(FakeModelPort(script), port)
        orch.run("run-b8")
        assert len(port.audits) == 6
        assert "repeat" not in repr(
            [record.as_dict() for record in port.audits]).lower()

    def test_repeat_state_never_reaches_backend_request(self):
        seen = []

        def handler(invocation):
            seen.append(invocation)
            return ok_result({})

        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[_logs_call("c1")])]
        model_tools = FakeToolPort(handler)
        orch = AgentOrchestrator(FakeModelPort(script), model_tools)
        orch.run("run-b9b")
        assert len(model_tools.invocations) == 2
        for invocation in model_tools.invocations:
            assert "repeat_count" not in dict(invocation.arguments)
            assert "next_identical_request_will_stop" not in dict(
                invocation.arguments)

    def test_repeated_denial_keeps_classification(self):
        responses = synthetic_responses()
        reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
        port = RealBackendToolPort(reads, run_scope="run-b10",
                                   actor="m6c-b",
                                   scenario_id="test-scenario")
        bad = AgentToolCall(call_id="x", tool_id="iam_get_user",
                            arguments={"UserName": "unknown-name"})
        script = [ModelTurn(tool_calls=[bad]),
                  ModelTurn(tool_calls=[AgentToolCall(
                      call_id="y", tool_id="iam_get_user",
                      arguments={"UserName": "unknown-name"})])]
        model = FakeModelPort(script)
        orch = AgentOrchestrator(model, port)
        _, _ = orch.run("run-b10")
        assert [obs.classification
                for obs in model.contexts[2].observations] == \
            ["broker_denied", "broker_denied"]


class TestModelVisibleForm:
    def test_context_text_carries_repeat_state(self):
        script = [ModelTurn(tool_calls=[_logs_call("c0")]),
                  ModelTurn(tool_calls=[_logs_call("c1")]),
                  ModelTurn(tool_calls=[_logs_call("c2")])]
        _, _, model, _ = _run(script, run_id="run-b11")
        text = adapter.build_investigation_text(model.contexts[2])
        assert "repeat_count=2" in text
        assert "next_identical_request_will_stop=True" in text

    def test_prompt_unchanged_by_feedback(self):
        assert "repeat" not in adapter.SYSTEM_INSTRUCTION


class RecoveringProvider(ModelPort):
    def complete(self, context):
        observations = context.observations
        if observations:
            last = observations[-1]
            if last.next_identical_request_will_stop:
                return ModelTurn(tool_calls=[AgentToolCall(
                    call_id="switch", tool_id="s3_list_objects",
                    arguments={"Bucket": "synth-neutral-bucket"})])
        if len(observations) >= 2:
            return ModelTurn(final_answer=AgentFinalAnswer(
                compromised_principal="analytics-worker",
                compromised_access_key_id=SYNTH_KEY, confidence=0.5,
                findings=("recovered after warning",),
                evidence_refs=(observations[0].request_id,),
                recommended_action=RecommendedAction(
                    tool_id="update_access_key",
                    arguments={"UserName": "analytics-worker",
                               "AccessKeyId": SYNTH_KEY,
                               "Status": "Inactive"},
                    reason="m6c track-b test"),
                rationale_summary="recovered"))
        return ModelTurn(tool_calls=[AgentToolCall(
            call_id=f"r{len(observations)}",
            tool_id="logs_get_log_events", arguments=dict(LOGS))])


class TestTrackBOnly:
    def test_warning_diverts_before_fatal_repeat(self):
        tools = FakeToolPort(lambda invocation: ok_result({"echo": True}))
        orch = AgentOrchestrator(RecoveringProvider(), tools)
        result, _ = orch.run("run-b12")
        assert result.status is InvestigationStatus.COMPLETE
        assert [invocation.tool_id
                for invocation in tools.invocations] == [
            "logs_get_log_events", "logs_get_log_events",
            "s3_list_objects"]


class TestBothTracks:
    def test_neutral_briefing_repeat_recovery_completes(self):
        from cloudsec_agent.scenario import determinism as d
        from tests.m6c_fakes import LeadFreeModel
        user = d.RESOURCES.incident_user
        group = d.RESOURCES.log_group
        stream = d.RESOURCES.log_stream
        responses = synthetic_responses(user=user)
        briefing = neutral_briefing()
        assert user not in briefing
        reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
        port = RealBackendToolPort(reads, run_scope="run-m6c-both",
                                   actor="m6c-both",
                                   scenario_id="test-scenario")

        class BothModel(LeadFreeModel):
            def complete(self, context):
                keys_call = {"UserName": user}
                if len(context.observations) == 2:
                    last = context.observations[-1]
                    assert last.repeat_count == 1
                    assert last.next_identical_request_will_stop is False
                    return ModelTurn(tool_calls=[AgentToolCall(
                        call_id="first-keys", tool_id="iam_list_access_keys",
                        arguments=dict(keys_call))])
                if len(context.observations) == 3:
                    last = context.observations[-1]
                    assert last.repeat_count == 1
                    return ModelTurn(tool_calls=[AgentToolCall(
                        call_id="repeat-keys",
                        tool_id="iam_list_access_keys",
                        arguments=dict(keys_call))])
                if len(context.observations) == 4:
                    last = context.observations[-1]
                    assert last.repeat_count == 2
                    assert last.next_identical_request_will_stop is True
                    return ModelTurn(tool_calls=[AgentToolCall(
                        call_id="rec", tool_id="logs_get_log_events",
                        arguments={"logGroupName": group,
                                   "logStreamName": stream})])
                return super().complete(context)

        orch = AgentOrchestrator(BothModel(briefing, group, stream), port)
        result, events = orch.run("run-m6c-both")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == user
        assert result.compromised_access_key_id == SYNTH_KEY
        assert dict(result.recommended_action.arguments)["Status"] == \
            "Inactive"
        methods = [method for method, _ in reads.calls]
        assert "list_users" in methods
        assert "update_access_key" not in methods
        assert "get_secret_value" not in methods
        blob = repr(result) + repr([event.as_dict() for event in events])
        for token in ("SecretString", "SecretBinary", "SecretAccessKey",
                      "SessionToken"):
            assert token not in blob
