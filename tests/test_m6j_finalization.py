"""M6J finalization guidance: pure tests, no network."""

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelPort
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.providers import kilo as adapter
from tests.agent_fakes import FakeModelPort, FakeToolPort, ok_result


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("finalization tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


def _turn(*calls):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(tool_calls=list(calls))


def _call(call_id, tool_id, arguments):
    return AgentToolCall(call_id=call_id, tool_id=tool_id,
                         arguments=arguments)


def _final(principal, key_id, action=True):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(final_answer=AgentFinalAnswer(
        compromised_principal=principal,
        compromised_access_key_id=key_id, confidence=0.6,
        findings=("guided finding",),
        evidence_refs=("run:req:0",),
        recommended_action=RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": principal, "AccessKeyId": key_id,
                       "Status": "Inactive"},
            reason="guided") if action else None,
        rationale_summary="guided"))


class TestPromptVersions:
    def test_new_version(self):
        assert adapter.PROMPT_VERSION == "m6j-kilo-sys-v1"
        assert adapter.ADAPTER_VERSION == "m6g-kilo-v1"

    def test_previous_prompts_preserved(self):
        assert "must use them before concluding" in \
            adapter.SYSTEM_INSTRUCTION_M6G_V1
        assert "preserve budget for the final answer" in \
            adapter.SYSTEM_INSTRUCTION_M6I_V1
        assert "Tool calls exist only to gather evidence" in \
            adapter.SYSTEM_INSTRUCTION
        assert "must use them before concluding" not in \
            adapter.SYSTEM_INSTRUCTION

    def test_m6i_preserved(self):
        assert "preserve budget for the final answer" in \
            adapter.SYSTEM_INSTRUCTION_M6I_V1
        assert "Tool calls exist only to gather evidence" not in \
            adapter.SYSTEM_INSTRUCTION_M6I_V1

    def test_tool_use_not_goal(self):
        assert "Tool calls exist only to gather evidence" in \
            adapter.SYSTEM_INSTRUCTION

    def test_sufficient_evidence(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "relevant principal" in text
        assert "materially change the recommendation" in text

    def test_diminishing_returns(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "unlikely to materially change" in text
        assert "finalize instead" in text

    def test_uncertainty_allowed(self):
        assert "Perfect certainty is not required" in \
            adapter.SYSTEM_INSTRUCTION

    def test_budget_concepts(self):
        assert "finite turn and tool budget" in adapter.SYSTEM_INSTRUCTION
        assert "Reserve enough" in adapter.SYSTEM_INSTRUCTION

    def test_no_m1_hints(self):
        lowered = adapter.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "csi-", "akia",
                      "iam_list_users", "iam_list_access_keys",
                      "s3_list_objects", "logs_get_log_events"):
            assert token not in lowered, token
        assert "→" not in adapter.SYSTEM_INSTRUCTION


class TestBudgetMetadata:
    def test_initial_state(self):
        model = FakeModelPort([_turn(_call("c0", "s3_list_objects",
                                           {"Bucket": "b"}))])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-b0")
        context = model.contexts[0]
        assert context.turns_used == 0
        assert context.tool_calls_used == 0
        assert context.turns_remaining == 19
        assert context.tool_calls_remaining == 30
        assert context.budget_warning == ""

    def test_mid_run_state(self):
        calls = [_turn(_call(f"c{i}", "s3_list_objects", {"Bucket": "b"}))
                 for i in range(3)]
        model = FakeModelPort(calls)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-b1")
        context = model.contexts[2]
        assert context.turns_used == 2
        assert context.tool_calls_used == 2
        assert context.turns_remaining == 17
        assert context.tool_calls_remaining == 28
        assert context.budget_warning == ""

    def test_near_budget_warning(self):
        from cloudsec_agent.agent.models import AgentLimits
        calls = [_turn(_call(f"c{i}", "s3_list_objects",
                                {"Bucket": f"b{i}"}))
                 for i in range(19)]
        model = FakeModelPort(calls)
        orch = AgentOrchestrator(
            model, FakeToolPort(lambda invocation: ok_result({})),
            limits=AgentLimits(max_turns=20, max_tool_calls=30))
        orch.run("run-b2")
        late = model.contexts[17]
        assert late.turns_remaining == 2
        assert "nearly exhausted" in late.budget_warning
        assert "final answer now" in late.budget_warning
        assert "materially change the conclusion" in late.budget_warning

    def test_warning_rendered_to_model(self):
        from cloudsec_agent.agent.models import AgentLimits
        calls = [_turn(_call(f"c{i}", "s3_list_objects",
                                {"Bucket": f"b{i}"}))
                 for i in range(19)]
        model = FakeModelPort(calls)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})),
            limits=AgentLimits(max_turns=20, max_tool_calls=30))
        orch.run("run-b3")
        text = adapter.build_investigation_text(model.contexts[17])
        assert "Budget warning:" in text
        assert "Budget: 17 turns used (2 remaining)" in text

    def test_repeat_warning_still_works(self):
        from cloudsec_agent.agent.orchestrator import REPEAT_WARNING
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = FakeModelPort([_turn(call), _turn(call),
                               _turn(call)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-b4")
        assert model.contexts[2].observations[1].repeat_warning == \
            REPEAT_WARNING


class Scripted(ModelPort):
    def __init__(self, script):
        self._script = list(script)
        self.contexts = []

    def complete(self, context):
        self.contexts.append(context)
        return self._script.pop(0)


class TestJ1EarlyStage:
    def test_useful_evidence_continues(self):
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": "b"})),
            _turn(_call("h1", "iam_list_users", {})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-j1")
        assert result.status is InvestigationStatus.COMPLETE


class TestJ2GroundedAmpleBudget:
    def test_final_accepted_without_more_tools(self):
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": "b"})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-j2")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.tool_call_count == 1


class TestJ3LowBudgetFinal:
    def test_warning_then_final_completes(self):
        from cloudsec_agent.agent.models import AgentLimits
        script = [_turn(_call(f"c{i}", "s3_list_objects",
                                {"Bucket": f"b{i}"}))
                  for i in range(17)]
        script.append(_final("u", "k"))
        model = Scripted(script)
        orch = AgentOrchestrator(
            model, FakeToolPort(lambda invocation: ok_result({})),
            limits=AgentLimits(max_turns=20, max_tool_calls=30))
        result, _ = orch.run("run-j3")
        assert result.status is InvestigationStatus.COMPLETE
        assert model.contexts[17].budget_warning != ""


class TestJ4WarningIsGuidance:
    def test_necessary_read_still_allowed(self):
        from cloudsec_agent.agent.models import AgentLimits
        script = [_turn(_call(f"c{i}", "s3_list_objects",
                                {"Bucket": f"b{i}"}))
                  for i in range(17)]
        script.append(_turn(_call("c17", "iam_list_users", {})))
        script.append(_final("u", "k"))
        model = Scripted(script)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})),
            limits=AgentLimits(max_turns=20, max_tool_calls=30))
        result, _ = orch.run("run-j4")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.tool_call_count == 18


class TestJ5FullPath:
    def test_guided_path_proposes_action(self):
        from cloudsec_agent.agent.events import AgentEventKind
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": "b"})),
            _turn(_call("h1", "iam_list_users", {})),
            _turn(_call("h2", "iam_list_access_keys",
                       {"UserName": "u"})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, events = orch.run("run-j5")
        assert result.status is InvestigationStatus.COMPLETE
        assert dict(result.recommended_action.arguments)["Status"] == \
            "Inactive"
        assert AgentEventKind.ACTION_PROPOSED in [
            event.kind for event in events]


class TestJ6BenignFinal:
    def test_uncertain_no_action_terminates_without_forcing(self):
        import json
        from types import SimpleNamespace

        class FakeCompletions:
            def __init__(self, text):
                self._text = text

            def create(self, **kwargs):
                part = SimpleNamespace(text=self._text, function_call=None)
                content = SimpleNamespace(parts=[part])
                del content, part
                message = SimpleNamespace(content=self._text,
                                          tool_calls=None)
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=message)],
                    usage=None)

        payload = {"compromised_principal": "",
                   "compromised_access_key_id": "",
                   "confidence": 0.2, "findings": ["nothing conclusive"],
                   "evidence_refs": [],
                   "recommended_action": None,
                   "rationale_summary": "insufficient evidence"}
        text = "```json\n" + json.dumps(payload) + "\n```"

        from cloudsec_agent.providers.kilo import KiloModelPort
        port = KiloModelPort(client=SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions(text))))
        orch = AgentOrchestrator(
            port, FakeToolPort(lambda invocation: ok_result({})))
        result, _ = orch.run("run-j6")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert "no_actionable_finding" in result.stop_reason
        assert result.recommended_action is None
