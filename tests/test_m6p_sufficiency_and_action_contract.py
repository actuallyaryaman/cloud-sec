"""M6P sufficiency + action-contract guidance: pure tests, no network."""

import pytest

from cloudsec_agent.agent import grounding as gr
from cloudsec_agent.agent import sufficiency as sf
from cloudsec_agent.agent.model_port import ModelPort
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.providers import kilo as adapter
from cloudsec_agent.scenario import determinism as d
from tests.agent_fakes import FakeToolPort, ok_result


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("sufficiency tests must not create clients")

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
        compromised_access_key_id=key_id, confidence=0.7,
        findings=("guided finding",),
        evidence_refs=("run:req:0",),
        recommended_action=RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": principal, "AccessKeyId": key_id,
                       "Status": "Inactive"},
            reason="guided") if action else None,
        rationale_summary="guided"))


def _action(tool_id="update_access_key", arguments=None):
    return RecommendedAction(tool_id=tool_id,
                             arguments=dict(arguments or {}),
                             reason="r")


class Scripted(ModelPort):
    def __init__(self, script):
        self._script = list(script)
        self.contexts = []

    def complete(self, context):
        self.contexts.append(context)
        return self._script.pop(0)


class TestPromptVersions:
    def test_new_version(self):
        assert adapter.PROMPT_VERSION == "m6p-kilo-sys-v1"
        assert adapter.ADAPTER_VERSION == "m6g-kilo-v1"

    def test_all_old_prompts_preserved(self):
        assert "must use them before concluding" in \
            adapter.SYSTEM_INSTRUCTION_M6G_V1
        assert "preserve budget for the final answer" in \
            adapter.SYSTEM_INSTRUCTION_M6I_V1
        assert "Tool calls exist only to gather evidence" in \
            adapter.SYSTEM_INSTRUCTION_M6J_V1
        assert "Requests already flagged as" in \
            adapter.SYSTEM_INSTRUCTION_M6K_V1
        assert "Requests already flagged as" in adapter.SYSTEM_INSTRUCTION

    def test_sufficiency_guidance(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "grounded in enough evidence" in text
        assert "continue investigating" in text
        assert "finalize with" in text
        assert "uncertainty or no action" in text

    def test_uncertainty_rule(self):
        assert "return null for the" in adapter.SYSTEM_INSTRUCTION
        assert "prose-shaped object" in adapter.SYSTEM_INSTRUCTION

    def test_action_contract_spelled(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert 'tool_id "update_access_key"' in text
        assert '"UserName", "AccessKeyId"' in text
        assert '"Inactive"' in text

    def test_no_m1_hints(self):
        lowered = adapter.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "csi-", "akia",
                      "iam_list_users", "iam_list_access_keys",
                      "s3_list_objects", "logs_get_log_events"):
            assert token not in lowered, token
        assert "→" not in adapter.SYSTEM_INSTRUCTION

    def test_no_numeric_threshold(self):
        import re
        assert not re.search(r"\b\d+ (tool calls|turns|reads)\b",
                            adapter.SYSTEM_INSTRUCTION)


class TestSufficiencyModel:
    USER_OBS = [{"user_name": "alice"},
                {"access_keys": [{"access_key_id": "AKIA-X"}]}]

    def test_p1_premature_action(self):
        action = _action(arguments={"UserName": "alice",
                                    "AccessKeyId": "AKIA-X",
                                    "Status": "Inactive"})
        assert sf.classify_final(action, [{"bucket": "b"}]) == \
            sf.SufficiencyStatus.PREMATURE_ACTIONABLE

    def test_p2_grounded_action(self):
        action = _action(arguments={"UserName": "alice",
                                    "AccessKeyId": "AKIA-X",
                                    "Status": "Inactive"})
        assert sf.classify_final(action, self.USER_OBS) == \
            sf.SufficiencyStatus.ACTIONABLE_SUFFICIENT

    def test_p3_safe_uncertain_final(self):
        assert sf.classify_final(None, [{"bucket": "b"}]) == \
            sf.SufficiencyStatus.NONACTIONABLE_SAFE

    def test_unknown_tool_is_unknown(self):
        action = _action(tool_id="something_else",
                         arguments={"UserName": "alice"})
        assert sf.classify_final(action, self.USER_OBS) == \
            sf.SufficiencyStatus.INSUFFICIENT_UNKNOWN


class TestActionContractStrict:
    def _adapter_final(self, payload):
        import json
        from types import SimpleNamespace

        class FakeCompletions:
            def create(self, **kwargs):
                text = "```json\n" + json.dumps(payload) + "\n```"
                message = SimpleNamespace(content=text, tool_calls=None)
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=message)], usage=None)

        return adapter.KiloModelPort(client=SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())))

    def _base(self, **overrides):
        payload = {"compromised_principal": "u",
                   "compromised_access_key_id": "k", "confidence": 0.7,
                   "findings": ["f"], "evidence_refs": ["r"],
                   "recommended_action": {
                       "tool_id": "update_access_key",
                       "arguments": {"UserName": "u", "AccessKeyId": "k",
                                     "Status": "Inactive"},
                       "reason": "r"},
                   "rationale_summary": "r"}
        payload.update(overrides)
        return payload

    def _code(self, payload):
        from cloudsec_agent.agent.model_port import ModelContext
        from cloudsec_agent.providers.kilo import KiloProviderError
        port = self._adapter_final(payload)
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(ModelContext(run_id="r", turn_number=1,
                                       observations=()))
        return excinfo.value.code

    def test_p4_malformed_action_rejected(self):
        payload = self._base()
        payload["recommended_action"] = {"tool_id": "update_access_key"}
        assert self._code(payload) == "final_action_schema_error"

    def test_p5_wrong_tool_rejected(self):
        payload = self._base()
        payload["recommended_action"]["tool_id"] = "disable_access_key"
        assert self._code(payload) == "final_action_schema_error"

    def test_p6_wrong_status_rejected(self):
        payload = self._base()
        payload["recommended_action"]["arguments"] = dict(
            payload["recommended_action"]["arguments"], Status="Active")
        assert self._code(payload) == "final_action_schema_error"

    def test_p7_non_string_reason_rejected(self):
        payload = self._base()
        payload["recommended_action"]["reason"] = 42
        assert self._code(payload) == "final_action_schema_error"

    def test_p8_missing_argument_rejected(self):
        payload = self._base()
        payload["recommended_action"]["arguments"] = {"UserName": "u"}
        assert self._code(payload) == "final_action_schema_error"

    def test_p9_exact_valid_action_accepted(self):
        from cloudsec_agent.agent.model_port import ModelContext
        port = self._adapter_final(self._base())
        turn = port.complete(ModelContext(run_id="r", turn_number=1,
                                          observations=()))
        assert turn.is_final is True
        assert turn.final_answer.recommended_action.tool_id == \
            "update_access_key"


class TestAntiOverfit:
    def test_p10_no_hints(self):
        lowered = adapter.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "csi-incident",
                      "iam_list_users", "s3_list_objects",
                      "logs_get_log_events", "iam_list_access_keys"):
            assert token not in lowered, token

    def test_p11_no_numeric_threshold(self):
        import re
        assert not re.search(r"after \d+ (tool|turn)", adapter.SYSTEM_INSTRUCTION,
                            re.IGNORECASE)

    def test_p13_discovery_optionality(self):
        assert "discovery" in adapter.SYSTEM_INSTRUCTION.lower()
        assert "listing mechanism" in adapter.SYSTEM_INSTRUCTION

    def test_p14_runtime_unchanged(self):
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": "b"})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-p14")
        assert result.status is InvestigationStatus.COMPLETE
        assert "PROMPT_VERSION" not in repr(result)


class TestP15ThinEvidenceAction:
    def test_premature_measured_no_execution(self):
        from cloudsec_agent.agent.models import RecommendedAction
        action = RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": "u", "AccessKeyId": "k",
                       "Status": "Inactive"},
            reason="thin")
        observations = [{"bucket": "b", "keys": ["k1"]}]
        assert sf.classify_final(action, observations) == \
            sf.SufficiencyStatus.PREMATURE_ACTIONABLE


class TestP16ThinEvidenceUncertain:
    def test_benign_terminal_without_fabrication(self):
        import json
        from types import SimpleNamespace
        payload = {"compromised_principal": "",
                   "compromised_access_key_id": "",
                   "confidence": 0.2, "findings": ["nothing conclusive"],
                   "evidence_refs": [],
                   "recommended_action": None,
                   "rationale_summary": "insufficient"}
        text = "```json\n" + json.dumps(payload) + "\n```"

        class FakeCompletions:
            def create(self, **kwargs):
                message = SimpleNamespace(content=text, tool_calls=None)
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=message)], usage=None)

        port = adapter.KiloModelPort(client=SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())))
        orch = AgentOrchestrator(
            port, FakeToolPort(lambda invocation: ok_result({})))
        result, _ = orch.run("run-p16")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert "no_actionable_finding" in result.stop_reason
        assert result.recommended_action is None


class TestP17DiscoveryThenAction:
    def test_typed_path_sufficient(self):
        USER = "synth-user"
        KEY = "AKIA-SYNTH-M6P-01"
        observations = [{"users": [{"user_name": USER}]},
                        {"user_name": USER,
                         "access_keys": [{"access_key_id": KEY}]}]
        action = RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": USER, "AccessKeyId": KEY,
                       "Status": "Inactive"},
            reason="guided")
        assert sf.classify_final(action, observations) == \
            sf.SufficiencyStatus.ACTIONABLE_SUFFICIENT
