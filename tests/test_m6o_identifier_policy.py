"""M6O identifier-type grounding guidance: pure tests, no network."""

import pytest

from cloudsec_agent.agent import grounding as gr
from cloudsec_agent.agent.model_port import ModelPort
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
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
        raise AssertionError("grounding tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


def _turn(*calls):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(tool_calls=list(calls))


def _call(call_id, tool_id, arguments):
    return AgentToolCall(call_id=call_id, tool_id=tool_id,
                         arguments=arguments)


def _final(principal, key_id):
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
            reason="guided"),
        rationale_summary="guided"))


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
        assert "Requests already flagged as" in adapter.SYSTEM_INSTRUCTION

    def test_identifier_type_policy(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "grounded only for the identifier type" in text
        assert "established by its source" in text

    def test_no_heuristic_rule(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "Do not strip suffixes or prefixes" in text
        assert "explicitly defines" in text

    def test_discovery_before_guessing(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "prefer an available discovery or listing mechanism" in text
        assert "do not fabricate" in text.lower()

    def test_documented_transform_allowed(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "documented ARN structure" in text

    def test_no_m1_hints(self):
        lowered = adapter.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "csi-", "akia",
                      "iam_list_users", "iam_list_access_keys",
                      "s3_list_objects", "logs_get_log_events"):
            assert token not in lowered, token
        assert "→" not in adapter.SYSTEM_INSTRUCTION


class TestDescriptionClarification:
    def _specs(self):
        return {spec.tool_id: spec for spec in rg.READ_ONLY_SPECS}

    def test_targeted_require_established_name(self):
        for tool_id in ("iam_get_user", "iam_list_access_keys",
                        "iam_get_user_policy", "iam_list_user_policies"):
            text = self._specs()[tool_id].description
            assert "established as such" in text
            assert "actor" in text.lower()

    def test_list_users_still_discovery(self):
        text = self._specs()["iam_list_users"].description
        assert "not yet known" in text
        assert "established as such" not in text


class TestTypedGrounding:
    def test_o1_typed_username(self):
        assert gr.classify_use("alice", [{"user_name": "alice"}],
                               "username") == gr.GroundingStatus.OBSERVED_TYPED

    def test_o2_actor_literal_reused(self):
        assert gr.classify_use("alice-session", [{"actor": "alice-session"}],
                               "username") == gr.GroundingStatus.LITERAL_ONLY

    def test_o3_suffix_strip_ungrounded(self):
        assert gr.classify_use("alice", [{"actor": "alice-session"}],
                               "username") == gr.GroundingStatus.UNGROUNDED

    def test_o4_access_key_typed(self):
        assert gr.classify_use("AKIA-X", [{"actor_access_key_id": "AKIA-X"}],
                               "access_key_id") == \
            gr.GroundingStatus.OBSERVED_TYPED

    def test_o5_documented_arn_allowed(self):
        observations = [{"user_name": "doc-user",
                         "derived_from": "user_arn per documented format"}]
        assert gr.classify_use("doc-user", observations,
                               "username") == gr.GroundingStatus.OBSERVED_TYPED

    def test_o6_heuristic_unsupported(self):
        observations = [{"user_arn": "arn:aws:iam::1:user/raw-user"}]
        assert gr.classify_use("raw-user", observations,
                               "username") in (
                                   gr.GroundingStatus.LITERAL_ONLY,
                                   gr.GroundingStatus.UNGROUNDED)

    def test_o7_same_literal_two_fields(self):
        observations = [{"actor": "sam"}, {"user_name": "sam"}]
        assert gr.classify_use("sam", observations,
                               "username") == gr.GroundingStatus.OBSERVED_TYPED

    def test_o8_s3_body_text_not_typed(self):
        observations = [{"body": "owner sam reported this"}]
        assert gr.classify_use("sam", observations,
                               "username") in (
                                   gr.GroundingStatus.LITERAL_ONLY,
                                   gr.GroundingStatus.UNGROUNDED)


class TestO9SafeDiscoveryPath:
    def test_listed_name_is_typed(self):
        USER = d.RESOURCES.incident_user
        responses = {
            "list_users": {"users": [{"user_name": USER}], "count": 1,
                           "truncated": False},
            "list_access_keys": {"user_name": USER, "access_keys": [],
                                 "count": 0, "truncated": False},
        }
        reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
        port = RealBackendToolPort(reads, run_scope="run-o9",
                                   actor="m6o", scenario_id="test-scenario")
        model = Scripted([
            _turn(_call("h0", "iam_list_users", {})),
            _turn(_call("h1", "iam_list_access_keys",
                       {"UserName": USER})),
            _final(USER, "AKIA-SYNTH-M6O-01")])
        orch = AgentOrchestrator(model, port)
        result, _ = orch.run("run-o9")
        assert result.status is InvestigationStatus.COMPLETE
        users = model.contexts[1].observations[0].data["users"]
        assert gr.classify_use(users[0]["user_name"],
                               [dict(users[0])],
                               "username") == gr.GroundingStatus.OBSERVED_TYPED


class TestO10UnsafeReuseUnchanged:
    def test_denied_request_still_flows(self):
        model = Scripted([
            _turn(_call("h0", "iam_get_user",
                       {"UserName": "actor-string-value"})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-o10")
        assert result.status is InvestigationStatus.COMPLETE

    def test_label_is_literal_only(self):
        observations = [{"actor": "actor-string-value"}]
        assert gr.classify_use("actor-string-value", observations,
                               "username") == gr.GroundingStatus.LITERAL_ONLY


class TestO11NoDiscoveryPath:
    def test_uncertain_terminal_without_fabrication(self):
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
        result, _ = orch.run("run-o11")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert "no_actionable_finding" in result.stop_reason
        assert result.recommended_action is None


class TestBenignRegression:
    def test_benign_finalization_still_permitted(self):
        assert "no action when the" in adapter.SYSTEM_INSTRUCTION.lower()
        assert "Use empty strings and null" in adapter.SYSTEM_INSTRUCTION
