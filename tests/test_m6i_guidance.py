"""M6I generic investigation guidance: pure tests, no network."""

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelPort
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import (AgentOrchestrator,
                                               REPEAT_WARNING)
from cloudsec_agent.agent.tool_port import KNOWN_TOOL_IDS
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.providers import kilo as adapter
from cloudsec_agent.scenario import determinism as d
from tests.agent_fakes import FakeModelPort, FakeToolPort, ok_result


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("guidance tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


def _turn(*calls):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(tool_calls=list(calls))


def _call(call_id, tool_id, arguments):
    return AgentToolCall(call_id=call_id, tool_id=tool_id,
                         arguments=arguments)


def _final(principal, key_id, confidence=0.6):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(final_answer=AgentFinalAnswer(
        compromised_principal=principal,
        compromised_access_key_id=key_id, confidence=confidence,
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


class TestRepeatWarning:
    def test_first_call_has_no_warning(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = FakeModelPort([_turn(call), _turn(call)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-w0")
        (first,) = model.contexts[1].observations
        assert first.repeat_count == 1
        assert first.next_identical_request_will_stop is False
        assert first.repeat_warning == ""

    def test_second_call_carries_warning(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = FakeModelPort([_turn(call), _turn(call),
                               _turn(call)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({"k": "v"})))
        orch.run("run-w1")
        second = model.contexts[2].observations[1]
        assert second.repeat_count == 2
        assert second.next_identical_request_will_stop is True
        assert second.repeat_warning == REPEAT_WARNING
        assert "already been repeated" in second.repeat_warning
        assert "terminate the investigation" in second.repeat_warning
        assert "final answer" in second.repeat_warning
        assert dict(second.data) == {"k": "v"}

    def test_warning_rendered_before_evidence(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = FakeModelPort([_turn(call), _turn(call),
                               _turn(call)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({"k": "v"})))
        orch.run("run-w2")
        text = adapter.build_investigation_text(model.contexts[2])
        assert "warning=" in text
        warned = [line for line in text.splitlines()
                  if "repeat_count=2" in line]
        assert len(warned) == 1
        assert warned[0].index("warning=") < warned[0].index("data=")
        assert "already been repeated" in text

    def test_warning_has_no_scenario_literals(self):
        lowered = REPEAT_WARNING.lower()
        for token in ("incident-user", "csi-", "akia", "log",
                      "iam", "bucket", "secret"):
            assert token not in lowered, token

    def test_no_warning_without_repeat(self):
        text = adapter.build_investigation_text(ModelContext(
            run_id="r", turn_number=1, observations=()))
        assert "warning=" not in text


class TestNewPrompt:
    PROMPT = adapter.SYSTEM_INSTRUCTION

    def test_version_bumped(self):
        assert adapter.PROMPT_VERSION == "m6i-kilo-sys-v1"
        assert adapter.ADAPTER_VERSION == "m6g-kilo-v1"

    def test_old_prompt_preserved(self):
        assert "must use them before concluding" in \
            adapter.SYSTEM_INSTRUCTION_M6G_V1
        assert "must use them before concluding" not in self.PROMPT

    def test_evidence_sufficiency(self):
        assert "do not" in self.PROMPT.lower()
        assert "exhaust every available function" in self.PROMPT

    def test_pivot_guidance(self):
        assert "change" in self.PROMPT.lower()
        assert "investigative direction" in self.PROMPT

    def test_repeat_guidance(self):
        assert "identical request" in self.PROMPT

    def test_finalization_guidance(self):
        assert "final answer once" in self.PROMPT.lower()
        assert "preserve budget" in self.PROMPT.lower()

    def test_uncertainty_guidance(self):
        assert "confidence" in self.PROMPT
        assert "do not invent identifiers" in self.PROMPT

    def test_no_m1_hints(self):
        lowered = self.PROMPT.lower()
        for token in ("incident-user", "csi-", "akia",
                      "iam_list_users", "logs_get_log_events",
                      "s3_list_objects"):
            assert token not in lowered, token

    def test_no_prescribed_sequence(self):
        assert "→" not in self.PROMPT
        assert "step 1" not in self.PROMPT.lower()


class TestToolDescriptions:
    def _descriptions(self):
        return {spec.tool_id: spec.description
                for spec in rg.tools_for_category(rg.Category.READ_ONLY)}

    def test_list_users_communicates_discovery(self):
        text = self._descriptions()["iam_list_users"]
        assert "numer" in text.lower() or "iscover" in text.lower()
        assert "not yet known" in text

    def test_targeted_tools_require_known_name(self):
        for tool_id in ("iam_get_user", "iam_list_access_keys",
                        "iam_get_user_policy", "iam_list_user_policies"):
            text = self._descriptions()[tool_id]
            assert "known" in text.lower()
            assert "user name" in text.lower()

    def test_evidence_tools_state_purpose(self):
        descriptions = self._descriptions()
        assert "bucket" in descriptions["s3_list_objects"].lower()
        assert "log" in descriptions["logs_get_log_events"].lower()
        assert "function" in \
            descriptions["lambda_get_function_configuration"].lower()

    def test_all_ten_distinct_and_generic(self):
        descriptions = self._descriptions()
        assert len(descriptions) == 10
        assert len(set(descriptions.values())) == 10
        blob = " ".join(descriptions.values()).lower()
        for token in ("incident-user", "csi-", "akia"):
            assert token not in blob, token

    def test_kilo_declarations_use_registry_text(self):
        decls = {tool["function"]["name"]: tool["function"]
                 for tool in adapter.build_function_tools()}
        specs = {spec.tool_id: spec for spec in rg.READ_ONLY_SPECS}
        for name, function in decls.items():
            assert function["description"] == specs[name].description


class TestR1WarningVisibility:
    def test_warning_present_before_next_decision(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = Scripted([_turn(call), _turn(call),
                          _turn(_call("c2", "iam_list_users", {})),
                          _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-r1")
        text = adapter.build_investigation_text(model.contexts[2])
        assert "already been repeated" in text
        assert result.status is InvestigationStatus.COMPLETE


class TestR2PivotAccepted:
    def test_domain_switch_needs_no_routing(self):
        model = Scripted([
            _turn(_call("c0", "logs_get_log_events",
                       {"logGroupName": "g", "logStreamName": "s"})),
            _turn(_call("c1", "iam_list_users", {})),
            _final("u", "k")])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-r2")
        assert result.status is InvestigationStatus.COMPLETE


class TestR3EarlyFinalization:
    def test_partial_evidence_final_accepted(self):
        model = Scripted([
            _turn(_call("c0", "s3_list_objects", {"Bucket": "b"})),
            _final("u", "k", confidence=0.35)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-r3")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.confidence == 0.35


USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
KEY = "AKIA-SYNTH-M6I-01"


def _responses():
    import json
    log_message = json.dumps({
        "id": "EV-003", "actor": f"{USER}-compromised-access-key",
        "actor_access_key_id": KEY, "operation": "s3:ListObjectsV2"})
    return {
        "list_users": {"users": [{"user_name": USER,
                                  "arn": "arn:aws:iam::000000000000:user/x"}],
                       "count": 1, "truncated": False},
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.notes_object],
                         "count": 1, "truncated": False},
        "get_object": {"bucket": BUCKET, "key": d.RESOURCES.notes_object,
                       "body": "notes", "size": 5, "truncated": False},
        "get_user": {"user_name": USER, "truncated": False},
        "list_access_keys": {"user_name": USER,
                             "access_keys": [{"access_key_id": KEY,
                                              "status": "Active"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": USER, "policy_names": [],
                               "count": 0, "truncated": False},
        "get_user_policy": {"user_name": USER, "policy_name": "p",
                            "policy_document": "{}", "truncated": False},
        "describe_secret": {"name": "s", "truncated": False},
        "get_function_configuration": {"function_name": "f",
                                       "truncated": False},
        "get_log_events": {"events": [{"message": log_message}],
                           "count": 1, "truncated": False},
    }


class TestR4FullGoodPath:
    def test_guided_path_proposes_action(self):
        from cloudsec_agent.agent.events import AgentEventKind
        reads = FakeReadPort(
            lambda method, kwargs: dict(_responses()[method]))
        port = RealBackendToolPort(reads, run_scope="run-r4",
                                   actor="m6i", scenario_id="test-scenario")
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": BUCKET})),
            _turn(_call("h1", "logs_get_log_events",
                       {"logGroupName": GROUP, "logStreamName": STREAM})),
            _turn(_call("h2", "iam_list_users", {})),
            _turn(_call("h3", "iam_list_access_keys",
                       {"UserName": USER})),
            _final(USER, KEY, confidence=0.8)])
        orch = AgentOrchestrator(model, port)
        result, events = orch.run("run-r4")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == USER
        assert result.compromised_access_key_id == KEY
        assert dict(result.recommended_action.arguments)["Status"] == \
            "Inactive"
        assert AgentEventKind.ACTION_PROPOSED in [
            event.kind for event in events]
        assert all(method not in ("update_access_key", "get_secret_value")
                   for method, _ in reads.calls)
