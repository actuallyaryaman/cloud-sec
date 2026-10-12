"""M6A pure adapter tests. The Google SDK boundary is faked; no API calls."""

import json
import os
from types import SimpleNamespace

import pytest

from cloudsec_agent.agent.model_port import (ModelContext, ModelPort,
                                             ModelTurn)
from cloudsec_agent.agent.models import ToolObservation
from cloudsec_agent.backend.registry import READ_ONLY_SPECS
from cloudsec_agent.providers import gemini as g
from cloudsec_agent.providers.gemini import (DEFAULT_MODEL,
                                             SYSTEM_INSTRUCTION,
                                             GeminiModelPort,
                                             GeminiProviderError,
                                             build_investigation_text,
                                             build_tool_declarations,
                                             classify_provider_exception,
                                             resolve_model_name)


def _obs(call_id="c0", tool_id="s3_list_objects", data=None):
    return ToolObservation(call_id=call_id, request_id=f"r:{call_id}",
                           tool_id=tool_id, ok=True,
                           classification="success", data=dict(data or {}))


def _ctx(*observations, turn=1):
    return ModelContext(run_id="run-test", turn_number=turn,
                        observations=observations)


class FakeFunctionCall:
    def __init__(self, name, args=None, call_id=""):
        self.name = name
        self.args = args if args is not None else {}
        self.id = call_id


class FakePart:
    def __init__(self, text=None, function_call=None):
        self.text = text
        self.function_call = function_call


class FakeResponse:
    def __init__(self, parts, usage=None):
        self.candidates = [SimpleNamespace(
            content=SimpleNamespace(parts=list(parts)))]
        self.usage_metadata = usage


class FakeModels:
    def __init__(self, responses=None, error=None):
        self._responses = list(responses or [])
        self.error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if not self._responses:
            raise AssertionError("fake SDK script exhausted")
        return self._responses.pop(0)


def _port(models, **overrides):
    return GeminiModelPort(client=SimpleNamespace(models=models),
                           **overrides)


def _final_text(payload):
    return "```json\n" + json.dumps(payload) + "\n```"


def _answer_payload(**overrides):
    payload = {
        "compromised_principal": "some-user",
        "compromised_access_key_id": "AKIA-SYNTH-01",
        "confidence": 0.8,
        "findings": ["odd access"],
        "evidence_refs": ["run-test:req:0000"],
        "recommended_action": {
            "tool_id": "update_access_key",
            "arguments": {"UserName": "some-user",
                          "AccessKeyId": "AKIA-SYNTH-01",
                          "Status": "Inactive"},
            "reason": "disable the observed key"},
        "rationale_summary": "observed then contained"}
    payload.update(overrides)
    return payload


class TestRequestConversion:
    def test_context_converted_to_provider_request(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall(
                "s3_list_objects", {"Bucket": "b"}, "f1"))])])
        port = _port(models)
        turn = port.complete(_ctx(_obs(data={"keys": ["a"]})))
        assert len(models.calls) == 1
        request = models.calls[0]
        assert request["model"] == DEFAULT_MODEL
        assert request["contents"]
        assert request["config"].system_instruction == SYSTEM_INSTRUCTION
        assert turn.tool_calls[0].tool_id == "s3_list_objects"

    def test_observations_feed_provider_text(self):
        text = build_investigation_text(
            _ctx(_obs(call_id="c7", data={"keys": ["k1"]}), turn=3))
        assert "c7" in text and "s3_list_objects" in text and "k1" in text

    def test_system_instruction_has_no_m1_literals(self):
        lowered = SYSTEM_INSTRUCTION.lower()
        forbidden = ["incident-user", "security-agent-backend", "csi-",
                     "there is exactly one compromised",
                     "the attacker attempted to read a secret",
                     "disable the access key"]
        for token in forbidden:
            assert token not in lowered, token
        assert "AKIA" not in SYSTEM_INSTRUCTION


class TestToolDeclarations:
    def test_exposes_only_registry_reads(self):
        decls = build_tool_declarations()
        assert [decl["name"] for decl in decls] == \
            [spec.tool_id for spec in READ_ONLY_SPECS]
        assert len(decls) == 10

    def test_declaration_arguments_match_registry(self):
        specs = {spec.tool_id: spec for spec in READ_ONLY_SPECS}
        for decl in build_tool_declarations():
            spec = specs[decl["name"]]
            assert decl["required"] == list(spec.required_arguments)
            assert decl["optional"] == list(spec.optional_arguments)

    def test_no_secret_or_containment_declarations(self):
        names = [decl["name"] for decl in build_tool_declarations()]
        assert "get_secret_value" not in names
        assert "update_access_key" not in names


class TestTurnMapping:
    def test_function_call_to_agent_tool_call(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall(
                "iam_get_user", {"UserName": "u"}, "prov-1"))])])
        turn = _port(models).complete(_ctx())
        (call,) = turn.tool_calls
        assert call.call_id == "prov-1"
        assert call.tool_id == "iam_get_user"
        assert dict(call.arguments) == {"UserName": "u"}
        assert turn.is_final is False

    def test_multiple_ordered_function_calls(self):
        models = FakeModels([FakeResponse([
            FakePart(function_call=FakeFunctionCall("iam_get_user", {}, "")),
            FakePart(text="interim note"),
            FakePart(function_call=FakeFunctionCall(
                "iam_list_access_keys", {}, ""))])])
        turn = _port(models).complete(_ctx())
        assert [call.tool_id for call in turn.tool_calls] == \
            ["iam_get_user", "iam_list_access_keys"]
        assert turn.tool_calls[0].call_id != turn.tool_calls[1].call_id

    def test_final_structured_output_to_answer(self):
        models = FakeModels([FakeResponse(
            [FakePart(text=_final_text(_answer_payload()))])])
        turn = _port(models).complete(_ctx())
        assert turn.is_final is True
        answer = turn.final_answer
        assert answer.compromised_principal == "some-user"
        assert answer.recommended_action.tool_id == "update_access_key"
        assert dict(answer.recommended_action.arguments)["Status"] == \
            "Inactive"

    def test_benign_answer_is_safe_failure_not_accusation(self):
        payload = _answer_payload(compromised_principal="",
                                  compromised_access_key_id="",
                                  recommended_action=None)
        models = FakeModels([FakeResponse([FakePart(text=_final_text(payload))])])
        with pytest.raises(GeminiProviderError) as excinfo:
            _port(models).complete(_ctx())
        assert excinfo.value.code == "no_actionable_finding"

    def test_malformed_json_is_safe_failure(self):
        models = FakeModels([FakeResponse([FakePart(text="not json")])])
        with pytest.raises(GeminiProviderError) as excinfo:
            _port(models).complete(_ctx())
        assert excinfo.value.code == "invalid_response"
        assert "not json" not in str(excinfo.value)

    def test_unknown_function_is_safe_failure(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall(
                "get_secret_value", {"SecretId": "x"}))])])
        with pytest.raises(GeminiProviderError) as excinfo:
            _port(models).complete(_ctx())
        assert excinfo.value.code == "unknown_tool"

    def test_secret_recommendation_rejected(self):
        payload = _answer_payload()
        payload["recommended_action"] = {
            "tool_id": "get_secret_value",
            "arguments": {"SecretId": "x"}, "reason": "peek"}
        models = FakeModels([FakeResponse([FakePart(text=_final_text(payload))])])
        with pytest.raises(GeminiProviderError):
            _port(models).complete(_ctx())

    def test_active_status_recommendation_rejected(self):
        payload = _answer_payload()
        payload["recommended_action"]["arguments"] = dict(
            payload["recommended_action"]["arguments"], Status="Active")
        models = FakeModels([FakeResponse([FakePart(text=_final_text(payload))])])
        with pytest.raises(GeminiProviderError):
            _port(models).complete(_ctx())

    def test_invalid_arguments_pass_through_for_downstream(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall(
                "s3_list_objects", {"Bucket": 123}))])])
        turn = _port(models).complete(_ctx())
        assert dict(turn.tool_calls[0].arguments) == {"Bucket": 123}


class FakeStatusError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"status {status_code}")


class TestProviderErrors:
    def test_raw_exception_sanitized(self):
        models = FakeModels(error=RuntimeError("boom raw detail 12345"))
        with pytest.raises(GeminiProviderError) as excinfo:
            _port(models).complete(_ctx())
        assert excinfo.value.code == "provider_error"
        assert "boom" not in str(excinfo.value)

    def test_auth_failure_classification(self):
        assert classify_provider_exception(FakeStatusError(401)) == \
            "auth_error"

    def test_rate_limit_classification(self):
        assert classify_provider_exception(FakeStatusError(429)) == \
            "rate_limited"

    def test_timeout_classification(self):
        assert classify_provider_exception(TimeoutError("slow")) == \
            "timeout"

    def test_model_unavailable_classification(self):
        assert classify_provider_exception(FakeStatusError(404)) == \
            "model_unavailable"

    def test_no_api_key_in_errors(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "CANARY-KEY-VALUE-XYZ")
        models = FakeModels(error=FakeStatusError(401))
        with pytest.raises(GeminiProviderError) as excinfo:
            _port(models).complete(_ctx())
        assert "CANARY" not in str(excinfo.value)
        assert "CANARY" not in repr(excinfo.value)


class TestSafetyProperties:
    def test_no_hidden_reasoning_stored(self):
        usage = SimpleNamespace(prompt_token_count=10,
                                candidates_token_count=5,
                                total_token_count=15,
                                thinking="secret chain of thought")
        models = FakeModels([FakeResponse(
            [FakePart(text=_final_text(_answer_payload()))], usage=usage)])
        port = _port(models)
        turn = port.complete(_ctx())
        assert "secret chain" not in repr(turn)
        assert port.last_usage == {"input_tokens": 10, "output_tokens": 5,
                                   "total_tokens": 15}

    def test_metadata_does_not_leak_raw_payloads(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall("iam_get_user", {}))])])
        port = _port(models)
        port.complete(_ctx(_obs(data={"keys": ["k1"]})))
        assert port.last_usage == {}
        assert "k1" not in repr(port.last_usage)

    def test_automatic_function_execution_disabled(self):
        models = FakeModels([FakeResponse(
            [FakePart(function_call=FakeFunctionCall("iam_get_user", {}))])])
        _port(models).complete(_ctx())
        config = models.calls[0]["config"]
        assert config.automatic_function_calling.disable is True
        declared = [decl.name for tool in config.tools
                    for decl in tool.function_declarations]
        assert sorted(declared) == sorted(
            spec.tool_id for spec in READ_ONLY_SPECS)

    def test_no_backend_or_cloud_imports(self):
        import inspect
        source = inspect.getsource(g)
        for token in ("boto3", "floci", "Floci", "subprocess",
                      "BrokerGrant", "ContainmentExecutor",
                      "GEMINI_API_KEY", "get_secret_value"):
            assert token not in source, token

    def test_satisfies_model_port_contract(self):
        port = _port(FakeModels([FakeResponse(
            [FakePart(text=_final_text(_answer_payload()))])]))
        assert isinstance(port, ModelPort)
        turn = port.complete(_ctx())
        assert isinstance(turn, ModelTurn) and turn.is_final


class TestModelConfiguration:
    def test_model_name_configurable(self, monkeypatch):
        monkeypatch.setenv(g.MODEL_ENV_VAR, "gemini-env-model")
        assert resolve_model_name() == "gemini-env-model"
        assert GeminiModelPort().model_name == "gemini-env-model"
        assert GeminiModelPort(model="gemini-explicit").model_name == \
            "gemini-explicit"

    def test_default_model_is_m6a_default(self, monkeypatch):
        monkeypatch.delenv(g.MODEL_ENV_VAR, raising=False)
        assert DEFAULT_MODEL == "gemini-2.5-pro"
        assert resolve_model_name() == "gemini-2.5-pro"
        assert GeminiModelPort().model_name == "gemini-2.5-pro"

    def test_temperature_recorded(self):
        assert _port(FakeModels([]), temperature=0).temperature == 0.0

    def test_env_key_never_read_by_adapter(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "CANARY-KEY-VALUE-XYZ")
        models = FakeModels([FakeResponse(
            [FakePart(text=_final_text(_answer_payload()))])])
        _port(models).complete(_ctx())
        assert "CANARY" not in repr(models.calls)
