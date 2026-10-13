"""M6G Kilo adapter pure tests. OpenAI boundary is faked; no network."""

import json
import os

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelPort
from cloudsec_agent.agent.models import ToolObservation
from cloudsec_agent.backend.registry import READ_ONLY_SPECS
from cloudsec_agent.providers import kilo as k
from cloudsec_agent.providers.kilo import (KiloModelPort, KiloProviderError,
                                           build_function_tools,
                                           build_investigation_text,
                                           classify_kilo_exception,
                                           describe_kilo_exception,
                                           resolve_kilo_model)

CANARY = "CANARY-KILO-KEY-XYZ"


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("kilo tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


class FakeFunction:
    def __init__(self, name, arguments="{}", ):
        self.name = name
        self.arguments = arguments


class FakeToolCall:
    def __init__(self, name, arguments="{}", call_id=""):
        self.id = call_id
        self.function = FakeFunction(name, arguments)


class FakeMessage:
    def __init__(self, content=None, tool_calls=None, reasoning=None):
        self.content = content
        self.tool_calls = tool_calls
        if reasoning is not None:
            self.reasoning_content = reasoning


class FakeResponse:
    def __init__(self, message, usage=None):
        self.choices = [FakeChoice(message)]
        self.usage = usage


class FakeChoice:
    def __init__(self, message):
        self.message = message


class FakeUsage:
    def __init__(self, prompt=0, completion=0, total=0):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.total_tokens = total


class FakeCompletions:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.chat = FakeChat(responses)


class FakeChat:
    def __init__(self, responses):
        self.completions = FakeCompletions(responses)


def _port(responses, **overrides):
    return KiloModelPort(client=FakeClient(responses), **overrides)


def _ctx(*observations, turn=1):
    return ModelContext(run_id="run-kilo", turn_number=turn,
                        observations=observations)


def _obs(call_id="c0", tool_id="s3_list_objects", data=None):
    return ToolObservation(call_id=call_id, request_id=f"r:{call_id}",
                           tool_id=tool_id, ok=True,
                           classification="success", data=dict(data or {}))


def _answer(**overrides):
    payload = {
        "compromised_principal": "synth-user",
        "compromised_access_key_id": "AKIA-SYNTH-KILO-01",
        "confidence": 0.8,
        "findings": ["odd access"],
        "evidence_refs": ["run:req:0000"],
        "recommended_action": {
            "tool_id": "update_access_key",
            "arguments": {"UserName": "synth-user",
                          "AccessKeyId": "AKIA-SYNTH-KILO-01",
                          "Status": "Inactive"},
            "reason": "disable the observed key"},
        "rationale_summary": "observed then concluded"}
    payload.update(overrides)
    return payload


def _final(*parts):
    return FakeResponse(FakeMessage(
        content="".join(parts) if parts else None))


def _call_turn(*calls):
    made = []
    for name, arguments, call_id in calls:
        made.append(FakeToolCall(name, arguments, call_id))
    return FakeResponse(FakeMessage(tool_calls=made))


class FakeOpenAIError(Exception):
    def __init__(self, status_code=None, code=None, type_=None):
        self.status_code = status_code
        self.code = code
        self.type = type_
        self.message = f"failed {CANARY}"
        super().__init__(f"{status_code} {CANARY}")


class TestConfiguration:
    def test_kilo_env_wins(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CLOUDSEC_KILO_MODEL", "kilo-env-model")
        assert resolve_kilo_model() == "kilo-env-model"

    def test_gemini_env_ignored(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CLOUDSEC_GEMINI_MODEL", "gemini-env-model")
        monkeypatch.delenv("CLOUDSEC_KILO_MODEL", raising=False)
        assert resolve_kilo_model() == k.DEFAULT_MODEL

    def test_default_model_is_kilo_default(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CLOUDSEC_KILO_MODEL", raising=False)
        monkeypatch.delenv("CLOUDSEC_GEMINI_MODEL", raising=False)
        assert k.DEFAULT_MODEL == \
            "nvidia/nemotron-3-ultra-550b-a55b:free"
        assert resolve_kilo_model() == k.DEFAULT_MODEL

    def test_missing_key_is_auth_error(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("KILO_API_KEY", raising=False)
        port = KiloModelPort()
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(_ctx())
        assert excinfo.value.code == "auth_error"

    def test_satisfies_model_port(self):
        assert isinstance(_port([_final(json.dumps(_answer()))]),
                          ModelPort)


class TestSecrets:
    def test_key_never_in_output(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("KILO_API_KEY", CANARY)
        port = self._raising_port(FakeOpenAIError(status_code=500))
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(_ctx())
        assert CANARY not in str(excinfo.value)
        assert CANARY not in repr(excinfo.value.info)

    @staticmethod
    def _raising_port(exc):
        class Raising:
            def __init__(self):
                self.chat = self

            @property
            def completions(self):
                outer = self

                class _Create:
                    def create(self, **kwargs):
                        raise exc
                return _Create()
        return KiloModelPort(client=Raising())


class TestRequestTranslation:
    def test_system_and_user_messages(self):
        port = _port([_final(json.dumps(_answer()))],
                     case_briefing="Review bucket b.")
        port.complete(_ctx(_obs(data={"keys": ["k1"]})))
        assert port._client.chat.completions.calls
        request = port._client.chat.completions.calls[0]
        roles = [message["role"] for message in request["messages"]]
        assert roles[0] == "system"
        assert roles[1] == "user"
        assert "untrusted evidence" in request["messages"][0]["content"]
        assert "Review bucket b." in request["messages"][1]["content"]
        assert "k1" in request["messages"][1]["content"]

    def test_all_ten_tools_declared(self):
        tools = build_function_tools()
        assert len(tools) == 10
        assert [tool["function"]["name"] for tool in tools] == \
            [spec.tool_id for spec in READ_ONLY_SPECS]
        for tool in tools:
            assert tool["type"] == "function"
            assert tool["function"]["parameters"]["type"] == "object"

    def test_zero_arg_list_users_shape(self):
        tools = {tool["function"]["name"]: tool
                 for tool in build_function_tools()}
        schema = tools["iam_list_users"]["function"]["parameters"]
        assert schema["properties"] == {}
        assert schema["required"] == []

    def test_required_args_preserved(self):
        tools = {tool["function"]["name"]: tool
                 for tool in build_function_tools()}
        schema = tools["s3_get_object"]["function"]["parameters"]
        assert sorted(schema["required"]) == ["Bucket", "Key"]

    def test_no_backend_or_state_changing_tools(self):
        names = [tool["function"]["name"]
                 for tool in build_function_tools()]
        assert "get_secret_value" not in names
        assert "update_access_key" not in names

    def test_no_backend_imports(self):
        import inspect
        source = inspect.getsource(k)
        for token in ("boto3", "floci", "Floci", "subprocess",
                      "BrokerGrant", "ContainmentExecutor",
                      "KILO_API_KEY", "GEMINI_API_KEY", "get_secret_value"):
            assert token not in source, token

    def test_system_prompt_has_no_m1_literals(self):
        lowered = k.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "security-agent-backend", "csi-",
                      "there is exactly one compromised",
                      "the attacker attempted to read a secret",
                      "disable the access key"):
            assert token not in lowered, token
        assert "AKIA" not in k.SYSTEM_INSTRUCTION

    def test_no_callables_sent(self):
        port = _port([_final(json.dumps(_answer()))])
        port.complete(_ctx())
        request = port._client.chat.completions.calls[0]
        blob = repr(request["tools"])
        assert "object at 0x" not in blob


class TestResponseTranslation:
    def test_single_tool_call(self):
        port = _port([_call_turn(
            ("iam_get_user", '{"UserName": "u"}', "call-1"))])
        turn = port.complete(_ctx())
        (call,) = turn.tool_calls
        assert call.call_id == "call-1"
        assert call.tool_id == "iam_get_user"
        assert dict(call.arguments) == {"UserName": "u"}

    def test_multiple_ordered_tool_calls(self):
        port = _port([_call_turn(
            ("iam_list_users", "{}", ""),
            ("s3_list_objects", '{"Bucket": "b"}', ""))])
        turn = port.complete(_ctx())
        assert [call.tool_id for call in turn.tool_calls] == \
            ["iam_list_users", "s3_list_objects"]
        assert turn.tool_calls[0].call_id != turn.tool_calls[1].call_id

    def test_malformed_arguments_rejected(self):
        port = _port([_call_turn(("iam_get_user", "{oops", "c"))])
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(_ctx())
        assert excinfo.value.code == "invalid_response"

    def test_unknown_tool_rejected(self):
        port = _port([_call_turn(("get_secret_value", "{}", "c"))])
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(_ctx())
        assert excinfo.value.code == "unknown_tool"

    def test_valid_final_answer(self):
        turn = _port([_final("```json\n" + json.dumps(_answer()) +
                             "\n```")]).complete(_ctx())
        assert turn.is_final is True
        assert turn.final_answer.compromised_principal == "synth-user"
        assert turn.final_answer.recommended_action.tool_id == \
            "update_access_key"

    def test_prose_wrapped_final_accepted(self):
        text = "Done:\n" + json.dumps(_answer()) + "\nEnd."
        turn = _port([_final(text)]).complete(_ctx())
        assert turn.is_final is True

    def test_malformed_final_rejected(self):
        for text, code in (("not json", "final_not_json"),
                           ('{"a": }', "final_json_parse_error"),
                           ('{"a": "b"', "final_truncated")):
            with pytest.raises(KiloProviderError) as excinfo:
                _port([_final(text)]).complete(_ctx())
            assert excinfo.value.code == code, text

    def test_schema_invalid_rejected(self):
        payload = _answer()
        del payload["confidence"]
        with pytest.raises(KiloProviderError) as excinfo:
            _port([_final(json.dumps(payload))]).complete(_ctx())
        assert excinfo.value.code == "final_schema_error"

    def test_benign_final_is_safe_failure(self):
        payload = _answer(compromised_principal="",
                          compromised_access_key_id="",
                          recommended_action=None)
        with pytest.raises(KiloProviderError) as excinfo:
            _port([_final(json.dumps(payload))]).complete(_ctx())
        assert excinfo.value.code == "no_actionable_finding"

    def test_invalid_action_rejected(self):
        payload = _answer()
        payload["recommended_action"]["arguments"] = dict(
            payload["recommended_action"]["arguments"], Status="Active")
        with pytest.raises(KiloProviderError) as excinfo:
            _port([_final(json.dumps(payload))]).complete(_ctx())
        assert excinfo.value.code == "final_action_schema_error"

    def test_reasoning_ignored(self):
        usage = FakeUsage(prompt=10, completion=5, total=15)
        port = _port([FakeResponse(FakeMessage(
            content="```json\n" + json.dumps(_answer()) + "\n```",
            reasoning="secret chain of thought"), usage=usage)])
        turn = port.complete(_ctx())
        assert turn.is_final is True
        assert "secret chain" not in repr(turn)
        assert port.last_usage == {"input_tokens": 10, "output_tokens": 5,
                                   "total_tokens": 15}


class TestProviderErrors:
    @pytest.mark.parametrize(
        "status,raw_code,expected,stored_code,retry", [
            (400, "INVALID_ARGUMENT", "bad_request", "INVALID_ARGUMENT",
             False),
            (401, "UNAUTHENTICATED", "auth_error", "UNAUTHENTICATED", False),
            (403, "PERMISSION_DENIED", "permission_denied",
             "PERMISSION_DENIED", False),
            (404, "NOT_FOUND", "model_unavailable", "NOT_FOUND", False),
            (429, "insufficient_quota", "quota_exhausted",
             "INSUFFICIENT_QUOTA", True),
            (429, None, "rate_limited", None, True),
            (500, "INTERNAL", "provider_error", "INTERNAL", True),
            (503, "UNAVAILABLE", "service_unavailable", "UNAVAILABLE", True),
        ])
    def test_mapping(self, status, raw_code, expected, stored_code, retry):
        info = describe_kilo_exception(
            FakeOpenAIError(status_code=status, code=raw_code))
        assert (info.classification, info.http_status, info.provider_code,
                info.retryable) == (expected, status, stored_code, retry)
        assert classify_kilo_exception(
            FakeOpenAIError(status_code=status,
                            code=raw_code)) == expected

    def test_timeout_and_unknown(self):
        assert describe_kilo_exception(
            TimeoutError(f"slow {CANARY}")).classification == "timeout"
        unknown = describe_kilo_exception(RuntimeError(f"x {CANARY}"))
        assert (unknown.classification, unknown.retryable) == \
            ("provider_error", False)

    def test_adapter_error_carries_safe_info(self):
        port = TestSecrets._raising_port(
            FakeOpenAIError(status_code=401, code="UNAUTHENTICATED"))
        with pytest.raises(KiloProviderError) as excinfo:
            port.complete(_ctx())
        assert excinfo.value.code == "auth_error"
        assert excinfo.value.info.http_status == 401
        assert CANARY not in str(excinfo.value)
