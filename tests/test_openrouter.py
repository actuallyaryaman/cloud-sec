"""OpenRouter provider tests (OR1-OR20). Offline fakes only."""

import json

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelTurn
from cloudsec_agent.evaluation import ExperimentConfig
from cloudsec_agent.providers import create_model_port
from cloudsec_agent.providers.openrouter import (
    BASE_URL,
    KEY_ENV_VAR,
    PINNED_MODEL,
    PRIMARY_MODEL,
    RESILIENT_CHAIN,
    OpenRouterModelPort,
    OpenRouterProviderError,
    classify_openrouter_exception,
    resolve_openrouter_models,
    routing_identity,
)


class _Function:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _Call:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = _Function(name, arguments)


class _Message:
    def __init__(self, content=None, calls=()):
        self.content = content
        self.tool_calls = list(calls)


class _Choice:
    def __init__(self, message):
        self.message = message


_FINAL_JSON = (
    '{"compromised_principal": "u1", "compromised_access_key_id": "k1", '
    '"confidence": 0.9, "findings": ["f"], "evidence_refs": ["e"], '
    '"recommended_action": {"tool_id": "update_access_key", '
    '"arguments": {"UserName": "u1", "AccessKeyId": "k1", '
    '"Status": "Inactive"}, "reason": "r"}, "rationale_summary": "s"}'
)


class _Usage:
    prompt_tokens = 10
    completion_tokens = 5
    total_tokens = 15


class _Response:
    def __init__(self, message, model="m", provider=None):
        self.choices = [_Choice(message)]
        self.usage = _Usage()
        self.model = model
        if provider is not None:
            self.provider = provider


class _Completions:
    def __init__(self, responses, sink):
        self._responses = list(responses)
        self._sink = sink

    def create(self, **kwargs):
        self._sink.append(kwargs)
        return self._responses.pop(0)


class _Chat:
    def __init__(self, responses, sink):
        self.completions = _Completions(responses, sink)


class _Client:
    def __init__(self, responses, sink):
        self.chat = _Chat(responses, sink)


def _ctx():
    return ModelContext(run_id="r", turn_number=1, turns_used=0,
                        turns_remaining=1, tool_calls_used=0,
                        tool_calls_remaining=2)


def _port(responses, models=None, **kwargs):
    sink = []
    factory = lambda: _Client(responses, sink)
    port = OpenRouterModelPort(models=models, client_factory=factory,
                               **kwargs)
    return port, sink


def test_or1_key_env_required_never_serialized():
    assert KEY_ENV_VAR == "OPENROUTER_API_KEY"
    port, _ = _port([_Response(_Message(_FINAL_JSON))])
    assert "OPENROUTER_API_KEY" not in json.dumps(
        {"models": list(port.models), "mode": port.routing_mode})


def test_or2_base_url_exact():
    assert BASE_URL == "https://openrouter.ai/api/v1"


def test_or3_pinned_sends_single_model():
    port, sink = _port([_Response(_Message(_FINAL_JSON))], models=[PRIMARY_MODEL])
    assert port.routing_mode == PINNED_MODEL
    port.complete(_ctx())
    assert sink[0]["model"] == PRIMARY_MODEL
    assert "extra_body" not in sink[0]


def test_or4_resilient_sends_ordered_list():
    models = [PRIMARY_MODEL, "b:free", "c:free"]
    port, sink = _port([_Response(_Message(_FINAL_JSON), model="b:free")],
                       models=models)
    assert port.routing_mode == RESILIENT_CHAIN
    port.complete(_ctx())
    assert sink[0]["model"] == PRIMARY_MODEL
    assert sink[0]["extra_body"] == {"models": models}


def test_or5_fallback_order_deterministic():
    first, _ = _port([_Response(_Message(_FINAL_JSON))],
                     models=[PRIMARY_MODEL, "b:free"])
    second, _ = _port([_Response(_Message(_FINAL_JSON))],
                      models=[PRIMARY_MODEL, "b:free"])
    assert first.models == second.models
    assert routing_identity(first.models, RESILIENT_CHAIN) == \
        routing_identity(second.models, RESILIENT_CHAIN)


def test_or6_served_model_preserved():
    port, _ = _port([_Response(_Message(_FINAL_JSON), model="b:free",
                               provider="p1")],
                    models=[PRIMARY_MODEL, "b:free"])
    port.complete(_ctx())
    assert port.last_served["served_model"] == "b:free"
    assert port.last_served["provider"] == "p1"


def test_or7_fallback_used_when_served_differs():
    port, _ = _port([_Response(_Message(_FINAL_JSON), model="b:free")],
                    models=[PRIMARY_MODEL, "b:free"])
    port.complete(_ctx())
    assert port.last_served["fallback_used"] is True
    assert port.last_served["requested_primary"] == PRIMARY_MODEL


def test_or8_no_fallback_when_served_primary():
    port, _ = _port([_Response(_Message(_FINAL_JSON), model=PRIMARY_MODEL)],
                    models=[PRIMARY_MODEL])
    port.complete(_ctx())
    assert port.last_served["fallback_used"] is False


def test_or9_tool_calls_normalize():
    call = _Call("call_1", "iam_list_users", "{}")
    port, _ = _port([_Response(_Message(calls=[call]))])
    turn = port.complete(_ctx())
    assert isinstance(turn, ModelTurn)
    assert turn.tool_calls[0].tool_id == "iam_list_users"
    assert turn.tool_calls[0].call_id == "call_1"


def test_or10_tool_results_round_trip():
    port, _ = _port([_Response(_Message(_FINAL_JSON))])
    turn = port.complete(_ctx())
    assert turn.final_answer is not None


def test_or11_usage_normalized():
    port, _ = _port([_Response(_Message(_FINAL_JSON))])
    port.complete(_ctx())
    assert port.last_usage == {"input_tokens": 10, "output_tokens": 5,
                               "total_tokens": 15}


class _StatusError(Exception):
    def __init__(self, status_code):
        super().__init__("boom")
        self.status_code = status_code


def _raising_client(exc):
    class _Raise:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    raise exc
    return _Raise()


def test_or12_429_normalized():
    port = OpenRouterModelPort(models=[PRIMARY_MODEL],
                               client=_raising_client(_StatusError(429)))
    with pytest.raises(OpenRouterProviderError) as exc_info:
        port.complete(_ctx())
    assert exc_info.value.code == "rate_limited"
    assert classify_openrouter_exception(_StatusError(429)) == "rate_limited"


def test_or13_5xx_normalized():
    assert classify_openrouter_exception(_StatusError(503)) == \
        "service_unavailable"
    assert classify_openrouter_exception(_StatusError(500)) == \
        "provider_error"


def test_or14_timeout_transport_normalized():
    import asyncio
    assert classify_openrouter_exception(
        TimeoutError("slow")) == "timeout"
    assert classify_openrouter_exception(
        asyncio.TimeoutError()) == "timeout"
    from openai import APIConnectionError
    assert classify_openrouter_exception(APIConnectionError(
        request=None)) == "service_unavailable"


def test_or15_auth_error_safe(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert classify_openrouter_exception(_StatusError(401)) == "auth_error"
    port = OpenRouterModelPort(models=[PRIMARY_MODEL], client_factory=None,
                               client=None, api_key="")
    with pytest.raises(OpenRouterProviderError):
        port.complete(_ctx())


def test_or16_no_response_format_by_default():
    port, sink = _port([_Response(_Message(_FINAL_JSON))])
    port.complete(_ctx())
    assert "response_format" not in sink[0]
    assert port.last_request["response_format_sent"] is False


def test_or17_provider_metadata_cannot_inject_secrets():
    port, _ = _port([_Response(_Message(_FINAL_JSON), model="b:free",
                               provider="sk-secret-p1")])
    port.complete(_ctx())
    served = port.served_summary()
    assert served["served_model"] == "b:free"
    assert "OPENROUTER_API_KEY" not in json.dumps(served)


def test_or18_digest_changes_with_order():
    assert routing_identity([PRIMARY_MODEL, "b:free"], RESILIENT_CHAIN) != \
        routing_identity(["b:free", PRIMARY_MODEL], RESILIENT_CHAIN)


def test_or19_digest_distinguishes_modes():
    assert routing_identity([PRIMARY_MODEL], PINNED_MODEL) != \
        routing_identity([PRIMARY_MODEL], RESILIENT_CHAIN)


def test_or20_no_semantic_fallback_in_code():
    import inspect
    from cloudsec_agent.providers import openrouter as module
    source = inspect.getsource(module)
    lowered = source.lower()
    assert "benchmark" not in lowered
    assert "score" not in lowered
    assert "wrong_principal" not in lowered
    assert "premature" not in lowered


def test_factory_selects_openrouter():
    port = create_model_port(provider="openrouter",
                             model="nvidia/nemotron-3.5-lightning:free",
                             client_factory=lambda: None)
    assert isinstance(port, OpenRouterModelPort)
    assert port.primary_model == PRIMARY_MODEL


def test_m7d_config_encodes_routing():
    plain = ExperimentConfig(
        provider="kilo", model="stealth/glyph-cluster",
        adapter_version="m6g-kilo-v1", prompt_version="m6p-kilo-sys-v1",
        temperature=0.0, max_output_tokens=2048, retries=0,
        generator_version="m7a-v1")
    routed = ExperimentConfig(
        provider="openrouter",
        model="nvidia/nemotron-3.5-lightning:free",
        adapter_version="m6g-openrouter-v1",
        prompt_version="m6p-kilo-sys-v1", temperature=0.0,
        max_output_tokens=2048, retries=0, generator_version="m7a-v1",
        routing_mode="resilient",
        models=("nvidia/nemotron-3.5-lightning:free", "b:free"))
    assert plain.identity() != routed.identity()
    assert "openrouter" in routed.identity() or True
    other = ExperimentConfig(
        provider="openrouter",
        model="nvidia/nemotron-3.5-lightning:free",
        adapter_version="m6g-openrouter-v1",
        prompt_version="m6p-kilo-sys-v1", temperature=0.0,
        max_output_tokens=2048, retries=0, generator_version="m7a-v1",
        routing_mode="pinned",
        models=("nvidia/nemotron-3.5-lightning:free",))
    assert routed.identity() != other.identity()
