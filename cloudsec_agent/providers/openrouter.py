__all__ = [
    "ADAPTER_VERSION",
    "PROMPT_VERSION",
    "PRIMARY_MODEL",
    "MODEL_ENV_VAR",
    "KEY_ENV_VAR",
    "BASE_URL",
    "PINNED_MODEL",
    "RESILIENT_CHAIN",
    "RESPONSE_FORMAT_MODELS",
    "ROUTING_IDENTITY",
    "FROZEN_PRIMARY",
    "FROZEN_FALLBACKS",
    "OpenRouterProviderError",
    "OpenRouterModelPort",
    "resolve_openrouter_models",
    "resolve_openrouter_mode",
    "routing_identity",
    "build_function_tools",
    "describe_openrouter_exception",
    "classify_openrouter_exception",
    "load_openrouter_key",
]

import json
import os

from ..agent.model_port import (ModelContext, ModelPort, ModelPortError,
                                ModelTurn)
from ..agent.models import AgentToolCall
from .gemini import ProviderErrorInfo
from .kilo import (READ_TOOL_IDS, SYSTEM_INSTRUCTION,
                   _parse_final_document, build_function_tools,
                   build_investigation_text, parse_kilo_final)
from .model_config import load_key

ADAPTER_VERSION = "m6g-openrouter-v1"
PROMPT_VERSION = "m6p-kilo-sys-v1"

PRIMARY_MODEL = "nvidia/nemotron-3.5-lightning:free"
MODEL_ENV_VAR = "CLOUDSEC_OPENROUTER_MODEL"
KEY_ENV_VAR = "OPENROUTER_API_KEY"
BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_OUTPUT_TOKENS = 2048
APPLICATION_RETRIES = 0

PINNED_MODEL = "pinned"
RESILIENT_CHAIN = "resilient"

RESPONSE_FORMAT_MODELS = frozenset()

ROUTING_IDENTITY = "openrouter-free-chain-v1"
FROZEN_PRIMARY = PRIMARY_MODEL
FROZEN_FALLBACKS = (
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
)


class OpenRouterProviderError(ModelPortError):
    def __init__(self, code, info=None):
        self.code = code
        self.info = info
        super().__init__(f"openrouter {code}")


def load_openrouter_key(env=None, path=None):
    return load_key(KEY_ENV_VAR, env, path)


def _safe_status(exc):
    for attr in ("status_code", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and 100 <= value <= 599:
            return value
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and 100 <= status <= 599:
        return status
    return None


def _safe_symbol(exc):
    import re as _re
    for attr in ("code", "type"):
        value = getattr(exc, attr, None)
        if isinstance(value, str) and \
                _re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value):
            return value.upper()
    return None


def _error_names(exc) -> str:
    names = [type(exc).__name__]
    names.extend(cls.__name__ for cls in type(exc).__mro__)
    return "".join(
        "".join(char for char in name.lower() if char.isalnum())
        for name in names)


def describe_openrouter_exception(exc) -> ProviderErrorInfo:
    status = _safe_status(exc)
    code = _safe_symbol(exc)
    lowered = (code or "").lower()
    if status == 401:
        return ProviderErrorInfo("auth_error", status, code, False)
    if status == 403:
        return ProviderErrorInfo("permission_denied", status, code, False)
    if status == 400 or status == 422:
        return ProviderErrorInfo("bad_request", status, code, False)
    if status == 404:
        return ProviderErrorInfo("model_unavailable", status, code, False)
    if status == 429:
        if "quota" in lowered or "insufficient" in lowered:
            return ProviderErrorInfo("quota_exhausted", status, code, True)
        return ProviderErrorInfo("rate_limited", status, code, True)
    if status == 500:
        return ProviderErrorInfo("provider_error", status, code, True)
    if status in (502, 503, 504):
        return ProviderErrorInfo("service_unavailable", status, code, True)
    names = _error_names(exc)
    if "timeout" in names or "timedout" in names:
        return ProviderErrorInfo("timeout", status, code, True)
    if "connectionerror" in names or "connecterror" in names:
        return ProviderErrorInfo("service_unavailable", status, code, True)
    return ProviderErrorInfo("provider_error", status, code, False)


def classify_openrouter_exception(exc) -> str:
    return describe_openrouter_exception(exc).classification


def _clean_model(value):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""


def resolve_openrouter_models(explicit=None) -> tuple:
    if explicit is not None:
        if isinstance(explicit, str):
            explicit = [explicit]
        models = tuple(_clean_model(item) for item in explicit)
        models = tuple(item for item in models if item)
        if not models:
            raise ValueError("models must list at least one model id")
        return models
    env_value = os.environ.get(MODEL_ENV_VAR, "")
    if env_value.strip():
        return tuple(part.strip() for part in env_value.split(",")
                     if part.strip())
    return (FROZEN_PRIMARY,) + tuple(FROZEN_FALLBACKS)


def resolve_openrouter_mode(explicit=None, models=()) -> str:
    if explicit is not None:
        if explicit not in (PINNED_MODEL, RESILIENT_CHAIN):
            raise ValueError("routing mode must be pinned or resilient")
        if explicit == PINNED_MODEL and len(models) != 1:
            raise ValueError("pinned mode requires exactly one model")
        return explicit
    if len(models) == 1:
        return PINNED_MODEL
    return RESILIENT_CHAIN


def routing_identity(models, mode, adapter_version=ADAPTER_VERSION,
                     prompt_version=PROMPT_VERSION,
                     temperature=DEFAULT_TEMPERATURE,
                     max_output_tokens=DEFAULT_MAX_OUTPUT_TOKENS) -> str:
    import hashlib
    canonical = json.dumps(
        {"provider": "openrouter", "primary": models[0],
         "fallbacks": list(models[1:]), "routing_mode": mode,
         "adapter_version": adapter_version,
         "prompt_version": prompt_version, "temperature": temperature,
         "max_output_tokens": max_output_tokens,
         "application_retries": APPLICATION_RETRIES},
        sort_keys=True, separators=(",", ":"))
    return "openrouter-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


class OpenRouterModelPort(ModelPort):
    def __init__(self, *, models=None, routing_mode=None, temperature=None,
                 max_output_tokens=None, client=None, client_factory=None,
                 case_briefing="", api_key=None, sdk_retries=None):
        resolved_models = resolve_openrouter_models(models)
        self._models = resolved_models
        self._mode = resolve_openrouter_mode(routing_mode, resolved_models)
        if sdk_retries is not None and (type(sdk_retries) is not int or
                                        sdk_retries != 0):
            raise ValueError("explicit SDK retries must be zero")
        self._sdk_retries = sdk_retries
        resolved_temperature = DEFAULT_TEMPERATURE if temperature is None \
            else temperature
        if not isinstance(resolved_temperature, (int, float)):
            raise TypeError("temperature must be a number")
        self._temperature = float(resolved_temperature)
        resolved_tokens = DEFAULT_MAX_OUTPUT_TOKENS \
            if max_output_tokens is None else max_output_tokens
        if isinstance(resolved_tokens, bool) or \
                not isinstance(resolved_tokens, int) or resolved_tokens < 1:
            raise ValueError("max_output_tokens must be a positive int")
        self._max_output_tokens = resolved_tokens
        self._client = client
        self._client_factory = client_factory
        self._api_key = api_key
        if case_briefing is None:
            case_briefing = ""
        if not isinstance(case_briefing, str):
            raise TypeError("case_briefing must be a string")
        self._briefing = case_briefing
        self._last_usage = {}
        self._last_served = {}
        self._last_request = {}

    @property
    def models(self) -> tuple:
        return self._models

    @property
    def primary_model(self) -> str:
        return self._models[0]

    @property
    def routing_mode(self) -> str:
        return self._mode

    @property
    def temperature(self) -> float:
        return self._temperature

    @property
    def last_usage(self) -> dict:
        return dict(self._last_usage)

    @property
    def last_served(self) -> dict:
        return dict(self._last_served)

    @property
    def last_request(self) -> dict:
        return dict(self._last_request)

    @property
    def application_retry_count(self) -> int:
        return APPLICATION_RETRIES

    def _client_or_create(self):
        if self._client is not None:
            if self._sdk_retries == 0 and self._client.max_retries != 0:
                raise ValueError("injected client must disable SDK retries")
            return self._client
        if self._client_factory is not None:
            self._client = self._client_factory()
            return self._client_or_create()
        from openai import OpenAI
        key = self._api_key or load_openrouter_key()
        if not key:
            raise OpenRouterProviderError("auth_error")
        options = {}
        if self._sdk_retries == 0:
            import httpx
            options = {"max_retries": 0, "http_client": httpx.Client(
                transport=httpx.HTTPTransport(retries=0), trust_env=False)}
        self._client = OpenAI(api_key=key, base_url=BASE_URL, **options)
        return self._client

    def complete(self, context: ModelContext) -> ModelTurn:
        if not isinstance(context, ModelContext):
            raise OpenRouterProviderError("invalid_response")
        investigation = build_investigation_text(context, self._briefing)
        try:
            client = self._client_or_create()
            response = self._generate(client, investigation)
        except OpenRouterProviderError:
            raise
        except Exception as exc:
            info = describe_openrouter_exception(exc)
            raise OpenRouterProviderError(info.classification, info)
        self._record_usage(response)
        self._record_served(response)
        if self._sdk_retries == 0 and self._mode == PINNED_MODEL and \
                self._last_served["served_model"] != self.primary_model:
            raise OpenRouterProviderError("routing_violation")
        return self._to_turn(context, response)

    def _request_kwargs(self, investigation):
        messages = [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": investigation}]
        kwargs = {
            "model": self._models[0],
            "messages": messages,
            "tools": list(build_function_tools()),
            "tool_choice": "auto",
            "temperature": self._temperature,
            "max_tokens": self._max_output_tokens,
        }
        if self._mode == RESILIENT_CHAIN:
            kwargs["extra_body"] = {"models": list(self._models)}
        elif self._sdk_retries == 0:
            kwargs["extra_body"] = {"provider": {"allow_fallbacks": False}}
        if self._models[0] in RESPONSE_FORMAT_MODELS:
            kwargs["response_format"] = {"type": "json_object"}
        return kwargs

    def _generate(self, client, investigation):
        kwargs = self._request_kwargs(investigation)
        self._last_request = {
            "model": kwargs["model"],
            "models": list(kwargs.get("extra_body", {}).get("models", [])
                           or [kwargs["model"]]),
            "routing_mode": self._mode,
            "response_format_sent": "response_format" in kwargs,
            "temperature": kwargs["temperature"],
            "max_tokens": kwargs["max_tokens"],
        }
        return client.chat.completions.create(**kwargs)

    def _record_usage(self, response):
        usage = getattr(response, "usage", None)
        if usage is None:
            self._last_usage = {}
            return
        record = {}
        for public, raw in (("input_tokens", "prompt_tokens"),
                            ("output_tokens", "completion_tokens"),
                            ("total_tokens", "total_tokens")):
            value = getattr(usage, raw, None)
            if isinstance(value, int) and value >= 0:
                record[public] = value
        self._last_usage = record

    def _record_served(self, response):
        served = getattr(response, "model", None)
        if not isinstance(served, str) or not served:
            served = None
        provider = getattr(response, "provider", None)
        if not isinstance(provider, str) or not provider:
            provider = None
        self._last_served = {
            "requested_primary": self._models[0],
            "configured_models": list(self._models),
            "served_model": served,
            "provider": provider,
            "fallback_used": bool(served) and served != self._models[0],
            "fallback_hops": None,
            "application_retry_count": APPLICATION_RETRIES,
        }

    def served_summary(self) -> dict:
        return dict(self._last_served)

    def _to_turn(self, context, response) -> ModelTurn:
        try:
            choices = getattr(response, "choices", None) or ()
            message = getattr(choices[0], "message", None)
            calls = getattr(message, "tool_calls", None) or ()
            calls = [call for call in calls
                     if getattr(call, "function", None) is not None]
        except (IndexError, AttributeError, TypeError):
            raise OpenRouterProviderError("invalid_response")
        if calls:
            return ModelTurn(tool_calls=tuple(
                self._to_tool_call(context, call, index)
                for index, call in enumerate(calls)))
        text = getattr(message, "content", None)
        if not isinstance(text, str) or not text.strip():
            raise OpenRouterProviderError("final_not_json")
        return ModelTurn(final_answer=parse_kilo_final(
            _parse_final_document(text)))

    @staticmethod
    def _to_tool_call(context, call, index) -> AgentToolCall:
        function = call.function
        name = getattr(function, "name", None)
        if name not in READ_TOOL_IDS:
            raise OpenRouterProviderError("unknown_tool")
        raw = getattr(function, "arguments", None)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            arguments = {}
        elif isinstance(raw, dict):
            arguments = dict(raw)
        elif isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                raise OpenRouterProviderError("invalid_response")
            if not isinstance(parsed, dict):
                raise OpenRouterProviderError("invalid_response")
            arguments = parsed
        else:
            raise OpenRouterProviderError("invalid_response")
        call_id = getattr(call, "id", None)
        if not isinstance(call_id, str) or not call_id:
            call_id = (f"{context.run_id}:openrouter:"
                       f"{context.turn_number}:{index}")
        return AgentToolCall(call_id=call_id, tool_id=name,
                             arguments=arguments)
