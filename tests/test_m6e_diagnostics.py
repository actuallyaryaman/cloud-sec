"""M6E provider error diagnostics: pure tests, no provider calls."""

import pytest

from cloudsec_agent.agent.model_port import ModelContext
from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.providers.gemini import (GeminiModelPort,
                                             GeminiProviderError,
                                             ProviderErrorInfo,
                                             classify_provider_exception,
                                             describe_provider_exception)
from tests.agent_fakes import FakeModelPort, FakeToolPort, ok_result

CANARY = "CANARY-KEY-VALUE-XYZ"


@pytest.fixture(autouse=True)
def _no_provider_clients(monkeypatch):
    try:
        from google import genai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("diagnostic tests must not create clients")

    monkeypatch.setattr(genai, "Client", _blocked)


class FakeApiError(Exception):
    def __init__(self, code=None, status=None):
        self.code = code
        self.status = status
        self.message = f"request failed {CANARY}"
        self.details = {"error": {"message": f"detail {CANARY}"}}
        self.response = {"body": f"raw {CANARY}",
                         "headers": {"Authorization": f"Bearer {CANARY}"}}
        super().__init__(f"{code} {status} {CANARY}")


def _tuple(exc):
    info = describe_provider_exception(exc)
    assert CANARY not in repr(info)
    assert CANARY not in info.safe_message
    return (info.classification, info.http_status, info.provider_code,
            info.retryable)


class TestStatusMapping:
    def test_400_bad_request(self):
        assert _tuple(FakeApiError(code=400, status="FAILED_PRECONDITION")) \
            == ("bad_request", 400, "FAILED_PRECONDITION", False)

    def test_401_auth(self):
        assert _tuple(FakeApiError(code=401,
                                   status="UNAUTHENTICATED")) == \
            ("auth_error", 401, "UNAUTHENTICATED", False)

    def test_403_permission(self):
        assert _tuple(FakeApiError(code=403,
                                   status="PERMISSION_DENIED")) == \
            ("permission_denied", 403, "PERMISSION_DENIED", False)

    def test_403_without_code_is_not_billing(self):
        assert _tuple(FakeApiError(code=403, status=None)) == \
            ("permission_denied", 403, None, False)

    def test_billing_only_on_explicit_code(self):
        assert _tuple(FakeApiError(code=403,
                                   status="BILLING_DISABLED")) == \
            ("billing_or_account", 403, "BILLING_DISABLED", False)

    def test_404_model_unavailable(self):
        assert _tuple(FakeApiError(code=404, status="NOT_FOUND")) == \
            ("model_unavailable", 404, "NOT_FOUND", False)

    def test_429_quota_exhausted(self):
        assert _tuple(FakeApiError(code=429,
                                   status="RESOURCE_EXHAUSTED")) == \
            ("quota_exhausted", 429, "RESOURCE_EXHAUSTED", True)

    def test_429_without_code_is_rate_limited(self):
        assert _tuple(FakeApiError(code=429, status=None)) == \
            ("rate_limited", 429, None, True)

    def test_500_provider_error(self):
        assert _tuple(FakeApiError(code=500, status="INTERNAL")) == \
            ("provider_error", 500, "INTERNAL", True)

    def test_503_unavailable(self):
        assert _tuple(FakeApiError(code=503, status="UNAVAILABLE")) == \
            ("service_unavailable", 503, "UNAVAILABLE", True)

    def test_timeout(self):
        assert _tuple(TimeoutError(f"slow {CANARY}")) == \
            ("timeout", None, None, True)

    def test_unknown_exception(self):
        assert _tuple(RuntimeError(f"boom {CANARY}")) == \
            ("provider_error", None, None, False)

    def test_no_status_available(self):
        assert _tuple(Exception()) == \
            ("provider_error", None, None, False)

    def test_non_integer_code_ignored(self):
        assert _tuple(FakeApiError(code="AccessDenied",
                                   status=None)) == \
            ("provider_error", None, None, False)

    def test_classify_matches_describe(self):
        assert classify_provider_exception(
            FakeApiError(code=401, status="UNAUTHENTICATED")) == "auth_error"


class TestInfoContract:
    def test_safe_message_is_fixed(self):
        info = ProviderErrorInfo("quota_exhausted", 429,
                                 "RESOURCE_EXHAUSTED", True)
        assert info.safe_message == "gemini quota_exhausted"
        assert CANARY not in info.safe_message

    def test_invalid_status_rejected(self):
        with pytest.raises(ValueError):
            ProviderErrorInfo("provider_error", 99, None, False)
        with pytest.raises(ValueError):
            ProviderErrorInfo("provider_error", "503", None, False)

    def test_invalid_code_rejected(self):
        with pytest.raises(ValueError):
            ProviderErrorInfo("provider_error", 503, "has spaces", False)
        with pytest.raises(ValueError):
            ProviderErrorInfo("provider_error", 503, "lowercase", False)

    def test_error_carries_info_without_leak(self):
        info = describe_provider_exception(
            FakeApiError(code=429, status="RESOURCE_EXHAUSTED"))
        error = GeminiProviderError(info.classification, info)
        assert error.info is info
        assert str(error) == "gemini quota_exhausted"
        assert CANARY not in str(error)
        assert CANARY not in repr(error)


class TestAdapterBoundary:
    def _port(self, exc):
        class RaisingModels:
            def generate_content(self, **kwargs):
                raise exc

        from types import SimpleNamespace
        return GeminiModelPort(client=SimpleNamespace(models=RaisingModels()))

    def test_adapter_attaches_safe_info(self):
        port = self._port(FakeApiError(code=503, status="UNAVAILABLE"))
        with pytest.raises(GeminiProviderError) as excinfo:
            port.complete(ModelContext(run_id="r", turn_number=1,
                                       observations=()))
        info = excinfo.value.info
        assert (info.classification, info.http_status, info.provider_code,
                info.retryable) == \
            ("service_unavailable", 503, "UNAVAILABLE", True)
        assert CANARY not in str(excinfo.value)

    def test_orchestrator_stop_unchanged(self):
        port = self._port(FakeApiError(code=429,
                                       status="RESOURCE_EXHAUSTED"))
        tools = FakeToolPort(lambda invocation: ok_result({}))
        orch = AgentOrchestrator(port, tools)
        result, events = orch.run("run-m6e")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert result.stop_reason == "model_stopped:gemini_quota_exhausted"
        assert CANARY not in repr([event.as_dict() for event in events])
