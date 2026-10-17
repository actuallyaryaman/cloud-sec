import json

import httpx
import openai
import pytest

from cloudsec_agent.agent.model_port import ModelContext
from cloudsec_agent.providers.openrouter import (
    OpenRouterModelPort, OpenRouterProviderError, PINNED_MODEL, PRIMARY_MODEL,
)


def context():
    return ModelContext(run_id='offline', turn_number=1, turns_used=0,
                        turns_remaining=1, tool_calls_used=0,
                        tool_calls_remaining=2)


def port_with_transport(monkeypatch, handler):
    real = openai.OpenAI
    options = []

    def factory(**kwargs):
        options.append(kwargs)
        assert kwargs['max_retries'] == 0
        kwargs['http_client'].close()
        kwargs['http_client'] = httpx.Client(transport=httpx.MockTransport(handler))
        return real(**kwargs)

    monkeypatch.setattr(openai, 'OpenAI', factory)
    return OpenRouterModelPort(models=[PRIMARY_MODEL], routing_mode=PINNED_MODEL,
                               sdk_retries=0, api_key='offline-placeholder'), options


@pytest.mark.parametrize('failure', [429, 500, 503, 'timeout'])
def test_one_http_attempt_on_interruption(monkeypatch, failure):
    requests = []

    def handler(request):
        requests.append(request)
        if failure == 'timeout':
            raise httpx.ReadTimeout('offline', request=request)
        return httpx.Response(failure, json={'error': {'message': 'offline'}})

    port, options = port_with_transport(monkeypatch, handler)
    with pytest.raises(OpenRouterProviderError) as caught:
        port.complete(context())
    assert len(requests) == 1
    assert caught.value.code in {'rate_limited', 'provider_error',
                                 'service_unavailable', 'timeout'}
    assert options[0]['max_retries'] == 0
    body = json.loads(requests[0].content)
    assert body['model'] == PRIMARY_MODEL
    assert 'models' not in body
    assert body['provider'] == {'allow_fallbacks': False}
    assert body['temperature'] == 0.0 and body['max_tokens'] == 2048


@pytest.mark.parametrize('served', ['wrong-model', None])
def test_pinned_served_identity_fails_closed(monkeypatch, served):
    def handler(request):
        return httpx.Response(200, json={
            'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': served, 'choices': []})
    port, _ = port_with_transport(monkeypatch, handler)
    with pytest.raises(OpenRouterProviderError, match='routing_violation'):
        port.complete(context())


def test_explicit_retry_configuration_rejected():
    with pytest.raises(ValueError):
        OpenRouterModelPort(sdk_retries=2)
