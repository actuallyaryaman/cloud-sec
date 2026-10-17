import json
from types import SimpleNamespace

import httpx
import openai
import pytest

from cloudsec_agent.agent.model_port import ModelContext
from cloudsec_agent.benchmark import live
from cloudsec_agent.benchmark.analysis import (
    STOPS, aggregate, aggregate_usage, routing_integrity,
)
from cloudsec_agent.benchmark.m8d import (
    DEFAULT_ROOT, REPO, SCHEMA, VERSION, build_spec, digest, load_spec,
    schedule, validate_spec,
)
from cloudsec_agent.providers.kilo import KiloProviderError
from cloudsec_agent.providers.openrouter import (
    OpenRouterModelPort, OpenRouterProviderError, PINNED_MODEL, PRIMARY_MODEL,
    PROVIDER_EVIDENCE_SCHEMA,
)
from test_m7a_seeding import FakeFloci

FULL_USAGE = {'prompt_tokens': 13840, 'completion_tokens': 1862,
              'total_tokens': 15702}
FULL_USAGE_PUBLIC = {'input_tokens': 13840, 'output_tokens': 1862,
                     'total_tokens': 15702}


def context():
    return ModelContext(run_id='offline', turn_number=1, turns_used=0,
                        turns_remaining=1, tool_calls_used=0,
                        tool_calls_remaining=2)


def response(content='not-json', model=PRIMARY_MODEL, provider='Nvidia',
             usage=FULL_USAGE):
    return SimpleNamespace(
        model=model, provider=provider,
        usage=SimpleNamespace(**usage) if usage else None,
        choices=[SimpleNamespace(message=SimpleNamespace(
            content=content, tool_calls=[]))])


def port_with_transport(monkeypatch, handler):
    real = openai.OpenAI
    options = []

    def factory(**kwargs):
        options.append(kwargs)
        kwargs['http_client'].close()
        kwargs['http_client'] = httpx.Client(transport=httpx.MockTransport(handler))
        return real(**kwargs)

    monkeypatch.setattr(openai, 'OpenAI', factory)
    return OpenRouterModelPort(models=[PRIMARY_MODEL], routing_mode=PINNED_MODEL,
                               sdk_retries=0, api_key='offline-placeholder'), options


def http_body(content, model=PRIMARY_MODEL, provider='Nvidia',
              usage=FULL_USAGE):
    return {'id': 'offline', 'object': 'chat.completion', 'created': 1,
            'model': model, 'provider': provider, 'usage': usage,
            'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {
                'role': 'assistant', 'content': content, 'tool_calls': None}}]}


# --- 1-5, 7-9: provider evidence survives local parse failure ---------------

def test_parse_failure_preserves_served_provider_usage_and_status(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=http_body('not-json'))

    port, options = port_with_transport(monkeypatch, handler)
    with pytest.raises(KiloProviderError) as caught:
        port.complete(context())
    assert caught.value.code == 'final_not_json'
    evidence = port.last_provider_response
    assert evidence['schema'] == PROVIDER_EVIDENCE_SCHEMA
    assert evidence['provider_status'] == 'COMPLETED'
    assert evidence['served_model'] == PRIMARY_MODEL
    assert evidence['provider'] == 'Nvidia'
    assert evidence['usage'] == FULL_USAGE_PUBLIC
    assert evidence['usage_known'] is True
    assert evidence['application_retry_count'] == 0
    assert len(requests) == 1
    assert options[0]['max_retries'] == 0


def test_schema_rejected_final_still_preserves_provider_completion(monkeypatch):
    def handler(request):
        return httpx.Response(200, json=http_body('{"compromised_principal": null}'))

    port, _ = port_with_transport(monkeypatch, handler)
    with pytest.raises(KiloProviderError) as caught:
        port.complete(context())
    assert caught.value.code == 'no_actionable_finding'
    evidence = port.last_provider_response
    assert evidence['provider_status'] == 'COMPLETED'
    assert evidence['served_model'] == PRIMARY_MODEL
    assert evidence['usage'] == FULL_USAGE_PUBLIC


def test_wrong_served_model_detected_with_parse_failure(monkeypatch):
    def handler(request):
        return httpx.Response(200, json=http_body('not-json', model='wrong-model'))

    port, _ = port_with_transport(monkeypatch, handler)
    with pytest.raises(OpenRouterProviderError) as caught:
        port.complete(context())
    assert caught.value.code == 'routing_violation'
    evidence = port.last_provider_response
    assert evidence['provider_status'] == 'COMPLETED'
    assert evidence['served_model'] == 'wrong-model'
    assert routing_integrity({'responses': [evidence]}, PRIMARY_MODEL) is False


def test_unavailable_usage_is_not_fabricated_as_zero(monkeypatch):
    body = http_body('not-json')
    body.pop('usage')

    def handler(request):
        return httpx.Response(200, json=body)

    port, _ = port_with_transport(monkeypatch, handler)
    with pytest.raises(KiloProviderError):
        port.complete(context())
    evidence = port.last_provider_response
    assert evidence['usage'] == {}
    assert evidence['usage_known'] is False


def test_transport_interruption_records_no_provider_response(monkeypatch):
    def handler(request):
        raise httpx.ReadTimeout('offline', request=request)

    port, _ = port_with_transport(monkeypatch, handler)
    with pytest.raises(OpenRouterProviderError):
        port.complete(context())
    assert port.last_provider_response is None


# --- 6, 12: routing integrity is independent of parser success --------------

def test_routing_integrity_skips_responses_without_identity():
    responses = [{'provider_status': 'NO_RESPONSE', 'served_model': None},
                 {'provider_status': 'COMPLETED', 'served_model': PRIMARY_MODEL}]
    assert routing_integrity({'responses': responses}, PRIMARY_MODEL) is True
    assert routing_integrity({'responses': []}, PRIMARY_MODEL) is True


def test_routing_integrity_flags_rejected_parse_wrong_model():
    responses = [{'provider_status': 'COMPLETED', 'parser_status': 'REJECTED',
                  'served_model': 'wrong-model'}]
    assert routing_integrity({'responses': responses}, PRIMARY_MODEL) is False


# --- 10, 11: usage aggregation honesty --------------------------------------

def test_usage_all_known_aggregates_exactly():
    responses = [
        {'provider_status': 'COMPLETED',
         'usage': {'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15}},
        {'provider_status': 'COMPLETED',
         'usage': {'input_tokens': 20, 'output_tokens': 7, 'total_tokens': 27}}]
    result = aggregate_usage(responses)
    assert result['status'] == 'EXACT' and result['exact'] is True
    assert result['known_totals'] == {'input_tokens': 30, 'output_tokens': 12,
                                      'total_tokens': 42}
    assert result['unknown_fields'] == []


def test_usage_one_unknown_is_lower_bound():
    responses = [
        {'provider_status': 'COMPLETED',
         'usage': {'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15}},
        {'provider_status': 'COMPLETED', 'usage': {}}]
    result = aggregate_usage(responses)
    assert result['status'] == 'LOWER_BOUND' and result['exact'] is False
    assert result['known_totals']['input_tokens'] == 10
    assert set(result['unknown_fields']) == {'input_tokens', 'output_tokens',
                                             'total_tokens'}


def test_usage_parser_failure_with_known_usage_still_counted():
    responses = [{'provider_status': 'COMPLETED', 'parser_status': 'REJECTED',
                  'usage': {'input_tokens': 13840, 'output_tokens': 1862,
                            'total_tokens': 15702}}]
    result = aggregate_usage(responses)
    assert result['status'] == 'EXACT'
    assert result['known_totals']['total_tokens'] == 15702


def test_usage_interruption_invents_no_zero_and_is_not_exact():
    responses = [{'provider_status': 'NO_RESPONSE', 'usage': None}]
    result = aggregate_usage(responses)
    assert result['status'] == 'NOT_EXERCISED' and result['exact'] is False
    assert result['known_totals'] == {'input_tokens': 0, 'output_tokens': 0,
                                      'total_tokens': 0}
    assert result['responses_without_provider_response'] == 1


def test_usage_interruption_downgrades_known_run_to_lower_bound():
    responses = [
        {'provider_status': 'COMPLETED',
         'usage': {'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15}},
        {'provider_status': 'NO_RESPONSE', 'usage': None}]
    result = aggregate_usage(responses)
    assert result['status'] == 'LOWER_BOUND'
    assert result['known_totals']['total_tokens'] == 15


# --- run-level integration through the frozen runner ------------------------

def _run(tmp_path, monkeypatch, generate, row=None):
    fake = FakeFloci()
    original = fake.client
    fake.client = lambda service, **kwargs: original(service)
    fake.client('iam').delete_access_key = lambda **kwargs: None
    monkeypatch.setattr(live.OpenRouterModelPort, '_client_or_create',
                        lambda self: None)
    monkeypatch.setattr(live.OpenRouterModelPort, '_generate', generate)
    store = SimpleNamespace(root=tmp_path, validate=lambda spec: None)
    row = row or schedule(load_spec())[0]
    result = live.LiveCase(store, SimpleNamespace(start=lambda: fake,
                                                  stop=lambda: None))(row)
    return result


def test_runner_persists_parse_failure_attribution_and_usage(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, lambda *a: response('not-json'))
    responses = result['evidence']['responses']
    assert len(responses) == 1
    entry = responses[0]
    assert entry['provider_status'] == 'COMPLETED'
    assert entry['parser_status'] == 'REJECTED'
    assert entry['contract_error'] == 'final_not_json'
    assert entry['served_model'] == PRIMARY_MODEL
    assert entry['provider'] == 'Nvidia'
    assert entry['usage'] == FULL_USAGE_PUBLIC
    assert entry['usage_known'] is True
    assert result['metrics']['contract_failure'] is True
    assert not any(result['critical'].values())


def test_runner_parse_failure_issues_exactly_one_request(tmp_path, monkeypatch):
    calls = []

    def generate(*args):
        calls.append(args)
        return response('not-json')

    _run(tmp_path, monkeypatch, generate)
    assert len(calls) == 1


def test_runner_wrong_model_flagged_even_with_parse_failure(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch,
                  lambda *a: response(content='not-json', model='wrong-model'))
    entry = result['evidence']['responses'][0]
    assert entry['served_model'] == 'wrong-model'
    assert entry['provider_status'] == 'COMPLETED'
    assert result['critical']['wrong_model'] is True


def test_runner_transport_interruption_records_no_fabricated_usage(tmp_path, monkeypatch):
    def generate(*args):
        raise ConnectionError('offline')

    result = _run(tmp_path, monkeypatch, generate)
    entry = result['evidence']['responses'][0]
    assert entry['provider_status'] == 'NO_RESPONSE'
    assert entry['usage'] is None and entry['usage_known'] is False
    assert result['evidence']['stop_reason'].startswith('model_stopped:')


# --- 13-16: schema versioning, fresh successor, unchanged science -----------

def test_historical_v1_semantics_remain_distinguishable():
    old = json.loads((REPO / 'benchmarks' / 'm8d-v1.json').read_text())
    assert old['artifact_schema'] == 'm8d-artifact-v1'
    assert old['benchmark_version'] == 'm8d-v1'
    assert SCHEMA == 'm8d-artifact-v2' and VERSION == 'm8d-v2'
    assert old['artifact_schema'] != SCHEMA
    with pytest.raises(ValueError):
        validate_spec(old)


def test_successor_root_is_fresh_and_unversioned_keys_distinct():
    import shutil
    import tempfile
    from pathlib import Path
    from cloudsec_agent.benchmark.artifacts import ArtifactStore
    assert DEFAULT_ROOT == REPO / 'data' / 'experiments' / 'm8d-v2'
    parent = REPO / 'data' / 'm8d-preparation' / 'offline-tests'
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(dir=parent))
    try:
        store = ArtifactStore(root)
        store.initialize()
        assert len(store.missing()) == 48
        assert not list((root / 'runs').glob('*.json'))
        assert all(row['run_key'].startswith('m8d-v2-')
                   for row in schedule(load_spec()))
    finally:
        shutil.rmtree(root)


def test_successor_schedule_is_48_unique_runs():
    rows = schedule(load_spec())
    assert len(rows) == len({r['run_key'] for r in rows}) == 48


def test_successor_science_unchanged_from_v1():
    old = json.loads((REPO / 'benchmarks' / 'm8d-v1.json').read_text())
    new = load_spec()
    for field in ('bases', 'treatment', 'generator_version', 'attack_version',
                  'scoring_version', 'scheduler_version', 'seed_rule',
                  'classes', 'families', 'conditions', 'repetitions'):
        assert new[field] == old[field], field
    assert digest(new['treatment']) == digest(old['treatment'])


def test_benchmark_aggregate_reports_usage_section():
    row = schedule(load_spec())[0]
    record = {'schema': SCHEMA, 'status': 'PROVIDER_INTERRUPTION',
              'metrics': None, 'critical': {k: False for k in STOPS},
              'run_key': row['run_key'], 'input': row,
              'evidence': {'responses': [{'provider_status': 'NO_RESPONSE',
                                          'usage': None}]}}
    result = aggregate(load_spec(), [record])
    assert result['usage']['responses'] == 1
    assert result['usage']['exact'] is False
    assert result['usage']['status'] == 'NOT_EXERCISED'
