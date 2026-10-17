from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import shutil
import tempfile

import pytest

from cloudsec_agent.benchmark.analysis import METRICS, STOPS
from cloudsec_agent.benchmark.artifacts import (
    ArtifactStore, atomic_json, check_account, read_json,
)
from cloudsec_agent.benchmark.m8d import REPO, SCHEMA, load_spec
from cloudsec_agent.providers.openrouter import OpenRouterProviderError


@pytest.fixture
def store():
    parent = REPO / 'data' / 'm8d-preparation' / 'offline-tests'
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(dir=parent))
    artifact = ArtifactStore(root)
    artifact.initialize()
    yield artifact
    shutil.rmtree(root)


def account():
    return {'checked_at': datetime.now(timezone.utc).isoformat(),
            'remaining_calls': 400, 'funded_verified': True,
            'source': 'openrouter-account-metadata'}


def sample(row):
    return {'schema': SCHEMA, 'status': 'COMPLETED',
            'metrics': {m: m == 'no_action' for m in METRICS},
            'critical': {s: False for s in STOPS}}


def test_prepare_resume_and_immutable_run(store):
    assert len(store.missing()) == 48
    first = store.run_next(sample, account(), execution_authorized=True)
    assert len(store.missing()) == 47
    assert all(r['run_key'] != first['run_key'] for r in store.missing())
    path = store.root / 'runs' / (first['run_key'] + '.json')
    old = path.read_bytes()
    with pytest.raises(FileExistsError):
        atomic_json(path, {'corrupt': True})
    assert path.read_bytes() == old
    store.initialize()
    assert len(store.records()) == 1
    assert read_json(store.root / 'progress.json')['terminal_run_keys'] == [first['run_key']]


def test_atomic_failure_leaves_no_partial_result(store, monkeypatch):
    import os
    path = store.root / 'atomic-test.json'

    def fail(*args):
        raise OSError('simulated disk error')

    monkeypatch.setattr(os, 'link', fail)
    with pytest.raises(OSError):
        atomic_json(path, {'safe': True})
    assert not path.exists()
    assert not list(store.root.glob('.pending-*'))


def test_durable_default_and_reject_ephemeral():
    from cloudsec_agent.benchmark.m8d import DEFAULT_ROOT
    assert DEFAULT_ROOT == REPO / 'data' / 'experiments' / 'm8d-v1'
    for root in ('/tmp/m8d-invalid', '/dev/shm/m8d-invalid', REPO / 'tracked-output'):
        with pytest.raises(ValueError):
            ArtifactStore(root)


@pytest.mark.parametrize('file', ['spec.json', 'order.json', 'pairs.json', 'preflight.json', 'freeze.json'])
def test_changed_frozen_inputs_rejected(store, file):
    value = read_json(store.root / file)
    if isinstance(value, list):
        value.reverse()
    else:
        value['altered'] = True
    atomic_json(store.root / file, value, replace=True)
    with pytest.raises(ValueError):
        store.missing()


def test_source_head_runtime_or_content_drift_refused(store, monkeypatch):
    from cloudsec_agent.benchmark import artifacts
    original = artifacts.source_snapshot

    def drift(repo):
        value = original(repo)
        value['head'] = 'changed'
        return value

    monkeypatch.setattr(artifacts, 'source_snapshot', drift)
    with pytest.raises(ValueError, match='source HEAD/content/runtime drift'):
        store.run_next(sample, account(), execution_authorized=True)
    assert read_json(store.root / 'STOP.json')['reasons'] == ['input_config_drift']
    assert not list(store.root.glob('runs/*.json'))


def test_attempted_without_result_never_replaced(store):
    row = store.missing()[0]
    atomic_json(store.root / 'attempts' / (row['run_key'] + '.json'), {'started': True})
    with pytest.raises(ValueError, match='no automatic replacement'):
        store.missing()


def test_result_integrity_refusal(store):
    result = store.run_next(sample, account(), execution_authorized=True)
    path = store.root / 'runs' / (result['run_key'] + '.json')
    value = read_json(path)
    value['record']['metrics']['no_action'] = False
    atomic_json(path, value, replace=True)
    with pytest.raises(ValueError, match='integrity'):
        store.records()


@pytest.mark.parametrize('name', STOPS)
def test_critical_evidence_durable_before_stop(store, name):
    def execute(row):
        result = sample(row)
        result['critical'][name] = True
        return result
    with pytest.raises(ValueError, match='STOP'):
        store.run_next(execute, account(), execution_authorized=True)
    assert len(store.records()) == 1
    assert name in read_json(store.root / 'STOP.json')['reasons']
    with pytest.raises(ValueError, match='stopped'):
        store.missing()


def test_provider_interruption_not_retried_or_replaced(store):
    count = []

    def execute(row):
        count.append(row['run_key'])
        raise OpenRouterProviderError('rate_limited')

    with pytest.raises(ValueError, match='STOP'):
        store.run_next(execute, account(), execution_authorized=True)
    assert len(count) == 1
    assert store.records()[0]['status'] == 'PROVIDER_INTERRUPTION'
    assert store.records()[0]['metrics'] is None
    with pytest.raises(ValueError):
        store.run_next(execute, account(), execution_authorized=True)
    assert len(count) == 1


def test_malformed_measurement_persisted_then_halted(store):
    def execute(row):
        value = sample(row)
        del value['metrics']['secret_requested']
        return value
    with pytest.raises(ValueError, match='STOP'):
        store.run_next(execute, account(), execution_authorized=True)
    assert len(list(store.root.glob('runs/*.json'))) == 1
    assert (store.root / 'STOP.json').exists()


def test_concurrent_writer_refused(store):
    with store.locked():
        with pytest.raises(BlockingIOError):
            with store.locked():
                pass


@pytest.mark.parametrize('change', [{'funded_verified': False}, {'remaining_calls': 399},
                                    {'remaining_calls': True}, {'source': 'unverified'},
                                    {'checked_at': '2020-01-01T00:00:00+00:00'}])
def test_funding_precondition_never_faked(store, change):
    metadata = {**account(), **change}
    with pytest.raises(ValueError):
        store.run_next(sample, metadata, execution_authorized=True)
    assert not list(store.root.glob('attempts/*.json'))


def test_authorization_gate_and_account_age(store):
    with pytest.raises(ValueError, match='authorization'):
        store.run_next(sample, account())
    now = datetime.now(timezone.utc)
    value = account()
    value['checked_at'] = (now + timedelta(seconds=60)).isoformat()
    with pytest.raises(ValueError):
        check_account(value, load_spec(), now)
