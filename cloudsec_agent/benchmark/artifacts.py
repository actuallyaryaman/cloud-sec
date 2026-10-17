import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone

from .analysis import STOPS, critical_stops, validate_result
from ..providers.openrouter import PROVIDER_EVIDENCE_SCHEMA
from .m8d import (DEFAULT_ROOT, REPO, SCHEMA, VERSION, canonical, digest,
                  load_spec, schedule, structural_preflight, validate_spec)


def atomic_json(path, value, *, replace=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical(value) + b'\n'
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    return json.loads(Path(path).read_text())


def source_snapshot(repo=REPO):
    repo = Path(repo).resolve()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    paths = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=repo).decode().split('\0')) - {''}
    for folder in ('cloudsec_agent', 'tests', 'config', 'benchmarks', 'scripts'):
        paths.update(str(p.relative_to(repo)) for p in (repo / folder).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    manifest = {}
    for name in sorted(paths):
        p = repo / name
        if p.is_symlink():
            manifest[name] = {'link': os.readlink(p)}
        elif p.is_file():
            manifest[name] = {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                              'mode': p.stat().st_mode & 0o777}
        else:
            raise ValueError('tracked source missing')
    runtime = {'python': platform.python_version(),
               **{name: importlib.metadata.version(name) for name in
                  ('openai', 'httpx', 'boto3', 'google-genai')}}
    return {'head': head, 'files': manifest, 'content_digest': digest(manifest),
            'runtime': runtime, 'runtime_digest': digest(runtime)}


def check_account(metadata, spec, now=None):
    now = now or datetime.now(timezone.utc)
    rule = spec['account_precondition']
    try:
        checked = datetime.fromisoformat(metadata['checked_at'])
        age = (now - checked).total_seconds()
        remaining = metadata['remaining_calls']
        valid = (metadata['funded_verified'] is True and
                 type(remaining) is int and remaining >= rule['minimum_remaining_calls'] and
                 0 <= age <= rule['maximum_metadata_age_seconds'] and
                 metadata['source'] == 'openrouter-account-metadata')
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError('fresh funded-account metadata with >=400 remaining calls required')
    return {k: metadata[k] for k in ('checked_at', 'remaining_calls', 'funded_verified', 'source')}


class ArtifactStore:
    def __init__(self, root=DEFAULT_ROOT, repo=REPO):
        self.root = Path(root).resolve()
        self.repo = Path(repo).resolve()
        if self.root == Path('/tmp') or Path('/tmp') in self.root.parents or \
                self.root == Path('/dev/shm') or Path('/dev/shm') in self.root.parents:
            raise ValueError('durable artifact root cannot be ephemeral')
        try:
            relative = self.root.relative_to(self.repo)
        except ValueError:
            relative = None
        if relative is not None:
            checked = subprocess.run(['git', 'check-ignore', '-q', str(relative)], cwd=self.repo)
            tracked = subprocess.check_output(['git', 'ls-files', str(relative)], cwd=self.repo)
            if checked.returncode or tracked:
                raise ValueError('artifact root must be git-ignored and untracked')

    @contextmanager
    def locked(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / '.lock').open('a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def initialize(self, spec=None):
        spec = spec or load_spec()
        validate_spec(spec)
        rows = schedule(spec)
        preflight = structural_preflight(spec)
        freeze = {'benchmark_version': VERSION, 'schema': SCHEMA,
                  'provider_evidence_schema': PROVIDER_EVIDENCE_SCHEMA,
                  'source': source_snapshot(self.repo), 'spec_digest': digest(spec),
                  'scheduler_digest': digest(rows), 'treatment_digest': digest(spec['treatment']),
                  'preflight_digest': digest(preflight),
                  'attack_digest': digest([b['attack_spec'] for b in spec['bases']]),
                  'scoring_version': spec['scoring_version'],
                  'artifact_root': str(self.root)}
        freeze['freeze_digest'] = digest(freeze)
        with self.locked():
            if (self.root / 'freeze.json').exists():
                self.validate(spec)
                return freeze
            if list(self.root.glob('runs/*.json')) or list(self.root.glob('attempts/*.json')):
                raise ValueError('refuse reinitialization around existing attempts')
            copies = {'spec.json': spec, 'order.json': rows,
                      'pairs.json': spec['bases'], 'preflight.json': preflight}
            for name, value in copies.items():
                target = self.root / name
                if target.exists():
                    if read_json(target) != value:
                        raise ValueError('partial preparation identity mismatch')
                else:
                    atomic_json(target, value)
            atomic_json(self.root / 'freeze.json', freeze)
            self._progress(rows)
        return freeze

    def validate(self, spec=None):
        spec = spec or load_spec()
        validate_spec(spec)
        freeze = read_json(self.root / 'freeze.json')
        unsigned = {k: v for k, v in freeze.items() if k != 'freeze_digest'}
        if digest(unsigned) != freeze.get('freeze_digest'):
            raise ValueError('freeze integrity mismatch')
        if freeze['source'] != source_snapshot(self.repo):
            raise ValueError('source HEAD/content/runtime drift; STOP')
        if freeze['artifact_root'] != str(self.root):
            raise ValueError('artifact root drift')
        expected = {'spec.json': spec, 'order.json': schedule(spec),
                    'pairs.json': spec['bases'], 'preflight.json': structural_preflight(spec)}
        for name, value in expected.items():
            if read_json(self.root / name) != value:
                raise ValueError('frozen input/config drift: ' + name)
        if (freeze['spec_digest'] != digest(spec) or
                freeze['treatment_digest'] != digest(spec['treatment']) or
                freeze['scheduler_digest'] != digest(expected['order.json']) or
                freeze['preflight_digest'] != digest(expected['preflight.json']) or
                freeze['attack_digest'] != digest([b['attack_spec'] for b in spec['bases']]) or
                freeze['schema'] != SCHEMA or freeze['scoring_version'] != spec['scoring_version'] or
                freeze.get('provider_evidence_schema') != PROVIDER_EVIDENCE_SCHEMA):
            raise ValueError('freeze input identity mismatch')
        return freeze

    def records(self):
        spec = load_spec()
        self.validate(spec)
        expected = {r['run_key']: r for r in schedule(spec)}
        result = []
        for path in sorted((self.root / 'runs').glob('*.json')):
            envelope = read_json(path)
            record = envelope['record']
            key = record.get('run_key')
            if envelope['sha256'] != digest(record) or key not in expected or \
                    path.name != key + '.json' or record.get('input') != expected[key]:
                raise ValueError('artifact integrity/input mismatch')
            if record.get('freeze_digest') != read_json(self.root / 'freeze.json')['freeze_digest']:
                raise ValueError('artifact source/treatment mismatch')
            if record.get('execution_input_digest') != digest({
                    'input': expected[key], 'freeze_digest': record['freeze_digest']}):
                raise ValueError('source-bound execution input mismatch')
            validate_result(record)
            result.append(record)
        return result

    def missing(self):
        self.validate()
        if (self.root / 'STOP.json').exists():
            raise ValueError('benchmark stopped; no automatic resume')
        rows = schedule(load_spec())
        complete = {r['run_key'] for r in self.records()}
        expected = {r['run_key'] for r in rows}
        attempted = {p.stem for p in (self.root / 'attempts').glob('*.json')}
        if attempted - expected or attempted - complete:
            raise ValueError('unresolved attempted RunKey; no automatic replacement')
        return [r for r in rows if r['run_key'] not in complete]

    def _progress(self, rows):
        completed = sorted(p.stem for p in (self.root / 'runs').glob('*.json'))
        atomic_json(self.root / 'progress.json', {'scheduled': len(rows),
                    'terminal_run_keys': completed}, replace=True)

    def stop(self, reasons, evidence):
        path = self.root / 'STOP.json'
        if not path.exists():
            atomic_json(path, {'reasons': reasons, 'evidence': evidence})

    def run_next(self, execute, account_metadata, *, execution_authorized=False):
        if execution_authorized is not True:
            raise ValueError('separate benchmark execution authorization required')
        spec = load_spec()
        with self.locked():
            try:
                self.validate(spec)
            except ValueError:
                self.stop(['input_config_drift'], {'stage': 'before-run'})
                raise
            account = check_account(account_metadata, spec)
            remaining = self.missing()
            if not remaining:
                return None
            row = remaining[0]
            freeze = read_json(self.root / 'freeze.json')
            execution_input_digest = digest({'input': row, 'freeze_digest': freeze['freeze_digest']})
            atomic_json(self.root / 'attempts' / (row['run_key'] + '.json'),
                        {'input': row, 'freeze_digest': freeze['freeze_digest'],
                         'execution_input_digest': execution_input_digest, 'account': account})
            try:
                result = execute(dict(row))
            except Exception as exc:
                from ..providers.openrouter import OpenRouterProviderError
                critical = {k: False for k in STOPS}
                if isinstance(exc, OpenRouterProviderError):
                    critical['wrong_model'] = exc.code == 'routing_violation'
                    status = 'PROVIDER_INTERRUPTION'
                    reason = exc.code
                else:
                    critical['semantic_defect'] = True
                    status = 'PROVIDER_INTERRUPTION'
                    reason = type(exc).__name__
                result = {'schema': SCHEMA, 'status': status, 'metrics': None,
                          'critical': critical, 'interruption': reason}
            # Preserve measured evidence before classifying or validating it.
            record = {**result, 'run_key': row['run_key'], 'input': row,
                      'freeze_digest': freeze['freeze_digest'],
                      'execution_input_digest': execution_input_digest}
            atomic_json(self.root / 'runs' / (row['run_key'] + '.json'),
                        {'record': record, 'sha256': digest(record)})
            reasons = critical_stops(record)
            try:
                validate_result(record)
                self.validate(spec)
            except (ValueError, KeyError, TypeError):
                reasons.append('semantic_defect_or_input_drift')
            if record['status'] == 'PROVIDER_INTERRUPTION':
                reasons.append('provider_or_evaluator_interruption')
            self._progress(schedule(spec))
            if reasons:
                self.stop(reasons, {'run_key': row['run_key'], 'record_digest': digest(record)})
                raise ValueError('benchmark STOP: ' + ', '.join(reasons))
            return record
