"""Protected versioned operational policy; pure source never executes root actions."""
from contextlib import contextmanager
import ast
import builtins
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import sys
import tempfile
import time

# Isolated (-I) workers do not inherit the importing process's sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bounded import run as bounded_run
from programs import validate_source as validate_program_source, FUNCTIONS, bounded_range
from commit_messages import SECRET_PATTERNS

STATE = Path('/var/lib/net-gateway-agent')
BUILTIN = Path('/usr/local/share/net-gateway-agent/workflow.py')
INPUT_LIMIT = 131072
STATE_LIMIT = 262144
RESULT_KEYS = {'summary', 'wake', 'incident_ids', 'probe_domains', 'route_candidates', 'next_check_seconds'}


class DecisionError(ValueError):
    """Only static trusted output-validation diagnostics may cross worker stderr."""


def _encoded(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        raise ValueError('workflow data must be finite JSON') from None


def _secret(value):
    return any(re.search(pattern, value) for pattern in SECRET_PATTERNS)


def validate_source(source):
    tree = validate_program_source(source)
    args = tree.body[0].args
    if args.posonlyargs or args.kwonlyargs or args.kw_defaults or tree.body[0].type_comment:
        raise ValueError('expected one plain inspect(snapshot) argument')
    if _secret(source):
        raise ValueError('credential-like workflow source rejected')
    return tree


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _domain(value):
    return (isinstance(value, str) and len(value) <= 253 and
            re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value) is not None and
            value.rsplit('.', 1)[-1] not in {'local', 'localhost', 'internal', 'invalid', 'test', 'home', 'lan', 'onion'})


def validate_snapshot(snapshot):
    required = {'schema_version', 'now', 'path_health', 'incidents', 'observations', 'routing', 'audit'}
    if not isinstance(snapshot, dict) or not required <= set(snapshot) or type(snapshot['schema_version']) is not int or snapshot['schema_version'] != 1 or not _finite(snapshot['now']):
        raise ValueError('workflow schema_version=1 and explicit snapshot fields required')
    health = snapshot['path_health']
    if (not isinstance(health, dict) or not isinstance(health.get('checks'), dict) or
            not isinstance(health.get('hard_faults'), list) or len(health['hard_faults']) > 64 or
            any(not isinstance(name, str) or not 1 <= len(name) <= 160 for name in health['hard_faults'])):
        raise ValueError('explicit bounded path_health checks and hard_faults required')
    cases = snapshot['incidents']
    if not isinstance(cases, list) or len(cases) > 128:
        raise ValueError('bounded incidents required')
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get('id'), str) or not 1 <= len(case['id']) <= 160 or
                case['id'] in seen or case.get('status') not in {'open', 'working', 'verifying', 'blocked', 'closed'} or
                case.get('priority') not in {'urgent', 'normal'} or type(case.get('requires_attention')) is not bool or
                not _finite(case.get('next_review_at')) or not isinstance(case.get('facts'), dict)):
            raise ValueError('invalid incident attention contract')
        seen.add(case['id'])
    for key, nested in [('observations', 'domains'), ('routing', 'candidates')]:
        container = snapshot[key]
        if not isinstance(container, dict) or not isinstance(container.get(nested, []), list) or len(container.get(nested, [])) > 256:
            raise ValueError('bounded workflow ' + key + ' required')
        for entry in container.get(nested, []):
            if not isinstance(entry, dict) or not _domain(entry.get('domain')):
                raise ValueError('public domain workflow observations required')
    if not isinstance(snapshot['audit'], dict):
        raise ValueError('workflow audit object required')
    if len(_encoded(snapshot)) > INPUT_LIMIT - 16000:
        raise ValueError('workflow snapshot exceeds input budget')
    return snapshot


def validate_output(output, snapshot):
    if not isinstance(output, dict) or set(output) != RESULT_KEYS:
        raise DecisionError('workflow must return only explicit decision fields')
    if not isinstance(output['summary'], str) or len(output['summary']) > 1600 or _secret(output['summary']):
        raise DecisionError('bounded nonsensitive workflow summary required')
    if output['wake'] not in ['none', 'routine', 'urgent']:
        raise DecisionError('invalid workflow wake')
    if type(output['next_check_seconds']) is not int or not 30 <= output['next_check_seconds'] <= 900:
        raise DecisionError('workflow next check must be 30..900 seconds')
    ids = output['incident_ids']
    known = {case['id'] for case in snapshot['incidents']}
    if (not isinstance(ids, list) or len(ids) > 16 or any(not isinstance(ident, str) or ident not in known for ident in ids) or
            len(set(ids)) != len(ids)):
        raise DecisionError('workflow incident references must be known and bounded')
    for key in ['probe_domains', 'route_candidates']:
        values = output[key]
        if not isinstance(values, list) or len(values) > 3 or any(not _domain(value) for value in values) or len(set(values)) != len(values):
            raise DecisionError('at most three unique public domains required')
    candidates = {entry['domain'] for entry in snapshot['routing'].get('candidates', []) if entry.get('needs_route_review') is True}
    if not set(output['route_candidates']) <= candidates:
        raise DecisionError('route candidates require supplied current-path quality review evidence')
    if snapshot['path_health']['hard_faults'] and output['wake'] != 'urgent':
        raise DecisionError('confirmed hard faults require urgent wake')
    urgent = [case['id'] for case in snapshot['incidents'] if case['priority'] == 'urgent' and case['requires_attention']]
    if len(urgent) > 16:
        raise DecisionError('urgent attention overflow requires trusted maintenance; no case may be silently omitted')
    if urgent and (output['wake'] != 'urgent' or not set(urgent) <= set(ids)):

        raise DecisionError('urgent incidents requiring attention cannot be dropped or downgraded')
    encoded = _encoded(output)
    if _secret(encoded.decode()):
        raise DecisionError('credential-like workflow output rejected')
    if len(encoded) > 16384:
        raise DecisionError('workflow output budget exceeded')
    return output


def worker(source, snapshot):
    tree = validate_source(source)
    validate_snapshot(snapshot)
    safe = {name: getattr(builtins, name) for name in FUNCTIONS}
    safe['range'] = bounded_range
    scope = {'__builtins__': safe}
    exec(compile(tree, '<gateway-workflow>', 'exec'), scope)
    return validate_output(scope['inspect'](snapshot), snapshot)


def evaluate(source, snapshot):
    validate_source(source)
    validate_snapshot(snapshot)
    payload = _encoded({'source': source, 'snapshot': snapshot})
    if len(payload) > INPUT_LIMIT:
        raise ValueError('workflow input budget exceeded')
    args = [sys.executable, '-I', str(Path(__file__).resolve()), '--worker']
    if os.geteuid() == 0:
        args = ['/usr/sbin/runuser', '-u', 'dsh', '--', *args]
    result = bounded_run(args, input=payload.decode(), timeout=4, stdout_limit=16384, stderr_limit=2048,
                         env={'PATH': '/usr/bin:/bin', 'HOME': '/var/empty', 'LANG': 'C.UTF-8'})
    if result.returncode:
        # Worker emits only an exception class, never source/snapshot/secret values.
        detail = result.stderr.strip()[-160:] or 'worker exit ' + str(result.returncode)
        raise ValueError('workflow isolated evaluation failed: ' + detail)
    try:
        output = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise ValueError('invalid workflow worker JSON') from None
    return validate_output(output, snapshot)


def _fixture():
    return {'schema_version': 1, 'now': 1000, 'path_health': {'hard_faults': [], 'checks': {
        'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 100}},
        'mainland_https': {'ok': True, 'result': {'http_status': 200}}}}, 'incidents': [],
        'observations': {'domains': []}, 'routing': {'candidates': []},
        'audit': {'node_count': 4, 'previous_node_count': 5},
        'checks': {'proxy_https': {'ok': True}}, 'history': [{'at': 999, 'node_count': 5}],
        'business_observations': {'issues': []}}


def fixed_tests(source):
    """Immutable publisher fixtures use production schema, never legacy health inference."""
    validate_source(source)
    results = []
    case = {'id': 'protected-case', 'status': 'open', 'priority': 'urgent', 'reason': 'new observed business fault',
            'outcome': None, 'next_review_at': 1000, 'facts': {'current_failure': True},
            'evidence': ['protected:observation'], 'revision': 1, 'requires_attention': True}
    scenarios = [('healthy', None, 'none'), ('urgent_new', {}, 'urgent'),
        ('urgent_blocked_not_due', {'status': 'blocked', 'requires_attention': False, 'next_review_at': 1100}, 'none'),
        ('urgent_blocked_due', {'status': 'blocked'}, 'urgent'),
        ('failed_working_lease', {'status': 'working'}, 'urgent'),
        ('closed_not_due', {'status': 'closed', 'requires_attention': False, 'next_review_at': 1100, 'outcome': 'no_route_remedy'}, 'none'),
        ('unknown_business', {'id': 'protected-new-unknown', 'facts': {'unrecognized_failure': True}}, 'urgent'),
        ('normal_due', {'priority': 'normal'}, 'routine')]
    for name, changes, expected in scenarios:
        snapshot = _fixture()
        if changes is not None:
            current = copy.deepcopy(case); current.update(changes); snapshot['incidents'] = [current]
        result = evaluate(source, snapshot)
        if result['wake'] != expected:
            raise ValueError('protected workflow test failed: ' + name)
        if changes is not None and snapshot['incidents'][0]['requires_attention'] and snapshot['incidents'][0]['id'] not in result['incident_ids']:
            raise ValueError('protected workflow incident omitted: ' + name)
        results.append({'case': name, 'passed': True})
    snapshot = _fixture(); snapshot['path_health']['hard_faults'] = ['protected_control_route']
    if evaluate(source, snapshot)['wake'] != 'urgent':
        raise ValueError('protected hard fault test failed')
    results.append({'case': 'hard_fault', 'passed': True})
    for name, domain, extra in [
            ('healthy_faster_alternative', 'healthy.example.com', {'alternative_faster': True}),
            ('openai_direct_fast_region_denied', 'api.openai.com',
             {'alternative_faster': True, 'alternative_business_outcome': 'unsupported_region'}),
            ('tls_root4xx_unknown_business', 'unknown.example.com',
             {'tls_ok': True, 'http_status': 403, 'business_outcome': 'unknown'})]:
        snapshot = _fixture()
        snapshot['routing']['candidates'] = [dict(domain=domain, current_path_healthy=True, needs_probe=True, **extra)]
        snapshot['observations']['domains'] = [{'domain': domain, 'needs_probe': True}]
        result = evaluate(source, snapshot)
        if result['route_candidates'] or result['wake'] != 'none':
            raise ValueError('protected routing review negative failed: ' + name)
        results.append({'case': name, 'passed': True})
    try:
        evaluate(source, {})
    except ValueError:
        results.append({'case': 'missing_data', 'passed': True})
    else:
        raise ValueError('protected missing data test failed')
    return results


def _builtin():
    path = BUILTIN if BUILTIN.is_file() else Path(__file__).resolve().parent.parent / 'maintained/workflow.py'
    source = path.read_text()
    validate_source(source)
    return {'source': source, 'version': hashlib.sha256(source.encode()).hexdigest()[:16], 'tests': [], 'published_at': None}


@contextmanager
def _state():
    STATE.mkdir(parents=True, exist_ok=True)
    fd = os.open(STATE / 'workflow-state.json.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = STATE / 'workflow-state.json'
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as file:
                raw = file.read(STATE_LIMIT + 1)
            if len(raw.encode()) > STATE_LIMIT:
                raise ValueError('workflow storage exceeds byte budget')
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('format') != 1:
                raise ValueError('workflow storage requires recovery')
            for key in ['active', 'previous']:
                record = data.get(key)
                if record is not None and (not isinstance(record, dict) or not isinstance(record.get('source'), str) or
                        record.get('version') != hashlib.sha256(record['source'].encode()).hexdigest()[:16]):
                    raise ValueError('workflow version integrity failed')
        except FileNotFoundError:
            data = {'format': 1, 'active': None, 'previous': None}
        before = _encoded(data)
        yield data
        encoded = _encoded(data)
        if encoded == before:
            return
        if len(encoded) > STATE_LIMIT:
            raise ValueError('workflow storage exceeds byte budget')
        fd, name = tempfile.mkstemp(prefix='workflow-state.', dir=STATE)
        try:
            with os.fdopen(fd, 'wb') as file:
                file.write(encoded); file.flush(); os.fsync(file.fileno())
            os.replace(name, path)
            directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(name).unlink(missing_ok=True)


def workflow_action(operation, source=None):
    if operation not in {'workflow_status', 'workflow_test', 'workflow_publish'}:
        raise ValueError('unsupported workflow operation')
    if operation == 'workflow_status':
        with _state() as data:
            current = data['active'] or _builtin()
            return dict(current, active=data['active'] is not None, scope='pure operational decisions',
                        previous_version=(data.get('previous') or {}).get('version'), last_failure=data.get('last_failure'))
    tests = fixed_tests(source)
    version = hashlib.sha256(source.encode()).hexdigest()[:16]
    if operation == 'workflow_test':
        return {'tests': tests, 'version': version, 'deployed': False}
    with _state() as data:
        if not data.get('active') or data['active']['version'] != version:
            data['previous'] = data.get('active') or _builtin()
            data['active'] = {'source': source, 'version': version, 'tests': tests, 'published_at': time.time()}
        data.pop('last_failure', None)
    return {'tests': tests, 'version': version, 'deployed': True, 'scope': 'pure operational decisions'}


def _safe(snapshot):
    counts = ''
    try:
        validate_snapshot(snapshot)
        urgent = [case['id'] for case in snapshot['incidents'] if case['priority'] == 'urgent' and case['requires_attention']]
        normal = [case['id'] for case in snapshot['incidents'] if case['priority'] == 'normal' and case['requires_attention']]
        ids = (urgent + normal)[:16]
        counts = str(len(urgent)) + ' urgent and ' + str(len(normal)) + ' normal cases require attention. '
    except ValueError:
        ids = []
    return {'summary': counts + 'Workflow requires maintenance; retain independent network checks and incident ownership.',
            'wake': 'urgent', 'incident_ids': ids, 'probe_domains': [], 'route_candidates': [], 'next_check_seconds': 30}


def inspect_active(snapshot):
    # A malformed caller snapshot is not evidence that either published source failed.
    try:
        validate_snapshot(snapshot)
    except ValueError as error:
        return {'active': False, 'version': 'safe-builtin', 'result': _safe(snapshot), 'safe_fallback': True,
                'failures': [{'version': 'workflow-input', 'error': str(error)[:400]}], 'maintenance_required': True}
    failures = []
    try:
        with _state() as data:
            active = data.get('active')
            current = active or _builtin()
            failed_version = current['version']
            try:
                result = evaluate(current['source'], snapshot)
                return {'active': active is not None, 'version': current['version'], 'result': result,
                        'failures': [], 'maintenance_required': False}
            except Exception as error:
                failures.append({'version': current['version'], 'error': str(error)[:400]})
            previous = data.get('previous')
            if previous and previous['version'] != current['version']:
                try:
                    result = evaluate(previous['source'], snapshot)
                    data.update(active=previous, previous=None, last_failure={'at': time.time(), 'failures': failures})
                    return {'active': True, 'version': previous['version'], 'result': result, 'rolled_back': True,
                            'failed_version': failed_version, 'failures': failures, 'maintenance_required': True}
                except Exception as error:
                    failures.append({'version': previous['version'], 'error': str(error)[:400]})
            data.update(active=None, previous=None, last_failure={'at': time.time(), 'failures': failures})
            return {'active': False, 'version': 'safe-builtin', 'result': _safe(snapshot), 'safe_fallback': True,
                    'rolled_back': active is not None, 'failed_version': failed_version,
                    'failures': failures, 'maintenance_required': True}
    except Exception as error:
        failures.append({'version': 'workflow-storage', 'error': type(error).__name__ + ': workflow state unavailable'})
        return {'active': False, 'version': 'safe-builtin', 'result': _safe(snapshot), 'safe_fallback': True,
                'failures': failures, 'maintenance_required': True}


def _main():
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    signal.alarm(3)
    try:
        raw = sys.stdin.read(INPUT_LIMIT + 1)
        if len(raw.encode()) > INPUT_LIMIT:
            raise ValueError('workflow input budget exceeded')
        request = json.loads(raw)
        print(json.dumps(worker(request['source'], request['snapshot']), ensure_ascii=False, allow_nan=False))
    except BaseException as error:
        # A traceback would reproduce user-controlled source and possibly credentials.
        sys.stderr.write(type(error).__name__ + (': ' + str(error) if isinstance(error, DecisionError) else ''))
        return 1
    return 0


if __name__ == '__main__' and '--worker' in sys.argv:
    sys.exit(_main())
