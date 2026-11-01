"""Classify bounded root-controlled direct/proxy probes without changing policy.

The injected transport must pin DNS and public destination addresses, prohibit
redirect following, enforce time/byte limits, and verify the selected path.
HTTP root reachability alone is not proof of a real application's usability.
"""
import math
import statistics
from urllib.parse import urlsplit

from traffic import hostname


SAMPLES_PER_PATH = 3


def _target(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(char) < 33 for char in value):
        raise ValueError('expected a public DNS hostname or HTTPS root')
    if '://' in value:
        try:
            parsed = urlsplit(value)
            if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None, 443):
                raise ValueError('expected a public HTTPS root')
        except ValueError:
            raise ValueError('expected a public HTTPS root') from None
        if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ValueError('only the HTTPS root is permitted')
        value = parsed.hostname
    domain = hostname(value)
    if domain is None:
        raise ValueError('expected a public DNS hostname')
    return domain


def _sample(result):
    result = result if isinstance(result, dict) else {}
    transport = result.get('transport_ok') is True
    status = result.get('http_status')
    status = status if type(status) is int and 100 <= status <= 599 else None
    http_ok = transport and status is not None and 200 <= status < 300
    content = result.get('content_ok')
    content = content if type(content) is bool else None
    if not transport:
        application = 'unverified'
    elif status == 429:
        application = 'rate_limited'
    elif status is not None and status >= 500:
        application = 'server_error'
    elif status is not None and (not http_ok or content is False):
        application = 'rejected'
    elif http_ok and content is True:
        application = 'healthy'
    else:
        application = 'unverified'
    business = False if not http_ok else content
    elapsed = result.get('elapsed_ms')
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not 0 <= elapsed <= 120000 or not math.isfinite(elapsed):
        elapsed = None
    return {'transport_ok': transport, 'http_status': status, 'http_ok': http_ok,
            'business_ok': business, 'usable': business is True,
            'application_state': application, 'elapsed_ms': elapsed,
            'path_verified': result.get('path_verified') is True}


def _path(samples):
    failed = sum(item['business_ok'] is False for item in samples)
    passed = sum(item['business_ok'] is True for item in samples)
    elapsed = [item['elapsed_ms'] for item in samples if item['http_ok'] and item['elapsed_ms'] is not None]
    states = [item['application_state'] for item in samples]
    if all(item == 'healthy' for item in states):
        application = 'healthy'
    else:
        application = next((kind for kind in ('rate_limited', 'server_error', 'rejected') if states.count(kind) >= 2), 'unverified')
    return {'sample_count': len(samples), 'transport_ok': all(item['transport_ok'] for item in samples),
            'http_ok': all(item['http_ok'] for item in samples),
            'business_ok': True if passed == len(samples) else False if failed else None,
            'usable': passed == len(samples), 'application_state': application,
            'path_verified': all(item['path_verified'] for item in samples),
            'passed_samples': passed, 'failed_samples': failed,
            'median_elapsed_ms': statistics.median(elapsed) if elapsed else None,
            'samples': samples}


def compare(target, run_probe, now):
    """Run three samples of each protected path; produce evidence/review hints only."""
    target = _target(target)
    samples = {'direct': [], 'proxy': []}
    for _ in range(SAMPLES_PER_PATH):
        for path in ('direct', 'proxy'):
            try:
                result = run_probe(target, path=path)
            except Exception:
                # Exception messages may contain proxy URLs, credentials or body text.
                result = {'transport_ok': False}
            samples[path].append(_sample(result))
    paths = {path: _path(values) for path, values in samples.items()}
    verified = all(item['path_verified'] for item in paths.values())
    issues = []
    for path, evidence in paths.items():
        other = 'proxy' if path == 'direct' else 'direct'
        if evidence['failed_samples'] >= 2:
            issue = {'kind': 'recurring_path_failure', 'domain': target, 'path': path,
                     'failed_samples': evidence['failed_samples'],
                     'application_state': evidence['application_state'], 'action': 'investigate'}
            if verified and paths[other]['passed_samples'] >= 2:
                issue.update(preferred_path=other, action='review_domain_policy')
            issues.append(issue)
    if not issues and verified and all(item['usable'] for item in paths.values()):
        direct, proxy = paths['direct']['median_elapsed_ms'], paths['proxy']['median_elapsed_ms']
        if direct is not None and proxy is not None:
            faster = 'direct' if direct < proxy else 'proxy'
            slower = 'proxy' if faster == 'direct' else 'direct'
            fast_times = [item['elapsed_ms'] for item in samples[faster] if item['elapsed_ms'] is not None]
            slow_times = [item['elapsed_ms'] for item in samples[slower] if item['elapsed_ms'] is not None]
            if len(fast_times) == 3 and len(slow_times) == 3 and min(slow_times) >= max(fast_times) * 2 and min(slow_times) - max(fast_times) >= 200:
                issues.append({'kind': 'repeated_latency_gap', 'domain': target, 'preferred_path': faster,
                               'action': 'review_only', 'slower_path': slower})
    return {'target': target, 'checked_at': now, 'origin': 'protected_synthetic_probe',
            'paths': paths, 'path_identity_verified': verified,
            'business_evidence': 'probe_endpoint_only_not_real_client_application',
            'issue_candidates': issues, 'policy_changed': False,
            'counters': {'samples': 6, 'failed_samples': sum(item['failed_samples'] for item in paths.values()),
                         'unverified_business_samples': sum(item['business_ok'] is None for values in samples.values() for item in values),
                         'transient_paths': sum(item['failed_samples'] == 1 for item in paths.values()),
                         'recurring_failure_paths': sum(item['failed_samples'] >= 2 for item in paths.values())}}
