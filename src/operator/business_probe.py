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
            'transport_failed_samples':sum(not item['transport_ok'] for item in samples),
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


def endpoint_spec(value):
    if not isinstance(value,dict):return None
    network=value.get('network');port=value.get('port',value.get('destinationPort'))
    if isinstance(port,str) and port.isascii() and port.isdigit():port=int(port)
    if network not in ('tcp','udp') or type(port) is not int or not 1<=port<=65535:return None
    protocol=value.get('application_protocol','unknown')
    if protocol not in ('tcp','tls','http','https','udp','quic','dns','unknown'):return None
    if network=='tcp' and protocol in ('udp','quic','dns'):return None
    return {'network':network,'port':port,'application_protocol':protocol}


def compare_endpoint(target,endpoint,run_probe,now):
    """Relevant-stage evidence, never an inferred logged-in application result."""
    target=_target(target);endpoint=endpoint_spec(endpoint)
    result={'target':target,'endpoint':endpoint,'observed_at':now,'origin':'protected_synthetic_probe',
            'cached':False,'application_verified':False,'paths':{},'path_identity_verified':False}
    if endpoint is None:return {**result,'state':'insufficient_endpoint_evidence'}
    if endpoint['network']!='tcp':return {**result,'state':'unsupported_protocol'}
    protocol=endpoint['application_protocol'];stage='http_response' if protocol in ('http','https') else 'tls_handshake' if protocol=='tls' else 'tcp_connect'
    result['acceptance_stage']=stage;samples={'direct':[],'proxy':[]}
    for _ in range(3):
        for path in ('direct','proxy'):
            try:raw=run_probe(target,path=path)
            except Exception:raw={}
            raw=raw if isinstance(raw,dict) else {};status=raw.get('http_status')
            status=status if type(status) is int and 100<=status<=599 else None
            okay=(raw.get('connect_ok') is True if raw.get('target_dial_verified') is True else None) if stage=='tcp_connect' else raw.get('tls_ok') is True if stage=='tls_handshake' else status is not None and raw.get('transport_ok') is True
            elapsed=raw.get('elapsed_ms')
            if type(elapsed) not in (int,float) or not math.isfinite(elapsed) or not 0<=elapsed<=120000:elapsed=None
            samples[path].append({'stage_ok':okay,'path_verified':raw.get('path_verified') is True,
                'elapsed_ms':elapsed,'http_status':status,'content_ok':raw.get('content_ok') if type(raw.get('content_ok')) is bool else None,
                'business_rejected':status is not None and status>=400 or raw.get('content_ok') is False,
                'business_error_kind':raw.get('business_error_kind') if raw.get('business_error_kind') in ('region_rejected','rate_limited','server_error','auth_required') else None})
    for path,rows in samples.items():
        times=[x['elapsed_ms'] for x in rows if x['stage_ok'] and x['elapsed_ms'] is not None]
        result['paths'][path]={'sample_count':3,'success_samples':sum(x['stage_ok'] is True for x in rows),'failed_samples':sum(x['stage_ok'] is False for x in rows),
          'unknown_samples':sum(x['stage_ok'] is None for x in rows),
          'path_verified':all(x['path_verified'] for x in rows),'business_rejection_samples':sum(x['business_rejected'] for x in rows),
          'region_rejected_samples':sum(x['business_error_kind']=='region_rejected' for x in rows),
          'median_elapsed_ms':statistics.median(times) if times else None,'samples':rows}
    result['path_identity_verified']=all(x['path_verified'] for x in result['paths'].values())
    return {**result,'state':'insufficient_target_dial_evidence' if any(row['unknown_samples'] for row in result['paths'].values()) else 'observed'}
