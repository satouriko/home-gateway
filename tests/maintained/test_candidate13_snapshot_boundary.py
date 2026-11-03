"""Reproduce the production snapshot boundary for the v12 staleness branch.

patrol.main() passes {diagnosis, history, quality_summary} to inspect(); it never
passes traffic_status()/observations. broker.quality() *does* contain
client_observations, but patrol keeps only preferred_pool/active_domains.
"""
import os
SRC = os.path.join(os.path.dirname(__file__), '..', 'programs', 'patrol_inspect_candidate12.py')
ns = {}
exec(open(SRC, encoding='utf-8').read(), ns)
inspect = ns['inspect']

NOW = 1793697365
POOL = [{'name': 'California (G18)', 'alive': True, 'history': [{'delay': 800}]}] * 3

def checks():
    return {
        'mainland_https': {'ok': True, 'result': {'expected_health_status': True, 'http_status': 200}},
        'proxy_https': {'ok': True, 'result': {'expected_health_status': True, 'http_status': 204}},
        'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
        'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        'bootstrap_dns_api': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
    }

def issues():
    return [
        {'domain': 'apd-pcdnwxstat.teg.tencent-cloud.net', 'kind': 'recurring_client_failure', 'resolved': False, 'fingerprint': 'f1'},
        {'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'resolved': False, 'fingerprint': 'f2'},
        {'domain': 'amp-api-edge.apps.apple.com', 'kind': 'recurring_client_failure', 'resolved': False, 'fingerprint': 'f3'},
    ]

def transport_fail():
    return {'sample_count': 3, 'transport_ok': False, 'failed_samples': 3,
            'samples': [{'transport_ok': False}] * 3}

def rejected_404():
    return {'sample_count': 3, 'transport_ok': True, 'failed_samples': 3, 'http_status': 404,
            'samples': [{'transport_ok': True, 'http_status': 404}] * 3}

def business_checks():
    return {
        'apd-pcdnwxstat.teg.tencent-cloud.net': {'at': NOW - 900, 'result': {'paths': {'direct': transport_fail(), 'proxy': transport_fail()}}},
        'amp-api-edge.apps.apple.com': {'at': NOW - 500, 'result': {'paths': {'direct': rejected_404(), 'proxy': rejected_404()}}},
        'a.v.smtcdns.com': {'at': NOW - 600, 'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}},
    }

def patrol_snapshot():
    """Shape produced by patrol.main: no traffic_status / observations key."""
    return {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}, 'pending_recovery': None,
                   'policy': {'mode': 'rule'}},
        'checks': checks(),
        'node_observations': {'state': 'healthy', 'urgent': False, 'checked_at': NOW - 5, 'events': [
            {'attempts': [{'region': 'US_AUTO', 'ok': True}], 'preferred_failed': False, 'unavailable': False}]},
        'business_observations': {'checked_at': NOW, 'issues': issues(), 'checks': business_checks()},
        'history': [{'at': NOW - 95 * (12 - i), 'faults': [
            'client_business:apd-pcdnwxstat.teg.tencent-cloud.net',
            'client_business:a.v.smtcdns.com',
            'client_business:amp-api-edge.apps.apple.com'], 'proxy_ms': 500 + i} for i in range(12)],
        'quality_summary': {'preferred_pool': POOL, 'active_domains': {}},
    }

base = inspect(patrol_snapshot())
assert '客户端观测超过一小时' not in base['summary'], base['summary']
assert base['action'] == 'none', base['action']
assert 'review_request' not in base, base

# If the same data were delivered, the branch would work: proves input gap, not logic gap.
with_obs = patrol_snapshot()
with_obs['observations'] = {'domains': [{'last_seen': NOW - 6 * 3600}], 'devices': [{'last_seen': NOW - 6 * 3600}]}
res = inspect(with_obs)
assert '客户端观测超过一小时' in res['summary'], res['summary']

# The dead branch must not suppress real fixed-path failure advice.
broken = patrol_snapshot()
broken['checks']['proxy_https'] = {'ok': False, 'error': 'TimeoutError'}
assert inspect(broken)['action'] == 'recheck_nodes'
print('boundary reproduction: OK (production snapshot lacks observations; no staleness note)')
