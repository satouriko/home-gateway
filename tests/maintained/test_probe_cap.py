"""Regression: persistent client endpoint must not keep requesting probes.

Why this matters: patrol builds the program snapshot before running target
probes. The probe API raises ValueError for non-resolving hosts, and patrol
then records a `target:<domain>` fault for that cycle. That flips the fault
signature and re-triggers urgent AI. A persistent client endpoint therefore
must stop asking for repeated probes; the unresolved issue stays visible with
a stable review_request.

Run: python3 tests/test_probe_cap.py
"""
import json
import sys

sys.path.insert(0, '/usr/local/lib/net-gateway-agent')
from programs import evaluate  # noqa: E402

SOURCE = '/var/lib/dsh/workspace/network-maintainer/programs/patrol_inspect_candidate4.py'
DOMAIN = 'dead.example.com'


def snapshot(history_len, with_paths=False):
    history = [
        {'faults': ['client_business:' + DOMAIN],
         'faults_after_confirmation': ['client_business:' + DOMAIN],
         'proxy_ms': 420}
        for _ in range(history_len)
    ]
    checks = {
        'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 420,
                                                'expected_health_status': True}},
        'mainland_https': {'ok': True, 'result': {'http_status': 200, 'elapsed_ms': 60,
                                                   'expected_health_status': True}},
        'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
        'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
    }
    business = {'issues': [{'kind': 'recurring_client_failure', 'domain': DOMAIN,
                            'fingerprint': 'fp1', 'resolved': False}]}
    if with_paths:
        business['checks'] = {DOMAIN: {'at': 1, 'result': {'paths': {
            'direct': {'transport_ok': False, 'failed_samples': 3},
            'proxy': {'transport_ok': False, 'failed_samples': 3}}}}}
    return {'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}},
                       'policy': {'mode': 'rule'}},
            'checks': checks, 'history': history,
            'quality_summary': {'preferred_pool': []},
            'business_observations': business}


def main():
    source = open(SOURCE).read()
    cases = [
        ('persistent_without_cached_paths', snapshot(12), False, True),
        ('dual_path_failure_classified_external', snapshot(12, True), False, False),
        ('new_issue_still_probed', snapshot(2), True, True),
    ]
    for name, snap, want_probe, want_review in cases:
        result = evaluate(source, snap)
        probe = DOMAIN in result['probe_domains']
        review = 'review_request' in result
        assert probe == want_probe, (name, 'probe', probe)
        assert review == want_review, (name, 'review', review)
        print('PASS', name)
    healthy = {'checks': {'proxy_https': {'ok': True, 'result': {'http_status': 204}},
                          'mainland_https': {'ok': True, 'result': {'http_status': 200}}},
               'history': []}
    result = evaluate(source, healthy)
    assert result['action'] == 'none' and not result['probe_domains'], result
    print('PASS healthy')
    print(json.dumps({'tests': len(cases) + 1, 'status': 'passed'}))


if __name__ == '__main__':
    main()
