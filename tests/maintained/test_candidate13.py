import os
SRC = os.path.join(os.path.dirname(__file__), '..', 'programs', 'patrol_inspect_candidate13.py')
ns = {}
exec(open(SRC, encoding='utf-8').read(), ns)
inspect = ns['inspect']

NOW = 1793697200

def ok_checks():
    return {
        'mainland_https': {'ok': True, 'result': {'expected_health_status': True}},
        'proxy_https': {'ok': True, 'result': {'expected_health_status': True}},
        'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
        'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        'bootstrap_dns_api': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
    }

def base():
    return {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}},
                   'pending_recovery': None},
        'checks': ok_checks(),
        'history': [{'at': NOW - 50, 'faults': [], 'proxy_ms': 500}],
        'quality_summary': {'preferred_pool': [{'name': 'a', 'alive': True},
                                               {'name': 'b', 'alive': True}]},
        'node_observations': {'state': 'healthy', 'checked_at': NOW - 10, 'events': []},
        'business_observations': {'checked_at': NOW, 'issues': [], 'checks': {}},
        'observations': {'status': 'observed', 'domains': [{'last_seen': NOW - 60}]},
    }

def amp_issue():
    return {
        'checked_at': NOW,
        'issues': [{'domain': 'amp-api-edge.apps.apple.com', 'fingerprint': 'y'}],
        'checks': {'amp-api-edge.apps.apple.com': {'result': {'paths': {
            'direct': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3},
            'proxy': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3}}}}},
    }

fails = []
def check(name, cond):
    if cond:
        print('PASS', name)
    else:
        fails.append(name)
        print('FAIL', name)

# 1 healthy baseline unchanged (regression against v12 behaviour)
r = inspect(base())
check('healthy_action_none', r['action'] == 'none')
check('healthy_no_review', 'review_request' not in r)
check('healthy_summary', '固定国内与代理健康检查通过' in r['summary'])

# 2 proxy failure alone still suggests bounded recheck (regression)
s = base()
s['checks']['proxy_https'] = {'ok': False}
r = inspect(s)
check('proxy_fail_recheck', r['action'] == 'recheck_nodes')
check('proxy_fail_summary', '建议重新检测节点' in r['summary'])
check('proxy_fail_no_issues_no_review', 'review_request' not in r)

# 3 proxy failure + pending recheck + reviewable client issue: defer, no duplicate review
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['status']['pending_recovery'] = {'operation': 'recheck_nodes', 'deadline': NOW + 95}
s['business_observations'] = amp_issue()
r = inspect(s)
check('pending_recheck_action', r['action'] == 'recheck_nodes')
check('pending_recheck_no_duplicate_review', 'review_request' not in r)
check('pending_recheck_defer_text', '待节点复检完成后按新证据复核' in r['summary'])

# 4 same shape without pending recovery: review request still emitted
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['business_observations'] = amp_issue()
r = inspect(s)
check('no_pending_review_kept', r.get('review_request', {}).get('fingerprint') == 'y')

# 5 expired pending recheck must not suppress the review
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['status']['pending_recovery'] = {'operation': 'recheck_nodes', 'deadline': NOW - 60}
s['business_observations'] = amp_issue()
r = inspect(s)
check('expired_pending_review_kept', r.get('review_request', {}).get('fingerprint') == 'y')

# 6 pending recheck of another operation type does not suppress review
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['status']['pending_recovery'] = {'operation': 'restore_gateway', 'deadline': NOW + 95}
s['business_observations'] = amp_issue()
r = inspect(s)
check('other_pending_review_kept', 'review_request' in r)

# 7 healthy fixed paths + capped endpoint: no review, no reprobe
s = base()
s['history'] = [{'at': NOW - 1000 + i * 60, 'proxy_ms': 500,
                 'faults': ['client_business:amp-api-edge.apps.apple.com']} for i in range(12)]
s['status']['pending_recovery'] = {'operation': 'recheck_nodes', 'deadline': NOW + 95}
s['business_observations'] = amp_issue()
r = inspect(s)
check('capped_no_review', 'review_request' not in r)
check('capped_not_probed', 'amp-api-edge.apps.apple.com' not in r['probe_domains'])

# 8 unprobeable NXDOMAIN domain stays recorded, not reprobed, no review
s = base()
s['status']['pending_recovery'] = {'operation': 'recheck_nodes', 'deadline': NOW + 95}
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'a.v.smtcdns.com', 'fingerprint': 'x'}],
    'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable',
                                              'error_category': 'ValueError'}}},
}
r = inspect(s)
check('unprobeable_no_review', 'review_request' not in r)
check('unprobeable_not_probed', r['probe_domains'] == [])
check('unprobeable_summary', '没有可用的公共解析地址' in r['summary'])

print('FAILURES', len(fails))
raise SystemExit(1 if fails else 0)
