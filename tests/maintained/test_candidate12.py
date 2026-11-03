import os
SRC = os.path.join(os.path.dirname(__file__), '..', 'programs', 'patrol_inspect_candidate12.py')
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

def run(s):
    return inspect(s)

fails = []
def check(name, cond):
    if cond:
        print('PASS', name)
    else:
        fails.append(name)
        print('FAIL', name)

# 1 healthy baseline unchanged
r = run(base())
check('healthy_action_none', r['action'] == 'none')
check('healthy_summary', '固定国内与代理健康检查通过' in r['summary'])
check('healthy_no_contradiction', '相互矛盾' not in r['summary'])

# 2 current 17:11 shape: node pool unavailable while fixed proxy check passes
s = base()
s['node_observations'] = {
    'state': 'unavailable', 'checked_at': NOW - 8,
    'events': [{'unavailable': True, 'preferred_failed': True, 'selected_region': None,
                'attempts': [{'region': 'US_AUTO', 'ok': False},
                             {'region': 'US_AUTO', 'ok': False},
                             {'region': 'OTHER_AUTO', 'ok': False}]}],
}
r = run(s)
check('pool_contradiction_action_none', r['action'] == 'none')
check('pool_contradiction_reported', '相互矛盾' in r['summary'])
check('pool_contradiction_no_recheck', '建议重新检测节点' not in r['summary'])
check('pool_contradiction_not_down', '认定用户路径中断' in r['summary'])

# 3 stale node observation must not be treated as current
s = base()
s['node_observations'] = dict(s['node_observations'])
s['node_observations']['state'] = 'unavailable'
s['node_observations']['checked_at'] = NOW - 7200
s['node_observations']['events'] = [{'unavailable': True, 'preferred_failed': True,
                                     'attempts': []}]
r = run(s)
check('stale_node_no_contradiction', '相互矛盾' not in r['summary'])

# 4 proxy failure still suggests bounded node recheck
s = base()
s['checks']['proxy_https'] = {'ok': False}
r = run(s)
check('proxy_fail_recheck', r['action'] == 'recheck_nodes')
check('proxy_fail_summary', '建议重新检测节点' in r['summary'])

# 5 stale client observations get an explicit caveat; fresh data does not
s = base()
s['observations'] = {'domains': [{'last_seen': NOW - 7200}]}
r = run(s)
check('stale_clients_reported', '超过一小时没有新连接' in r['summary'])
s = base()
r = run(s)
check('fresh_clients_silent', '超过一小时没有新连接' not in r['summary'])

# 6 unprobeable NXDOMAIN domain: record, no reprobe, no review request
s = base()
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'a.v.smtcdns.com', 'fingerprint': 'x'}],
    'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable',
                                              'error_category': 'ValueError'}}},
}
r = run(s)
check('unprobeable_summary', '没有可用的公共解析地址' in r['summary'])
check('unprobeable_not_probed', r['probe_domains'] == [])
check('unprobeable_no_review', 'review_request' not in r)

# 7 dual-path 4xx endpoint stays capped, no repeated review
s = base()
s['history'] = [{'at': NOW - 200 + i * 60, 'proxy_ms': 500,
                 'faults': ['client_business:amp-api-edge.apps.apple.com']} for i in range(2)]
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'amp-api-edge.apps.apple.com', 'fingerprint': 'y'}],
    'checks': {'amp-api-edge.apps.apple.com': {'result': {'paths': {
        'direct': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3},
        'proxy': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3}}}}},
}
r = run(s)
check('app_rejected_summary', '应用层拒绝' in r['summary'])
check('app_rejected_no_review', 'review_request' not in r)
check('app_rejected_not_probed', 'amp-api-edge.apps.apple.com' not in r['probe_domains'])

# 8 pending recovery is surfaced, not duplicated by a second action
s = base()
s['status']['pending_recovery'] = {'operation': 'recheck_nodes'}
r = run(s)
check('pending_recovery_reported', '系统已安排节点复检' in r['summary'])
check('pending_recovery_action_none', r['action'] == 'none')

# 9 same endpoint with >=8 recent rounds: capped, still no review or reprobe
s = base()
s['history'] = [{'at': NOW - 1000 + i * 60, 'proxy_ms': 500,
                 'faults': ['client_business:amp-api-edge.apps.apple.com']} for i in range(12)]
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'amp-api-edge.apps.apple.com', 'fingerprint': 'y'}],
    'checks': {'amp-api-edge.apps.apple.com': {'result': {'paths': {
        'direct': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3},
        'proxy': {'transport_ok': True, 'http_status': 404, 'failed_samples': 0, 'passed_samples': 3}}}}},
}
r = run(s)
check('probe_capped_summary', '已停止重复探测' in r['summary'])
check('probe_capped_no_review', 'review_request' not in r)
check('probe_capped_not_probed', 'amp-api-edge.apps.apple.com' not in r['probe_domains'])

print('FAILURES', len(fails))
raise SystemExit(1 if fails else 0)
