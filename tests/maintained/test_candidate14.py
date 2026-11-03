import os
SRC = os.path.join(os.path.dirname(__file__), '..', 'programs', 'patrol_inspect_candidate14.py')
ns = {}
exec(open(SRC, encoding='utf-8').read(), ns)
inspect = ns['inspect']

NOW = 1793713400

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
        'checked_at': NOW,
        'history': [{'at': NOW - 50, 'faults': [], 'proxy_ms': 500}],
        'quality_summary': {'preferred_pool': [{'name': 'a', 'alive': True},
                                               {'name': 'b', 'alive': True}]},
        'node_observations': {'state': 'healthy', 'checked_at': NOW - 10, 'events': []},
        'business_observations': {'checked_at': NOW, 'issues': [], 'checks': {}},
    }

def app_issue(domain='amp-api-edge.apps.apple.com', at=None):
    return {
        'checked_at': NOW,
        'issues': [{'domain': domain, 'fingerprint': 'fp'}],
        'checks': {domain: {'at': at if at is not None else NOW - 60,
                            'result': {'checked_at': at if at is not None else NOW - 60,
                                       'paths': {
                                           'direct': {'transport_ok': True, 'http_status': 404,
                                                      'failed_samples': 0, 'passed_samples': 3},
                                           'proxy': {'transport_ok': True, 'http_status': 404,
                                                     'failed_samples': 0, 'passed_samples': 3}}}}},
    }

fails = []
def check(name, cond):
    if cond:
        print('PASS', name)
    else:
        fails.append(name)
        print('FAIL', name)

# 1 healthy baseline: none, no review, no stale caveat
r = inspect(base())
check('healthy_action_none', r['action'] == 'none')
check('healthy_no_review', 'review_request' not in r)
check('healthy_no_stale_note', '路径对照样本' not in r['summary'])

# 2 proxy fixed-check failure + known app-layer endpoint: recheck nodes only, no duplicate review
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['history'] = [{'at': NOW - 1000 + i * 60, 'proxy_ms': 500,
                 'faults': ['client_business:amp-api-edge.apps.apple.com']} for i in range(12)]
s['business_observations'] = app_issue()
r = inspect(s)
check('proxy_fail_recheck', r['action'] == 'recheck_nodes')
check('proxy_fail_no_review', 'review_request' not in r)
check('proxy_fail_no_probe', r['probe_domains'] == [])
check('proxy_fail_note', '客户端端点复核留待固定路径恢复后' in r['summary'])

# 3 same but node recheck already pending: still no duplicate review
s = base()
s['checks']['proxy_https'] = {'ok': False}
s['status']['pending_recovery'] = {'operation': 'recheck_nodes', 'deadline': NOW + 120}
s['business_observations'] = app_issue()
r = inspect(s)
check('pending_recheck_action', r['action'] == 'recheck_nodes')
check('pending_recheck_no_review', 'review_request' not in r)
check('pending_recheck_no_probe', r['probe_domains'] == [])
check('pending_recheck_waits', '等待其完成后按新证据判断' in r['summary'])

# 4 recovered fixed paths: long-standing app-layer endpoint stays capped, no review
s = base()
s['history'] = [{'at': NOW - 1000 + i * 60, 'proxy_ms': 500,
                 'faults': ['client_business:amp-api-edge.apps.apple.com']} for i in range(12)]
s['business_observations'] = app_issue()
r = inspect(s)
check('recovered_app_rejected_no_review', 'review_request' not in r)
check('recovered_app_rejected_not_probed', r['probe_domains'] == [])
check('recovered_app_rejected_summary', '已停止重复探测' in r['summary'])

# 5 unprobeable endpoint: record only, no probe, no review
s = base()
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'a.v.smtcdns.com', 'fingerprint': 'x'}],
    'checks': {'a.v.smtcdns.com': {'at': NOW - 60,
                                   'result': {'state': 'probe_unavailable',
                                              'error_category': 'ValueError'}}},
}
r = inspect(s)
check('unprobeable_no_review', 'review_request' not in r)
check('unprobeable_no_probe', r['probe_domains'] == [])

# 6 sustained proxy latency alone: bounded node recheck, no client review
s = base()
s['history'] = [{'at': NOW - 400 + i * 60, 'proxy_ms': v, 'faults': []}
                for i, v in enumerate([400, 500, 600, 1300, 1400, 1500, 1250])]
r = inspect(s)
check('sustained_recheck', r['action'] == 'recheck_nodes')
check('sustained_no_review', 'review_request' not in r)

# 7 stale business path samples are called out with their age
s = base()
s['business_observations'] = app_issue(at=NOW - 4 * 3600)
r = inspect(s)
check('stale_business_reported', '路径对照样本约4小时前采集' in r['summary'])

# 8 fresh business path samples do not carry the stale caveat
s = base()
s['business_observations'] = app_issue(at=NOW - 300)
r = inspect(s)
check('fresh_business_silent', '路径对照样本' not in r['summary'])

# 9 endpoint whose transport fails on both paths is recorded, not re-probed
s = base()
s['business_observations'] = {
    'checked_at': NOW,
    'issues': [{'domain': 'apd-pcdnwxstat.teg.tencent-cloud.net', 'fingerprint': 'z'}],
    'checks': {'apd-pcdnwxstat.teg.tencent-cloud.net': {
        'at': NOW - 60,
        'result': {'checked_at': NOW - 60, 'paths': {
            'direct': {'transport_ok': False, 'failed_samples': 3, 'passed_samples': 0},
            'proxy': {'transport_ok': False, 'failed_samples': 3, 'passed_samples': 0}}}}},
}
r = inspect(s)
check('dial_only_no_probe', r['probe_domains'] == [])
check('dial_only_summary', '指向端点问题' in r['summary'])

print('FAILURES', len(fails))
raise SystemExit(1 if fails else 0)
