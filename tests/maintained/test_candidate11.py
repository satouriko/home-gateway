import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate11.py'
spec = importlib.util.spec_from_file_location('patrol11', p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

DOMAIN = 'amp-api-edge.apps.apple.com'

def base(**kw):
    snap = {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
        'checks': {
            'proxy_https': {'ok': True, 'result': {'expected_health_status': True}},
            'mainland_https': {'ok': True, 'result': {'expected_health_status': True}},
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        },
        'history': [], 'quality_summary': {'preferred_pool': []}, 'node_observations': {'events': []},
    }
    snap.update(kw); return snap

def paths(direct_status=404, proxy_status=404, direct_ok=True, proxy_ok=True):
    return {'paths': {
        'direct': {'transport_ok': direct_ok, 'http_status': direct_status, 'passed_samples': 0, 'failed_samples': 3},
        'proxy': {'transport_ok': proxy_ok, 'http_status': proxy_status, 'passed_samples': 0, 'failed_samples': 3},
    }}

def issue_snap(recent, business_check=None, **kw):
    hist = []
    for _ in range(recent):
        hist.append({'proxy_ms': 500, 'faults': ['client_business:' + DOMAIN],
                     'faults_after_confirmation': ['client_business:' + DOMAIN]})
    bc = business_check if business_check is not None else paths()
    snap = base(history=hist, **kw)
    snap['business_observations'] = {
        'checks': {DOMAIN: {'result': bc}},
        'issues': [{'domain': DOMAIN, 'kind': 'recurring_client_failure', 'fingerprint': 'fp-apple'}],
    }
    return snap

# 1) 生产形态：已连续 2 轮，直连/代理传输可达但根路径 404 -> 保留记录、不探测、不再请求复核
r1 = m.inspect(issue_snap(2))
assert r1['action'] == 'none', r1
assert r1['probe_domains'] == [], r1
assert 'review_request' not in r1, r1
assert '应用层拒绝' in r1['summary'], r1
assert '不可' in r1['summary'] or '未验证' in r1['summary'], r1

# 2) 首轮出现仍请求一次定向复核（不能一出现就静默）
r2 = m.inspect(issue_snap(1))
assert r2.get('review_request', {}).get('fingerprint') == 'fp-apple', r2

# 3) 连续 >=8 轮但端点可达（非应用拒绝）应停止升级，且不再发 review_request
r3 = m.inspect(issue_snap(8, paths(direct_status=200, proxy_status=200)))
assert r3['action'] == 'none', r3
assert 'review_request' not in r3, r3
assert r3['probe_domains'] == [], r3

# 4) 固定路径退化时不得用“应用层拒绝”压制复核
s4 = issue_snap(2)
s4['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r4 = m.inspect(s4)
assert 'review_request' in r4, r4
assert '应用层拒绝' not in r4['summary'], r4

# 5) 代理传输失败时也不算应用层拒绝，仍需复核
r5 = m.inspect(issue_snap(2, paths(proxy_ok=False)))
assert 'review_request' in r5, r5
assert '应用层拒绝' not in r5['summary'], r5

# 6) v8 回归：不可探测域名不重复探测
s6 = base()
s6['business_observations'] = {'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}}, 'issues': [{'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp'}]}
r6 = m.inspect(s6)
assert r6['action'] == 'none' and r6['probe_domains'] == [] and 'review_request' not in r6, r6

# 7) v10 回归：bootstrap 超时仍不换节点
s7 = base(); s7['checks']['bootstrap_dns_api'] = {'ok': False, 'error': 'TimeoutError'}
r7 = m.inspect(s7)
assert r7['action'] == 'none' and '引导 DNS' in r7['summary'], r7
print('candidate11 assertions passed: 7')
