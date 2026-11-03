import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate10.py'
spec = importlib.util.spec_from_file_location('patrol10', p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

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

# 1) 生产快照形态：bootstrap 超时、国内/代理正常 -> 不换节点、不探测、明确记录
s = base()
s['checks']['bootstrap_dns_api'] = {'ok': False, 'error': 'TimeoutError'}
r = m.inspect(s)
assert r['action'] == 'none', r
assert r['probe_domains'] == [], r
assert '引导 DNS' in r['summary'], r
assert 'review_request' not in r, r
# 2) bootstrap 正常时不说这条
s2 = base(); s2['checks']['bootstrap_dns_api'] = {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}}
r2 = m.inspect(s2)
assert '引导 DNS' not in r2['summary'], r2
# 3) 快照无 bootstrap 键：保持原健康输出
r3 = m.inspect(base())
assert r3['action'] == 'none' and '健康检查通过' in r3['summary'], r3
# 4) bootstrap 失败 + 代理失败仍优先 recheck_nodes
s4 = base(); s4['checks']['bootstrap_dns_api'] = {'ok': False, 'error': 'TimeoutError'}
s4['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
r4 = m.inspect(s4)
assert r4['action'] == 'recheck_nodes', r4
# 5) v9 回归：国内失败仍不换节点
s5 = base(); s5['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r5 = m.inspect(s5)
assert r5['action'] == 'none' and '国内直连检查失败' in r5['summary'], r5
# 6) v8 回归：不可探测域名不重复探测
s6 = base(); s6['business_observations'] = {'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}}, 'issues': [{'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp'}]}
r6 = m.inspect(s6)
assert r6['action'] == 'none' and r6['probe_domains'] == [] and 'review_request' not in r6, r6
# 7) v8 回归：dial_only 不重复升级
s7 = base(); s7['business_observations'] = {'checks': {'dead.example.com': {'result': {'paths': {'direct': {'transport_ok': False, 'failed_samples': 3}, 'proxy': {'transport_ok': False, 'failed_samples': 3}}}}}, 'issues': [{'domain': 'dead.example.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp'}]}
r7 = m.inspect(s7)
assert r7['action'] == 'none' and 'review_request' not in r7, r7
print('candidate10 assertions passed: 7')
