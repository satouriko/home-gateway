import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate9.py'
spec = importlib.util.spec_from_file_location('patrol', p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def base(**kw):
    snap = {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
        'checks': {
            'proxy_https': {'ok': True, 'result': {'expected_health_status': True}},
            'mainland_https': {'ok': True, 'result': {'expected_health_status': True}},
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        },
        'history': [], 'quality_summary': {'preferred_pool': []},
    }
    snap.update(kw); return snap

# 1) v9 核心回归：国内直连失败、代理正常，不得输出“健康检查通过”
s1 = base(node_observations={'events': []})
s1['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r1 = m.inspect(s1)
assert r1['action'] == 'none', r1
assert '国内直连检查失败' in r1['summary'], r1
assert '健康检查通过' not in r1['summary'], r1
assert r1['probe_domains'] == [], r1

# 2) 国内失败时不得建议换节点（换节点修不了直连）
assert r1['action'] != 'recheck_nodes', r1

# 3) 回归：仅代理失败仍建议 recheck_nodes
s3 = base(node_observations={'events': []})
s3['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
r3 = m.inspect(s3)
assert r3['action'] == 'recheck_nodes', r3
assert '代理路径失败而国内直连正常' in r3['summary'], r3

# 4) 回归：健康快照 action=none 且明确健康
r4 = m.inspect(base(node_observations={'events': [{'preferred_failed': False, 'unavailable': False, 'attempts': [{'region': 'US_AUTO', 'ok': True}]}]}))
assert r4['action'] == 'none', r4
assert '健康检查通过' in r4['summary'], r4

# 5) 回归：不可解析客户端域名仍不探测、不升级
s5 = base()
s5['business_observations'] = {
    'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}},
    'issues': [{'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-a'}],
}
r5 = m.inspect(s5)
assert r5['action'] == 'none', r5
assert r5['probe_domains'] == [], r5
assert 'review_request' not in r5, r5
assert '没有可用的公共解析地址' in r5['summary'], r5

# 6) 回归：双失败且首选池失败 -> recheck_nodes
ev = {'preferred_failed': True, 'unavailable': True,
      'attempts': [{'region': 'US_AUTO', 'ok': False}, {'region': 'US_AUTO', 'ok': False}, {'region': 'OTHER_AUTO', 'ok': False}]}
s6 = base(node_observations={'events': [ev]})
s6['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
s6['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r6 = m.inspect(s6)
assert r6['action'] == 'recheck_nodes', r6
assert '首选美国池连续失败' in r6['summary'], r6
print('candidate9 assertions passed: 6')
