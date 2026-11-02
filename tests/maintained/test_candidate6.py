import importlib.util, pathlib, sys
p = pathlib.Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate6.py'
spec = importlib.util.spec_from_file_location('cand6', p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

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

# 1) 本轮真实形态：国内与代理同时失败 + 节点池选路三次尝试全部失败 -> 应建议有界复检
ev = {'preferred_failed': True, 'unavailable': True,
      'attempts': [{'region': 'US_AUTO', 'ok': False}, {'region': 'US_AUTO', 'ok': False}, {'region': 'OTHER_AUTO', 'ok': False}]}
s = base(node_observations={'events': [ev]})
s['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
s['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r = m.inspect(s)
assert r['action'] == 'recheck_nodes', r
assert '首选美国池连续失败' in r['summary'], r

# 2) 国内与代理同时失败但没有节点选路证据 -> 保持保守不换节点
s2 = base(node_observations={'events': []})
s2['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
s2['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r2 = m.inspect(s2)
assert r2['action'] == 'none', r2
assert '不宜仅换节点' in r2['summary'], r2

# 3) 只有代理失败、国内正常 -> 仍推荐复检（既有行为）
s3 = base(node_observations={'events': []})
s3['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
r3 = m.inspect(s3)
assert r3['action'] == 'recheck_nodes', r3

# 4) 健康快照 -> 不建议动作（既有行为）
r4 = m.inspect(base(node_observations={'events': [{'preferred_failed': False, 'unavailable': False, 'attempts': [{'region': 'US_AUTO', 'ok': True}]}]}))
assert r4['action'] == 'none', r4
assert '健康检查通过' in r4['summary'], r4

# 5) 全部节点 alive=false 但固定代理通过 -> 不据此刷新订阅（v5 既有行为）
s5 = base(quality_summary={'preferred_pool': [{'alive': False}, {'alive': False}]})
r5 = m.inspect(s5)
assert r5['action'] == 'none', r5
assert '测速结果不可信' in r5['summary'], r5
print('candidate6 assertions passed: 5')
