import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate8.py'
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

def hist(domain, n):
    return [{'at': i, 'faults': ['client_business:' + domain], 'faults_after_confirmation': ['client_business:' + domain]} for i in range(n)]

# 1) 既有：国内与代理同时失败 + 节点池选路失败 -> 有界复检
ev = {'preferred_failed': True, 'unavailable': True,
      'attempts': [{'region': 'US_AUTO', 'ok': False}, {'region': 'US_AUTO', 'ok': False}, {'region': 'OTHER_AUTO', 'ok': False}]}
s = base(node_observations={'events': [ev]})
s['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
s['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r = m.inspect(s)
assert r['action'] == 'recheck_nodes', r
assert '首选美国池连续失败' in r['summary'], r

# 2) 国内与代理同时失败且无节点证据 -> 保守不换节点
s2 = base(node_observations={'events': []})
s2['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
s2['checks']['mainland_https'] = {'ok': False, 'error': 'URLError'}
r2 = m.inspect(s2)
assert r2['action'] == 'none', r2
assert '不宜仅换节点' in r2['summary'], r2

# 3) 只有代理失败 -> recheck_nodes
s3 = base(node_observations={'events': []})
s3['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
r3 = m.inspect(s3)
assert r3['action'] == 'recheck_nodes', r3

# 4) 健康快照 -> action none
r4 = m.inspect(base(node_observations={'events': [{'preferred_failed': False, 'unavailable': False, 'attempts': [{'region': 'US_AUTO', 'ok': True}]}]}))
assert r4['action'] == 'none', r4
assert '健康检查通过' in r4['summary'], r4

# 5) 全部节点 alive=false 但固定代理通过 -> 不据此刷新订阅
s5 = base(quality_summary={'preferred_pool': [{'alive': False}, {'alive': False}]})
r5 = m.inspect(s5)
assert r5['action'] == 'none', r5
assert '测速结果不可信' in r5['summary'], r5

# 6) v7 形态：checks 里的 target:<domain> ValueError -> 不探测、不升级
s6 = base()
s6['checks']['target:a.v.smtcdns.com'] = {'ok': False, 'error': 'ValueError'}
s6['business_observations'] = {'checks': {}, 'issues': [
    {'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-a'},
]}
r6 = m.inspect(s6)
assert r6['action'] == 'none', r6
assert r6['probe_domains'] == [], r6
assert 'review_request' not in r6, r6
assert '没有可用的公共解析地址' in r6['summary'], r6

# 7) 不可解析域名不应遮蔽另一个可探测的客户端端点
s7 = base()
s7['checks']['target:a.v.smtcdns.com'] = {'ok': False, 'error': 'ValueError'}
s7['business_observations'] = {'checks': {}, 'issues': [
    {'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-a'},
    {'domain': 'real.example', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-b'},
]}
r7 = m.inspect(s7)
assert r7['probe_domains'] == ['real.example'], r7
assert 'review_request' in r7, r7

# 8) 无合成检查且连续多轮失败的端点仍保留复核请求（不遮蔽真实问题）
s8 = base(history=hist('apd.example', 12))
s8['business_observations'] = {'checks': {}, 'issues': [
    {'domain': 'apd.example', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-c'},
]}
r8 = m.inspect(s8)
assert r8['action'] == 'none', r8
assert r8['probe_domains'] == [], r8
assert r8['review_request']['fingerprint'] == 'fp-c', r8

# 9) v8 回归：真实快照形态（business_observations.checks.<domain>.result
#    state=probe_unavailable, error_category=ValueError）-> 不重复探测、不升级
s9 = base(history=hist('a.v.smtcdns.com', 8))
s9['business_observations'] = {
    'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}},
    'issues': [{'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-a'}],
}
r9 = m.inspect(s9)
assert r9['action'] == 'none', r9
assert r9['probe_domains'] == [], r9
assert 'review_request' not in r9, r9
assert '没有可用的公共解析地址' in r9['summary'], r9
assert '不是代理或分流故障' in r9['summary'], r9

# 10) v8 回归：真实形态的不可解析域名 + 另一真实端点 -> 仍请求复核后者
s10 = base(history=hist('a.v.smtcdns.com', 8) + hist('real.example', 2))
s10['business_observations'] = {
    'checks': {'a.v.smtcdns.com': {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}},
    'issues': [
        {'domain': 'a.v.smtcdns.com', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-a'},
        {'domain': 'real.example', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-b'},
    ],
}
r10 = m.inspect(s10)
assert r10['action'] == 'none', r10
assert r10['probe_domains'] == ['real.example'], r10
assert 'review_request' in r10, r10
assert r10['review_request']['fingerprint'] == 'fp-b', r10

# 11) v8 边界：probe_unavailable 但不是解析错误（如 TimeoutError）-> 不静默
s11 = base(history=hist('slow.example', 2))
s11['business_observations'] = {
    'checks': {'slow.example': {'result': {'state': 'probe_unavailable', 'error_category': 'TimeoutError'}}},
    'issues': [{'domain': 'slow.example', 'kind': 'recurring_client_failure', 'fingerprint': 'fp-t'}],
}
r11 = m.inspect(s11)
assert 'review_request' in r11, r11
assert r11['probe_domains'] == ['slow.example'], r11
print('candidate8 assertions passed: 11')
