"""回归：新出现的“双路径可达但根路径 4xx”端点不得触发模型复核；
连续故障计数不得把持续的客户端工单写成链路故障连续出现。"""
import importlib.util


def load(path):
    spec = importlib.util.spec_from_file_location('inspect_mod', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.inspect


def snap(faults=None, issues=None, checks=None):
    faults = faults or []
    history = [{'at': 1000 + i, 'faults': faults,
                'faults_after_confirmation': faults} for i in range(6)]
    return {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}},
                   'pending_recovery': None},
        'checks': {
            'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 400,
                                                   'expected_health_status': True}},
            'mainland_https': {'ok': True, 'result': {'http_status': 200, 'elapsed_ms': 110,
                                                      'expected_health_status': True}},
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        },
        'history': history,
        'quality_summary': {'preferred_pool': [{'alive': True}, {'alive': True}]},
        'business_observations': {'checked_at': 1100, 'issues': issues or [], 'checks': checks or {}},
    }


def rejected(domain, status=403):
    path = {'transport_ok': True, 'http_status': status, 'failed_samples': 3,
            'passed_samples': 0, 'application_state': 'rejected'}
    return {domain: {'at': 1090, 'result': {'checked_at': 1090, 'paths': {
        'direct': dict(path), 'proxy': dict(path)}}}}


v16 = load('programs/patrol_inspect_candidate16.py')
v17 = load('programs/patrol_inspect_candidate17.py')

# A. 复现 v16 缺口：新出现的应用层 403 端点（无历史故障轮数）仍升级
app = snap(issues=[{'domain': 'mmec.example.com', 'fingerprint': 'fpapp'}],
           checks=rejected('mmec.example.com'))
r16 = v16(app)
assert r16.get('review_request'), ('v16 未复现缺口', r16)
r17 = v17(app)
assert not r17.get('review_request'), r17
assert 'mmec.example.com' not in r17['probe_domains'], r17
assert 'HTTP 4xx' in r17['summary'], r17['summary']
assert r17['action'] == 'none', r17

# B. 不过度抑制：没有任何探测数据的新端点仍需复核
fresh = snap(issues=[{'domain': 'new.example.com', 'fingerprint': 'fpnew'}])
assert v17(fresh).get('review_request'), v17(fresh)

# C. 持续的客户端工单不再写成“同一链路故障连续出现”
tickets = snap(faults=['client_business:mmec.example.com',
                       'client_business:apd.example.com',
                       'client_business:amp.example.com'],
               issues=[{'domain': 'apd.example.com', 'fingerprint': 'fpapd'}],
               checks={})
r16c = v16(tickets)
assert '同一故障连续出现6次' in r16c['summary'], ('v16 未复现', r16c['summary'])
r17c = v17(tickets)
assert '同一故障连续出现' not in r17c['summary'], r17c['summary']
assert '固定国内与代理健康检查通过' in r17c['summary'], r17c['summary']

# D. 真实固定路径故障仍然升级为节点复检
proxy_bad = snap()
proxy_bad['checks']['proxy_https'] = {'ok': False, 'error': 'URLError'}
r = v17(proxy_bad)
assert r['action'] == 'recheck_nodes', r

# E. 健康的真实采样（含历史路径故障后恢复）不得产生复核
healthy = snap()
assert v17(healthy)['action'] == 'none', v17(healthy)
assert not v17(healthy).get('review_request'), v17(healthy)
print('v17 regression cases passed')
