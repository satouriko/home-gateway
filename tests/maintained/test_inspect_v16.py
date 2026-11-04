"""回归：固定检查瞬时失败时，不得把已连续多轮的客户端端点重新当成新问题。"""
import importlib.util, pathlib, sys

def load(path):
    spec = importlib.util.spec_from_file_location('inspect_mod', path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod.inspect

def snapshot(with_mainland=True):
    history = [{'at': 1000+i, 'faults': ['client_business:amp.example.com'],
                'faults_after_confirmation': ['client_business:amp.example.com']} for i in range(12)]
    return {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}, 'pending_recovery': None},
        'checks': {
            'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 300, 'expected_health_status': True}},
            'mainland_https': ({'ok': False, 'error': 'TimeoutError'} if with_mainland else
                               {'ok': True, 'result': {'http_status': 200, 'elapsed_ms': 120, 'expected_health_status': True}}),
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
        },
        'history': history,
        'quality_summary': {'preferred_pool': [{'alive': True}]},
        'business_observations': {'issues': [
            {'domain': 'amp.example.com', 'fingerprint': 'fpamp', 'resolved': False}]},
    }

v15 = load('programs/patrol_inspect_candidate15.py')
v16 = load('programs/patrol_inspect_candidate16.py')

# 复现 v15 缺陷：mainland 瞬时失败 + 已连续多轮失败的同一端点 -> 仍发 review_request
r15 = v15(snapshot(True))
assert r15.get('review_request'), ('v15 未复现缺陷', r15)

# v16：同一快照不再升级，且不谎称“固定检查正常”
r16 = v16(snapshot(True))
assert not r16.get('review_request'), r16
assert '固定检查正常' not in r16['summary'], r16['summary']
assert '国内直连检查失败' in r16['summary'], r16['summary']
assert r16['action'] == 'none', r16

# 双路径都失败的端点 + 固定检查异常：描述不得再写“固定检查正常”
dual = snapshot(True)
dual['business_observations'] = {'issues': [{'domain': 'drop.example.com', 'fingerprint': 'fpdrop', 'resolved': False}],
 'checks': {'drop.example.com': {'result': {'paths': {
   'direct': {'transport_ok': False, 'failed_samples': 3},
   'proxy': {'transport_ok': False, 'failed_samples': 3}}}}}}
rdual = v16(dual)
assert not rdual.get('review_request'), rdual
assert '固定检查当前异常' in rdual['summary'], rdual['summary']
assert '固定检查正常' not in rdual['summary'], rdual['summary']

# 固定检查健康时行为一致：也不升级已知端点
r16b = v16(snapshot(False))
assert not r16b.get('review_request'), r16b
assert '固定国内与代理健康检查通过' in r16b['summary'], r16b['summary']

# 不过度抑制：新端点（无历史故障）仍需复核
fresh = snapshot(False)
fresh['business_observations']['issues'] = [{'domain': 'new.example.com', 'fingerprint': 'fpnew', 'resolved': False}]
r = v16(fresh)
assert r.get('review_request'), r
assert 'new.example.com' in r['probe_domains'], r
print('v16 regression cases passed')
