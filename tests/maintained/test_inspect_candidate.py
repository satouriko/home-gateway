"""本地回归：候选 inspect 对不同证据的判定（发布前运行）。"""
import ast
import json
from pathlib import Path

SOURCE = Path('/var/lib/dsh/workspace/network-maintainer/programs/patrol_inspect_candidate.py').read_text()
TREE = ast.parse(SOURCE)
assert len(TREE.body) == 1 and isinstance(TREE.body[0], ast.FunctionDef)
NAMESPACE = {}
exec(compile(TREE, '<candidate>', 'exec'), NAMESPACE)
inspect = NAMESPACE['inspect']


def healthy():
    return {
        'checks': {
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
            'mainland_https': {'ok': True, 'result': {'expected_health_status': True}},
            'proxy_https': {'ok': True, 'result': {'expected_health_status': True}},
        },
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
        'history': [{'proxy_ms': 450, 'faults': []} for _ in range(8)],
        'quality_summary': {'preferred_pool': [{'name': 'A', 'alive': True}, {'name': 'B', 'alive': True}]},
        'business_observations': {'issues': [], 'checks': {}},
        'observations': {'domains': []},
    }


def check(name, snapshot, expect):
    out = inspect(json.loads(json.dumps(snapshot)))
    for key, value in expect.items():
        assert out.get(key) == value, (name, key, out.get(key), value)
    print('ok', name, '| action=', out['action'], '| review=', 'review_request' in out, '| probes=', out['probe_domains'])


# 1 健康：不动作、不升级
check('healthy', healthy(), {'action': 'none', 'probe_domains': []})

# 2 代理失败而国内正常：建议重检节点
snap = healthy()
snap['checks']['proxy_https'] = {'ok': True, 'result': {'expected_health_status': False}}
check('proxy_failure', snap, {'action': 'recheck_nodes'})

# 3 检查缺失：不判断路径健康、不升级
snap = healthy()
snap['checks'] = {}
check('missing_checks', snap, {'action': 'none'})

# 4 真实客户端问题（历史有成功流量）：升级复核并要求定向探测
snap = healthy()
snap['business_observations']['issues'] = [{'domain': 'ios.chat.openai.com', 'fingerprint': 'fp-traffic', 'resolved': False}]
snap['observations']['domains'] = [{'domain': 'ios.chat.openai.com', 'connections_seen': 144, 'observed_bytes_lower_bound': 9942695}]
out = inspect(snap)
assert 'review_request' in out and out['probe_domains'] == ['ios.chat.openai.com'], out
print('ok client_issue_with_traffic | review=True probes=', out['probe_domains'])

# 5 从未成功、直连与代理同样失败的信标主机：保留观察，不升级、不重复探测
snap = healthy()
domain = 'apd-pcdnwxstat.teg.tencent-cloud.net'
snap['business_observations']['issues'] = [{'domain': domain, 'fingerprint': 'fp-beacon', 'resolved': False}]
snap['business_observations']['checks'] = {domain: {'result': {'paths': {
    'direct': {'transport_ok': False}, 'proxy': {'transport_ok': False}}}}}
snap['observations']['domains'] = [{'domain': domain, 'connections_seen': 0, 'observed_bytes_lower_bound': 0, 'failure_count': 5}]
check('beacon_dual_path_failure', snap, {'action': 'none', 'probe_domains': []})

# 6 同样的信标但客户端曾成功连接过：仍按真实客户端问题升级
snap = healthy()
snap['business_observations']['issues'] = [{'domain': domain, 'fingerprint': 'fp-beacon', 'resolved': False}]
snap['business_observations']['checks'] = {domain: {'result': {'paths': {
    'direct': {'transport_ok': False}, 'proxy': {'transport_ok': False}}}}}
snap['observations']['domains'] = [{'domain': domain, 'connections_seen': 3, 'observed_bytes_lower_bound': 2048}]
out = inspect(snap)
assert 'review_request' in out, out
print('ok beacon_with_prior_traffic | review=True probes=', out['probe_domains'])

# 7 追踪探测报错但双路径检查缺失、且从未成功：仍算端点问题（有报错证据）
snap = healthy()
snap['business_observations']['issues'] = [{'domain': domain, 'fingerprint': 'fp-beacon', 'resolved': False}]
snap['checks']['target:' + domain] = {'ok': False, 'error': 'ValueError'}
snap['observations']['domains'] = [{'domain': domain, 'connections_seen': 0, 'observed_bytes_lower_bound': 0}]
check('beacon_tracked_probe_error', snap, {'action': 'none', 'probe_domains': []})

# 8 缺证据（无观测记录）：不降级，保持升级
snap = healthy()
snap['business_observations']['issues'] = [{'domain': 'real.example.com', 'fingerprint': 'fp-missing', 'resolved': False}]
out = inspect(snap)
assert 'review_request' in out, out
print('ok client_issue_without_observations | review=True')
print('ALL CANDIDATE REGRESSION CASES PASSED')
