"""候选程序回归断言：只依赖纯函数 inspect(snapshot)。"""
import importlib.util
import sys

PATH = '/var/lib/dsh/workspace/network-maintainer/programs/patrol_inspect_candidate5.py'
spec = importlib.util.spec_from_file_location('cand5', PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def snap(proxy_ok=True, mainland_ok=True, pool_alive=False, history=None, issues=None, checks=None):
    base_checks = {
        'proxy_https': {'ok': proxy_ok, 'result': {'expected_health_status': proxy_ok}},
        'mainland_https': {'ok': mainland_ok, 'result': {'expected_health_status': mainland_ok}},
        'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
        'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
    }
    if checks:
        base_checks.update(checks)
    domains = [{'name': 'US_%d' % i, 'alive': pool_alive} for i in range(12)]
    return {
        'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
        'checks': base_checks,
        'history': history or [],
        'quality_summary': {'preferred_pool': domains},
        'business_observations': {'issues': issues or [], 'checks': {}},
    }


results = []

# 1. 全部节点测速失败 + 固定路径健康 -> 不得建议刷新订阅/换节点
out = mod.inspect(snap(pool_alive=False))
results.append(('all_dead_but_healthy_no_action',
                out['action'] == 'none' and '不可信' in out['summary'], out))

# 2. 代理失败、国内正常 -> 仍建议重新检测节点
out = mod.inspect(snap(proxy_ok=False))
results.append(('proxy_failure_recheck_nodes', out['action'] == 'recheck_nodes', out))

# 3. 两条固定路径都失败 -> 不换节点
out = mod.inspect(snap(proxy_ok=False, mainland_ok=False))
results.append(('dual_failure_no_node_action', out['action'] == 'none', out))

# 4. 健康 -> none
out = mod.inspect(snap(pool_alive=True))
results.append(('healthy_none', out['action'] == 'none', out))

# 5. 持续客户端零字节端点（近12轮>=8次失败）-> 保留 review_request、不重复探测
hist = [{'at': i, 'faults': ['client_business:dead.example'],
         'faults_after_confirmation': ['client_business:dead.example']} for i in range(12)]
checks = {'dead.example': {'result': {'paths': {
    'direct': {'transport_ok': False, 'failed_samples': 3},
    'proxy': {'transport_ok': False, 'failed_samples': 3},
}}}}
out = mod.inspect(snap(pool_alive=True, history=hist,
                       issues=[{'domain': 'dead.example', 'fingerprint': 'fp1'}], checks=checks))
results.append(('recurring_client_no_reprobe',
                out.get('probe_domains') == [] and out.get('review_request', {}).get('fingerprint') == 'fp1',
                out))

# 6. 客户端连续失败(>=8/12)但固定路径健康 -> 按 v4 语义封顶探测，保留 review_request
checks2 = {'alive.example': {'result': {'paths': {
    'direct': {'transport_ok': True, 'passed_samples': 3},
    'proxy': {'transport_ok': True, 'passed_samples': 3},
}}}}
hist2 = [{'at': i, 'faults': ['client_business:alive.example']} for i in range(12)]
out = mod.inspect(snap(pool_alive=True, history=hist2,
                       issues=[{'domain': 'alive.example', 'fingerprint': 'fp2'}], checks=checks2))
results.append(('persistent_client_failure_probe_capped',
                out.get('probe_domains') == []
                and out.get('review_request', {}).get('fingerprint') == 'fp2', out))

# 7. 新出现的客户端失败(仅1轮) -> 仍允许定向探测，不封顶
hist3 = [{'at': i, 'faults': []} for i in range(11)] + [
    {'at': 11, 'faults': ['client_business:new.example']}]
out = mod.inspect(snap(pool_alive=True, history=hist3,
                       issues=[{'domain': 'new.example', 'fingerprint': 'fp3'}], checks=checks2))
results.append(('new_client_failure_probe_allowed',
                out.get('probe_domains') == ['new.example'], out))

failed = [name for name, ok, _ in results if not ok]
for name, ok, out in results:
    print(('PASS ' if ok else 'FAIL ') + name)
print('SUMMARY', len(results) - len(failed), '/', len(results), 'passed')
sys.exit(1 if failed else 0)
