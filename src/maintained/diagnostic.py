# 保守巡检分析：健康时不建议操作；只有能区分原因的持续证据才建议有界修复。
# 只读快照与 history；不把单次成功、单次慢、存活状态或小样本当成整条路径健康。
# v5：修正“偏好池全部 alive=false 就建议刷新订阅”的误动作。实测该标记会整体失真：
# 2026-11-02 05:32-05:33 全部 12 个美国节点 alive=false（delay 0），而同一时段受保护
# probe_compare 经该池节点代理成功（baidu 200、3/3 样本）、真实客户端也有代理流量。
# 该分支只在固定国内+代理检查都通过时才会到达，此时“全部节点不可用”与实测矛盾，
# 刷新订阅属于多余风险动作。改为仅记录“节点测速结果不可信、不作为动作依据”，
# 仍保留真实的代理失败分支（recheck_nodes）与持续时延分支。
# v4：修复“持续客户端端点”反复探测导致的升级循环（评估快照里没有 target: 检查，
# 旧版靠 probe_failed 判定外部端点恒为假）。固定路径健康且同一客户端故障在多轮
# 历史中持续出现时停止重复请求探测，保留稳定指纹的 review_request。

def inspect(snapshot):
    checks = snapshot.get('checks', {})
    status = snapshot.get('status', {})
    services = status.get('services', {})
    history = snapshot.get('history', [])
    quality = snapshot.get('quality_summary', {})

    proxy_present = 'proxy_https' in checks
    mainland_present = 'mainland_https' in checks
    proxy = checks.get('proxy_https', {})
    proxy_result = proxy.get('result', {})
    proxy_bad = proxy_present and (
        proxy.get('ok') is not True or proxy_result.get('expected_health_status') is False
    )

    mainland = checks.get('mainland_https', {})
    mainland_result = mainland.get('result', {})
    mainland_bad = mainland_present and (
        mainland.get('ok') is not True or mainland_result.get('expected_health_status') is False
    )

    dns_cn = checks.get('gateway_dns_cn', {})
    dns_cn_result = dns_cn.get('result', {})
    dns_cn_count = dns_cn_result.get('answer_count', 1)
    dns_cn_bad = 'gateway_dns_cn' in checks and (
        dns_cn.get('ok') is not True
        or dns_cn_result.get('rcode', 0) != 0
        or (dns_cn_count is not None and dns_cn_count < 1)
    )

    dns_foreign = checks.get('gateway_dns_foreign', {})
    dns_foreign_result = dns_foreign.get('result', {})
    dns_foreign_count = dns_foreign_result.get('answer_count', 1)
    dns_foreign_bad = 'gateway_dns_foreign' in checks and (
        dns_foreign.get('ok') is not True
        or dns_foreign_result.get('rcode', 0) != 0
        or (dns_foreign_count is not None and dns_foreign_count < 1)
    )

    service_bad = services.get('net-gateway.service', {}).get('ActiveState', 'active') != 'active'

    pool = quality.get('preferred_pool', [])
    dead = [node for node in pool if node.get('alive') is False]
    samples = [
        entry.get('proxy_ms')
        for entry in history
        if entry.get('proxy_ms') is not None and entry.get('proxy_ms') >= 1
    ]

    tail = history[-6:]
    flags = [1 if entry.get('faults') else 0 for entry in tail]
    streak = 0
    running = 1
    for offset in range(len(flags)):
        if running == 1 and flags[len(flags) - 1 - offset] == 1:
            streak = streak + 1
        else:
            running = 0

    sustained = 0
    baseline = 0
    if len(samples) >= 6:
        recent = samples[-4:]
        earlier = sorted(samples[:-4])
        baseline = earlier[len(earlier) // 2]
        if min(recent) >= 1200 and baseline < 700:
            sustained = 1

    parts = []
    action = 'none'
    probes = []
    business = snapshot.get('business_observations', {})
    issues = business.get('issues', [])
    business_checks = business.get('checks', {})
    real_targets = [item.get('domain') for item in issues if item.get('domain')][:3]
    stable_fixed_paths = (
        proxy_present and mainland_present and not proxy_bad and not mainland_bad
        and not service_bad and not dns_cn_bad and not dns_foreign_bad
    )

    if not proxy_present or not mainland_present:
        parts = parts + ['检查数据缺失，不据此判断路径健康']
    elif service_bad:
        parts = parts + ['网关服务未处于 active，交由外部恢复流程，不建议自行换节点']
    elif proxy_bad and not mainland_bad:
        action = 'recheck_nodes'
        probes = real_targets
        parts = parts + ['代理路径失败而国内直连正常，建议重新检测节点']
    elif proxy_bad and mainland_bad:
        probes = real_targets
        parts = parts + ['国内与代理同时失败，更像出口或解析层问题，不宜仅换节点']
    elif sustained == 1:
        action = 'recheck_nodes'
        probes = real_targets
        parts = parts + ['代理时延连续四次高于 1200ms 且此前基线低于 700ms，建议重新检测节点']
    else:
        parts = parts + ['固定国内与代理健康检查通过；用户业务仍以独立观测为准']
        if len(pool) >= 2 and len(dead) == len(pool):
            parts = parts + ['节点测速把偏好池全部标为不可用，但固定代理检查通过，测速结果不可信，不据此刷新订阅或换节点']

    if dns_cn_bad or dns_foreign_bad:
        parts = parts + ['网关 DNS 检查异常，需先看解析层']
    if 0 < len(dead) < len(pool):
        parts = parts + ['偏好池有%d/%d个节点测速失败' % (len(dead), len(pool))]
    if streak >= 3:
        parts = parts + ['同一故障连续出现%d次' % streak]
    if sustained == 1:
        parts = parts + ['时延仅作路径证据，不代表吞吐上限']

    dial_only = []
    actionable = []
    probe_capped = []
    for issue in issues:
        domain = issue.get('domain')
        paths = business_checks.get(domain, {}).get('result', {}).get('paths', {})
        direct = paths.get('direct', {})
        proxy_path = paths.get('proxy', {})
        direct_fail = direct.get('transport_ok') is False and (direct.get('failed_samples') or 0) >= 1
        proxy_fail = proxy_path.get('transport_ok') is False and (proxy_path.get('failed_samples') or 0) >= 1
        direct_reach = direct.get('transport_ok') is True or (direct.get('passed_samples') or 0) >= 1
        proxy_reach = proxy_path.get('transport_ok') is True or (proxy_path.get('passed_samples') or 0) >= 1
        dual_fail = direct_fail and proxy_fail and not (direct_reach or proxy_reach)
        recent_faults = 0
        for entry in history[-12:]:
            faults = entry.get('faults_after_confirmation')
            if faults is None:
                faults = entry.get('faults', [])
            if 'client_business:' + domain in faults:
                recent_faults = recent_faults + 1
        if dual_fail:
            dial_only = dial_only + [domain]
        else:
            actionable = actionable + [domain]
            if recent_faults >= 8 and stable_fixed_paths:
                probe_capped = probe_capped + [domain]

    if len(dial_only) > 0:
        parts = parts + ['固定检查正常但同一客户端端点验证失败且指向端点问题，保留记录但不重复升级；未验证为用户业务恢复']
    if len(probe_capped) > 0:
        parts = parts + ['同一客户端端点连续多轮失败，已停止重复探测以避免同一错误反复升级；问题仍未解决，也未验证为用户业务恢复']

    targets = [item for item in real_targets if item not in dial_only and item not in probe_capped]

    summary = parts[0] if len(parts) > 0 else '无检查数据'
    for part in parts[1:]:
        summary = summary + '；' + part

    if len(issues) > 0 and len(actionable) == 0:
        return {'summary': summary, 'action': action, 'probe_domains': targets}
    if len(issues) > 0:
        first = issues[0]
        return {'summary': summary + '；实际客户端问题尚未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}
