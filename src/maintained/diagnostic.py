# 保守的巡检分析：健康时不建议操作；只有能区分原因的持续证据才建议有界修复。
# 只读快照与 history；不把单次成功、单次慢、存活状态或小样本当成整条路径健康或带宽结论。
# 注意：diagnose 快照不含 observations，target:* 检查在程序评估之后才写入，
# 所以外部端点判定必须只依赖评估时确实存在的 business_observations/tracked_probes。
# v2：客户端观测里“有连接尝试但上下行零字节、且从无成功流量”的端点，即使
# business_checks 缓存已过期，也应按外部端点处理，避免每轮缓存过期后重复升级。

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
    elif len(pool) >= 2 and len(dead) == len(pool):
        action = 'refresh_subscription'
        parts = parts + ['偏好地区节点全部不可用，建议刷新订阅']
    else:
        parts = parts + ['固定国内与代理健康检查通过；用户业务仍以独立观测为准']

    if dns_cn_bad or dns_foreign_bad:
        parts = parts + ['网关 DNS 检查异常，需先看解析层']
    if 0 < len(dead) and len(dead) < len(pool):
        parts = parts + ['偏好池有%d/%d个节点不可用' % (len(dead), len(pool))]
    if streak >= 3:
        parts = parts + ['同一故障连续出现%d次' % streak]
    if sustained == 1:
        parts = parts + ['时延仅作路径证据，不代表吞吐上限']

    observed_domains = snapshot.get('observations', {}).get('domains', [])
    tracked_probes = snapshot.get('tracked_probes', {})
    dial_only = []
    actionable = []
    for issue in issues:
        domain = issue.get('domain')
        record = {}
        for item in observed_domains:
            if item.get('domain') == domain:
                record = item
        tracked = checks.get('target:' + domain, {})
        if len(tracked) == 0:
            tracked = tracked_probes.get(domain, {})
        probe_failed = tracked.get('ok') is False or tracked.get('error') is not None
        paths = business_checks.get(domain, {}).get('result', {}).get('paths', {})
        direct = paths.get('direct', {})
        proxy_path = paths.get('proxy', {})
        direct_fail = direct.get('transport_ok') is False and (direct.get('failed_samples') or 0) >= 1
        proxy_fail = proxy_path.get('transport_ok') is False and (proxy_path.get('failed_samples') or 0) >= 1
        direct_reach = direct.get('transport_ok') is True or (direct.get('passed_samples') or 0) >= 1
        proxy_reach = proxy_path.get('transport_ok') is True or (proxy_path.get('passed_samples') or 0) >= 1
        dual_fail = direct_fail and proxy_fail and not (direct_reach or proxy_reach)
        # 客户端记录里有连接尝试但上下行始终零字节、且有失败样本：从未成功传输过业务数据。
        # 不再要求 connections_seen 为 0（连接尝试会被计入），因此缓存过期后判定仍成立。
        record_failures = record.get('failure_count') or 0
        record_bytes = record.get('observed_bytes_lower_bound')
        if record_bytes is None:
            record_bytes = (record.get('observed_upload_bytes') or 0) + (record.get('observed_download_bytes') or 0)
        never_transferred = (
            len(record) > 0
            and record_bytes == 0
            and record_failures >= 1
        )
        external = dual_fail
        if not external and never_transferred and probe_failed:
            external = True
        if external:
            dial_only = dial_only + [domain]
        else:
            actionable = actionable + [domain]

    if len(dial_only) > 0:
        parts = parts + ['直连与代理两条路径都无法建立连接，判定为外部端点不可达，已记录待观察，不再重复升级']
    targets = [item for item in real_targets if item not in dial_only]

    summary = parts[0] if len(parts) > 0 else '无检查数据'
    for part in parts[1:]:
        summary = summary + '；' + part

    if len(issues) > 0 and len(actionable) == 0:
        return {'summary': summary, 'action': action, 'probe_domains': targets}
    if len(issues) > 0:
        first = issues[0]
        return {'summary': summary + '；实际客户端问题尚未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}
