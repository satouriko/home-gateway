# v10：补齐 bootstrap_dns_api（经上游 192.168.2.1 解析 api.deepseek.com，控制路径引导 DNS）
# 的检查。v9 及更早版本在该项 TimeoutError 时仍输出“固定国内与代理健康检查通过”，
# 与本轮观测（bootstrap 失败、国内/代理正常）矛盾，属于同类“部分检查被当作全部通过”的误判。
# v10 仅在摘要中明确记录该失败，不据此换节点、不请求探测：它属于控制路径解析，不是用户
# 数据面证据；若国内/代理同时失败，仍走原有 recheck_nodes 分支。
# v7：修复“不可探测域名”导致的反复升级循环。2026-11-03 09:2x 实测：客户端反复对
# a.v.smtcdns.com 报 DNS 失败（never connected）。网关原样查询该名返回 rcode=3（NXDOMAIN），
# 受保护 probe 因“无公共 IPv4 应答”抛 ValueError；旧版把它当作可探测端点，下一轮又请求
# 同一目标，形成“探测-失败-再探测”的循环，且把已知外部死端点持续升级为 anomaly。
# 本版把 target:<domain> 检查中 ValueError/gaierror 的域名标为“不可探测”：保留问题记录、
# 不重复请求探测、避免重复 review；文字明确这是客户端引用的无解析地址，不是代理/分流故障，
# 应用层影响仍未验证。另对无任何合成检查、连续 >=8 轮失败且固定路径健康的端点同样停止升级。
# 注意：本程序源码受 AST 白名单限制，只能用 len/list 等允许的函数，不能用 isinstance、
# 字符串 startswith 或 f-string（Attribute 仅允许字典方法）。
# 保守巡检分析：健康时不建议操作；只有能区分原因的持续证据才建议有界修复。
# 只读快照与 history；不把单次成功、单次慢、存活状态或小样本当成整条路径健康。
# v6：国内与代理同时失败时读取 node_observations 的选路尝试记录，首选池失败才建议
# recheck_nodes；无节点证据时保持保守。
# v5：全部节点 alive=false 但固定代理通过时，仅记录测速结果不可信，不刷新订阅或换节点。
# v4：同一外部客户端端点连续多轮失败后停止重复探测，保留稳定指纹的 review_request。

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

    bootstrap = checks.get('bootstrap_dns_api', {})
    bootstrap_bad = 'bootstrap_dns_api' in checks and bootstrap.get('ok') is not True

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

    # 快照中的 node_observations 由网关自身校验后写入；程序白名单不允许 isinstance，
    # 这里用真值判断与 .get 访问。
    node_obs = snapshot.get('node_observations', {})
    node_events = node_obs.get('events', []) if node_obs else []
    node_events = node_events if node_events else []
    last_node_event = node_events[-1] if len(node_events) > 0 else {}
    pool_selection_failed = (
        last_node_event.get('preferred_failed') is True or last_node_event.get('unavailable') is True
    )
    us_attempts_failed = 0
    for row in last_node_event.get('attempts', []):
        if row.get('region') == 'US_AUTO' and row.get('ok') is False:
            us_attempts_failed = us_attempts_failed + 1

    if not proxy_present or not mainland_present:
        parts = parts + ['检查数据缺失，不据此判断路径健康']
    elif service_bad:
        parts = parts + ['网关服务未处于 active，交由外部恢复流程，不建议自行换节点']
    elif proxy_bad and not mainland_bad:
        action = 'recheck_nodes'
        probes = real_targets
        parts = parts + ['代理路径失败而国内直连正常，建议重新检测节点']
    elif proxy_bad and mainland_bad and pool_selection_failed and us_attempts_failed >= 1:
        action = 'recheck_nodes'
        parts = parts + ['国内与代理同时失败，但节点池选路记录显示首选美国池连续失败，先做有界节点复检；出口层仍未排除']
    elif proxy_bad and mainland_bad:
        probes = real_targets
        parts = parts + ['国内与代理同时失败，更像出口或解析层问题，不宜仅换节点']
    elif mainland_bad:
        # v9：旧逻辑只在代理失败时分支，国内直连失败而代理正常会落入 else，
        # 错误输出“固定国内与代理健康检查通过”。mainland_direct=true 时这是
        # 用户直连路径退化，必须明确指出，且换节点不能修复直连。
        parts = parts + ['国内直连检查失败而代理正常，问题在直连或解析层，不建议仅换节点']
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
    if bootstrap_bad:
        parts = parts + ['控制路径引导 DNS 检查失败（解析 api.deepseek.com 超时），网关 DNS 与国内/代理检查未受影响，保留观察、不据此换节点']
    if 0 < len(dead) < len(pool):
        parts = parts + ['偏好池有%d/%d个节点测速失败' % (len(dead), len(pool))]
    if streak >= 3:
        parts = parts + ['同一故障连续出现%d次' % streak]
    if sustained == 1:
        parts = parts + ['时延仅作路径证据，不代表吞吐上限']

    # ValueError/gaierror 表示受保护探测无法解析出可用的公共地址（实测
    # a.v.smtcdns.com 在网关与上游均返回 NXDOMAIN）。这不是数据面证据，继续请求
    # 同一探测只会重复得到同一错误。v8 修正：生产快照把这一状态写在
    # business_observations.checks.<domain>.result 的 state/error_category，
    # 而不是 checks 的 target:<domain> 键；只认后者会漏判并反复升级。
    probe_errors = {}
    for key in checks:
        if key[:7] == 'target:' and checks[key].get('ok') is not True:
            probe_errors[key[7:]] = checks[key].get('error', 'unknown')
    for domain in business_checks:
        result = business_checks.get(domain, {}).get('result', {})
        if result.get('state') == 'probe_unavailable' and domain not in probe_errors:
            probe_errors[domain] = result.get('error_category', 'unknown')

    dial_only = []
    actionable = []
    probe_capped = []
    unprobeable = []
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
        probe_error = probe_errors.get(domain, '')
        unprobe = probe_error == 'ValueError' or probe_error == 'gaierror'
        recent_faults = 0
        for entry in history[-12:]:
            faults = entry.get('faults_after_confirmation')
            if faults is None:
                faults = entry.get('faults', [])
            if 'client_business:' + domain in faults:
                recent_faults = recent_faults + 1
        if unprobe:
            unprobeable = unprobeable + [domain]
        elif dual_fail:
            dial_only = dial_only + [domain]
        else:
            actionable = actionable + [domain]
            if recent_faults >= 8 and stable_fixed_paths:
                probe_capped = probe_capped + [domain]

    if len(dial_only) > 0:
        parts = parts + ['固定检查正常但同一客户端端点验证失败且指向端点问题，保留记录但不重复升级；未验证为用户业务恢复']
    if len(unprobeable) > 0:
        parts = parts + ['客户端引用的域名没有可用的公共解析地址（受保护探测无法完成），保留记录且不重复探测；不是代理或分流故障，实际应用影响仍未验证']
    if len(probe_capped) > 0:
        parts = parts + ['同一客户端端点连续多轮失败，已停止重复探测以避免同一错误反复升级；问题仍未解决，也未验证为用户业务恢复']

    targets = [
        item for item in real_targets
        if item not in dial_only and item not in probe_capped and item not in unprobeable
    ]

    summary = parts[0] if len(parts) > 0 else '无检查数据'
    for part in parts[1:]:
        summary = summary + '；' + part

    if len(issues) > 0 and len(actionable) == 0:
        return {'summary': summary, 'action': action, 'probe_domains': targets}
    if len(issues) > 0:
        first = issues[0]
        matching = [issue for issue in issues if issue.get('domain') in actionable]
        if len(matching) > 0:
            first = matching[0]
        return {'summary': summary + '；实际客户端问题尚未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}
