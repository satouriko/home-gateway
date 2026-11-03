# 主动巡检（v14）：action=recheck_nodes 已确定时不再附带 review_request/probe_domains，
# 避免一次代理检查失败既安排节点复检又重复复核已知端点（pending 在程序运行后才创建）。
# 另用 business_observations.checks 时间判断路径样本过期；生产快照不含 observations，
# 旧时效分支已移除。v13 防重复复核、v12 矛盾提示、v11 应用层拒绝、v8 不重复探测不变。
# 只读快照，不触发测速，不改变用户分流目标。

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

    node_obs = snapshot.get('node_observations', {})
    node_events = node_obs.get('events', []) if node_obs else []
    last_node_event = node_events[-1] if len(node_events) > 0 else {}
    pool_selection_failed = (
        last_node_event.get('preferred_failed') is True or last_node_event.get('unavailable') is True
    )

    node_state = node_obs.get('state', '') if node_obs else ''
    pool_unavailable = False
    if node_state == 'unavailable':
        pool_unavailable = True
    if last_node_event.get('unavailable') is True:
        pool_unavailable = True
    now_ts = business.get('checked_at', 0)
    if now_ts is None or now_ts <= 0:
        now_ts = 0
        if len(history) > 0:
            now_ts = history[-1].get('at', 0)
    node_checked = node_obs.get('checked_at', 0) if node_obs else 0
    node_recent = False
    if pool_unavailable and now_ts > 0 and node_checked > 0 and (now_ts - node_checked) <= 900:
        node_recent = True
    pending = status.get('pending_recovery', {})
    pending_recheck = False
    if pending and pending.get('operation') == 'recheck_nodes':
        deadline = pending.get('deadline')
        if deadline is None or deadline <= 0:
            pending_recheck = True
        elif now_ts <= 0 or deadline >= now_ts:
            pending_recheck = True
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
        parts = parts + ['国内直连检查失败而代理正常，问题在直连或解析层，不建议仅换节点']
    elif sustained == 1:
        action = 'recheck_nodes'
        probes = real_targets
        parts = parts + ['代理时延连续四次高于 1200ms 且此前基线低于 700ms，建议重新检测节点']
    else:
        parts = parts + ['固定国内与代理健康检查通过；用户业务仍以独立观测为准']
        if len(pool) >= 2 and len(dead) == len(pool):
            parts = parts + ['节点测速把偏好池全部标为不可用，但固定代理检查通过，测速结果不可信，不据此刷新订阅或换节点']
        if node_recent:
            parts = parts + ['节点池健康探测同时全部失败（选中节点为空），与固定代理检查通过相互矛盾；更可能是健康URL或测速假阴性，不能据此认定用户路径中断，不重复换节点']

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
    app_rejected = []
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
        direct_status = direct.get('http_status')
        proxy_status = proxy_path.get('http_status')
        direct_rejected = direct_status in (400, 401, 403, 404)
        proxy_rejected = proxy_status in (400, 401, 403, 404)
        root_rejected = (
            direct.get('transport_ok') is True and proxy_path.get('transport_ok') is True
            and direct_rejected and proxy_rejected
        )
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
            elif root_rejected and recent_faults >= 2 and stable_fixed_paths:
                app_rejected = app_rejected + [domain]

    if len(dial_only) > 0:
        parts = parts + ['固定检查正常但同一客户端端点验证失败且指向端点问题，保留记录但不重复升级；未验证为用户业务恢复']
    if len(unprobeable) > 0:
        parts = parts + ['客户端引用的域名没有可用的公共解析地址（受保护探测无法完成），保留记录且不重复探测；不是代理或分流故障，实际应用影响仍未验证']
    if len(probe_capped) > 0:
        parts = parts + ['同一客户端端点连续多轮失败，已停止重复探测以避免同一错误反复升级；问题仍未解决，也未验证为用户业务恢复']
    if len(app_rejected) > 0:
        parts = parts + ['端点根路径返回 HTTP 4xx（应用层拒绝）且直连/代理传输均可达，保留问题记录并停止重复探测与复核；这不证明应用层可用，实际业务影响仍未验证']

    # 生产快照不含 observations（patrol 只传 diagnosis+history+quality_summary），
    # 客户端活动时效仍需受保护层补充；这里只用快照内真实可得的时间戳判断样本时效。
    newest_business_ts = 0
    for domain in business_checks:
        entry = business_checks.get(domain, {})
        result = entry.get('result', {})
        stamps = [entry.get('at'), result.get('checked_at'), result.get('observed_at')]
        for stamp in stamps:
            if stamp is not None and stamp > newest_business_ts:
                newest_business_ts = stamp
    business_stale = False
    if newest_business_ts > 0 and now_ts > newest_business_ts and (now_ts - newest_business_ts) >= 7200:
        business_stale = True
    if business_stale and len(issues) > 0:
        hours = (now_ts - newest_business_ts) // 3600
        parts = parts + ['路径对照样本约%d小时前采集，直连/代理比较不代表当前时刻；固定检查与真实客户端流量优先' % hours]
    if pending:
        parts = parts + ['系统已安排节点复检，等待其完成后按新证据判断']

    targets = [
        item for item in real_targets
        if item not in dial_only and item not in probe_capped
        and item not in unprobeable and item not in app_rejected
    ]

    summary = parts[0] if len(parts) > 0 else '无检查数据'
    for part in parts[1:]:
        summary = summary + '；' + part

    reviewable = [
        domain for domain in actionable
        if domain not in probe_capped and domain not in app_rejected
    ]

    if action == 'recheck_nodes':
        note = ''
        if len(issues) > 0 and not pending_recheck:
            note = '；节点复检已确定，客户端端点复核留待固定路径恢复后'
        return {'summary': summary + note, 'action': action, 'probe_domains': []}
    if len(issues) > 0 and len(reviewable) == 0:
        return {'summary': summary, 'action': action, 'probe_domains': targets}
    if len(issues) > 0 and len(reviewable) > 0 and pending_recheck:
        return {'summary': summary + '；已知客户端问题保留记录，待节点复检完成后按新证据复核', 'action': action, 'probe_domains': targets}
    if len(issues) > 0:
        first = issues[0]
        matching = [issue for issue in issues if issue.get('domain') in reviewable]
        if len(matching) > 0:
            first = matching[0]
        return {'summary': summary + '；实际客户端问题尚未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}
