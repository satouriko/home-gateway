# 主动巡检（v19）。只读快照，不改用户分流目标。
# 修复 v18 的漏报复核：v18 在没有观测历史、快照也未提供观测时间的残缺输入下，
# 也把未探测的客户端问题当成“陈旧记录”延后，会掩盖新的客户端失败（固定回归
# recurring_client_failure 失败）。v19 只在观测管线确实已运行（history 或
# business checked_at 存在）且近期无该域名失败时，才延后无探测记录的旧问题。
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
    dns_bad = {}
    for key in ('gateway_dns_cn', 'gateway_dns_foreign'):
        item = checks.get(key)
        if item:
            res = item.get('result', {})
            count = res.get('answer_count', 1)
            dns_bad[key] = (item.get('ok') is not True or res.get('rcode', 0) != 0
                            or (count is not None and count < 1))
    dns_cn_bad = dns_bad.get('gateway_dns_cn', False)
    dns_foreign_bad = dns_bad.get('gateway_dns_foreign', False)

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
    flags = []
    for entry in history[-6:]:
        path_faults = 0
        for item in entry.get('faults') or []:
            if item[:15] != 'client_business':
                path_faults = path_faults + 1
        flags = flags + [1 if path_faults > 0 else 0]
    streak = 0
    running = 1
    for offset in range(len(flags)):
        if running == 1 and flags[len(flags) - 1 - offset] == 1:
            streak = streak + 1
        else:
            running = 0
    sustained = 0
    if len(samples) >= 6:
        earlier = sorted(samples[:-4])
        if min(samples[-4:]) >= 1200 and earlier[len(earlier) // 2] < 700:
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
        if history:
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
        parts += ['检查数据缺失，不据此判断路径健康']
    elif service_bad:
        parts += ['网关服务未 active，交由外部恢复，不建议自行换节点']
    elif proxy_bad and not mainland_bad:
        action = 'recheck_nodes'
        probes = real_targets
        parts += ['代理路径失败而国内直连正常，建议重新检测节点']
    elif proxy_bad and mainland_bad and pool_selection_failed and us_attempts_failed >= 1:
        action = 'recheck_nodes'
        parts += ['国内与代理同时失败，但节点池选路记录显示首选美国池连续失败，先做有界节点复检；出口层仍未排除']
    elif proxy_bad and mainland_bad:
        probes = real_targets
        parts += ['国内与代理同时失败，更像出口或解析层问题，不宜仅换节点']
    elif mainland_bad:
        parts += ['国内直连失败而代理正常，问题在直连或解析层，不建议仅换节点']
    elif sustained == 1:
        action = 'recheck_nodes'
        probes = real_targets
        parts += ['代理时延连续四次高于 1200ms 且此前基线低于 700ms，建议重新检测节点；时延不代表吞吐上限']
    else:
        parts += ['固定国内与代理健康检查通过；用户业务仍以独立观测为准']
        if len(pool) >= 2 and len(dead) == len(pool):
            parts += ['偏好池全部节点测速失败，但固定代理检查通过，测速不可信，不据此刷新订阅或换节点']
        if node_recent:
            parts += ['节点池健康探测同时全部失败，与固定代理检查通过矛盾，更像测速假阴性，不据此换节点']
    if dns_cn_bad or dns_foreign_bad:
        parts += ['网关 DNS 检查异常，需先看解析层']
    if bootstrap_bad:
        parts += ['控制路径引导 DNS 检查失败（解析 api.deepseek.com），网关 DNS 与国内/代理检查未受影响，保留观察、不据此换节点']
    if 0 < len(dead) < len(pool):
        parts += ['偏好池有%d/%d个节点测速失败' % (len(dead), len(pool))]
    if streak >= 3:
        parts += ['同一故障连续出现%d次' % streak]
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
    deferred = []
    for issue in issues:
        domain = issue.get('domain')
        paths = business_checks.get(domain, {}).get('result', {}).get('paths', {})
        direct = paths.get('direct', {})
        proxy_path = paths.get('proxy', {})
        d_fail = direct.get('transport_ok') is False and (direct.get('failed_samples') or 0) >= 1
        p_fail = proxy_path.get('transport_ok') is False and (proxy_path.get('failed_samples') or 0) >= 1
        d_ok = direct.get('transport_ok') is True or (direct.get('passed_samples') or 0) >= 1
        p_ok = proxy_path.get('transport_ok') is True or (proxy_path.get('passed_samples') or 0) >= 1
        dual_fail = d_fail and p_fail and not (d_ok or p_ok)
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
        elif (not business_checks.get(domain) and recent_faults == 0
              and (history or business.get('checked_at'))):
            deferred = deferred + [domain]
        else:
            actionable = actionable + [domain]
            if recent_faults >= 8:
                probe_capped = probe_capped + [domain]
            elif root_rejected:
                app_rejected = app_rejected + [domain]
    if dial_only:
        if stable_fixed_paths:
            parts += ['固定检查正常但同一客户端端点验证失败，指向端点问题，保留记录不重复升级；未验证业务恢复']
        else:
            parts += ['固定检查当前异常且同一端点验证失败，暂不能区分端点与路径问题，待恢复后再判断']
    if unprobeable:
        parts += ['客户端域名受保护探测无法完成（ValueError/gaierror），原因未确认（不存在、解析失败或超上限）；保留记录不重复探测，非代理或分流故障']
    if probe_capped:
        parts += ['同一端点连续多轮失败，已停止重复探测；问题仍未解决，也未验证业务恢复']
    if app_rejected:
        parts += ['端点根路径 HTTP 4xx（应用层拒绝）且直连/代理传输均可达，停止重复探测与复核；不证明应用层可用']
    if deferred:
        parts += ['%d个已知端点无探测记录且近期无失败证据，保留记录不重复复核；不表示用户业务已恢复' % len(deferred)]
    newest_business_ts = 0
    for entry in business_checks.values():
        res = entry.get('result', {})
        for t in (entry.get('at'), res.get('checked_at'), res.get('observed_at')):
            if t and t > newest_business_ts:
                newest_business_ts = t
    business_stale = False
    if newest_business_ts > 0 and now_ts > newest_business_ts and (now_ts - newest_business_ts) >= 7200:
        business_stale = True
    if business_stale and len(issues) > 0:
        hours = (now_ts - newest_business_ts) // 3600
        parts += ['路径对照约%d小时前采集，不代表当前时刻；固定检查与真实客户端流量优先' % hours]
    if pending:
        parts += ['系统已安排节点复检，完成后按新证据判断']
    targets = [
        item for item in real_targets
        if item not in dial_only and item not in probe_capped
        and item not in unprobeable and item not in app_rejected
        and item not in deferred
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
    if issues:
        first = issues[0]
        matching = [issue for issue in issues if issue.get('domain') in reviewable]
        if matching:
            first = matching[0]
        return {'summary': summary + '；实际客户端问题尚未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}