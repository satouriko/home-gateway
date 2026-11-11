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
    real_targets = [item.get('domain') for item in issues if item.get('domain')]
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
        parts += ['检查缺失，不判断健康']
    elif service_bad:
        parts += ['服务未 active，交由外部恢复']
    elif proxy_bad and not mainland_bad:
        probes = real_targets
        if bootstrap_bad:
            parts += ['代理失败且引导 DNS 异常，先查本地上联']
        else:
            action = 'recheck_nodes'
            parts += ['代理失败、直连正常，建议复检节点']
    elif proxy_bad and mainland_bad and pool_selection_failed and us_attempts_failed >= 1:
        probes = real_targets
        if bootstrap_bad:
            parts += ['双路径失败且引导 DNS 异常，先查本地上联']
        else:
            parts += ['双路径失败且首选池选路失败，更像共同上游中断，等待恢复不换节点']
    elif proxy_bad and mainland_bad:
        probes = real_targets
        parts += ['双路径失败更像出口/解析层，不换节点']
    elif mainland_bad:
        parts += ['直连失败、代理正常，不换节点']
    elif sustained == 1:
        action = 'recheck_nodes'
        probes = real_targets
        parts += ['代理时延连续四次>1200ms且基线<700ms，建议复检节点']
    else:
        parts += ['固定检查通过；业务独立观测']
        if len(pool) >= 2 and len(dead) == len(pool):
            parts += ['偏好池测速全失败，测速不可信']
        if node_recent:
            parts += ['节点测速全失败，不换节点']
    if dns_cn_bad or dns_foreign_bad:
        parts += ['网关 DNS 检查异常，需先看解析层']
    if bootstrap_bad:
        parts += ['引导 DNS 失败；网关 DNS 与路径正常，保留观察']
    if 0 < len(dead) < len(pool):
        parts += ['偏好池有%d/%d个节点测速失败' % (len(dead), len(pool))]
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
    udp_unverified = []
    unverifiable = []
    for issue in issues:
        domain = issue.get('domain')
        paths = (business_checks.get(domain) or {}).get('result', {}).get('paths', {})
        if not paths:
            for entry in business.get('domains', []):
                if entry.get('domain') == domain:
                    paths = ((entry.get('check') or {}).get('result') or {}).get('paths') or {}
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
        incident = issue.get('incident')
        held = incident is not None and incident.get('requires_attention') is False
        attention = incident is not None and incident.get('requires_attention') is True
        probed = [p for p in paths.values() if (p.get('sample_count') or 0) >= 1]
        unknown_only = len(probed) > 0 and all([(p.get('success_samples') or 0) == 0 and (p.get('failed_samples') or 0) == 0 for p in probed])
        if (issue.get('endpoint') or {}).get('network') in ('udp', 'icmp') and not d_fail and not p_fail:
            udp_unverified += [domain]
        elif unprobe and not attention:
            unprobeable += [domain]
        elif dual_fail and not attention:
            dial_only += [domain]
        elif held:
            deferred += [domain]
        elif unknown_only and not d_fail and not p_fail:
            unverifiable += [domain]
        else:
            actionable += [domain]
            if recent_faults >= 8 and not attention:
                probe_capped += [domain]
            elif root_rejected and not attention:
                app_rejected += [domain]
    if dial_only:
        if stable_fixed_paths:
            parts += ['固定检查正常、端点失败']
        else:
            parts += ['固定检查异常且端点失败']
    if unprobeable:
        parts += ['受保护探测无法完成']
    if probe_capped:
        parts += ['同一端点连续失败，停止探测']
    if app_rejected:
        parts += ['根路径 4xx，停止重复探测']
    if deferred:
        parts += ['%d个端点已处置且未到期，保留记录不重复复核；不表示业务恢复' % len(deferred)]
    if udp_unverified:
        parts += ['%d个UDP/ICMP端点无法验证，停止探测；不表示业务恢复' % len(udp_unverified)]
    if unverifiable:
        parts += ['%d个端点只得到unknown样本，停止探测并保留复查；不表示业务恢复' % len(unverifiable)]
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
        parts += ['路径对照约%d小时前采集，固定检查优先' % hours]
    if pending:
        parts += ['系统已安排节点复检，完成后按新证据判断']
    targets = [
        item for item in real_targets
        if item not in dial_only and item not in probe_capped
        and item not in unprobeable and item not in app_rejected
        and item not in deferred and item not in udp_unverified
        and item not in unverifiable
    ][:3]
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
            note = '；节点复检已确定，端点复核留待固定路径恢复后'
        return {'summary': summary + note, 'action': action, 'probe_domains': []}
    if len(issues) > 0 and len(reviewable) == 0:
        return {'summary': summary, 'action': action, 'probe_domains': targets}
    if len(issues) > 0 and len(reviewable) > 0 and pending_recheck:
        return {'summary': summary + '；客户端问题保留记录，待节点复检后按新证据复核', 'action': action, 'probe_domains': targets}
    if issues:
        first = issues[0]
        matching = [issue for issue in issues if issue.get('domain') in reviewable]
        if matching:
            first = matching[0]
        return {'summary': summary + '；客户端问题未解决', 'action': action, 'probe_domains': targets, 'review_request': {'fingerprint': first.get('fingerprint', 'client-business-gap'), 'reason': '实际客户端反复失败，需要定向验证和持续处理，不能被固定检查成功覆盖'}}
    return {'summary': summary, 'action': action, 'probe_domains': probes}
