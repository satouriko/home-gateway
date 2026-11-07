def inspect(snapshot):
    now = int(snapshot['now'])
    health = snapshot.get('path_health') or {}
    hard_faults = [str(item) for item in (health.get('hard_faults') or [])][:16]
    checks = health.get('checks') or {}
    fixed_ok = (
        (checks.get('proxy_https') or {}).get('ok') is True and
        (checks.get('mainland_https') or {}).get('ok') is True
    )
    pool_only = hard_faults == ['proxy_node_pool']

    incidents = snapshot.get('incidents') or []
    flagged = [case for case in incidents
               if case.get('priority') == 'urgent' and case.get('requires_attention') is True]
    # 事件簿在证据签名变化时会重开已处置事件；若该端点最近一次真实客户端失败
    # 仍早于最后一次处置，且受保护探测没有给出任何传输失败样本，则属于“复查噪声”。
    # 这类重开没有新客户端失败。validator 仍要求紧急事件保持 urgent 且必须列出，
    # 所以不能降低 wake；但必须停止对它再次探测，否则每次探测都会改写签名并再次
    # 重开，形成“关注→探测→签名变化→关注”的自持循环。真实传输失败不会静默。
    reopen_noise_domains = set([
        case.get('domain') for case in flagged
        if case.get('status') == 'open' and case.get('outcome') is None and
        case.get('domain') and
        (case.get('facts') or {}).get('kind') == 'recurring_client_failure' and
        len([item for item in ((case.get('facts') or {}).get('paths') or {}).values()
             if (item.get('failed_samples') or 0) >= 1]) == 0 and
        case.get('last_observed_at') is not None and
        case.get('last_observed_at') <= max(
            [case.get('decided_at') or 0] +
            [item.get('at') or 0 for item in (case.get('history') or [])
             if item.get('kind') == 'disposition']) and
        (now - case.get('last_observed_at')) >= 7200
    ])
    urgent_cases = flagged
    normal_cases = [case for case in incidents
                    if case.get('priority') == 'normal' and case.get('requires_attention') is True]
    selected = [case['id'] for case in (urgent_cases + normal_cases)][:16]
    wake = 'urgent' if (hard_faults or urgent_cases) else ('routine' if normal_cases else 'none')

    case_by_domain = {}
    for case in urgent_cases + normal_cases:
        if case.get('domain'):
            case_by_domain[case['domain']] = case

    quiet_domains = set([case['domain'] for case in flagged
                         if case.get('domain') in reopen_noise_domains])

    observations = snapshot.get('observations') or {}
    probes = [str(entry['domain']) for entry in (observations.get('domains') or [])
              if entry.get('needs_probe') is True and entry.get('domain') and
              entry.get('domain') not in quiet_domains and
              not (case_by_domain.get(entry['domain']) and
                   case_by_domain[entry['domain']].get('facts', {}).get('paths') and
                   all([item.get('transport_ok') is False
                        for item in case_by_domain[entry['domain']]['facts']['paths'].values()])) and
              not (case_by_domain.get(entry['domain']) and
                   case_by_domain[entry['domain']].get('facts', {}).get('paths') and
                   all([item.get('application_state') == 'rejected'
                        for item in case_by_domain[entry['domain']]['facts']['paths'].values()]))][:3]

    routing = snapshot.get('routing') or {}
    routes = [str(candidate['domain']) for candidate in (routing.get('candidates') or [])
              if candidate.get('needs_route_review') is True and
              candidate.get('current_path_healthy') is not True and
              candidate.get('current_path_bad') is not False and
              (candidate.get('business_basis') or candidate.get('business_requirement_evidence_ids'))][:3]

    # 仅复查噪声时保持紧急但放宽到租约允许的最大复查间隔，避免同一旧失败在
    # 探测循环里反复唤醒模型；真实新失败或硬故障仍按短间隔。
    noise_only = bool(urgent_cases) and all([case.get('domain') in reopen_noise_domains
                                             for case in urgent_cases])
    if pool_only and fixed_ok:
        delay = 300
    elif hard_faults:
        delay = 60
    elif urgent_cases:
        delay = 900 if noise_only else 120
    elif normal_cases:
        future = [int(case['next_review_at'] - now) for case in incidents if case['next_review_at'] > now]
        delay = max(60, min(900, min(future))) if future else 900
    else:
        future = [int(case['next_review_at'] - now) for case in incidents if case['next_review_at'] > now]
        delay = max(60, min(900, min(future))) if future else 900

    if pool_only and fixed_ok:
        summary = '检测到首选节点池选路失败，但固定代理与国内检查通过；流量按用户策略回退其他地区，降低重复复查频率，未验证用户业务恢复。'
    elif hard_faults:
        summary = '检测到 %d 项固定路径硬故障；立即复查。' % len(hard_faults)
    elif urgent_cases:
        summary = '%d 个紧急事件待处理；按证据复核并保留有限复查期限。' % len(urgent_cases)
        if noise_only:
            summary = summary + '其中仅探测签名变化、无新客户端失败，已停止重复探测并放宽复查，避免自持重开。'
    elif normal_cases:
        summary = '%d 个普通事件待复核；按租约处理。' % len(normal_cases)
    else:
        summary = '固定路径与事件均无当前需关注项；保持独立检查。'

    return {'summary': summary, 'wake': wake, 'incident_ids': selected,
            'probe_domains': probes, 'route_candidates': routes, 'next_check_seconds': delay}
