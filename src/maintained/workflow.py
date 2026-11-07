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

    # 每个业务域名最近一次真实客户端失败时间，用于区分“新失败”和“复查签名抖动”。
    last_failure_by_domain = {}
    for bucket in ('business_observations', 'observations'):
        data = snapshot.get(bucket) or {}
        for entry in (data.get('domains') or []):
            domain = entry.get('domain')
            if domain:
                values = [entry.get('last_failure_at')] + [issue.get('last_failure_at') for issue in (entry.get('issues') or [])]
                for value in values:
                    if value is not None:
                        if domain not in last_failure_by_domain or value > last_failure_by_domain[domain]:
                            last_failure_by_domain[domain] = value

    flagged = [case for case in incidents
               if case.get('priority') == 'urgent' and case.get('requires_attention') is True]
    # 业务事件被探测状态签名变化重开、但最近 2 小时内没有新客户端失败：
    # 属复查噪声。保留事件与记录，降低关注等级，也不再请求重复探测。
    # UDP/443 等无法用受保护探测验证的端点尤其会制造这类签名抖动。
    review_cases = [case for case in flagged
                    if case.get('status') == 'open' and
                    case.get('outcome') is None and
                    case.get('domain') and
                    (case.get('facts') or {}).get('kind') == 'recurring_client_failure' and
                    last_failure_by_domain.get(case.get('domain')) is not None and
                    (now - last_failure_by_domain[case.get('domain')]) >= 7200]
    urgent_cases = [case for case in flagged
                    if not (case.get('status') == 'open' and
                            case.get('outcome') is None and
                            case.get('domain') and
                            (case.get('facts') or {}).get('kind') == 'recurring_client_failure' and
                            last_failure_by_domain.get(case.get('domain')) is not None and
                            (now - last_failure_by_domain[case.get('domain')]) >= 7200)]

    normal_cases = [case for case in incidents
                    if case.get('priority') == 'normal' and case.get('requires_attention') is True]
    selected = [case['id'] for case in (urgent_cases + normal_cases + review_cases)][:16]
    wake = 'urgent' if (hard_faults or urgent_cases) else ('routine' if normal_cases else 'none')

    case_by_domain = {}
    for case in urgent_cases + normal_cases + review_cases:
        if case.get('domain'):
            case_by_domain[case['domain']] = case

    quiet_domains = set([case['domain'] for case in review_cases if case.get('domain')])

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

    if pool_only and fixed_ok:
        # 首选池短时选路失败、但两条固定检查正常时，流量已按用户策略回退；
        # 保持紧急（硬故障不能降级为 routine），但把复查间隔从 60s 放宽到 300s，
        # 避免同一节点池抖动期间重复购买同一次分析。任一固定检查失败则仍按 60s。
        delay = 300
    elif hard_faults:
        delay = 60
    elif urgent_cases:
        delay = 120
    elif normal_cases:
        future = [int(case['next_review_at'] - now) for case in incidents if case['next_review_at'] > now]
        delay = max(60, min(900, min(future))) if future else 900
    elif review_cases:
        # 只有复查噪声：程序照常检查，模型不因同一事件反复唤醒。
        delay = 1800
    else:
        future = [int(case['next_review_at'] - now) for case in incidents if case['next_review_at'] > now]
        delay = max(60, min(900, min(future))) if future else 900

    if pool_only and fixed_ok:
        summary = '检测到首选节点池选路失败，但固定代理与国内检查通过；流量按用户策略回退其他地区，降低重复复查频率，未验证用户业务恢复。'
    elif hard_faults:
        summary = '检测到 %d 项固定路径硬故障；立即复查。' % len(hard_faults)
    elif urgent_cases:
        summary = '%d 个紧急事件待处理；按证据复核并保留有限复查期限。' % len(urgent_cases)
    elif normal_cases:
        summary = '%d 个普通事件待复核；按租约处理。' % len(normal_cases)
    elif review_cases:
        summary = '%d 个复查噪声事件（最近 2 小时无新客户端失败）；保留记录，不按紧急唤醒模型。' % len(review_cases)
    else:
        summary = '固定路径与事件均无当前需关注项；保持独立检查。'

    return {'summary': summary, 'wake': wake, 'incident_ids': selected,
            'probe_domains': probes, 'route_candidates': routes, 'next_check_seconds': delay}
