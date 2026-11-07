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

    # 事件簿重开会保持 urgent；这里识别“已处置旧失败仅因受保护探测签名变化重开”
    # 的场景，只停止重复探测，不降低 wake、不隐藏事件。实时摘要（maintenance._case）
    # 不带 last_observed_at/history，只带 decided_at 与 progress 最后一条，所以主判据
    # 建立在 decided_at、progress 与 facts 上：处置至少 2 小时、最近进展是
    # evidence_changed、最新对照没有 failed_samples。若事件端点本身是 UDP/ICMP，
    # 受保护探测无法验证应用层，重复探测只会让事件签名在“无样本/旧样本”之间翻转、
    # 反复重开，因此这类不可验证端点同样视为复查噪声。TCP 端点没有可用样本时
    # 不静默，仍请求探测补齐证据。真实新失败与传输失败样本不会静默：前者仍保持
    # urgent 列出并在 900 秒内唤醒处理，后者明确排除。
    reopen_noise_domains = {case.get('domain') for case in flagged
        if (
            case.get('status') == 'open' and
            case.get('outcome') is None and
            case.get('domain') and
            (case.get('facts') or {}).get('kind') == 'recurring_client_failure' and
            (case.get('facts') or {}).get('current_failure') is True and
            len([item for item in (((case.get('facts') or {}).get('paths') or {}).values())
                 if (item.get('failed_samples') or 0) >= 1]) == 0 and
            (
                (
                    case.get('decided_at') is not None and
                    (now - case.get('decided_at')) >= 7200 and
                    ((case.get('progress') or [])[-1].get('kind') if case.get('progress') else None) == 'evidence_changed' and
                    (
                        len([item for item in (((case.get('facts') or {}).get('paths') or {}).values())
                             if (item.get('sample_count') or 0) > 0]) > 0 or
                        ((case.get('facts') or {}).get('endpoint') or {}).get('network') in ['udp', 'icmp']
                    )
                ) or
                (
                    case.get('last_observed_at') is not None and
                    case.get('last_observed_at') <= max([case.get('decided_at') or 0] +
                        [item.get('at') or 0 for item in (case.get('history') or []) if item.get('kind') == 'disposition']) and
                    (now - case.get('last_observed_at')) >= 7200
                )
            )
        )}

    urgent_cases = flagged
    normal_cases = [case for case in incidents
                    if case.get('priority') == 'normal' and case.get('requires_attention') is True]
    selected = [case['id'] for case in (urgent_cases + normal_cases)][:16]
    wake = 'urgent' if (hard_faults or urgent_cases) else ('routine' if normal_cases else 'none')

    case_by_domain = {}
    for case in urgent_cases + normal_cases:
        if case.get('domain'):
            case_by_domain[case['domain']] = case

    quiet_domains = set(reopen_noise_domains)

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

    noise_only = bool(urgent_cases) and all([case.get('domain') in reopen_noise_domains
                                             for case in urgent_cases])
    if pool_only and fixed_ok:
        delay = 300
    elif hard_faults:
        delay = 60
    elif urgent_cases:
        delay = 900 if noise_only else 120
    else:
        future = [int(case['next_review_at'] - now) for case in incidents
                  if case.get('next_review_at', 0) > now]
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
