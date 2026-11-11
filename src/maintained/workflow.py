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

    observations = snapshot.get('observations') or {}
    business = snapshot.get('business_observations') or {}
    obs_domains = observations.get('domains') or []
    biz_domains = business.get('domains') or []

    # 判断处置后是否有新的真实客户端失败；时间戳缺失时返回未知。
    noise_verdict = {}
    candidate_cases = [case for case in flagged
                       if case.get('status') == 'open' and case.get('outcome') is None and
                       case.get('domain') and
                       (case.get('facts') or {}).get('kind') == 'recurring_client_failure' and
                       (case.get('facts') or {}).get('current_failure') is True]
    for case in candidate_cases:
        domain_now = case.get('domain')
        decided = case.get('decided_at') or 0
        stamps = []
        if case.get('last_observed_at') is not None:
            stamps = stamps + [case.get('last_observed_at')]
        stamps = stamps + [entry.get('last_failure_at') for entry in obs_domains
                           if entry.get('domain') == domain_now
                           and entry.get('last_failure_at') is not None]
        for entry in biz_domains:
            if entry.get('domain') == domain_now:
                stamps = stamps + [issue.get('last_failure_at')
                                   for issue in (entry.get('issues') or [])
                                   if issue.get('last_failure_at') is not None]
        if len(stamps) == 0:
            noise_verdict[domain_now] = False
        else:
            noise_verdict[domain_now] = not any([stamp > decided for stamp in stamps])

    # 仅探测签名变化重开（处置≥2h、无失败样本、处置后无新客户端失败）。
    reopen_noise_domains = {case.get('domain') for case in flagged
        if noise_verdict.get(case.get('domain')) is True and
           (case.get('facts') or {}).get('current_failure') is True and
           len([item for item in ((case.get('facts') or {}).get('paths') or {}).values()
                if (item.get('failed_samples') or 0) >= 1]) == 0 and
           (((case.get('decided_at') is not None) and (now - case.get('decided_at') >= 7200)) and
            (any([(item.get('sample_count') or 0) > 0
                  for item in ((case.get('facts') or {}).get('paths') or {}).values()]) or
             ((case.get('facts') or {}).get('endpoint') or {}).get('application_protocol') == 'unknown') and
            (((case.get('progress') or [])[-1].get('kind') if case.get('progress') else None) == 'evidence_changed'))}

    # 刚处置后的零字节重试：保留 urgent、15分钟复查。
    urgent_cases = flagged
    # 只剩 unknown 样本的端点不再重复探测（含 tracked_probes 来源）。
    unknown_check_domains = []
    sources = [(e.get('domain'), ((e.get('check') or {}).get('result') or {}).get('paths') or {}) for e in biz_domains]
    sources += [(p.get('target'), (p.get('paths') or {})) for p in (snapshot.get('tracked_probes') or {}).values()]
    for domain, paths in sources:
        probed = [p for p in paths.values() if (p.get('sample_count') or 0) >= 1]
        if domain and probed and all([(p.get('success_samples') or 0) == 0 and (p.get('failed_samples') or 0) == 0 for p in probed]):
            unknown_check_domains = unknown_check_domains + [str(domain)]
    burst_domains = []
    for case in urgent_cases:
        domain = case.get('domain')
        facts = case.get('facts') or {}
        paths = facts.get('paths') or {}
        endpoint = facts.get('endpoint') or {}
        entries = [entry for entry in obs_domains if entry.get('domain') == domain]
        eligible = (bool(domain) and case.get('status') == 'open'
                    and case.get('outcome') is None
                    and facts.get('kind') == 'recurring_client_failure'
                    and facts.get('current_failure') is True
                    and endpoint.get('application_protocol') == 'unknown'
                    and len(paths) > 0 and len(entries) > 0
                    and entries[0].get('observed_bytes_lower_bound') == 0)
        if eligible:
            cats_now = entries[0].get('error_categories') or []
            cats_facts = facts.get('error_categories') or []
            for cat in cats_now:
                if cats_facts and cat not in cats_facts:
                    eligible = False
        if eligible:
            decided = case.get('decided_at')
            if decided is not None and now >= decided and (now - decided) <= 1800:
                path_ok = True
                for item in paths.values():
                    if (item.get('failed_samples') or 0) >= 1:
                        path_ok = False
                    if (item.get('success_samples') or 0) >= 1:
                        path_ok = False
                    if (item.get('sample_count') or 0) < 1:
                        path_ok = False
                if path_ok:
                    stamps = []
                    if case.get('last_observed_at') is not None:
                        stamps = stamps + [case.get('last_observed_at')]
                    stamps = stamps + [entry.get('last_failure_at') for entry in entries
                                       if entry.get('last_failure_at') is not None]
                    for entry in biz_domains:
                        if entry.get('domain') == domain:
                            stamps = stamps + [issue.get('last_failure_at')
                                               for issue in (entry.get('issues') or [])
                                               if issue.get('last_failure_at') is not None]
                    fresh = False
                    for stamp in stamps:
                        if stamp > decided:
                            fresh = True
                    if fresh:
                        burst_domains = burst_domains + [domain]
    # 已定案且仅 unknown 样本：停止探测。
    unverifiable_domains = []
    for case in urgent_cases:
        domain = case.get('domain')
        ok = (bool(domain) and case.get('status') == 'open'
              and case.get('outcome') is None
              and case.get('decided_at') is not None)
        if ok:
            facts = case.get('facts') or {}
            entries = [e for e in obs_domains if e.get('domain') == domain]
            cats = facts.get('error_categories') or []
            for e in entries:
                if e.get('observed_bytes_lower_bound') not in (None, 0):
                    ok = False
                for cat in (e.get('error_categories') or []):
                    if cats and cat not in cats:
                        ok = False
            paths = facts.get('paths') or {}
            check_paths = []
            for e in biz_domains:
                if e.get('domain') == domain:
                    check_paths = [((e.get('check') or {}).get('result') or {}).get('paths') or {}]
            seen = False
            unknown = True
            for ps in [paths] + check_paths:
                if ps:
                    seen = True
                    if not all([(p.get('sample_count') or 0) >= 1
                                and (p.get('success_samples') or 0) == 0
                                and (p.get('failed_samples') or 0) == 0
                                for p in ps.values()]):
                        unknown = False
            if ok and not (seen and unknown):
                ok = False
            if ok:
                unverifiable_domains = unverifiable_domains + [domain]
    unverifiable_only = bool(urgent_cases)
    for case in urgent_cases:
        if case.get('domain') not in unverifiable_domains:
            unverifiable_only = False
    burst_only = bool(urgent_cases)
    for case in urgent_cases:
        if case.get('domain') not in burst_domains:
            burst_only = False
    normal_cases = [case for case in incidents
                    if case.get('priority') == 'normal' and case.get('requires_attention') is True]
    selected = [case['id'] for case in (urgent_cases + normal_cases)][:16]
    wake = 'urgent' if (hard_faults or urgent_cases) else ('routine' if normal_cases else 'none')

    case_by_domain = {}
    for case in urgent_cases + normal_cases:
        if case.get('domain'):
            case_by_domain[case['domain']] = case

    quiet_domains = set(reopen_noise_domains)

    probes = [str(entry['domain']) for entry in obs_domains
              if entry.get('needs_probe') is True and entry.get('domain') and
              entry.get('domain') not in quiet_domains and
              entry.get('domain') not in unknown_check_domains and
              entry.get('domain') not in unverifiable_domains and
              entry.get('domain') not in burst_domains and
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
        delay = 900 if (noise_only or burst_only or unverifiable_only) else 120
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
            summary = summary + '其中仅探测签名变化、且已确认无新客户端失败，停止重复探测并放宽复查，避免自持重开。'
        if burst_only:
            summary = summary + '其中零字节后台重试在刚处置后继续，属同一未恢复问题；保留记录并按15分钟复查，不重复探测轮换端口。'
        if unverifiable_only:
            summary = summary + '受保护探测只得到unknown样本的端点停止重复探测，保留事件与复查期限，不表示业务恢复。'
    elif normal_cases:
        summary = '%d 个普通事件待复核；按租约处理。' % len(normal_cases)
    else:
        summary = '固定路径与事件均无当前需关注项；保持独立检查。'

    return {'summary': summary, 'wake': wake, 'incident_ids': selected,
            'probe_domains': probes, 'route_candidates': routes, 'next_check_seconds': delay}
