def inspect(snapshot):
    now = int(snapshot['now'])
    health = snapshot.get('path_health') or {}
    hard_faults = [str(item) for item in (health.get('hard_faults') or [])][:16]

    incidents = snapshot.get('incidents') or []
    urgent_cases = [case for case in incidents
                    if case.get('priority') == 'urgent' and case.get('requires_attention') is True]
    normal_cases = [case for case in incidents
                    if case.get('priority') == 'normal' and case.get('requires_attention') is True]
    selected = [case['id'] for case in (urgent_cases + normal_cases)][:16]
    wake = 'urgent' if hard_faults or urgent_cases else ('routine' if normal_cases else 'none')

    case_by_domain = {}
    for case in urgent_cases + normal_cases:
        if case.get('domain'):
            case_by_domain[case['domain']] = case

    observations = snapshot.get('observations') or {}
    probes = [str(entry['domain']) for entry in (observations.get('domains') or [])
              if entry.get('needs_probe') is True and entry.get('domain') and
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

    if hard_faults:
        delay = 60
    elif urgent_cases:
        delay = 120
    else:
        future = [int(case['next_review_at'] - now) for case in incidents if case['next_review_at'] > now]
        delay = max(60, min(900, min(future))) if future else 900

    if hard_faults:
        summary = '检测到 %d 项固定路径硬故障；立即复查。' % len(hard_faults)
    elif urgent_cases:
        summary = '%d 个紧急事件待处理；按证据复核并保留有限复查期限。' % len(urgent_cases)
    elif normal_cases:
        summary = '%d 个普通事件待复核；按租约处理。' % len(normal_cases)
    else:
        summary = '固定路径与事件均无当前需关注项；保持独立检查。'

    return {'summary': summary, 'wake': wake, 'incident_ids': selected,
            'probe_domains': probes, 'route_candidates': routes, 'next_check_seconds': delay}
