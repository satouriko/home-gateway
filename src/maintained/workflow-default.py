def inspect(snapshot):
    urgent = [case['id'] for case in snapshot['incidents'] if case['priority'] == 'urgent' and case['requires_attention']]
    normal = [case['id'] for case in snapshot['incidents'] if case['priority'] == 'normal' and case['requires_attention']]
    faults = snapshot['path_health']['hard_faults']
    wake = 'urgent' if faults or urgent else 'routine' if normal else 'none'
    selected = (urgent + normal)[:16]
    probes = [entry['domain'] for entry in snapshot['observations'].get('domains', []) if entry.get('needs_probe')][:3]
    candidates = [entry for entry in snapshot['routing'].get('candidates', []) if entry.get('needs_route_review') is True]
    count = len(candidates)
    offset = int(snapshot['now'] // 300) % count if count else 0
    routes = [candidates[(offset + index) % count]['domain'] for index in range(min(count, 3))]
    reviews = [case['next_review_at'] - snapshot['now'] for case in snapshot['incidents'] if case['next_review_at'] > snapshot['now']]
    delay = int(max(30, min(300, min(reviews)))) if reviews else 300
    summary = 'Confirmed path faults require attention.' if faults else 'Incident attention follows recorded severity and review status.' if selected else 'No case currently requires attention; continue independent checks.'
    return {'summary': summary, 'wake': wake, 'incident_ids': selected, 'probe_domains': probes, 'route_candidates': routes, 'next_check_seconds': delay}
