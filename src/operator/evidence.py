"""Pure compact maintenance evidence with explicit, snapshot-scoped detail references.

Summaries select both failing and normal observations. Observed traffic is never
promoted to application success. A reference identifies the selected section's
content; callers must compare it with a fresh detail response before combining.
"""
import copy
import hashlib
import json

SCHEMA_VERSION=1
_SECTIONS={'diagnosis','checks','observations','business_observations','incidents','history',
           'node_health','runtime_facts','recent_system_changes','source_control','maintenance','operational_workflow'}
_CODE_KEYS={'code','source_code','program_source','content','native_task_prompt','last_diagnosis'}


def _dict(value):return value if isinstance(value,dict) else {}
def _list(value):return value if isinstance(value,list) else []
def _hash(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()[:20]


def _small(value,depth=0):
    """Bound structurally, recording omitted fields/items instead of cutting JSON."""
    if depth>6:return {'detail_required':True}
    if isinstance(value,dict):
        pairs=[(k,v) for k,v in value.items() if k not in _CODE_KEYS
               and not (k=='source' and isinstance(v,str) and len(v)>1000)]
        result={k:_small(v,depth+1) for k,v in pairs[:24]}
        if len(pairs)>24:result['omitted_field_count']=len(pairs)-24
        return result
    if isinstance(value,list):
        result=[_small(v,depth+1) for v in value[:6]]
        if len(value)>6:result.append({'more_count':len(value)-6})
        return result
    if isinstance(value,str) and len(value)>600:return {'excerpt':value[:600],'more_characters':len(value)-600}
    return copy.deepcopy(value)


def _pick(record,keys):return {k:_small(record[k]) for k in keys if k in record}


def _diagnosis(state):
    value=state.get('diagnosis',state.get('last_diagnosis'))
    if value is None:value=_dict(state.get('maintenance_event')).get('diagnosis')
    if value is None:value=state if 'checks' in state or 'status' in state else {}
    return _dict(value)


def _section(state,section):
    if section=='diagnosis':return _diagnosis(state)
    if section in state:return state[section]
    diagnosis=_diagnosis(state)
    if section in diagnosis:return diagnosis[section]
    if section=='node_health':return diagnosis.get('node_observations')
    return None


def _at(value):
    value=_dict(value)
    return next((value[k] for k in ['observed_at','checked_at','updated_at','last_seen'] if k in value),None)


def _ref(value,section,target=None):
    return {'section':section,'target':target,'snapshot_ref':_hash(value),'observed_at':_at(value),
            'freshness':'compare snapshot_ref with detail response; changed content requires re-read'}


def _observation_rows(value):
    """Join real business-watch issues/checks without inventing domain metadata.

    Traffic summaries contain domains; persisted business-watch states can instead
    contain only unresolved issues and domain-keyed checks. Newer producer states
    may contain both, so current domain metadata must not hide retained evidence.
    """
    value=_dict(value); rows={}
    for record in _list(value.get('domains')):
        if isinstance(record,dict) and isinstance(record.get('domain'),str):
            rows[record['domain']]=dict(record)
            for field in ['issues','pending_issues']:
                if field in record:rows[record['domain']][field]=list(_list(record[field]))
    for field in ['issues','pending_issues']:
        for issue in _list(value.get(field)):
            if isinstance(issue,dict) and isinstance(issue.get('domain'),str):
                row=rows.setdefault(issue['domain'],{'domain':issue['domain']})
                if issue not in row.setdefault(field,[]):row[field].append(issue)
    for domain,check in _dict(value.get('checks')).items():
        if isinstance(domain,str):rows.setdefault(domain,{'domain':domain})['check']=check
    return list(rows.values())


def _failure(row):
    return (row.get('recurring_failure') is True or row.get('current_failure') is True or row.get('failure_count',0)>0
            or any(_dict(issue).get('resolved') is False for issue in row.get('issues',[])+row.get('pending_issues',[])))


def _path_summary(path):
    # Keep the producer's explicit aggregate semantics. Reachable TCP/TLS/HTTP
    # stages and HTTP responses do not establish logged-in application success.
    return _pick(_dict(path),['sample_count','success_samples','passed_samples','failed_samples','unknown_samples',
        'transport_failed_samples','transport_ok','http_ok','http_status','business_ok','business_outcome','usable',
        'application_state','path_verified','business_rejection_samples','region_rejected_samples',
        'median_elapsed_ms','stage','region_status','logged_in_application_verified','application_verified'])


def _check_summary(check):
    check=_dict(check); original=_dict(check.get('result'))
    result=_pick(original,['state','target','domain','observed_at','checked_at','origin','cached',
        'acceptance_stage','stage','application_verified','logged_in_application_verified','acceptance_scope',
        'path_identity_verified','error_category','policy_changed','business_evidence','business_ok',
        'business_outcome','application_state','network_reachable'])
    if 'endpoint' in original:result['endpoint']=_pick(_dict(original['endpoint']),['network','port','application_protocol'])
    if 'paths' in original:result['paths']={name:_path_summary(path) for name,path in _dict(original['paths']).items() if name in ['direct','proxy']}
    if 'counters' in original:result['counters']=_pick(_dict(original['counters']),[
        'samples','failed_samples','unverified_business_samples','transient_paths','recurring_failure_paths'])
    return {**_pick(check,['at','observed_at','checked_at','state','error_category']),'result':result}


def _issue_summary(issue):
    issue=_dict(issue)
    result=_pick(issue,['domain','kind','resolved','fingerprint','last_failure_at','observed_at','updated_at',
        'current_failure','verified_recovery','error_categories','proxy_path','repair_status','status','priority',
        'reason','outcome','network_restored','next_review_at','evidence','plan'])
    if 'endpoint' in issue:result['endpoint']=_pick(_dict(issue['endpoint']),['network','port','application_protocol'])
    if 'facts' in issue:
        facts=_dict(issue['facts'])
        result['facts']=_pick(facts,['kind','current_failure','verified_recovery','logged_in_application_verified',
            'application_verified','repair_status','proxy_path','error_categories','action','reason','business_outcome',
            'region_status','next_review_at','status'])
        if 'endpoint' in facts:result['facts']['endpoint']=_pick(_dict(facts['endpoint']),['network','port','application_protocol'])
        if 'paths' in facts:result['facts']['paths']={name:_path_summary(path) for name,path in _dict(facts['paths']).items() if name in ['direct','proxy']}
    if 'progress' in issue:
        progress=issue['progress']
        if isinstance(progress,list):result['progress']=[_pick(_dict(row),['at','kind','status','reason','outcome','next_review_at','evidence']) for row in progress[-3:]]
        elif isinstance(progress,dict):result['progress']=_pick(progress,['at','kind','status','reason','outcome','next_review_at','evidence'])
        else:result['progress']=_small(progress)
    return result


def _observation_row_summary(row,value,section):
    result=_pick(row,['domain','last_seen','last_failure_at','failure_count','recurring_failure','current_failure',
        'error_categories','chains','rules','protocol','port','observed_bytes_lower_bound','connections_seen',
        'business_ok','application_state','network_reachable','acceptance_scope','sampling','origin'])
    if 'endpoints' in row:
        endpoints=_list(row['endpoints']);result['endpoints']=[_pick(_dict(e),['network','port','application_protocol']) for e in endpoints[:2]]
        if len(endpoints)>2:result['endpoint_more_count']=len(endpoints)-2
    for field in ['issues','pending_issues']:
        if field in row:
            issues=_list(row[field]);result[field]=[_issue_summary(issue) for issue in issues[:2]]
            if len(issues)>2:result[field+'_more_count']=len(issues)-2
    if 'check' in row:result['check']=_check_summary(row['check'])
    if 'check' in row or 'issues' in row or 'pending_issues' in row:
        result['detail_ref']={'section':section,'target':row.get('domain'),'snapshot_ref':_hash(value),'observed_at':_at(value)}
    return result


def _source_control_summary(value):
    value=_dict(value)
    result=_pick(value,['available','pending','phase','head','repository_url','branch','expected_branch','result',
        'last_attempt_at','last_success_at','local_commit','remote_commit','verification','error_code',
        'acknowledged_request','acknowledged_commit','acknowledged_versions'])
    if 'recent_publications' in value:
        rows=_list(value['recent_publications'])
        result['recent_publications']=[_pick(_dict(row),['id','sequence','reason','artifact','version','session_id',
            'status','revision','requested_at','updated_at','error_code','remote_commit','branch',
            'acknowledged_request','superseded_by']) for row in rows[-2:]]
        result['publication_more_count']=max(0,len(rows)-2)
        counts={}
        for row in rows:
            status=_dict(row).get('status','unknown')
            if not isinstance(status,str):status='unknown'
            counts[status]=counts.get(status,0)+1
        result['publication_status_counts']=counts
    return result


def _observation_summary(value,section):
    value=_dict(value); rows=_observation_rows(value)
    # Retain positive controls from distinct observed routes even under a large
    # failure population. Zero observed failures is explicitly not business health.
    failed=[r for r in rows if _failure(r)]; normal=[r for r in rows if not _failure(r)]
    selected=failed[:4]; routes=set()
    for row in normal:
        route=json.dumps(row.get('chains',row.get('route','unknown')),sort_keys=True)
        if route not in routes and len(selected)<8:selected.append(row);routes.add(route)
    for row in normal+failed:
        if len(selected)>=8:break
        if not any(row is item for item in selected):selected.append(row)
    result=_pick(value,['origin','scope','status','checked_at','observed_at','retention_hours','coverage',
                        'domain_count','device_count','failure_count','observed_bytes_lower_bound','sampling','evidence_gaps'])
    result.setdefault('status','unknown')
    result['domains']=[_observation_row_summary(row,value,section) for row in selected]
    result['issues']=[_issue_summary(row) for row in _list(value.get('issues'))[:6]]
    result['issue_more_count']=max(0,len(_list(value.get('issues')))-6)
    result.update(total_count=len(rows),more_count=len(rows)-len(selected),
                  sampling_scope='selected failing domains and normal route controls; absence of failures does not verify applications',
                  detail_ref=_ref(value,section))
    if not value:result['evidence_gaps']=['observation evidence unavailable']
    elif 'coverage' not in value:result['evidence_gaps']=[*_list(result.get('evidence_gaps')), 'sampling coverage unspecified']
    return result


def incident_summary(case):
    """Preserve disposition, severity, progress and next review independently."""
    case=_dict(case)
    result=_pick(case,['id','key','domain','revision','status','priority','source_priority','reason','outcome',
                      'network_restored','next_review_at','created_at','updated_at','last_observed_at',
                      'decided_at','actor','reopen_on_activity','facts','evidence','plan','progress'])
    result['history']=[_small(row) for row in _list(case.get('history'))[-3:]]
    result['history_more_count']=max(0,len(_list(case.get('history')))-3)
    return result


def _incidents(value,now=None):
    records=(_list(value) if isinstance(value,list) else
             _list(_dict(value).get('cases'))+_list(_dict(value).get('overflow_cases')))
    records=[r for r in records if isinstance(r,dict)]
    def rank(case):
        due=case.get('next_review_at')
        return (case.get('priority')!='urgent',case.get('status')=='closed',
                not (isinstance(due,(float,int)) and isinstance(now,(float,int)) and due<=now),
                due if isinstance(due,(float,int)) else float('inf'),str(case.get('id','')))
    selected=sorted(records,key=rank)[:12]
    return {'cases':[incident_summary(r) for r in selected],'total_count':len(records),
            'more_count':len(records)-len(selected),'urgent_count':sum(r.get('priority')=='urgent' for r in records),
            'unresolved_count':sum(r.get('status')!='closed' for r in records),
            'capacity_exceeded':_dict(value).get('capacity_exceeded',False),
            'detail_ref':_ref(value,'incidents')}


def diagnosis_summary(diagnosis):
    """Compact the current check evidence without converting its health semantics."""
    diagnosis=_dict(diagnosis); checks=_dict(diagnosis.get('checks'))
    names=list(checks); selected=[n for n in names if _dict(checks[n]).get('ok') is False][:6]
    controls=[n for n in names if n in ['gateway_dns_cn','gateway_dns_foreign','bootstrap_dns_api','mainland_https','proxy_https']]
    normal=[n for n in names if _dict(checks[n]).get('ok') is True]
    for name in controls+normal+names:
        if len(selected)>=12:break
        if name not in selected:selected.append(name)
    result={'schema_version':SCHEMA_VERSION,'observed_at':_at(diagnosis) or _at(diagnosis.get('status')),
        'status':_small(diagnosis.get('status',{})),
        'checks':{name:_small(checks[name]) for name in selected},
        'checks_more_count':len(checks)-len(selected),'checks_detail_ref':_ref(checks,'checks'),
        'business_observations':_observation_summary(diagnosis.get('business_observations'),'business_observations'),
        'detail_ref':_ref(diagnosis,'diagnosis'),'evidence_gaps':[]}
    if not checks:result['evidence_gaps'].append('current DNS/HTTPS controls unavailable')
    if not diagnosis.get('business_observations'):result['evidence_gaps'].append('client business observations unavailable')
    if 'node_observations' in diagnosis:result['node_observations']=_small(diagnosis['node_observations'])
    if 'note' in diagnosis:result['note']=_small(diagnosis['note'])
    return result


def _maintenance(value,now=None):
    value=_dict(value)
    result=_pick(value,['requires_attention','workflow','path_health','routing','faults','pending_signals',
                        'next_check_seconds','migration_complete','evidence_gaps'])
    cases=_incidents(value.get('cases',[]),now)
    result.update(cases=cases['cases'],case_more_count=cases['more_count'],urgent_count=cases['urgent_count'],
                  detail_ref=_ref(value,'maintenance'))
    if 'observations' in value:
        result['observations']=_observation_summary(value['observations'],'observations')
        result['observations']['detail_ref']=_ref(value,'maintenance','observations')
    return result


def _deduplicate_maintenance(result,raw):
    maintenance=result.get('maintenance')
    if not maintenance:return
    original=_dict(raw.get('maintenance'))
    if 'incidents' in result:
        ids={case.get('id') for case in result['incidents']['cases']}
        maintenance['cases']=[{
            **_pick(case,['id','revision','status','priority','reason','outcome','network_restored','next_review_at']),
            'detail_ref':{**result['incidents']['detail_ref'],'target':case.get('id')},'progress_summary_in':'incidents.cases'}
            if case.get('id') in ids else case for case in maintenance['cases']]
    alternatives=[('observations',raw.get('observations')),
                  ('diagnosis.business_observations',_diagnosis(raw).get('business_observations'))]
    for path,value in alternatives:
        if path.split('.')[0] not in result:continue
        if value is not None and original.get('observations')==value:
            maintenance['observations']={
                **_pick(_dict(original['observations']),['status','checked_at','observed_at']),
                'summary_in':path,'detail_ref':_ref(original,'maintenance','observations')}
            break


def task_context(raw):
    """Bound a fresh task; caller supplies native_task_prompt separately."""
    raw=_dict(raw)
    result=_pick(raw,['observed_at','checked_at','urgent','maintenance_trigger','native_job_id','native_session_id',
                     'native_deadline','native_task_id','dispatch_cause','diagnostic_program','quality_summary',
                     'pricing','review_request','runtime_facts','audit_rollup','storage','tracked_probes','operational_workflow'])
    result['schema_version']=SCHEMA_VERSION
    result['diagnosis']=diagnosis_summary(_diagnosis(raw))
    if 'maintenance' in raw:result['maintenance']=_maintenance(raw['maintenance'],_at(raw))
    if 'incidents' in raw:result['incidents']=_incidents(raw['incidents'],_at(raw))
    if 'observations' in raw:result['observations']=_observation_summary(raw['observations'],'observations')
    for key in ['history','recent_system_changes']:
        if key in raw:
            rows=_list(raw[key]);result[key]=[_small(r) for r in rows[-4:]]
            result[key+'_more_count']=max(0,len(rows)-4);result[key+'_detail_ref']=_ref(raw[key],key)
    if 'tickets' in raw:
        tickets=raw['tickets'];result['tickets']=_small(dict(list(tickets.items())[-4:]) if isinstance(tickets,dict) else tickets)
    _deduplicate_maintenance(result,raw)
    return result


def system_context(full):
    """Compact broker context; detail is fetched on demand from the same section."""
    full=_dict(full)
    result=_pick(full,['checked_at','observed_at','gateway_address','upstream','services','free_disk_bytes',
        'temperature_celsius','policy','control_route','region','node','provider_counts','pending_recovery',
        'storage','self','sources','skill_revision','release_capabilities','maintenance_pricing','audit_plan',
        'native_automation','probe_capabilities','protected_boundary','runtime_facts','operational_workflow'])
    result['schema_version']=SCHEMA_VERSION
    for key in ['observations','business_observations']:
        if key in full:result[key]=_observation_summary(full[key],key)
    if 'node_health' in full:
        result['node_health']=_small(full['node_health']);result['node_health_detail_ref']=_ref(full['node_health'],'node_health')
    if 'source_control' in full:
        result['source_control']=_source_control_summary(full['source_control'])
        result['source_control_detail_ref']=_ref(full['source_control'],'source_control')
    task=_dict(full.get('native_automation')).get('task')
    for key in ['native_schedule','schedule']:
        if task is not None and _dict(full.get('audit_plan')).get(key)==task:
            result['audit_plan'][key]={'summary_in':'native_automation.task'}
    if 'maintenance' in full:result['maintenance']=_maintenance(full['maintenance'],_at(full))
    if 'incidents' in full:result['incidents']=_incidents(full['incidents'],_at(full))
    if 'maintenance_event' in full:
        event=_dict(full['maintenance_event'])
        result['maintenance_event']=_pick(event,['urgent','observed_at','maintenance_trigger','native_job_id',
                                               'native_session_id','native_deadline','dispatch_cause'])
        result['maintenance_event']['diagnosis_detail_ref']=_ref(_diagnosis(event),'diagnosis')
    if 'recent_system_changes' in full:
        result['recent_system_changes']=[_small(r) for r in _list(full['recent_system_changes'])[-4:]]
        result['recent_system_changes_detail_ref']=_ref(full['recent_system_changes'],'recent_system_changes')
    result['evidence_gaps']=[key+' unavailable' for key in ['observations','runtime_facts','incidents'] if key not in full]
    _deduplicate_maintenance(result,full)
    return result


def detail(state,section,target=None,limit=16):
    """Return targeted original records and a fingerprint; never read files or mutate.

    ``limit`` bounds records, not serialized text fragments. Section inputs are
    already bounded by their owning store. A 256 KiB response ceiling fails
    explicitly, allowing the caller to request a domain or smaller page.
    """
    if section not in _SECTIONS:raise ValueError('unsupported evidence section')
    if type(limit) is not int or not 1<=limit<=64:raise ValueError('detail limit must be between 1 and 64')
    if target is not None and (not isinstance(target,str) or len(target)>300):raise ValueError('bounded detail target required')
    state=_dict(state);value=_section(state,section)
    if value is None and section=='diagnosis':value={}
    if section in ['observations','business_observations']:
        rows=_observation_rows(value)
    elif section=='incidents':
        rows=_list(value) if isinstance(value,list) else _list(_dict(value).get('cases'))+_list(_dict(value).get('overflow_cases'))
    elif isinstance(value,list):rows=value
    elif section=='checks':rows=[{'name':k,**v} if isinstance(v,dict) else {'name':k,'value':v} for k,v in _dict(value).items()]
    else:rows=[value] if value else []
    if section=='maintenance' and target in _dict(value):
        rows=[{'name':target,'value':value[target]}]
    elif target is not None:
        rows=[r for r in rows if isinstance(r,dict) and target in [r.get('domain'),r.get('id'),r.get('name')]]
    result={'schema_version':SCHEMA_VERSION,'section':section,'target':target,'snapshot_ref':_hash(value),
            'observed_at':_at(value),'status':'available' if value else 'unknown','items':copy.deepcopy(rows[:limit]),
            'total_count':len(rows),'more_count':max(0,len(rows)-limit),
            'evidence_gaps':[] if value else ['requested evidence unavailable']}
    if section in ['observations','business_observations']:
        result.update(_pick(_dict(value),['coverage','origin','scope','status']))
        if isinstance(_dict(value).get('evidence_gaps'),list):result['evidence_gaps']=copy.deepcopy(value['evidence_gaps'])
    if target is not None and value and not rows:
        result['status']='not_found'
        result['evidence_gaps']=[*result['evidence_gaps'],'no evidence for requested target in this snapshot']
    if len(json.dumps(result,ensure_ascii=False,default=str).encode())>256*1024:
        result.update(status='detail_budget_exceeded',items=[],more_count=len(rows),
                      evidence_gaps=['request a target or smaller limit; no partial record returned'])
    return result
