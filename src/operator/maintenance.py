"""Trusted observation and durable ownership around the maintained pure workflow."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
from incidents import IncidentStore
import workflow

STATE=Path('/var/lib/net-gateway-agent')
PENDING_LIMIT=512
REJECTED_LIMIT=1024


def _digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,allow_nan=False).encode()).hexdigest()[:20]


def path_faults(diagnosis):
    """Business dispositions never alter independently checked network paths."""
    faults=[];status=diagnosis.get('status',{});direct=status.get('policy',{}).get('mode')=='direct'
    if not direct and diagnosis.get('node_observations',{}).get('urgent') is True:faults.append('proxy_node_pool')
    if status.get('services',{}).get('net-gateway.service',{}).get('ActiveState')!='active':faults.append('gateway_service')
    if status.get('storage',{}).get('critical'):faults.append('disk_space')
    for name,item in diagnosis.get('checks',{}).items():
        if name.startswith('target:') or (direct and name in ['gateway_dns_foreign','proxy_https']):continue
        result=item.get('result',{})
        if not item.get('ok') or ('rcode' in result and (result['rcode']!=0 or (result.get('answer_count') or 0)<1)) or result.get('expected_health_status') is False:faults.append(name)
    return sorted(set(faults))


def _atomic(path,value):
    encoded=json.dumps(value,ensure_ascii=False,allow_nan=False).encode()
    if len(encoded)>8*1024**2:raise ValueError('maintenance state exceeds its byte budget')
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as file:
            os.fchmod(file.fileno(),0o600);file.write(encoded)
            file.flush();os.fsync(file.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:Path(name).unlink(missing_ok=True)


@contextmanager
def _exclusive(directory):
    directory.mkdir(parents=True,exist_ok=True)
    fd=os.open(directory/'maintenance-state.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        yield


def _recovery(directory):
    path=directory/'maintenance-pending-recovery.json'
    if not path.exists():return []
    with path.open() as file:raw=file.read(5*1024**2+1)
    data=json.loads(raw)
    if len(raw.encode())>5*1024**2 or not isinstance(data,dict) or not _valid_signals(data.get('pending'),REJECTED_LIMIT):raise ValueError('maintenance recovery input requires recovery')
    return data['pending']


def _valid_signals(signals,limit=PENDING_LIMIT):
    return isinstance(signals,list) and len(signals)<=limit and all(isinstance(signal,dict) and
        isinstance(signal.get('key'),str) and 1<=len(signal['key'])<=300 and
        isinstance(signal.get('signature'),str) and 1<=len(signal['signature'])<=300 and
        isinstance(signal.get('facts'),dict) and len(json.dumps(signal['facts'],allow_nan=False).encode())<=4096 and
        workflow._finite(signal.get('observed_at')) for signal in signals)


def _merge(signals):
    merged={}
    for signal in signals:
        current=merged.get(signal['key'])
        if current is None or signal.get('observed_at',0)>=current.get('observed_at',0):merged[signal['key']]=signal
    return list(merged.values())


@contextmanager
def _state(directory):
    with _exclusive(directory):
        path=directory/'maintenance-state.json'
        if path.exists():
            with path.open() as file:raw=file.read(8*1024**2+1)
            data=json.loads(raw)
            if len(raw.encode())>8*1024**2 or not isinstance(data,dict) or data.get('format')!=1 or type(data.get('migration_complete')) is not bool or not _valid_signals(data.get('pending')) or not _valid_signals(data.get('rejected',[]),REJECTED_LIMIT):raise ValueError('maintenance storage requires recovery')
        else:data={'format':1,'migration_complete':False,'pending':[]}
        recovery=_recovery(directory)
        if recovery:data['recovered']=recovery
        yield data
        recovery_consumed=data.pop('recovery_consumed',False)
        data.pop('recovered',None)
        _atomic(path,data)
        if recovery and recovery_consumed:(directory/'maintenance-pending-recovery.json').unlink(missing_ok=True)


def _probe_facts(entry):
    result=(entry or {}).get('result',{})
    return {path:{key:value for key,value in data.items() if key in ['transport_ok','business_ok','business_outcome','application_state','http_status','endpoint','stage','region_status',
                'sample_count','success_samples','failed_samples','path_verified','region_rejected_samples','business_rejection_samples']}
            for path,data in result.get('paths',{}).items() if path in ['direct','proxy'] and isinstance(data,dict)}


def _signals(state,diagnosis,now,migrated):
    business=diagnosis.get('business_observations',state.get('business_observations',{}))
    issues=list(business.get('issues',[]))+business.get('pending_issues',[])
    issues+=[{**item,'resolved':False,'kind':'recurring_client_failure'} for item in state.get('pending_business_input',{}).get('domains',[]) if item.get('recurring_failure') is True]
    if not migrated:issues+=state.get('business_observations',{}).get('issues',[])
    signals={}
    for issue in issues:
        domain=issue.get('domain')
        if issue.get('resolved') is not False or not workflow._domain(domain):continue
        failure=issue.get('last_failure_at')
        if failure is None and migrated:continue
        if failure is not None and (not workflow._finite(failure) or failure>now):continue
        facts={'kind':issue.get('kind','client_failure'),'current_failure':True,
               'error_categories':sorted(issue.get('error_categories',[]))[:8],
               'proxy_path':issue.get('proxy_path'),'endpoint':issue.get('endpoint'),
               'repair_status':issue.get('repair_status'),'paths':_probe_facts(business.get('checks',{}).get(domain))}
        signal={'key':'business:'+domain,'domain':domain,'signature':_digest(facts),'priority':'urgent',
                'observed_at':failure if failure is not None else min(issue.get('observed_at',now),now),'facts':facts}
        signals[signal['key']]=signal
    for name in path_faults(diagnosis):
        result=diagnosis.get('checks',{}).get(name,{}).get('result',{})
        facts={'kind':'path_fault','check':name,'current_failure':True,
               'result':{k:result[k] for k in ['rcode','http_status','expected_health_status'] if k in result}}
        if name=='proxy_node_pool':facts['incident']=diagnosis.get('node_observations',{}).get('fingerprint')
        signals['path:'+name]={'key':'path:'+name,'signature':_digest(facts),'priority':'urgent','observed_at':now,'facts':facts}
    for domain,review in state.get('routing_reviews',{}).items():
        result=review.get('result',{})
        if not workflow._domain(domain) or result.get('action') not in ['apply','investigate','no_route_remedy']:continue
        facts={'kind':'route_review','action':result['action'],'reason':result.get('reason'),
            'proposal':result.get('proposal'),'request':review.get('request'),'application_verified':False}
        signals['route-review:'+domain]={'key':'route-review:'+domain,'domain':domain,'signature':_digest(facts),
            'priority':'urgent','observed_at':review['at'],'facts':facts}
    return list(signals.values())


def _case(case,now):
    keys=['id','key','domain','revision','status','priority','outcome','network_restored','next_review_at','actor','decided_at']
    result={key:case[key] for key in keys if key in case}
    result.update(reason=case.get('reason','')[:300],facts=copy.deepcopy(case['facts']),
        evidence=case.get('evidence',[])[:3],requires_attention=case['status']=='open' or case['next_review_at']<=now,
        progress=copy.deepcopy(case.get('history',[])[-1:]))
    return result


def _routing_candidates(directory,diagnosis,business,preferences,now):
    path=directory/'route-evidence.json'
    if not path.exists():return []
    from route_evidence import EvidenceStore
    from adaptive_routing import evaluate_route
    store=EvidenceStore(path);approved_path=directory/'approved-policy.json'
    approved=json.loads(approved_path.read_text()) if approved_path.exists() else {
        'version':diagnosis.get('status',{}).get('policy',{}).get('version'),'preferences':preferences}
    status=store.status(now=now)
    requirements=store.get_many([item['id'] for item in status['recent'] if item['kind']=='requirement' and not item['expired']],now=now)
    domains=list(dict.fromkeys(item['domain'] for item in requirements))[:8];result=[]
    for domain in domains:
        basis=[item for item in requirements if item['domain']==domain and item.get('references_available')]
        if not basis or len({item['required_path'] for item in basis})!=1:continue
        entries=store.status(now=now,domain=domain)['recent']
        rounds=store.get_many([item['id'] for item in entries if item['kind']=='comparison' and not item['expired']],now=now)
        rounds=sorted((item for item in rounds if 0<=now-item.get('observed_at',0)<=900),key=lambda item:item['observed_at'])
        if len(rounds)<2:continue
        newest=rounds[-1];previous=next((item for item in reversed(rounds[:-1]) if newest['observed_at']-item['observed_at']>=60),None)
        if previous is None:continue
        refs=[previous['id'],newest['id']];knowledge=[item['id'] for item in basis]
        observed=next((item.get('endpoints',[]) for item in business.get('domains',[]) if item.get('domain')==domain),[])
        verdict=evaluate_route(domain,basis[0]['required_path'],refs,approved,store,now=now,
            observed_endpoints=observed,business_requirement_evidence_ids=knowledge)
        if verdict['action']!='apply':continue
        result.append({'domain':domain,'path':basis[0]['required_path'],'needs_route_review':True,
            'current_path_bad':True,'current_route_conflicts':True,'evidence_ids':refs,
            'business_requirement_evidence_ids':knowledge,'expected_version':approved.get('version'),
            'business_basis':{'public':True,'required_path':basis[0]['required_path'],'evidence':knowledge,
                              'semantic_truth_proven':False}})
    return result


def _snapshot(state,diagnosis,now,preferences,cases,faults,directory):
    business=diagnosis.get('business_observations',state.get('business_observations',{}))
    domains=[{'domain':item['domain'],'needs_probe':False} for item in business.get('domains',[]) if workflow._domain(item.get('domain'))][:256]
    for case in cases:
        if workflow._domain(case.get('domain')):
            domains=[item for item in domains if item['domain']!=case['domain']]
            domains.insert(0,{'domain':case['domain'],'needs_probe':case['requires_attention']})
    try:candidates=_routing_candidates(directory,diagnosis,business,preferences,now)
    except (ValueError,OSError,TypeError):faults.append('route_evidence_storage');candidates=[]
    return {'schema_version':1,'now':now,'path_health':{'hard_faults':path_faults(diagnosis)+['maintenance:'+f for f in faults],
            'checks':copy.deepcopy(diagnosis.get('checks',{}))},'incidents':cases,
        'observations':{'domains':domains[:256],'coverage':business.get('coverage'),'evidence_gaps':business.get('evidence_gaps',[])},
        'routing':{'preferences':copy.deepcopy(preferences),'routing_strategy':preferences.get('routing_strategy'),'candidates':candidates},
        'audit':{key:state.get(key) for key in ['last_independent_audit_at','last_routine_ai_at','audit_plan','healthy_samples']}}


def _fallback(faults,cases):
    return {'active':False,'version':'maintenance-safe','failures':[{'version':'maintenance','error':','.join(faults)}],
        'maintenance_required':True,'result':{'summary':'Maintenance evidence requires recovery; retain all pending cases.',
        'wake':'urgent','incident_ids':[c['id'] for c in cases if c['requires_attention']][:16],
        'probe_domains':[],'route_candidates':[],'next_check_seconds':30}}


def observe(state,diagnosis,now,preferences=None,directory=None,inspect=None):
    """Observe private cases, then execute the versioned workflow on an explicit snapshot."""
    directory=STATE if directory is None else Path(directory)
    preferences=preferences if preferences is not None else diagnosis.get('status',{}).get('policy',{}).get('preferences',{})
    inspect=workflow.inspect_active if inspect is None else inspect
    store=IncidentStore(directory/'incidents.json');faults=list(diagnosis.get('maintenance_input_errors',[]));cases=[];total=0;migrated=False;pending=[]
    try:
        with _state(directory) as data:
            incoming=_signals(state,diagnosis,now,data['migration_complete'])
            pending=_merge(data['pending']+data.get('rejected',[])+data.get('recovered',[])+incoming)
            if len(pending)>PENDING_LIMIT:
                faults.append('pending_capacity');accepted={signal['key'] for signal in data['pending']}
                rejected=[signal for signal in pending if signal['key'] not in accepted]
                if len(rejected)>REJECTED_LIMIT:raise ValueError('maintenance rejected input capacity exhausted')
                data['rejected']=rejected
                pending=list(data['pending']);view=store.list(now)
            else:
                data['pending']=pending;data.pop('rejected',None);data['recovery_consumed']=True
                try:
                    for index in range(0,len(pending),256):store.observe(pending[index:index+256],now)
                    view=store.list(now);data['migration_complete']=True
                    current=set(path_faults(diagnosis))
                    recovered=[]
                    for case in view['cases']+view['overflow_cases']:
                        if case['key'].startswith('path:') and case['key'][5:] not in current and case['facts'].get('current_failure') is True:
                            facts={**case['facts'],'current_failure':False,'verified_recovery':True}
                            recovered.append({'key':case['key'],'signature':_digest(facts),'facts':facts,'priority':case.get('source_priority','urgent'),'observed_at':now})
                    if recovered:store.observe(recovered,now);view=store.list(now)
                except (ValueError,OSError) as error:
                    capacity='capacity' in str(error)
                    faults.append('incident_capacity' if capacity else 'incident_storage')
                    view=store.list(now) if capacity else {'cases':[],'overflow_cases':[]}
            all_cases=view['cases']+view['overflow_cases'];total=len(all_cases)
            if view.get('capacity_exceeded') or total>128:faults.append('incident_capacity')
            ordered=sorted(all_cases,key=lambda c:(not (c['priority']=='urgent' and (c['status']=='open' or c['next_review_at']<=now)),
                not (c['status']=='open' or c['next_review_at']<=now),c['next_review_at'],c['id']))
            cases=[_case(case,now) for case in ordered[:128]]
            snapshot=_snapshot(state,diagnosis,now,preferences,cases,faults,directory)
            try:
                evaluated=inspect(snapshot)
                if not isinstance(evaluated,dict) or not {'result','maintenance_required','failures','version'}<=set(evaluated):raise ValueError('workflow result contract')
                workflow.validate_output(evaluated['result'],snapshot)
                if evaluated['maintenance_required']:faults.append('workflow_failure')
            except Exception:
                faults.append('workflow_failure');evaluated=_fallback(faults,cases)
            if not faults:data['pending']=[]
            pending=data['pending']+data.get('rejected',[])+(data.get('recovered',[]) if not data.get('recovery_consumed') else []);migrated=data['migration_complete']
    except (ValueError,OSError,TypeError):
        faults.append('maintenance_storage');pending=_signals(state,diagnosis,now,False)
        # Preserve damaged state and retain new bounded source input separately.
        with _exclusive(directory):
            pending=_merge(_recovery(directory)+pending)
            if len(pending)>REJECTED_LIMIT:raise ValueError('maintenance pending capacity exhausted; retain upstream observations')
            _atomic(directory/'maintenance-pending-recovery.json',{'format':1,'pending':pending})
        snapshot=_snapshot(state,diagnosis,now,preferences,cases,faults,directory);evaluated=_fallback(faults,cases)
    return {'schema_version':1,'cases':cases,'total_cases':total,'workflow':evaluated,
        'path_health':snapshot['path_health'],'observations':snapshot['observations'],'routing':snapshot['routing'],
        'faults':sorted(set(faults)),'pending_signals':len(pending),'next_check_seconds':evaluated['result']['next_check_seconds'],
        'migration_complete':migrated,'requires_attention':bool(faults or any(case['requires_attention'] for case in cases)),
        'evidence_gaps':[diagnosis['observation_failure']] if diagnosis.get('observation_failure') else []}
