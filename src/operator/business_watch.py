"""Program-first targeted follow-up of real client evidence, never fixed sites."""
import hashlib
import json
import math
from business_probe import endpoint_spec


def endpoint_for(row,previous=None):
    endpoints=row.get('endpoints',[]) if isinstance(row,dict) else []
    valid=[(clean,item.get('last_failure_at')) for item in endpoints if (clean:=endpoint_spec(item)) is not None]
    if not valid:return None
    latest=row.get('last_seen',0)
    failed=[(clean,at) for clean,at in valid if type(at) in (int,float) and math.isfinite(at) and at>0 and (not latest or latest-21600<=at<=latest)]
    choices=[clean for clean,at in sorted(failed,key=lambda pair:pair[1],reverse=True)] if failed else [clean for clean,at in valid]
    if previous in choices and len(choices)>1:return choices[(choices.index(previous)+1)%len(choices)]
    return choices[0]


def scan(observed,state,probe,now,allow_probe=True):
    state=dict(state) if isinstance(state,dict) else {}
    state.setdefault('checks',{})
    fresh=observed.get('status')=='observed'
    domains=[x for x in observed.get('domains',[]) if isinstance(x,dict) and isinstance(x.get('domain'),str) and now-21600<=x.get('last_seen',0)<=now] if fresh else []
    issues={x['domain']:x for x in state.get('issues',[])+state.get('pending_issues',[]) if isinstance(x,dict) and x.get('resolved') is False and isinstance(x.get('domain'),str)}
    gaps=[]
    for item in domains:
        if item.get('recurring_failure') is not True:continue
        domain=item['domain']
        failed=item.get('last_failure_at')
        if type(failed) not in (int,float) or not math.isfinite(failed):gaps.append({'domain':domain,'kind':'missing_failure_time'});continue
        if not now-21600<=failed<=now:continue
        endpoint=endpoint_for(item)
        fingerprint=hashlib.sha256(json.dumps([domain,sorted(item.get('error_categories',[])),endpoint],sort_keys=True).encode()).hexdigest()[:20]
        issues[domain]={'domain':domain,'kind':'recurring_client_failure','fingerprint':issues.get(domain,{}).get('fingerprint',fingerprint),'resolved':False,
                       'last_failure_at':failed,'error_categories':sorted(item.get('error_categories',[]))[:8],'endpoint':endpoint,
                       'proxy_path':bool(item.get('chains')) and 'DIRECT' not in item['chains'],
                       'evidence':'repeated real client dial failures; synthetic success cannot verify the client session'}
    retained=list(issues.values())
    if len(retained)>512:raise ValueError('business evidence capacity exceeded; retain traffic input and retry')
    state.update(checked_at=now,issues=retained,pending_issues=[],evidence_gaps=gaps[:256],
                 domains=[{key:item[key] for key in ['domain','last_seen','last_failure_at','endpoints','recurring_failure'] if key in item} for item in domains][:256],
                 coverage='recent client metadata and endpoint probes; application sessions remain unverified')
    ordered=sorted(domains,key=lambda x:(not x.get('recurring_failure',False),state['checks'].get(x['domain'],{}).get('at',0)))
    if allow_probe and now-state.get('last_probe_at',-100000)>=600:
        target=next((x['domain'] for x in ordered if now-state['checks'].get(x['domain'],{}).get('at',-100000)>=1800),None)
        if target:
            endpoint=endpoint_for(next(item for item in ordered if item['domain']==target),state['checks'].get(target,{}).get('endpoint'))
            try:result=probe(target,endpoint=endpoint) if endpoint else {'state':'endpoint_unknown','application_verified':False}
            except Exception as error:result={'state':'probe_unavailable','error_category':type(error).__name__}
            state['checks'][target]={'at':now,'endpoint':endpoint,'result':result};state['last_probe_at']=now
    state['checks']=dict(sorted(state['checks'].items(),key=lambda x:x[1]['at'],reverse=True)[:24])
    return state
