"""Program-first targeted follow-up of real client evidence, never fixed sites."""
import hashlib
import json


def scan(observed,state,probe,now):
    state=dict(state) if isinstance(state,dict) else {}
    state.setdefault('checks',{})
    fresh=observed.get('status')=='observed'
    domains=[x for x in observed.get('domains',[]) if isinstance(x,dict) and isinstance(x.get('domain'),str) and now-21600<=x.get('last_seen',0)<=now] if fresh else []
    issues={x['domain']:x for x in state.get('issues',[]) if isinstance(x,dict) and x.get('resolved') is False and isinstance(x.get('domain'),str)}
    for item in domains:
        if item.get('recurring_failure') is not True:continue
        domain=item['domain']
        fingerprint=hashlib.sha256(json.dumps([domain,sorted(item.get('error_categories',[])),int(now//86400)]).encode()).hexdigest()[:20]
        issues[domain]={'domain':domain,'kind':'recurring_client_failure','fingerprint':issues.get(domain,{}).get('fingerprint',fingerprint),'resolved':False,
                       'proxy_path':bool(item.get('chains')) and 'DIRECT' not in item['chains'],
                       'evidence':'repeated real client dial failures; synthetic success cannot verify the client session'}
    state.update(checked_at=now,issues=list(issues.values())[-24:],coverage='recent client metadata and gateway root probes; application sessions remain unverified')
    ordered=sorted(domains,key=lambda x:(not x.get('recurring_failure',False),state['checks'].get(x['domain'],{}).get('at',0)))
    if now-state.get('last_probe_at',-100000)>=600:
        target=next((x['domain'] for x in ordered if now-state['checks'].get(x['domain'],{}).get('at',-100000)>=1800),None)
        if target:
            try:result=probe(target)
            except Exception as error:result={'state':'probe_unavailable','error_category':type(error).__name__}
            state['checks'][target]={'at':now,'result':result};state['last_probe_at']=now
    state['checks']=dict(sorted(state['checks'].items(),key=lambda x:x[1]['at'],reverse=True)[:24])
    return state
