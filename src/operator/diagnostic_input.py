"""Current case leases and real-input acceptance for maintained diagnostics."""
import copy
import hashlib
import json
from pathlib import Path
import time
from incidents import IncidentStore,observation_change,requires_attention


def annotate(snapshot,directory,now):
    from maintenance import _signals,_digest
    result=copy.deepcopy(snapshot)
    try:
        view=IncidentStore(Path(directory)/'incidents.json').list(now)
        cases={case['key']:case for case in view['cases']+view.get('overflow_cases',[])}
        signals={signal['key']:signal for signal in _signals({},result,now,True)}
    except (ValueError,OSError,TypeError):
        result['incident_view']={'available':False,'evidence_gap':'current incident decisions unavailable'}
        return result
    result['incident_view']={'available':True,'schema_version':1,'evaluated_at':now}
    business=result.get('business_observations',{})
    for row in business.get('issues',[])+business.get('pending_issues',[]):
        key='business:'+str(row.get('domain'));case=cases.get(key)
        if case is None:continue
        signal=signals.get(key)
        probe=business.get('checks',{}).get(row.get('domain'),{}).get('at',0)
        failure=row.get('last_failure_at',0)
        probe=probe if type(probe) in (int,float) else 0
        failure=failure if type(failure) in (int,float) else 0
        cutoff=max(case.get('decided_at',0),case.get('updated_at',0))
        predates=max(probe,failure)<=cutoff
        # A fresh generic check cannot make retained domain facts fresh. Merge
        # only evidence whose own clock follows the current disposition.
        candidate=copy.deepcopy(signal) if signal else None
        if candidate:
            facts=copy.deepcopy(case['facts'])
            if failure>cutoff: facts.update({k:v for k,v in candidate['facts'].items() if k!='paths'})
            if probe>cutoff:facts['paths']=candidate['facts'].get('paths',{})
            candidate.update(facts=facts,signature=_digest(facts),observed_at=max(failure,probe))
        changed=bool(not predates and candidate and observation_change(case,candidate,now)['reopens'])
        row['incident']={k:case[k] for k in ['id','revision','status','priority','next_review_at']}
        row['incident'].update(requires_attention=changed or requires_attention(case,now),new_evidence=changed,snapshot_predates_decision=predates)
    result['observations']=copy.deepcopy(business)
    return result


def live(directory,now=None):
    now=time.time() if now is None else now;directory=Path(directory)
    path=directory/'patrol.json'
    try:
        if path.stat().st_size>2*1024**2:raise ValueError()
        state=json.loads(path.read_text());sample=state['checked_at']
        if not 0<=now-sample<=900 or not isinstance(state.get('last_diagnosis'),dict):raise ValueError()
    except (ValueError,OSError,KeyError,TypeError):raise ValueError('fresh bounded patrol observations required before diagnostic publication') from None
    snapshot=copy.deepcopy(state['last_diagnosis']);snapshot.pop('maintenance',None)
    snapshot.update(checked_at=sample,history=state.get('history',[])[-24:])
    if state.get('last_quality'):
        snapshot['quality_summary']={'preferred_pool':state['last_quality'].get('node_pools',{}).get('us',[]),
                                    'active_domains':state['last_quality'].get('active_domains',{})}
    return annotate(snapshot,directory,now)


def validate(output,snapshot):
    issues=snapshot.get('business_observations',{}).get('issues',[])
    deferred=[row for row in issues if row.get('incident',{}).get('requires_attention') is False]
    if set(output.get('probe_domains',[])) & {r.get('domain') for r in deferred}:
        raise ValueError('diagnostic advice ignores a current incident review deadline')
    review=output.get('review_request',{}).get('fingerprint')
    if review is not None and review in {r.get('fingerprint') for r in deferred}:
        raise ValueError('diagnostic review ignores a current incident review deadline')
    return output


def receipt(snapshot,output):
    return {'observed_at':snapshot.get('checked_at'),'input_revision':hashlib.sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()[:20],
            'output':validate(output,snapshot),'scope':'fresh real input and current case decisions; not proof of application recovery'}
