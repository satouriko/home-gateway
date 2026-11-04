"""Autonomous observation, bounded conventional repairs and scheduled AI maintenance."""
import grp
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import hashlib
import shutil
from programs import inspect_active
from pricing import routine_allowed, pricing_state
import native_jobs as native
import maintenance

STATE=Path('/var/lib/net-gateway-agent')
SOCKET='/run/net-gateway-agent/control.sock'
AI_SERVICE='net-gateway-ai-patrol.service'
CONTEXT=Path('/run/net-gateway-agent/patrol-context.json')

def preempt_needed(state,diagnosis,job,context):
    return bool(urgent_ai_needed(state,diagnosis,diagnosis.get('maintenance',{}).get('observed_at',time.time())) and job in ['active','activating'] and not context.get('urgent'))

def fault_keys(diagnosis):
    return sorted(set(maintenance.path_faults(diagnosis)+['maintenance:'+name for name in diagnosis.get('maintenance',{}).get('faults',[])]))

def fault_signature(diagnosis):
    faults=fault_keys(diagnosis)
    evidence={name:{key:diagnosis.get('checks',{}).get(name,{}).get('result',{}).get(key) for key in ['rcode','http_status','expected_health_status']} for name in faults}
    for name in faults:evidence[name]['error']=diagnosis.get('checks',{}).get(name,{}).get('error')
    if 'proxy_node_pool' in faults:evidence['proxy_node_pool']['incident']=diagnosis.get('node_observations',{}).get('fingerprint')
    cases=[{k:case.get(k) for k in ['id','revision','status','next_review_at']} for case in diagnosis.get('maintenance',{}).get('cases',[]) if case.get('priority')=='urgent' and case.get('requires_attention')]
    return hashlib.sha256(json.dumps({'faults':faults,'evidence':evidence,'cases':cases},sort_keys=True).encode()).hexdigest()[:20]

def urgent_ai_needed(state,diagnosis,now):
    upkeep=diagnosis.get('maintenance',{})
    attention=[case for case in upkeep.get('cases',[]) if case.get('priority')=='urgent' and case.get('requires_attention')]
    paths=maintenance.path_faults(diagnosis)
    if upkeep and (attention or upkeep.get('faults') or upkeep.get('workflow',{}).get('result',{}).get('wake')=='urgent'):
        owned={case.get('key','')[5:] for case in upkeep.get('cases',[]) if case.get('key','').startswith('path:') and
               case.get('status') in ['working','verifying','blocked'] and not case.get('requires_attention') and
               now<case.get('next_review_at',0)<=now+900}
        if paths and set(paths)<=owned and not attention and not upkeep.get('faults'):return False
        changed=fault_signature(diagnosis)!=state.get('last_ai_fingerprint')
        review=bool(attention or paths or upkeep.get('faults')) and now-state.get('last_ai_at',0)>=upkeep.get('next_check_seconds',300)
        return bool(changed or review)
    return bool(fault_keys(diagnosis) and (fault_signature(diagnosis)!=state.get('last_ai_fingerprint') or
        (state.get('last_ai_failed') and now-state.get('last_ai_at',0)>=6*3600 and state.get('failed_retries_today',0)<3)))

def should_run_ai(state, diagnosis, now):
    faults=fault_keys(diagnosis)
    if urgent_ai_needed(state,diagnosis,now):return True
    if not routine_allowed(now) or state.get('pause_routine') or state.get('audit_plan',{}).get('enabled') is False:return False
    budget=state.get('audit_plan',{}).get('daily_budget',6)
    if len([at for at in state.get('routine_run_times',[]) if now-at<86400])>=budget:return False
    if faults:return audit_due(state,now) and now-state.get('last_routine_ai_at',0)>=2*3600
    if state.get('last_ai_at',0)==0 and not state.get('diagnostic_program',{}).get('active'):return True
    if audit_due(state,now) and now-state.get('last_routine_ai_at',0)>=2*3600:return True
    review=state.get('review_request')
    if state.get('maintenance',{}).get('workflow',{}).get('result',{}).get('wake')=='routine' and now-state.get('last_routine_ai_at',0)>=2*3600:return True
    return bool(review and now-state.get('last_routine_ai_at',0)>=2*3600 and (review['fingerprint'] not in state.get('reviewed',{}) or state.get('last_ai_failed')))

def audit_interval(state,now):
    plan=state.get('audit_plan',{});version=state.get('diagnostic_program',{}).get('version')
    if plan.get('expires_at',0)>now and plan.get('for_program_version')==version:
        return max(plan['interval_hours'],24/plan.get('daily_budget',6))
    age=now-state.get('program_started_at',now);samples=state.get('healthy_samples',0)
    if age>=7*86400 and samples>=2000 and state.get('successful_audits',0)>=3:return 24
    if age>=3*86400 and samples>=720:return 12
    return 4

def audit_due(state,now):
    samples=state.get('audit_rollup',{}).get('samples',0)
    last=state.get('last_independent_audit_at',state.get('last_ai_at',now))
    interval=audit_interval(state,now)*3600
    periodic=now-last>=interval and samples>=8
    version=state.get('diagnostic_program',{}).get('version')
    changed=version and version!=state.get('last_audited_program_version',version) and now-last>=min(interval,4*3600) and samples>=8
    retry=state.get('last_ai_failed') and state.get('last_ai_kind')=='independent_audit' and now-state.get('last_ai_at',0)>=interval
    return bool(periodic or changed or retry)

def repair_choice(diagnosis):
    faults=fault_keys(diagnosis)
    if 'gateway_service' in faults:return 'restore_gateway'
    if 'bootstrap_dns_api' in faults:return None
    if 'proxy_node_pool' in faults:return 'recheck_nodes'
    if any(name in faults for name in ['gateway_dns_cn','gateway_dns_foreign']):return 'restore_gateway'
    if 'proxy_https' in faults and diagnosis.get('checks',{}).get('mainland_https',{}).get('ok'):return 'recheck_nodes'
    return None

def maybe_request_node_review(state,nodes,reviewed):
    fingerprint=nodes.get('fingerprint')
    if not nodes.get('review_due') or not fingerprint or fingerprint in reviewed:return
    current=state.get('review_request') or {}
    if current.get('fingerprint') and current['fingerprint'] not in reviewed:return
    state['review_request']={'fingerprint':fingerprint,'reason':'confirmed node-pool incident recovered; review bounded saved evidence at next permitted audit','node_incidents':nodes.get('incident_history',[])[-3:]}

def call(request):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(140);connection.connect(SOCKET);connection.sendall(json.dumps(request).encode()+b'\n')
        data=json.loads(connection.makefile('rb').readline(1048576))
    if not data.get('ok'):raise ValueError(data.get('message','gateway operation failed'))
    return data['result']

def save(path,data,group=None):
    temp=path.with_suffix('.next')
    with temp.open('w') as target:
        temp.chmod(0o640 if group else 0o600)
        if group:os.chown(temp,0,grp.getgrnam(group).gr_gid)
        json.dump(data,target,ensure_ascii=False);target.flush();os.fsync(target.fileno())
    temp.replace(path)

def bound_observations(state,now):
    cutoff=now-72*3600
    probes=state.get('tracked_probes',{})
    state['tracked_probes']=dict(sorted(((name,value) for name,value in probes.items() if isinstance(value,dict) and cutoff<=value.get('observed_at',0)<=now),key=lambda item:item[1]['observed_at'],reverse=True)[:24])
    rollup=state.get('audit_rollup',{});seen=rollup.get('fault_last_seen',{})
    retained=dict(sorted(((name,at) for name,at in seen.items() if isinstance(at,(int,float)) and cutoff<=at<=now),key=lambda item:item[1],reverse=True)[:64])
    rollup['fault_last_seen']=retained;rollup['fault_counts']={name:value for name,value in rollup.get('fault_counts',{}).items() if name in retained}
    checks=state.get('business_observations',{}).get('checks',{})
    if state.get('business_observations') is not None:state['business_observations']['checks']={name:value for name,value in checks.items() if isinstance(value,dict) and cutoff<=value.get('at',0)<=now}
    return state

def execute_workflow(state,diagnosis,upkeep,now,request=None):
    """Consume pure advice through the bounded, existing privileged adapters."""
    from business_watch import endpoint_for
    request=call if request is None else request
    business=state.setdefault('business_observations',{});checks=business.setdefault('checks',{})
    changed=False;executed={'at':now,'probes':[],'route_reviews':[]}
    batch_due=now-business.get('last_probe_at',-100000)>=600
    for domain in upkeep['workflow']['result'].get('probe_domains',[])[:3]:
        if not batch_due or now-checks.get(domain,{}).get('at',-100000)<1800:continue
        row=next((item for item in business.get('domains',[]) if item.get('domain')==domain),None)
        endpoint=endpoint_for(row,checks.get(domain,{}).get('endpoint'))
        if endpoint is None:
            issue=next((item for item in business.get('issues',[]) if item.get('domain')==domain),{})
            endpoint=endpoint_for({'endpoints':[issue['endpoint']]}) if issue.get('endpoint') else None
        if endpoint is None:result={'state':'endpoint_unknown','application_verified':False}
        else:
            try:result=request({'operation':'probe_compare','target':domain,'endpoint':endpoint})
            except Exception as error:result={'state':'probe_unavailable','error_category':type(error).__name__,'application_verified':False}
            business['last_probe_at']=now;executed['probes'].append({'domain':domain,'endpoint':endpoint})
        checks[domain]={'at':now,'endpoint':endpoint,'result':result}
        state.setdefault('tracked_probes',{})[domain]={**result,'observed_at':now}
        changed=True
    candidates={item['domain']:item for item in upkeep.get('routing',{}).get('candidates',[])}
    reviews=state.setdefault('routing_reviews',{})
    for domain in upkeep['workflow']['result'].get('route_candidates',[])[:3]:
        candidate=candidates.get(domain)
        if candidate is None:continue
        payload={'operation':'route_evaluate','target':domain,'path':candidate['path'],
            'evidence_ids':candidate['evidence_ids'],'business_requirement_evidence_ids':candidate['business_requirement_evidence_ids']}
        previous=reviews.get(domain,{})
        if previous.get('request')==payload and now-previous.get('at',0)<600:continue
        try:result=request(payload)
        except Exception as error:result={'action':'investigate','reason':'route_evaluation_'+type(error).__name__,'application_verified':False,'network_restored':False}
        reviews[domain]={'at':now,'request':payload,'result':result}
        executed['route_reviews'].append(domain);changed=True
    state['routing_reviews']=dict(sorted(reviews.items(),key=lambda item:item[1]['at'],reverse=True)[:24])
    state['workflow_execution']=executed
    diagnosis['business_observations']=business
    return changed


def main():
    path=STATE/'patrol.json';state=json.loads(path.read_text()) if path.exists() else {}
    now=time.time();bound_observations(state,now);diagnosis=call({'operation':'diagnose'})
    observed=None
    try:
        from business_watch import scan
        observed=call({'operation':'traffic_status'})
        business=scan(observed,state.get('business_observations',{}),lambda domain,endpoint=None:call({'operation':'probe_compare','target':domain,**({'endpoint':endpoint} if endpoint else {})}),now,allow_probe=False)
        state['business_observations']=business;diagnosis['business_observations']=business
        state.pop('business_observation_failure',None);state.pop('pending_business_input',None)
    except Exception as error:
        state['business_observation_failure']={'at':now,'error':type(error).__name__,'coverage':'real client observations unavailable; no application health claim'}
        if observed is not None:state['pending_business_input']=observed
        diagnosis['business_observations']=state.get('business_observations',{})
        diagnosis['observation_failure']=state['business_observation_failure']
    faults=fault_keys(diagnosis)
    history=state.get('history',[])
    history.append({'at':now,'faults':faults,'proxy_ms':diagnosis.get('checks',{}).get('proxy_https',{}).get('result',{}).get('elapsed_ms')})
    history=history[-96:]
    snapshot={**diagnosis,'observations':diagnosis.get('business_observations',{}),'history':history[-24:]}
    if state.get('last_quality'):snapshot['quality_summary']={'preferred_pool':state['last_quality'].get('node_pools',{}).get('us',[]),'active_domains':state['last_quality'].get('active_domains',{})}
    program=inspect_active(snapshot)
    if program.get('version')!=state.get('confidence_program_version'):
        state.update(confidence_program_version=program.get('version'),program_started_at=now,healthy_samples=0,successful_audits=0)
    state['healthy_samples']=state.get('healthy_samples',0)+1 if not faults else 0
    state.setdefault('last_independent_audit_at',state.get('last_ai_at') or now)
    state.setdefault('last_audited_program_version',program.get('version'))
    rollup=state.setdefault('audit_rollup',{'samples':0,'fault_counts':{}});rollup['samples']+=1
    for name in faults:
        rollup['fault_counts'][name]=rollup['fault_counts'].get(name,0)+1
        rollup.setdefault('fault_last_seen',{})[name]=now
    tickets=state.get('tickets',{})
    if faults:
        key='|'.join(faults)
        ticket=tickets.setdefault(key,{'first_seen':now,'occurrences':0,'state':'open'})
        ticket.update(last_seen=now,occurrences=ticket['occurrences']+1,state='open')
        state['healthy_streak']=0
    else:
        state['healthy_streak']=state.get('healthy_streak',0)+1
        if state['healthy_streak']>=3:
            for ticket in tickets.values():ticket.update(state='resolved',verified_at=now)
    state.update(checked_at=now,history=history,tickets=dict(list(tickets.items())[-24:]),last_diagnosis=diagnosis,diagnostic_program=program)
    action=repair_choice(diagnosis)
    advised=program.get('result',{}).get('action')
    if not action and advised in ['recheck_nodes','refresh_subscription'] and diagnosis['status'].get('policy',{}).get('mode')!='direct':action=advised
    if action and now-state.get('last_auto_repair_at',0)>=900 and not diagnosis['status'].get('pending_recovery'):
        state['last_auto_repair_at']=now
        try:state['last_auto_repair']=call({'operation':action})
        except Exception as error:state['last_auto_repair']={'operation':action,'error':str(error)}
        verification=state['last_auto_repair'].get('verification')
        if verification:
            before=faults;diagnosis={**verification,'business_observations':state.get('business_observations',{})};faults=fault_keys(diagnosis)
            history[-1].update(faults_before_repair=before,faults=faults)
            if not faults:
                key='|'.join(before)
                if key in tickets:tickets[key].update(state='resolved',verified_at=now)
            repairs=[event for event in state.get('repair_events',[]) if now-event['at']<86400]
            repairs.append({'at':now,'signature':'|'.join(before),'recovered':not faults});state['repair_events']=repairs[-32:]
            if sum(event['signature']=='|'.join(before) for event in repairs)>=3:
                state['review_request']={'fingerprint':'recurrence:'+'|'.join(before)+':'+str(int(now//86400)),'reason':'same local repair recurred at least three times within a day'}
    elif faults:
        # A transient failed probe should not buy a model call.
        confirmation=call({'operation':'diagnose'});diagnosis={**confirmation,'business_observations':state.get('business_observations',{})};faults=fault_keys(diagnosis)
        history[-1]['faults_after_confirmation']=faults
    if program.get('rolled_back'):
        state['review_request']={'fingerprint':'program-failed:'+str(program.get('failed_version')),'reason':'maintained diagnostic program failed and was rolled back'}
    if program.get('result',{}).get('review_request'):state['review_request']=program['result']['review_request']
    state.update(last_diagnosis=diagnosis)
    observed_nodes=diagnosis.get('node_observations',{})
    maybe_request_node_review(state,observed_nodes,native.effective_state(state,native.read()).get('reviewed',{}))
    state['diagnostic_probe_advice']=program.get('result',{}).get('probe_domains',[])[:3]
    faults=fault_keys(diagnosis)
    quality=None
    if now-state.get('last_quality_at',0)>=1800 or faults:
        try:quality=call({'operation':'quality'});state.update(last_quality_at=now,last_quality=quality)
        except Exception:pass
    approved=STATE/'approved-policy.json'
    try:preferences=json.loads(approved.read_text()).get('preferences',{}) if approved.exists() else diagnosis.get('status',{}).get('policy',{}).get('preferences',{})
    except (ValueError,OSError):
        preferences={};diagnosis['maintenance_input_errors']=['preferences_storage']
    upkeep=maintenance.observe(state,diagnosis,now,preferences=preferences,directory=STATE)
    if execute_workflow(state,diagnosis,upkeep,now):
        upkeep=maintenance.observe(state,diagnosis,now,preferences=preferences,directory=STATE)
    upkeep['observed_at']=now;state['maintenance']=upkeep;diagnosis['maintenance']=upkeep
    state['next_check_at']=now+upkeep['next_check_seconds']
    state['last_diagnosis']=diagnosis;faults=fault_keys(diagnosis)
    with native.dispatch_lock(STATE):
        job=subprocess.run(['systemctl','is-active',AI_SERVICE],capture_output=True,text=True).stdout.strip()
        last_result=subprocess.run(['systemctl','show',AI_SERVICE,'-p','Result','--value'],capture_output=True,text=True).stdout.strip()
        state['last_ai_failed']=job not in ['active','activating'] and last_result not in ['','success']
        if job not in ['active','activating'] and last_result=='success' and state.get('last_ai_kind')=='independent_audit' and state.get('audit_completed_at')!=state.get('last_ai_at'):
            state.update(audit_completed_at=state['last_ai_at'],successful_audits=state.get('successful_audits',0)+1)
        plan=STATE/'audit-plan.json';state['audit_plan']=json.loads(plan.read_text()) if plan.exists() else {'daily_budget':6}
        if time.strftime('%Y-%m-%d',time.gmtime(now))!=state.get('retry_day'):
            state.update(retry_day=time.strftime('%Y-%m-%d',time.gmtime(now)),failed_retries_today=0)
        disk=STATE/'storage.json';storage=json.loads(disk.read_text()) if disk.exists() else {}
        state['pause_routine']=storage.get('pause_routine',False) or shutil.disk_usage('/').free<4*1024**3
        native.supervise(diagnosis,now)
        native_enabled=bool(native.read().get('session_id'))
        state['native_automation']=native.status()
        running_context=json.loads(CONTEXT.read_text()) if CONTEXT.exists() else {}
        if preempt_needed(state,diagnosis,job,running_context):
            subprocess.run(['systemctl','stop',AI_SERVICE],check=True,timeout=15)
            state['routine_preempted_at']=now;job='inactive'
        if urgent_ai_needed(state,diagnosis,now) and job in ['active','activating'] and fault_signature(diagnosis)!=state.get('last_ai_fingerprint'):
            running_context.update(urgent=True,observed_at=now,diagnosis=diagnosis,maintenance_trigger='additional_fault')
            save(CONTEXT,running_context,'gateway-operators')
        bound_observations(state,now)
        window=[value for value in state.get('ai_run_times',[]) if now-value<86400]
        # Native Automation owns routine AI. Emergency reasoning retains its
        # independent process so a blocked/broken Web UI cannot prevent recovery.
        eligible=urgent_ai_needed(state,diagnosis,now) if native_enabled else should_run_ai(state,diagnosis,now)
        if eligible and job not in ['active','activating']:
            urgent=urgent_ai_needed(state,diagnosis,now)
            kind='anomaly' if urgent else ('independent_audit' if audit_due(state,now) or faults else 'evidence_driven_improvement')
            context={'observed_at':now,'diagnosis':diagnosis,'history':history[-16:],'tickets':state['tickets'],
                'diagnostic_program':program,'tracked_probes':state.get('tracked_probes',{}),
                'maintenance':upkeep,
                'maintenance_trigger':kind,'audit_rollup':rollup,
                'urgent':urgent,'pricing':pricing_state(now),
                'review_request':state.get('review_request'),'storage':storage,
                'quality_summary':{'preferred_pool':(quality or state.get('last_quality',{})).get('node_pools',{}).get('us',[]),
                                   'active_domains':(quality or state.get('last_quality',{})).get('active_domains',{})}}
            save(CONTEXT,context,'gateway-operators')
            subprocess.run(['systemctl','start','--no-block',AI_SERVICE],check=True)
            if state['last_ai_failed']:state['failed_retries_today']=state.get('failed_retries_today',0)+1
            state.update(last_ai_at=now,last_ai_kind=kind,last_ai_faults=faults,last_ai_fingerprint=fault_signature(diagnosis) if urgent else None,ai_run_times=[*window,now])
            if kind=='independent_audit':state.update(last_independent_audit_at=now,last_audited_program_version=program.get('version'),audit_rollup={'samples':0,'fault_counts':{}})
            if not urgent:
                state['last_routine_ai_at']=now
                state['routine_run_times']=[at for at in state.get('routine_run_times',[]) if now-at<86400]+[now]
                if state.get('review_request'):
                    reviewed=state.setdefault('reviewed',{});reviewed[state['review_request']['fingerprint']]=now;state['reviewed']=dict(list(reviewed.items())[-32:])
        if not faults and upkeep['workflow']['result']['wake']!='urgent':state.update(last_ai_faults=[],last_ai_fingerprint=None)
        state['pricing']=pricing_state(now)
        state['ai_job_state']=job
        save(path,state)
    print(json.dumps({'patrol':'complete','faults':faults,'ai_triggered_at':state.get('last_ai_at'),'at':now}))

if __name__=='__main__':main()
