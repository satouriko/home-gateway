"""Root-owned admission leases for real DSH Automation deliveries.

The scheduler may wake cheaply; only a fresh, due, off-peak audit buys a model
call. Human chat and the independent emergency worker do not use this gate.
"""
import contextlib
from datetime import datetime
import fcntl
import hashlib
import json
import os
import grp
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import uuid
from pricing import routine_allowed, pricing_state

STATE=Path('/var/lib/net-gateway-agent')
PATH=STATE/'native-maintenance.json'
PROMPT=Path('/usr/local/share/net-gateway-agent/maintenance-prompt.txt')
CONTEXT=Path('/run/net-gateway-agent/patrol-context.json')
IDENTITY=Path('/var/lib/dsh/native-task-identity/identity.json')


@contextlib.contextmanager
def dispatch_lock(directory=None):
    directory=STATE if directory is None else directory
    with (directory/'ai-dispatch.lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield


def read():
    return json.loads(PATH.read_text()) if PATH.exists() else {}


def save(value):
    temp=PATH.with_suffix('.next')
    with temp.open('w') as f:
        temp.chmod(0o600);json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
    temp.replace(PATH)


@contextlib.contextmanager
def locked():
    with (STATE/'native-maintenance.lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield


def storage_available():
    path=STATE/'storage.json';storage=json.loads(path.read_text()) if path.exists() else {}
    return not storage.get('pause_routine') and shutil.disk_usage('/').free>=4*1024**3 and os.statvfs('/').f_favail>=5000


def emergency_active():
    result=subprocess.run(['systemctl','is-active','net-gateway-ai-patrol.service'],capture_output=True,text=True,timeout=4)
    return result.stdout.strip() in ['active','activating']


def occurrence_time(occurrence,schedule_id):
    """Read the scheduler's occurrence clock, including pre-upgrade ledger rows."""
    prefix=str(schedule_id)+':'
    if not schedule_id or not isinstance(occurrence,str) or not occurrence.startswith(prefix):return None
    try:
        instant=datetime.fromisoformat(occurrence[len(prefix):].replace('Z','+00:00'))
        return instant.timestamp() if instant.tzinfo is not None else None
    except (ValueError,OverflowError):return None


def effective_state(state,ledger):
    result={**state};runs=[r for r in ledger.get('runs',[]) if r.get('kind')!='deployment_validation']
    if not runs:return result
    last=runs[-1]
    if last['at']>state.get('last_ai_at',0):
        result.update(last_ai_at=last['at'],last_ai_kind=last['kind'],last_ai_failed=last['state'] not in ['running','completed'])
    result['last_routine_ai_at']=max(state.get('last_routine_ai_at',0),last['at'])
    result['routine_run_times']=state.get('routine_run_times',[])+[r['at'] for r in runs]
    audits=[r for r in runs if r['kind']=='independent_audit']
    if audits:
        result['last_independent_audit_at']=max(state.get('last_independent_audit_at',0),audits[-1]['at'])
        if audits[-1]['at']>=state.get('last_independent_audit_at',0):
            result['last_audited_program_version']=audits[-1].get('program_version')
            scheduled=occurrence_time(audits[-1].get('occurrence'),audits[-1].get('schedule_id'))
            result['last_independent_audit_due_at']=scheduled if scheduled is not None and scheduled<=audits[-1]['at'] else audits[-1]['at']
    version=state.get('diagnostic_program',{}).get('version')
    result['successful_audits']=state.get('successful_audits',0)+sum(r['state']=='completed' and r.get('program_version')==version for r in audits)
    result['reviewed']={**state.get('reviewed',{}),**{r['review_fingerprint']:r['at'] for r in runs if r.get('review_fingerprint')}}
    return result


def status():
    ledger=read()
    result={k:ledger[k] for k in ['session_id','schedule_id','retired_schedule_ids','created_at','last_gate','runs','observed_task','enabled','provision_requested'] if k in ledger}
    plan_path=STATE/'audit-plan.json'
    plan=json.loads(plan_path.read_text()) if plan_path.exists() else {}
    result['enabled']=ledger.get('enabled',plan.get('enabled',True))
    result['preferences']=plan
    state_path=STATE/'patrol.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else {}
    candidate=retry_candidate(state,ledger,time.time())
    if candidate:result['retry_execution']=candidate
    return result


def admission_state(state,ledger,now):
    effective=effective_state(state,ledger)
    # Only cadence follows the scheduled clock. Budgets and spacing retain the
    # real admission timestamps; delayed native starts cannot shift every due.
    effective['last_independent_audit_at']=effective.get('last_independent_audit_due_at',effective.get('last_independent_audit_at',0))
    effective['audit_plan']={**effective.get('audit_plan',{}),'enabled':True}
    interval=(ledger.get('observed_task') or {}).get('everySeconds')
    if isinstance(interval,(int,float)):
        effective['audit_plan']={**effective['audit_plan'],'interval_hours':interval/3600,'expires_at':now+60,'for_program_version':state.get('diagnostic_program',{}).get('version')}
    if ledger.get('initial_review'):
        effective['review_request']={'fingerprint':'native-integration-review','reason':'first native maintenance integration review'}
    return effective


def admission_reason(state,ledger,effective,now,occurrence):
    from patrol import should_run_ai, urgent_ai_needed
    scheduled=occurrence_time(occurrence,ledger.get('schedule_id'))
    if ledger.get('enabled') is False:return 'automation task is disabled or deleted'
    if scheduled is not None and scheduled>now:return 'scheduled occurrence is in the future'
    if any(r['state']=='running' and r['deadline']>now for r in ledger.get('runs',[])):return 'audit already running'
    if now-state.get('checked_at',0)>900:return 'waiting for fresh program observations'
    if urgent_ai_needed(state,state.get('last_diagnosis',{}),now) or emergency_active():return 'emergency recovery takes priority'
    if not routine_allowed(now):return 'waiting for off-peak budget'
    if not storage_available():return 'storage reserve is protected'
    if now-effective.get('last_routine_ai_at',0)<7200:return 'minimum audit spacing'
    if not should_run_ai(effective,state.get('last_diagnosis',{}),now):return 'no due audit or new improvement evidence'
    return None


def retry_candidate(state,ledger,now):
    """Read-only eligibility; the executor rechecks the same gate under its lease."""
    gate=ledger.get('last_gate',{})
    retryable={'no due audit or new improvement evidence','waiting for off-peak budget',
               'waiting for fresh program observations','minimum audit spacing',
               'storage reserve is protected','emergency recovery takes priority','audit already running'}
    if gate.get('admitted') or gate.get('reason') not in retryable:return None
    task=ledger.get('observed_task') or {};receipt=task.get('lastDelivery') or {}
    if task.get('id')!=ledger.get('schedule_id') or task.get('status')!='active':return None
    if receipt.get('kind')!='execution' or receipt.get('status')!='skipped' or receipt.get('retry'):return None
    occurrence=ledger['schedule_id']+':'+receipt.get('scheduledAt','')
    scheduled=occurrence_time(occurrence,ledger['schedule_id'])
    next_at=occurrence_time(ledger['schedule_id']+':'+task.get('scheduledAt',''),ledger['schedule_id'])
    if scheduled is None or next_at is None or not scheduled<=now<next_at:return None
    if gate.get('execution_id',receipt.get('executionId'))!=receipt.get('executionId'):return None
    if gate.get('occurrence',occurrence)!=occurrence:return None
    if occurrence in ledger.get('occurrences',[]) or any(r.get('id')==receipt.get('executionId') for r in ledger.get('runs',[])):return None
    if admission_reason(state,ledger,admission_state(state,ledger,now),now,occurrence):return None
    return {'session_id':ledger['session_id'],'schedule_id':ledger['schedule_id'],
            'execution_id':receipt['executionId'],'occurrence_at':receipt['scheduledAt']}


def admit(session_id,state,now=None,occurrence=None,execution_id=None):
    from patrol import audit_due, fault_keys, fault_signature
    now=time.time() if now is None else now
    with locked():
        ledger=read()
        if session_id in ledger.get('retired',[]):return {'managed':True,'admitted':False,'reason':'retired maintenance session'}
        if session_id!=ledger.get('session_id'):return {'managed':False,'admitted':False}
        effective=admission_state(state,ledger,now)
        if occurrence and occurrence in ledger.get('occurrences',[]):
            existing=next((r for r in reversed(ledger.get('runs',[])) if r.get('occurrence')==occurrence),None)
            return {'managed':True,'admitted':False,'reason':'this occurrence was already handled','existing_job':existing}
        reason=admission_reason(state,ledger,effective,now,occurrence)
        if reason:
            ledger['last_gate']={'at':now,'session_id':session_id,'admitted':False,'reason':reason,
                                 'occurrence':occurrence,'execution_id':execution_id};save(ledger)
            return {'managed':True,'admitted':False,'reason':reason}
        clock=pricing_state(now);remaining=clock.get('off_peak_seconds_remaining',0)
        duration=min(540,remaining-60) if remaining else 540
        job={'id':execution_id or uuid.uuid4().hex,'at':now,'deadline':now+duration,'state':'running',
             'session_id':session_id,'schedule_id':ledger.get('schedule_id'),'occurrence':occurrence,
             'kind':'independent_audit' if ledger.get('initial_review') or audit_due(effective,now) else 'evidence_driven_improvement',
             'fault_fingerprint':fault_signature(state.get('last_diagnosis',{})) if fault_keys(state.get('last_diagnosis',{})) else None,
             'review_fingerprint':effective.get('review_request',{}).get('fingerprint') if effective.get('review_request') else None,
             'program_version':state.get('diagnostic_program',{}).get('version')}
        ledger['runs']=[*ledger.get('runs',[]),job][-48:]
        ledger['initial_review']=False
        ledger['last_gate']={'at':now,'session_id':session_id,'admitted':True};
        if occurrence:ledger['occurrences']=[*ledger.get('occurrences',[]),occurrence][-128:]
        save(ledger)
        context={k:state.get(k) for k in ['last_diagnosis','diagnostic_program','audit_rollup','review_request','maintenance']}
        context['history']=state.get('history',[])[-16:]
        context.update(maintenance_trigger=job['kind'],urgent=False,pricing=clock)
        context['review_request']=effective.get('review_request')
        return {'managed':True,'admitted':True,**job,'instructions':PROMPT.read_text(),'context':context}


def finish(session_id,job_id,outcome,now=None,execution_session_id=None,summary=None):
    now=time.time() if now is None else now
    if outcome not in ['completed','failed','interrupted','expired']:raise ValueError('invalid maintenance outcome')
    with locked():
        ledger=read();runs=ledger.get('runs',[])
        if session_id!=ledger.get('session_id') or not runs or runs[-1]['id']!=job_id or runs[-1]['state']!='running':return {'updated':False}
        job=runs[-1];job.update(state='expired' if now>job['deadline'] else outcome,finished_at=now)
        if execution_session_id:job['execution_session_id']=execution_session_id
        if summary:job['summary']=summary[:1500]
        save(ledger)
        return {'updated':True,'state':job['state']}


def check(session_id,job_id,now=None):
    now=time.time() if now is None else now
    ledger=read();runs=ledger.get('runs',[]);job=runs[-1] if runs else {}
    allowed=session_id==ledger.get('session_id') and job_id==job.get('id') and job.get('state')=='running' and job.get('deadline',0)>now
    return {'continue':bool(allowed and routine_allowed(now) and storage_available()),'deadline':job.get('deadline')}


def rpc(method,request=None):
    url='http://192.168.2.4/api/'+method
    body={'type':'client-request','rpcId':'maintenance-'+uuid.uuid4().hex,'method':method,'payload':{'args':{} if request is None else {'request':request}}}
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':'http://192.168.2.4'},method='POST')
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=12) as response:reply=json.load(response)
    result=reply.get('result',{})
    if not result.get('ok'):raise ValueError('native automation request failed: '+method)
    return result.get('value')


def supervise(diagnosis,now=None):
    from patrol import fault_keys, fault_signature
    now=time.time() if now is None else now
    if not PATH.exists():return
    cancel=None
    with locked():
        ledger=read();runs=ledger.get('runs',[])
        if runs and runs[-1]['state']=='running':
            job=runs[-1]
            outcome='expired' if now>=job['deadline'] else 'preempted' if fault_keys(diagnosis) and fault_signature(diagnosis)!=job.get('fault_fingerprint') else None
            if outcome:
                job.update(state=outcome,finished_at=now);cancel=job;save(ledger)
    if cancel:
        try:
            context_path=CONTEXT
            context=json.loads(context_path.read_text()) if context_path.exists() else {}
            if context.get('native_job_id')==cancel['id'] and not context.get('urgent'):
                subprocess.run(['systemctl','stop','net-gateway-ai-patrol.service'],check=True,timeout=15)
            elif cancel.get('execution_session_id'):
                rpc('session/cancel',{'sessionId':cancel['execution_session_id']})
        except Exception:pass


def bind(session_id,schedule_id):
    with locked():
        ledger=read();current=ledger.get('session_id')
        if current==session_id and ledger.get('schedule_id')==schedule_id:return {'bound':True}
        if ledger.get('runs') and ledger['runs'][-1]['state']=='running' and ledger['runs'][-1]['deadline']>time.time():
            raise ValueError('cannot rotate a running audit')
        old_task=ledger.get('schedule_id')
        if old_task and old_task!=schedule_id:ledger['retired_schedule_ids']=[*ledger.get('retired_schedule_ids',[]),old_task][-128:]
        ledger.update(enabled=True,session_id=session_id,schedule_id=schedule_id,created_at=time.time(),
                      retired=[*ledger.get('retired',[]),*([current] if current and current!=session_id else [])][-128:],
                      initial_review=not bool(ledger.get('created_at')) or ledger.get('initial_review',False))
        ledger.pop('provision_requested',None)
        save(ledger)
        publish_identity(ledger)
        return {'bound':True}


def observe(task):
    """Mirror the native task without replacing its identity, content or timing."""
    with locked():
        ledger=read()
        if not ledger.get('schedule_id'):raise ValueError('native task not initialized')
        if task is not None and task.get('id')!=ledger['schedule_id']:raise ValueError('unexpected native task')
        ledger['enabled']=task is not None
        ledger['observed_task']=task
        save(ledger)
    plan_path=STATE/'audit-plan.json'
    plan=json.loads(plan_path.read_text()) if plan_path.exists() else {'interval_hours':4,'daily_budget':6}
    definition={k:task[k] for k in ['kind','title','prompt','everySeconds','time','timeZone','weekdays','expression','afterSeconds','execution'] if task is not None and k in task} if task else plan.get('schedule')
    if task and task.get('kind')=='at':definition['scheduledAt']=task['scheduledAt']
    active=task is not None and task.get('status','active')=='active'
    changed=plan.get('enabled',True)!=active or plan.get('schedule')!=definition
    result={'enabled':ledger['enabled'],'preference_changed':changed}
    if changed:
        plan.update(enabled=active,schedule=definition)
        if task and task.get('kind')=='every':plan['interval_hours']=task['everySeconds']/3600
        from patrol import save as save_state
        save_state(plan_path,plan)
        public={key:plan[key] for key in ['interval_hours','daily_budget','enabled','schedule'] if key in plan}
        result['source_sync_version']=hashlib.sha256((json.dumps(public,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()).hexdigest()[:16]
    return result


def dispatch_job(lease,task_prompt=None,cancelled=lambda:False):
    """The Web scheduler never runs a model; one isolated DSH worker owns each run."""
    if not lease.get('admitted'):return lease
    context={**lease['context'],'observed_at':lease['at'],'diagnosis':lease['context'].get('last_diagnosis'),
             'native_job_id':lease['id'],'native_session_id':read()['session_id'],'native_deadline':lease['deadline'],
             'native_task_prompt':task_prompt or read().get('observed_task',{}).get('prompt','')}
    from patrol import save as save_state
    with dispatch_lock():
        if cancelled() or time.time()>=lease['deadline']:
            finish(read()['session_id'],lease['id'],'interrupted')
            return {'managed':True,'admitted':False,'reason':'dispatch cancelled or expired'}
        if emergency_active():
            finish(read()['session_id'],lease['id'],'interrupted')
            return {'managed':True,'admitted':False,'reason':'emergency recovery takes priority'}
        save_state(CONTEXT,context,'gateway-operators')
        try:subprocess.run(['systemctl','start','--no-block','net-gateway-ai-patrol.service'],check=True,timeout=8)
        except Exception:
            finish(read()['session_id'],lease['id'],'failed')
            raise ValueError('isolated DSH worker could not start')
    return {'managed':True,'admitted':True,'dispatched':True,'id':lease['id'],'deadline':lease['deadline']}


def update_schedule(hours):
    ledger=read()
    if ledger.get('enabled') is False:raise ValueError('native task was deleted; recreate it explicitly in DSH')
    if not ledger.get('schedule_id'):return
    task=next((t for t in rpc('schedule/catalog') if t['id']==ledger['schedule_id']),None)
    if task is None:raise ValueError('native task is missing; automatic recreation is disabled')
    expected={k:v for k,v in task.items() if k not in ['sessionId','status','lastDelivery']}
    result=rpc('schedule/update',{'sessionId':ledger['session_id'],'id':ledger['schedule_id'],'expected':expected,
                                 'change':{'kind':'every','every_seconds':int(hours*3600)}})
    if result.get('updated') is not True:raise ValueError('native task changed while editing; read its current state')
    observe({**result['record'],'sessionId':ledger['session_id'],'status':'active'})


def inspection(session_id):
    ledger=read()
    if session_id!=ledger.get('session_id') and session_id not in ledger.get('retired',[]):return {'managed':False}
    path=STATE/'patrol.json';state=json.loads(path.read_text()) if path.exists() else {}
    diagnosis=state.get('last_diagnosis',{})
    from patrol import fault_keys
    faults=fault_keys(diagnosis)
    labels={'bootstrap_dns_api':'维护通路 DNS','gateway_dns_cn':'国内 DNS','gateway_dns_foreign':'代理域名 DNS','mainland_https':'国内网站连通','proxy_https':'代理网站连通'}
    checks=[{'label':label,'ok':name not in faults} for name,label in labels.items() if name in diagnosis.get('checks',{})]
    if diagnosis.get('status',{}).get('services'):checks.insert(0,{'label':'网关服务','ok':'gateway_service' not in faults})
    return {'managed':True,'checked_at':state.get('checked_at'),'checks':checks,'last_gate':ledger.get('last_gate'),
            'last_execution':ledger.get('runs',[])[-1] if ledger.get('runs') else None,
            'enabled':ledger.get('enabled',True),'task_status':(ledger.get('observed_task') or {}).get('status'),'next_at':(ledger.get('observed_task') or {}).get('scheduledAt') if ledger.get('observed_task') else None}


def context_summary():
    ledger=read();runs=ledger.get('runs',[])
    task=ledger.get('observed_task') or {}
    return {'enabled':ledger.get('enabled',True),'task':{k:task[k] for k in ['title','kind','everySeconds','time','timeZone','expression','weekdays','scheduledAt','status'] if k in task},
            'last_gate':ledger.get('last_gate'),'last_execution':{k:v for k,v in (runs[-1] if runs else {}).items() if k!='summary'},
            'recent_result':(runs[-1].get('summary','')[:800] if runs else ''),
            'context_policy':'each real AI run starts a fresh bounded DSH process; program checks do not enter its conversation',
            'task_control':'native edits/deletion are authoritative; restore requires an explicit chat request'}


def publish_identity(ledger=None):
    ledger=read() if ledger is None else ledger
    if not ledger.get('schedule_id'):return
    value={k:ledger[k] for k in ['session_id','schedule_id','retired_schedule_ids'] if k in ledger}
    temporary=IDENTITY.with_suffix('.next')
    with temporary.open('w') as target:
        temporary.chmod(0o640);os.chown(temporary,0,grp.getgrnam('dsh').gr_gid)
        json.dump(value,target);target.flush();os.fsync(target.fileno())
    temporary.replace(IDENTITY)
