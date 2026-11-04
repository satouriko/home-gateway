"""Validation boundary shared by local operator tools and offline recovery."""
import ipaddress
import re
import json

READS = {'status','diagnose','probe','probe_compare','traffic_status','quality','patrol_status','policy','context','audit_plan','native_status','native_inspection','overview','source_sync_notices','incidents','incident_get','evidence_detail'}
REPAIRS = {'recheck_nodes', 'refresh_subscription', 'restart_gateway', 'restore_gateway'}
PROGRAMS = {'program_status','program_test','program_publish','tool_status','tool_test','tool_publish','tool_run','skill_status','skill_test','skill_publish','workflow_status','workflow_test','workflow_publish'}
POLICY = {'policy_test','policy_apply'}
AUX={'maintenance_register','audit_plan_set','native_bind','native_admit','native_check','native_finish','native_observe','audit_plan_enable','source_sync_notice_ack','incident_decide'}
PUBLISHES={'program_publish','tool_publish','skill_publish','workflow_publish','policy_apply','audit_plan_set','audit_plan_enable'}
SOURCE_OPERATIONS={'program_test','program_publish','tool_test','tool_publish','skill_test','skill_publish','workflow_test','workflow_publish'}
ROUTING={'route_status','route_get','route_source','route_requirement','route_evaluate','route_apply'}
PUBLISHES.add('route_apply')

def validate_request(request):
    if not isinstance(request, dict) or request.get('operation') not in READS | REPAIRS | PROGRAMS | POLICY | AUX | ROUTING:
        raise ValueError('unknown operation')
    operation = request['operation']
    allowed = {'operation','preferences','receipt'} if operation in POLICY else ({'operation', 'target'} if operation in ['probe','probe_compare'] else ({'operation','source'} if operation in SOURCE_OPERATIONS else ({'operation','request'} if operation=='tool_run' else {'operation'})))
    if operation=='incident_get':allowed={'operation','id'}
    if operation=='incident_decide':allowed={'operation','id','revision','decision','session_id'}
    if operation=='evidence_detail':allowed={'operation','section','target','limit','snapshot_ref'}
    if operation=='probe_compare':allowed.update(['endpoint','refresh'])
    if operation=='route_get':allowed={'operation','evidence_ids'}
    if operation=='route_status':allowed={'operation','target'}
    if operation=='route_source':allowed={'operation','url'}
    if operation=='route_requirement':allowed={'operation','target','path','source_ids','quotes','rationale','region_context','session_id'}
    if operation=='route_evaluate':allowed={'operation','target','path','evidence_ids','business_requirement_evidence_ids'}
    if operation=='route_apply':allowed={'operation','proposal'}
    if operation=='source_sync_notice_ack':allowed={'operation','request_id','revision','session_id','message_id'}
    if operation=='maintenance_register':allowed={'operation','session_id','kind'}
    if operation=='audit_plan_set':allowed={'operation','interval_hours','daily_budget','reason'}
    if operation=='audit_plan_enable':allowed={'operation','receipt'}
    if operation.startswith('native_') and operation!='native_status':
        allowed={'operation','session_id'}
        if operation=='native_bind':allowed.add('schedule_id')
        if operation in ['native_check','native_finish']:allowed.add('job_id')
        if operation=='native_finish':allowed.update(['outcome','execution_session_id','summary'])
        if operation=='native_admit':allowed.update(['occurrence','task_prompt','execution_id'])
        if operation=='native_observe':allowed={'operation','task'}
    if operation in ['skill_test','skill_publish']:allowed.update(['deadline','maintenance_session'])
    if operation in PUBLISHES:allowed.update(['session_id','commit_message'])
    if set(request) - allowed:
        raise ValueError('unexpected fields for '+operation+'; accepted fields: '+', '.join(sorted(allowed)))
    result = {'operation': operation}
    if operation=='source_sync_notice_ack':
        from source_sync import valid_session
        if not valid_session(request.get('session_id')) or not re.fullmatch(r'[a-f0-9]{32}',str(request.get('request_id',''))) or type(request.get('revision')) is not int or request['revision']<1:
            raise ValueError('valid publication receipt identity required')
        expected=f"gateway-source-sync-{request['request_id']}-{request['revision']}"
        if request.get('message_id')!=expected:raise ValueError('valid receipt message identity required')
        return {key:request[key] for key in allowed}
    if operation in PUBLISHES and 'commit_message' in request:
        from commit_messages import validate_commit_message
        result['commit_message']=validate_commit_message(request['commit_message'])
    if operation in PUBLISHES|{'incident_decide','route_requirement'} and request.get('session_id'):
        from source_sync import valid_session
        if not valid_session(request['session_id']):raise ValueError('valid originating session required')
        result['session_id']=request['session_id']
    if operation in {'incident_get','incident_decide'}:
        if not isinstance(request.get('id'),str) or not re.fullmatch(r'case-[a-f0-9]{20}',request['id']):raise ValueError('valid incident identity required')
        result['id']=request['id']
        if operation=='incident_decide':
            if type(request.get('revision')) is not int or request['revision']<1 or not isinstance(request.get('decision'),dict) or not result.get('session_id'):raise ValueError('incident revision, decision and actor session required')
            result.update(revision=request['revision'],decision=request['decision'])
    if operation in ROUTING:
        for key in ['evidence_ids','business_requirement_evidence_ids','source_ids']:
            if key not in request:continue
            values=request[key]
            if not isinstance(values,list) or not 1<=len(values)<=8 or any(not isinstance(v,str) or not re.fullmatch(r'(?:cmp|req|src)_[a-f0-9]{32}',v) for v in values):raise ValueError('bounded stored evidence references required')
            result[key]=values
        for key in ['target','path','url','quotes','rationale','region_context','proposal']:
            if key in request:result[key]=request[key]
        if operation=='route_get' and not result.get('evidence_ids'):raise ValueError('evidence references required')
        if operation=='route_source' and (not isinstance(result.get('url'),str) or not 1<=len(result['url'])<=2048):raise ValueError('bounded public source URL required')
        if operation=='route_requirement':
            if not result.get('session_id') or not result.get('source_ids') or not isinstance(result.get('quotes'),list) or not 1<=len(result['quotes'])<=8:raise ValueError('actor, collected source and exact quotations required')
            if not isinstance(result.get('rationale'),str) or not 12<=len(result['rationale'])<=2000 or not isinstance(result.get('region_context'),str) or not 2<=len(result['region_context'])<=300:raise ValueError('bounded public source interpretation required')
        if operation in ['route_evaluate','route_requirement']:
            if result.get('path') not in ['direct','proxy'] or not isinstance(result.get('target'),str) or not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,63}',result['target']):raise ValueError('exact public domain and path required')
        if operation=='route_status' and result.get('target') is not None and (not isinstance(result['target'],str) or not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,63}',result['target'])):raise ValueError('exact public domain required')
        if operation=='route_apply' and (not isinstance(result.get('proposal'),dict) or len(json.dumps(result['proposal']))>4096):raise ValueError('bounded proposal required')
    if operation=='evidence_detail':
        sections={'diagnosis','checks','observations','business_observations','incidents','history','node_health','runtime_facts','recent_system_changes','source_control','maintenance','operational_workflow'}
        if request.get('section') not in sections or type(request.get('limit',16)) is not int or not 1<=request.get('limit',16)<=32:raise ValueError('bounded known evidence section required')
        target=request.get('target')
        if target is not None and (not isinstance(target,str) or not 1<=len(target)<=253 or not re.fullmatch(r'[a-zA-Z0-9_.:-]+',target)):raise ValueError('valid evidence target required')
        ref=request.get('snapshot_ref')
        if ref is not None and (not isinstance(ref,str) or not re.fullmatch(r'[a-f0-9]{20}',ref)):raise ValueError('valid evidence snapshot reference required')
        result.update(section=request['section'],target=target,limit=request.get('limit',16),snapshot_ref=ref)
    if operation=='audit_plan_enable':result['receipt']=request.get('receipt')
    if operation=='native_observe':
        task=request.get('task')
        if task is not None and (not isinstance(task,dict) or len(str(task))>24000):raise ValueError('bounded task definition required')
        result['task']=task
    elif operation.startswith('native_') and operation!='native_status':
        if not re.fullmatch(r'session-[a-f0-9-]{36}',str(request.get('session_id',''))):raise ValueError('valid native session identity required')
        result['session_id']=request['session_id']
        if operation=='native_bind':
            if not re.fullmatch(r'schedule-[a-f0-9-]{36}',str(request.get('schedule_id',''))):raise ValueError('valid native task identity required')
            result['schedule_id']=request['schedule_id']
        if operation in ['native_check','native_finish']:
            if not re.fullmatch(r'[a-f0-9]{32}',str(request.get('job_id',''))):raise ValueError('valid maintenance lease required')
            result['job_id']=request['job_id']
        if operation=='native_admit':
            occurrence=request.get('occurrence')
            if occurrence is not None and (not isinstance(occurrence,str) or len(occurrence)>200):raise ValueError('bounded occurrence required')
            prompt=request.get('task_prompt','')
            if not isinstance(prompt,str) or len(prompt)>16000:raise ValueError('bounded task prompt required')
            execution_id=request.get('execution_id')
            if execution_id is not None and not re.fullmatch(r'[a-f0-9]{32}',execution_id):raise ValueError('valid execution identity required')
            result.update(occurrence=occurrence,task_prompt=prompt,execution_id=execution_id)
        if operation=='native_finish':
            if request.get('outcome') not in ['completed','failed','interrupted','expired']:raise ValueError('invalid maintenance outcome')
            result['outcome']=request['outcome']
            if request.get('execution_session_id'):
                if not re.fullmatch(r'session-[a-f0-9-]{36}',request['execution_session_id']):raise ValueError('valid execution session required')
                result['execution_session_id']=request['execution_session_id']
            if request.get('summary'):
                if not isinstance(request['summary'],str) or len(request['summary'])>1500:raise ValueError('bounded execution summary required')
                result['summary']=request['summary']
    if operation=='audit_plan_set':
        hours=request.get('interval_hours');budget=request.get('daily_budget',6);reason=request.get('reason')
        if not isinstance(hours,(int,float)) or not 2<=hours<=24 or not isinstance(budget,int) or not 1<=budget<=12 or not isinstance(reason,str) or not 1<=len(reason)<=1000:raise ValueError('audit interval 2-24h, daily routine budget 1-12, and evidence reason required')
        result.update(interval_hours=hours,daily_budget=budget,reason=reason)
    if operation=='maintenance_register':
        if request.get('kind') not in ['patrol','canary','user','automation'] or not re.fullmatch(r'session-[a-f0-9-]{36}',str(request.get('session_id',''))):raise ValueError('valid native session identity required')
        result.update(session_id=request['session_id'],kind=request['kind'])
    if operation in POLICY:
        if not isinstance(request.get('preferences'),dict):raise ValueError('preference patch object required')
        result['preferences']=request['preferences']
        result['receipt']=request.get('receipt')
    if operation in SOURCE_OPERATIONS:
        source=request.get('source')
        if not isinstance(source,str) or not 1<=len(source.encode())<=24000:raise ValueError('bounded source required')
        result['source']=source
        if operation.startswith('skill_') and 'deadline' in request:
            if not isinstance(request['deadline'],(int,float)):raise ValueError('numeric deadline required')
            result['deadline']=request['deadline']
        if 'maintenance_session' in request:
            if not re.fullmatch(r'session-[a-f0-9-]{36}',str(request['maintenance_session'])):raise ValueError('valid maintenance identity required')
            result['maintenance_session']=request['maintenance_session']
    if operation=='tool_run':
        payload=request.get('request',{})
        if not isinstance(payload,dict):raise ValueError('request must be an object')
        result['request']=payload
    if operation in ['probe','probe_compare']:
        target = request.get('target')
        if not isinstance(target, str) or len(target) > 253:
            raise ValueError('target must be a DNS hostname')
        target = target.lower().rstrip('.')
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', target):
            raise ValueError('target must be a DNS hostname, not a URL or command')
        result['target'] = target
        if operation=='probe_compare':
            endpoint=request.get('endpoint')
            if endpoint is not None:
                if not isinstance(endpoint,dict) or set(endpoint)-{'network','port','application_protocol'} or endpoint.get('network') not in ['tcp','udp'] or type(endpoint.get('port')) is not int or not 1<=endpoint['port']<=65535 or endpoint.get('application_protocol') not in ['tcp','tls','http','https','quic','unknown',None]:raise ValueError('actual endpoint network, port and protocol required')
                result['endpoint']=endpoint
            if 'refresh' in request:
                if type(request['refresh']) is not bool:raise ValueError('boolean comparison refresh required')
                result['refresh']=request['refresh']
    return result

INSTALL_POLICY = {'mode':'rule','proxy_chain':['US_AUTO','OTHER_AUTO'],
                  'region_providers':{'US_AUTO':'us','OTHER_AUTO':'other'},'default_rule':'MATCH,PROXY'}

def validate_baseline(config, uid, approved=None):
    approved=approved or INSTALL_POLICY
    groups = {g['name']:g for g in config.get('proxy-groups', [])}
    if config.get('mode') != approved['mode'] or groups.get('PROXY', {}).get('proxies') != approved['proxy_chain']:
        raise ValueError('configuration differs from the current user-approved policy')
    for group, provider in approved['region_providers'].items():
        if groups.get(group,{}).get('use') != [provider] or groups[group].get('empty-fallback') != 'REJECT':
            raise ValueError('region group policy changed')
    if uid not in config.get('tun',{}).get('exclude-uid',[]):
        raise ValueError('operator UID must bypass TUN')
    rules = config.get('rules', [])
    if not rules or rules[-1] != approved['default_rule']:
        raise ValueError('default routing differs from the current user-approved policy')

def recovery_due(transaction, now, boot_id):
    return bool(transaction and (transaction.get('boot_id') != boot_id or now >= transaction.get('deadline',0)))
