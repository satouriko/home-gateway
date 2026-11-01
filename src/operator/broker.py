#!/usr/bin/env python3
"""Fixed gateway operations over a private Unix socket; users interact only through DSH chat."""
from concurrent.futures import ThreadPoolExecutor
import json
import grp
import os
from pathlib import Path
import pwd
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import fcntl
import stat
import select
from policy import validate_request, validate_baseline, recovery_due, REPAIRS, READS, INSTALL_POLICY

STATE = Path('/var/lib/net-gateway-agent')
CONFIG = Path('/etc/net-gateway/config.json')
LOGIN=Path('/var/lib/dsh-login/credentials.yaml')
SOCKET = '/run/net-gateway-agent/control.sock'
LOCK = threading.Lock()
PROGRAM_LOCK = threading.Lock()
SKILL_LOCK = threading.Lock()
REQUEST=threading.local()
REGISTRY_LOCK=threading.Lock()
SYNC_STATUS=Path('/var/lib/home-gateway-backup/status.json')
SYNC_HOLD=Path('/run/home-gateway-integration')
SYNC_REQUEST_LOCK=threading.Lock()
SYNC_START_LOCK=threading.Lock()
SYNC_EVENT=threading.Event()
SYNC_THREAD=None

def source_sync_pending(status_path=None):
    try:
        request=json.loads((STATE/'source-sync-request.json').read_text())
        if not request.get('id'):return False
    except (OSError,ValueError,AttributeError):return False
    try:status=json.loads((status_path or SYNC_STATUS).read_text())
    except (OSError,ValueError):status={}
    return not isinstance(status,dict) or status.get('acknowledged_request')!=request['id']

def dispatch_source_sync_once():
    if SYNC_HOLD.exists():return False
    try:command('systemctl','start','home-gateway-backup.service',timeout=165)
    except Exception:return False  # Leave the durable request for the independent retry timer.
    # A publication may arrive while an already-running push is finishing.
    return source_sync_pending()

def start_sync_dispatcher():
    global SYNC_THREAD
    with SYNC_START_LOCK:
        if SYNC_THREAD is not None and SYNC_THREAD.is_alive():return
        def worker():
            while True:
                SYNC_EVENT.wait();SYNC_EVENT.clear()
                if source_sync_pending() and dispatch_source_sync_once():SYNC_EVENT.set()
        SYNC_THREAD=threading.Thread(target=worker,name='published-source-sync',daemon=True)
        SYNC_THREAD.start()

def publication_registry():
    from source_sync import SourceSyncRegistry
    return SourceSyncRegistry(STATE/'publication-receipts.json')

def publication_version(reason):
    from source_sync import snapshot_versions
    files={}
    for name,source in [('diagnostic','program_publish'),('tool','tool_publish')]:
        path=STATE/(name+'-active.json')
        if path.exists():files['src/maintained/'+('diagnostic.py' if name=='diagnostic' else 'tool.py')]=json.loads(path.read_text()).get('source','').encode()
    skill=Path('/usr/local/share/net-gateway-agent/skill/SKILL.md')
    if skill.exists():files['src/dsh/skill/SKILL.md']=skill.read_bytes()
    def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
    approved=STATE/'approved-policy.json'
    if approved.exists():files['preferences/network-policy.json']=encoded(json.loads(approved.read_text()))
    plan=STATE/'audit-plan.json'
    if plan.exists():
        value=json.loads(plan.read_text());files['preferences/audit-plan.json']=encoded({k:value[k] for k in ['interval_hours','daily_budget','enabled','schedule'] if k in value})
    return snapshot_versions(files).get(reason)

def queue_source_sync(reason,session_id=None):
    with SYNC_REQUEST_LOCK:
        receipt=publication_registry().register(reason,session_id,publication_version(reason))
        write_state(STATE/'source-sync-request.json',{'id':receipt['id'],'reason':reason,'requested_at':receipt['requested_at']})
    start_sync_dispatcher();SYNC_EVENT.set()
    return {'requested':True,'pending':True,'request_id':receipt['id'],'version':receipt['version'],
            'phase':'held' if SYNC_HOLD.exists() else 'pending','notification':'durable automatic receipt in originating chat' if session_id else 'background receipt'}

def acquire_transaction():
    if not LOCK.acquire(blocking=False):raise ValueError('another configuration operation is running')
    descriptor=None
    try:
        descriptor=(STATE/'transaction.lock').open('a')
        fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return descriptor
    except Exception:
        if descriptor:descriptor.close()
        LOCK.release();raise ValueError('another configuration operation is running') from None

def release_transaction(descriptor):
    descriptor.close();LOCK.release()

def command(*args, timeout=15, check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=timeout)

def write_state(path, data):
    tmp=path.with_suffix('.next')
    with tmp.open('w') as target:
        tmp.chmod(0o600);json.dump(data,target,ensure_ascii=False);target.flush();os.fsync(target.fileno())
    tmp.replace(path)
    descriptor=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)

def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def api(path, method='GET', data=None, timeout=15):
    c=json.loads(CONFIG.read_text())
    req=urllib.request.Request('http://127.0.0.1:9090'+path,method=method,
        headers={'Authorization':'Bearer '+c['secret'],'Content-Type':'application/json'},
        data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=timeout) as r:
        body=r.read();return json.loads(body) if body else {}

def service(name):
    result=command('systemctl','show',name,'-p','ActiveState','-p','SubState','-p','MemoryCurrent','-p','NRestarts',check=False)
    return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)

def current_policy():
    for path in [STATE/'approved-policy.json',STATE/'known-good/policy.json',STATE/'known-good-policy.json']:
        try:
            result=json.loads(path.read_text())
            if all(key in result for key in ['mode','proxy_chain','region_providers','default_rule']):return result
        except (OSError,ValueError,TypeError):pass
    return {**INSTALL_POLICY,'scope':'initial installation defaults; no valid approved checkpoint found'}

def audit_plan():
    path=STATE/'audit-plan.json'
    plan=json.loads(path.read_text()) if path.exists() else {'interval_hours':4,'daily_budget':6,'reason':'new deployment; adapt from observed coverage and stable samples','expires_at':0}
    sample=STATE/'patrol.json';state=json.loads(sample.read_text()) if sample.exists() else {}
    from patrol import audit_interval
    from native_jobs import effective_state,read as native_read
    state=effective_state(state,native_read())
    actual=(native_read().get('observed_task') or {})
    state['audit_plan']=plan
    if actual.get('kind')=='every':state['audit_plan']={**plan,'interval_hours':actual['everySeconds']/3600,'expires_at':time.time()+60,'for_program_version':state.get('diagnostic_program',{}).get('version')}
    return {**plan,'native_schedule':actual,'effective_interval_hours':audit_interval(state,time.time()),'selection_applies':plan.get('expires_at',0)>time.time() and plan.get('for_program_version')==state.get('diagnostic_program',{}).get('version')}

def checkpoint(config, approved):
    directory=STATE/'checkpoints'/uuid.uuid4().hex;directory.mkdir(parents=True,mode=0o700)
    write_state(directory/'config.json',config);write_state(directory/'policy.json',approved)
    shutil.copyfile('/etc/net-gateway/proxy-domains.yaml',directory/'rules.yaml');(directory/'rules.yaml').chmod(0o600)
    link=STATE/'known-good.next';link.unlink(missing_ok=True);link.symlink_to(directory)
    link.replace(STATE/'known-good')

def known_good():
    directory=STATE/'known-good'
    if directory.exists():return directory/'config.json',directory/'policy.json',directory/'rules.yaml'
    return STATE/'known-good-config.json',STATE/'known-good-policy.json',STATE/'known-good-rules.yaml'

def policy_action(operation, patch, receipt=None):
    from user_policy import merge_preferences, render
    old=json.loads(CONFIG.read_text());approved=current_policy()
    preferences=merge_preferences(approved.get('preferences',{}),patch)
    candidate,proposed=render(old,preferences,approved.get('preferences',{}))
    validate_baseline(candidate,pwd.getpwnam('dsh').pw_uid,proposed)
    transaction=acquire_transaction()
    temporary=CONFIG.with_suffix('.policy-next.json');pending=STATE/'pending.json'
    try:
        if pending.exists():raise ValueError('a previous repair is pending protected rollback')
        write_state(temporary,candidate)
        command('env','SAFE_PATHS=/etc/net-gateway','/usr/local/bin/mihomo','-t','-d','/var/lib/net-gateway','-f',str(temporary),timeout=25)
        if operation=='policy_test':return {'tested':True,'applied':False,'proposed_policy':proposed}
        if not isinstance(receipt,dict) or not isinstance(receipt.get('id'),str) or not isinstance(receipt.get('text'),str) or not receipt['text'].strip():raise ValueError('a current interactive user request is required')
        used=STATE/'policy-receipts.json';seen=json.loads(used.read_text()) if used.exists() else []
        if receipt['id'] in seen:raise ValueError('this user request has already been used; ask for a new explicit request')
        if not (STATE/'known-good').exists():checkpoint(old,approved)
        deadline=time.time()+90;ident=uuid.uuid4().hex
        write_state(pending,{'id':ident,'operation':'policy_apply','deadline':deadline,'boot_id':boot_id()})
        write_state(used,[*seen,receipt['id']][-128:])
        write_state(STATE/'approved-policy.json',proposed);temporary.replace(CONFIG)
        api('/configs','PUT',{'path':str(CONFIG)},timeout=25)
        if preferences['mode']=='global':api('/proxies/GLOBAL','PUT',{'name':'PROXY'})
        command('systemctl','start','net-gateway-maintain.service',timeout=40)
        result=diagnose();healthy=verification_healthy(result) and time.time()<deadline
        if healthy and json.loads(pending.read_text()).get('id')==ident:
            checkpoint(candidate,proposed);pending.unlink(missing_ok=True)
        return {'applied':True,'verified_healthy':healthy,'rollback_armed':not healthy,'policy':proposed,'verification':result}
    finally:
        temporary.unlink(missing_ok=True);release_transaction(transaction)

def source_control_status(path=None):
    path=path or SYNC_STATUS
    try:
        value=json.loads(path.read_text())
        if not isinstance(value,dict):return {'available':False}
        keys=['repository_url','branch','expected_branch','result','last_attempt_at','last_success_at',
              'local_commit','remote_commit','verification','error_code','acknowledged_request']
        pending=source_sync_pending(path)
        result={'available':True,'pending':pending,**{key:value[key] for key in keys if key in value}}
        result['phase']='held' if pending and SYNC_HOLD.exists() else 'pending' if pending else value.get('result','unknown')
        if (STATE/'publication-receipts.json').exists():
            registry=publication_registry();registry.reconcile(value,SYNC_HOLD.exists())
            result['recent_publications']=registry.records()[-6:]
        return result
    except (OSError,ValueError):return {'available':False,'pending':source_sync_pending(path)}

def context():
    import hashlib
    result=status()
    result['self']={'runtime':'DeepSeek Harness','reasoning':'external model API','data_plane':'Mihomo',
        'uid':pwd.getpwnam('dsh').pw_uid,'user_interface':'chat','control_path':'independent UID route and DNS; ordinary shell traffic is not a user-path test'}
    result['sources']={'code':'/usr/local/lib/net-gateway-agent','editable_source':'/var/lib/dsh/workspace/network-maintainer',
        'background':'/usr/local/share/net-gateway-agent/BACKGROUND.md','contracts':'/usr/local/share/net-gateway-agent/CONTRACTS.md',
        'skill_source':'/var/lib/dsh/workspace/network-maintainer/skill/SKILL.md','skill_active':'/usr/local/share/net-gateway-agent/skill/SKILL.md'}
    skill=Path(result['sources']['skill_active'])
    result['skill_revision']=hashlib.sha256(skill.read_bytes()).hexdigest()[:16]
    result['release_capabilities']={'diagnostic_programs':Path('/usr/local/lib/net-gateway-agent/programs.py').exists(),
        'maintained_tools':Path('/usr/local/lib/net-gateway-agent/extensions.py').exists(),
        'skills':Path('/usr/local/lib/net-gateway-agent/skills.py').exists()}
    from pricing import pricing_state
    result['maintenance_pricing']=pricing_state(time.time())
    result['audit_plan']=audit_plan()
    from native_jobs import context_summary
    result['native_automation']=context_summary()
    result['source_control']=source_control_status()
    result['observations']=traffic_status()
    result['node_health']=node_observations(result.get('policy',{}))
    result['probe_capabilities']={'operation':'probe_compare','paths':['direct','proxy'],'isolation':'disposable engine, separate UID route, concrete selected proxy; no household configuration changes','scope':'HTTPS root, not a logged-in client application','coding_sandbox':'capability-dropping bwrap; credentials, history and broker socket hidden'}
    changes=STATE/'deployment-events.json'
    if changes.exists():result['recent_system_changes']=json.loads(changes.read_text())[-6:]
    path=Path('/run/net-gateway-agent/patrol-context.json')
    if path.exists():
        event=json.loads(path.read_text())
        if event.get('urgent'):result['maintenance_event']={key:event.get(key) for key in ['urgent','observed_at','maintenance_trigger','diagnosis']}
    result['protected_boundary']='credentials, startup source, independent control route and recovery supervisor are not writable from maintained tools'
    return result

def status():
    result={'checked_at':time.time(),'gateway_address':'192.168.2.4','upstream':'192.168.2.1',
        'services':{name:service(name) for name in ['net-gateway.service','dsh.service']},
        'free_disk_bytes':shutil.disk_usage('/').free,
        'temperature_celsius':int(Path('/sys/class/thermal/thermal_zone0/temp').read_text())/1000,
        'policy':current_policy(),
        'control_route':json.loads(command('ip','-j','route','get','8.8.8.8','uid',str(pwd.getpwnam('dsh').pw_uid)).stdout)}
    try:
        providers=api('/providers/proxies')['providers']
        region=api('/proxies/PROXY').get('now')
        result.update(region=region,node=api('/proxies/'+region).get('now') if region not in [None,'DIRECT','REJECT'] else region,
            provider_counts={name:len(providers.get(name,{}).get('proxies',[])) for name in ['us','other']})
    except Exception as error:result['controller_error']=type(error).__name__
    pending=STATE/'pending.json'
    result['pending_recovery']=json.loads(pending.read_text()) if pending.exists() else None
    disk=STATE/'storage.json'
    if disk.exists():
        data=json.loads(disk.read_text());result['storage']={key:data.get(key) for key in ['checked_at','free_bytes','free_inodes','scratch_bytes','pause_routine','critical','emergency_reserve_present','policy']}
        result['storage']['background_history']={key:data.get('background_history',{}).get(key) for key in ['bytes','over_budget']}
    return result

def dns_probe(server, name):
    labels=b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\0'
    ident=int.from_bytes(os.urandom(2),'big')
    question=struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+labels+struct.pack('!HH',1,1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(3);s.sendto(question,(server,53));data,_=s.recvfrom(4096)
    header=struct.unpack('!HHHHHH',data[:12])
    return {'server':server,'name':name,'rcode':header[1]&15,'answer_count':header[3]}

def https_probe(domain, health=False):
    url='https://www.gstatic.com/generate_204' if health else 'https://'+domain+'/'
    proxy='http://192.168.2.4:7890'
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({'http':proxy,'https':proxy}),NoRedirect())
    start=time.monotonic()
    try:
        with opener.open(url,timeout=8) as response:
            body=response.read(32768);code=response.status;content_type=response.headers.get('Content-Type','')
    except urllib.error.HTTPError as error:code=error.code;body=b'';content_type=''
    from probe_transport import response_evidence
    evidence=response_evidence(domain,code,body,content_type,round((time.monotonic()-start)*1000))
    expected=(code==204) if health else evidence['content_ok']
    return {'domain':domain,'http_status':code,'elapsed_ms':round((time.monotonic()-start)*1000),
        'network_reachable':True,'business_rejection':code in [401,403,429],
        'business_ok':expected,'application_state':'healthy' if expected is True else 'rejected' if code>=400 else 'unverified',
        'acceptance_scope':'fixed health endpoint' if health else evidence['acceptance_scope'],
        'expected_health_status':expected,'origin':'synthetic_probe','routing':'Mihomo own rules; no forced DIRECT fallback'}

def diagnose():
    tests={
      'gateway_dns_cn':lambda:dns_probe('192.168.2.4','www.baidu.com'),
      'gateway_dns_foreign':lambda:dns_probe('192.168.2.4','www.google.com'),
      'bootstrap_dns_api':lambda:dns_probe('192.168.2.1','api.deepseek.com'),
      'mainland_https':lambda:https_probe('www.baidu.com'),
      'proxy_https':lambda:https_probe('www.gstatic.com',True),
    }
    results={}
    def wrapped(fn):
        try:return {'ok':True,'result':fn()}
        except Exception as error:return {'ok':False,'error':type(error).__name__}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures={name:pool.submit(wrapped,fn) for name,fn in tests.items()}
        for name,future in futures.items():results[name]=future.result()
    current=status()
    return {'status':current,'checks':results,'node_observations':node_observations(current.get('policy',{})),
            'note':'HTTP 401/403/429 are application responses, not proof of DNS or TCP failure.'}

def node_observations(policy):
    from node_health import summarize
    path=Path('/var/lib/net-gateway/health-state.json')
    try:
        if path.stat().st_size>128*1024:raise ValueError('node history exceeds budget')
        document=json.loads(path.read_text())
    except (OSError,ValueError):document={}
    return summarize(document,policy,time.time())

def quality():
    providers=api('/providers/proxies')['providers']
    pools={name:[{'name':p['name'],'alive':p.get('alive'),'history':p.get('history',[])[-5:]} for p in providers.get(name,{}).get('proxies',[])] for name in ['us','other']}
    connections=api('/connections').get('connections',[])
    domains={}
    for connection in connections[:500]:
        host=connection.get('metadata',{}).get('host')
        if not host:continue
        entry=domains.setdefault(host,{'connections':0,'upload':0,'download':0})
        entry['connections']+=1;entry['upload']+=connection.get('upload',0);entry['download']+=connection.get('download',0)
    return {'node_pools':pools,'active_domains':dict(sorted(domains.items(),key=lambda item:item[1]['download'],reverse=True)[:20]),'client_observations':traffic_status(),
        'sampling':'active-connection snapshot, not complete traffic accounting','node_test':'native provider health URL; not proof every application works'}

def traffic_status():
    from traffic import summary
    path=STATE/'traffic.json';now=time.time()
    try:
        if path.stat().st_size>2*1024**2:raise ValueError('traffic state exceeds budget')
        state=json.loads(path.read_text());result=summary(state,now)
        collector=state.get('collector',{});last=collector.get('last_success_at',0)
        result['collector']={**collector,'fresh':isinstance(last,(int,float)) and 0<=now-last<300}
        if not result['collector']['fresh']:result['status']='observation_stale'
        return result
    except (OSError,ValueError,TypeError,KeyError):
        return {'status':'observation_unavailable','origin':'mihomo_client_observations','domains':[],'issues':[],'coverage':{'complete':False,'gaps':['collector unavailable; no inference about client activity']}}

def restore_gateway():
    source,policy_source,rules_source=known_good()
    approved=json.loads(policy_source.read_text()) if policy_source.exists() else current_policy()
    config=json.loads(source.read_text());validate_baseline(config,pwd.getpwnam('dsh').pw_uid,approved)
    candidate=CONFIG.with_suffix('.recovery.json')
    rules_candidate=CONFIG.parent/'recovery-rules.yaml'
    shutil.copyfile(rules_source,rules_candidate);rules_candidate.chmod(0o600)
    config['rule-providers']['proxy-domains']['path']=str(rules_candidate)
    candidate.write_text(json.dumps(config,ensure_ascii=False));candidate.chmod(0o600)
    command('env','SAFE_PATHS=/etc/net-gateway','/usr/local/bin/mihomo','-t','-d','/var/lib/net-gateway','-f',str(candidate),timeout=25)
    rules_candidate.replace(CONFIG.parent/'proxy-domains.yaml')
    config['rule-providers']['proxy-domains']['path']=str(CONFIG.parent/'proxy-domains.yaml')
    candidate.write_text(json.dumps(config,ensure_ascii=False));candidate.replace(CONFIG)
    write_state(STATE/'approved-policy.json',approved)
    command('systemctl','restart','net-gateway.service',timeout=40)
    command('systemctl','start','net-gateway-maintain.timer')

def verification_healthy(result):
    if result['status']['services']['net-gateway.service'].get('ActiveState')!='active':return False
    checks=result['checks']
    direct=result['status'].get('policy',{}).get('mode')=='direct'
    for name in (['gateway_dns_cn','bootstrap_dns_api'] if direct else ['gateway_dns_cn','gateway_dns_foreign','bootstrap_dns_api']):
        item=checks.get(name,{})
        if not item.get('ok') or item.get('result',{}).get('rcode')!=0 or item['result'].get('answer_count',0)<1:return False
    mainland=checks.get('mainland_https',{})
    if not mainland.get('ok') or not 200<=mainland.get('result',{}).get('http_status',0)<400:return False
    if direct:return True
    proxy=checks.get('proxy_https',{})
    return bool(proxy.get('ok') and proxy.get('result',{}).get('http_status')==204)

def repair(operation):
    transaction=acquire_transaction()
    pending=STATE/'pending.json'
    try:
        if pending.exists() and operation!='restore_gateway':
            raise ValueError('a previous repair is pending protected rollback; inspect status')
        ident=uuid.uuid4().hex;deadline=time.time()+90
        write_state(pending,{'id':ident,'operation':operation,'deadline':deadline,'boot_id':boot_id()})
        if operation=='restore_gateway':restore_gateway()
        elif operation=='restart_gateway':
            validate_baseline(json.loads(CONFIG.read_text()),pwd.getpwnam('dsh').pw_uid,current_policy())
            command('env','SAFE_PATHS=/etc/net-gateway','/usr/local/bin/mihomo','-t','-d','/var/lib/net-gateway','-f',str(CONFIG),timeout=25)
            command('systemctl','restart','net-gateway.service',timeout=40)
        elif operation=='refresh_subscription':
            for name in ['us','other']:api('/providers/proxies/'+name,'PUT',timeout=15)
        if operation in ['recheck_nodes','refresh_subscription']:
            command('systemctl','start','net-gateway-maintain.service',timeout=40)
        else:
            # Allow asynchronous provider initialization; health timer continues independently.
            for _ in range(15):
                try:api('/proxies/PROXY');break
                except Exception:time.sleep(1)
        result=diagnose()
        if result['status']['services']['net-gateway.service'].get('ActiveState')!='active':
            raise RuntimeError('gateway inactive after repair')
        healthy=verification_healthy(result) and time.time()<deadline and json.loads(pending.read_text()).get('id')==ident
        if healthy:pending.unlink(missing_ok=True)
        write_state(STATE/'last-repair.json',{'operation':operation,'completed_at':time.time(),'verified_healthy':healthy,'result':result})
        return {'operation':operation,'verified_healthy':healthy,'rollback_armed':not healthy,'verification':result}
    except Exception:
        # Leave the independently supervised transaction armed for offline rollback.
        raise
    finally:release_transaction(transaction)

def dispatch(request):
    if request.get('operation')=='source_sync_notices':
        validate_request(request)
        source_control_status()
        return publication_registry().notices()
    if request.get('operation')=='source_sync_notice_ack':
        data=validate_request(request)
        return publication_registry().acknowledge(data['request_id'],data['revision'],data['session_id'],data['message_id'])
    if request.get('operation')=='traffic_status':
        validate_request(request)
        return traffic_status()
    if request.get('operation')=='probe_compare':
        data=validate_request(request)
        from probe_transport import compare
        return compare(data['target'],api,CONFIG)
    data=validate_request(request);op=data['operation']
    if op=='status':return status()
    if op=='overview':
        from overview import CACHE, build_snapshot
        return CACHE.get(lambda:build_snapshot(api,STATE,CONFIG))
    if op.startswith('native_'):
        import native_jobs as native
        if op=='native_status':return native.status()
        if op=='native_inspection':return native.inspection(data['session_id'])
        if op=='native_observe':return native.observe(data['task'])
        if op=='native_bind':
            result=native.bind(data['session_id'],data['schedule_id'])
            dispatch({'operation':'maintenance_register','session_id':data['session_id'],'kind':'automation'})
            return result
        if op=='native_admit':
            path=STATE/'patrol.json';state=json.loads(path.read_text()) if path.exists() else {}
            return native.dispatch_job(native.admit(data['session_id'],state,occurrence=data.get('occurrence'),execution_id=data.get('execution_id')),data.get('task_prompt'),getattr(REQUEST,'cancelled',lambda:False))
        if op=='native_check':return native.check(data['session_id'],data['job_id'])
        if op=='native_finish':return native.finish(data['session_id'],data['job_id'],data['outcome'],execution_session_id=data.get('execution_session_id'),summary=data.get('summary'))
    if op=='audit_plan':return audit_plan()
    if op=='audit_plan_enable':
        if not data.get('receipt'):raise ValueError('restoring a deleted task requires an explicit chat request')
        import native_jobs as native
        with native.locked():
            record=native.read();record.update(enabled=True,provision_requested=True);native.save(record)
        plan=audit_plan();plan['enabled']=True;write_state(STATE/'audit-plan.json',plan);return {'restore_requested':True}
    if op=='audit_plan_set':
        from native_jobs import update_schedule
        update_schedule(data['interval_hours'])
        program=STATE/'diagnostic-active.json'
        plan_path=STATE/'audit-plan.json'
        record=json.loads(plan_path.read_text()) if plan_path.exists() else {}
        record.update({key:data[key] for key in ['interval_hours','daily_budget','reason']})
        record.update(chosen_at=time.time(),expires_at=time.time()+7*86400,for_program_version=json.loads(program.read_text()).get('version') if program.exists() else None)
        write_state(STATE/'audit-plan.json',record);return record
    if op=='maintenance_register':
        with REGISTRY_LOCK:
            path=STATE/'background-sessions.json';records=json.loads(path.read_text()) if path.exists() else {}
            record=records.setdefault(data['session_id'],{'first_seen':time.time(),'kind':data['kind']})
            if data['kind']=='user':record['user_chat']=True
            if data['kind']=='automation':record['kind']='automation'
            write_state(path,dict(list(records.items())[-10000:]))
        return {'registered':True}
    if op=='diagnose':return diagnose()
    if op=='probe':return https_probe(data['target'])
    if op=='quality':return quality()
    if op=='policy':return current_policy()
    if op in ['policy_test','policy_apply']:return policy_action(op,data['preferences'],data.get('receipt'))
    if op=='context':return context()
    if op=='patrol_status':
        path=STATE/'patrol.json'
        return json.loads(path.read_text()) if path.exists() else {'started':False}
    if op.startswith('program_'):
        from programs import program_action
        if not PROGRAM_LOCK.acquire(blocking=False):raise ValueError('another diagnostic program test is running')
        try:return program_action(op,data.get('source'))
        finally:PROGRAM_LOCK.release()
    if op.startswith('tool_'):
        from extensions import action
        if not PROGRAM_LOCK.acquire(blocking=False):raise ValueError('another maintained program operation is running')
        try:return action(op,data.get('source'),data.get('request'))
        finally:PROGRAM_LOCK.release()
    if op.startswith('skill_'):
        from skills import action
        if op=='skill_status':return action(op)
        if not SKILL_LOCK.acquire(blocking=False):raise ValueError('another skill validation is running')
        try:return action(op,data.get('source'),data.get('deadline'),getattr(REQUEST,'cancelled',None))
        finally:SKILL_LOCK.release()
    return repair(op)

def handle(request):
    result=dispatch(request);op=request.get('operation')
    published=(op in ['program_publish','tool_publish','skill_publish'] and result.get('deployed') is True)
    published=published or op in ['audit_plan_set','audit_plan_enable'] or (op=='native_observe' and result.get('preference_changed')) or (op=='policy_apply' and result.get('verified_healthy') is True and result.get('rollback_armed') is False)
    if published:
        try:sync=queue_source_sync(op,request.get('session_id'))
        except Exception:sync={'requested':False,'retry':'independent timer'}
        result={**result,'source_control_sync':sync}
    return result

def envelope(request):
    try:return {'ok':True,'result':handle(request)}
    except Exception as error:return {'ok':False,'error':type(error).__name__,'message':str(error) if isinstance(error,ValueError) else 'operation failed; check local recovery status'}

class UnixHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(320)
        line=self.rfile.readline(65537)
        if len(line)>65536:return
        try:request=json.loads(line)
        except Exception:request={}
        _pid,uid,_gid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        cgroup=Path(f'/proc/{_pid}/cgroup').read_text()
        def cancelled():
            if not select.select([self.connection],[],[],0)[0]:return False
            try:return self.connection.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)==b''
            except BlockingIOError:return False
            except OSError:return True
        REQUEST.cancelled=cancelled
        readonly=uid not in [0,pwd.getpwnam('dsh').pw_uid] or 'net-gateway-skill-canary-' in cgroup
        if request.get('operation') in ['native_bind','native_admit','native_check','native_finish','native_observe','audit_plan_enable'] and not (uid==0 or (uid==pwd.getpwnam('dsh').pw_uid and ('/dsh.service' in cgroup or (request.get('operation')=='native_finish' and 'net-gateway-ai-patrol' in cgroup)))):
            self.wfile.write(b'{"ok":false,"error":"PermissionError","message":"native maintenance requires the Web runtime"}\n');return
        registered=request.get('operation')=='maintenance_register'
        allowed_registration=uid==0 or (uid==pwd.getpwnam('dsh').pw_uid and ((request.get('kind')=='canary' and 'net-gateway-skill-canary-' in cgroup) or (request.get('kind')=='patrol' and 'net-gateway-ai-patrol' in cgroup) or (request.get('kind')=='user' and '/dsh.service' in cgroup)))
        if registered and not allowed_registration:
            self.wfile.write(b'{"ok":false,"error":"PermissionError","message":"session registration does not match caller"}\n');return
        if readonly and request.get('operation') not in READS|{'program_status','tool_status','skill_status'} and not (registered and allowed_registration):
            self.wfile.write(b'{"ok":false,"error":"PermissionError","message":"worker tools may read evidence only"}\n');return
        if request.get('operation')=='policy_apply' and uid!=0 and '/dsh.service' not in cgroup:
            self.wfile.write(b'{"ok":false,"error":"PermissionError","message":"only an interactive chat request may change user objectives"}\n');return
        if request.get('operation') in ['skill_test','skill_publish'] and 'net-gateway-ai-patrol' in cgroup:
            from pricing import pricing_state
            path=Path('/run/net-gateway-agent/patrol-context.json')
            context=json.loads(path.read_text()) if path.exists() else {}
            if not context.get('urgent'):
                clock=pricing_state(time.time());deadline=request.get('deadline',0)
                if clock['peak'] or not isinstance(deadline,(int,float)) or deadline<=time.time():
                    self.wfile.write(b'{"ok":false,"error":"ValueError","message":"routine skill evaluation waits for its next off-peak budget"}\n');return
                if clock['off_peak_seconds_remaining']:deadline=min(deadline,time.time()+clock['off_peak_seconds_remaining']-60)
                if context.get('native_deadline'):deadline=min(deadline,context['native_deadline'])
                request['deadline']=deadline
        if request.get('operation') in ['skill_test','skill_publish'] and request.get('maintenance_session') and '/dsh.service' in cgroup:
            import native_jobs as native
            current=native.read();runs=current.get('runs',[]);job=runs[-1] if runs else {}
            if request['maintenance_session']==current.get('session_id') and job.get('state')=='running':
                if not native.check(current['session_id'],job['id'])['continue']:
                    self.wfile.write(b'{"ok":false,"error":"ValueError","message":"native routine budget ended"}\n');return
                request['deadline']=min(request.get('deadline',0),job['deadline'])
        self.wfile.write(json.dumps(envelope(request),ensure_ascii=False).encode()+b'\n')

class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True

def agent_ready():
    raw=command('systemctl','show','dsh.service','-p','ActiveEnterTimestampMonotonic','--value',check=False).stdout.strip()
    if raw.isdigit() and time.monotonic()-int(raw)/1000000<75:return True
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://192.168.2.4/',timeout=4) as response:
            return response.status==200
    except Exception:return False

def guard_login(restore=False):
    # Login records have their own bounded directory; provider keys remain protected.
    import yaml
    credentials=LOGIN
    bootstrap=STATE/'bootstrap-login.yaml'
    user=pwd.getpwnam('dsh')
    if restore or (credentials.exists() and not stat.S_ISREG(credentials.lstat().st_mode)) or credentials.is_symlink():
        if credentials.exists() or credentials.is_symlink():credentials.rename(credentials.with_name('invalid-'+uuid.uuid4().hex))
        temporary=credentials.with_suffix('.next');shutil.copyfile(bootstrap,temporary);os.chown(temporary,user.pw_uid,user.pw_gid);temporary.chmod(0o600);temporary.replace(credentials)
    if credentials.exists():
        os.chown(credentials,user.pw_uid,user.pw_gid);credentials.chmod(0o600)
        valid=False;values=None
        try:
            if credentials.stat().st_size<=262144:values=yaml.safe_load(credentials.read_text())
            valid=isinstance(values,dict) and values.get('version')==1 and isinstance(values.get('records'),dict)
        except (yaml.YAMLError,ValueError):pass
        backup=STATE/'known-login.yaml'
        if not backup.exists():shutil.copyfile(bootstrap,backup);backup.chmod(0o600)
        if not valid or values.get('refs'):
            if credentials.stat().st_size>262144:return guard_login(restore=True)
            user=pwd.getpwnam('dsh')
            command('node','/usr/local/lib/net-gateway-agent/credential_guard.mjs',str(user.pw_uid),str(user.pw_gid),timeout=8)
        elif not backup.exists() or backup.read_bytes()!=credentials.read_bytes():
            shutil.copyfile(credentials,backup);backup.chmod(0o600)

def watchdog():
    from control_route import apply
    apply()
    pending=STATE/'pending.json'
    if pending.exists() and recovery_due(json.loads(pending.read_text()),time.time(),boot_id()):
        try:transaction=acquire_transaction()
        except ValueError:
            # End an expired writer before taking its lease; no stale writer may commit.
            command('systemctl','restart','net-gateway-agent.service',timeout=20)
            transaction=acquire_transaction()
        try:
            if pending.exists() and recovery_due(json.loads(pending.read_text()),time.time(),boot_id()):
                restore_gateway();pending.unlink(missing_ok=True)
                write_state(STATE/'last-recovery.json',{'at':time.time(),'reason':'uncommitted repair deadline or reboot'})
        finally:release_transaction(transaction)
    try:guard_login()
    except Exception as error:
        try:write_state(STATE/'last-login-guard-error.json',{'at':time.time(),'error':type(error).__name__})
        except OSError:pass
    # A crashed agent is restarted from protected startup files, without using an LLM.
    state=service('dsh.service')
    if state.get('ActiveState') in ['failed','inactive'] or (state.get('ActiveState')=='activating' and int(state.get('NRestarts','0'))>=3):
        try:guard_login(restore=True)
        except Exception:pass
        command('systemctl','start','dsh.service',timeout=40)
    elif state.get('ActiveState')=='active' and not agent_ready():
        try:guard_login(restore=True)
        except Exception:pass
        command('systemctl','restart','dsh.service',timeout=40)
    print(json.dumps({'watchdog':'ok','at':time.time()}))

if __name__=='__main__':
    if '--watchdog' in sys.argv:watchdog();raise SystemExit(0)
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    from native_jobs import publish_identity
    publish_identity()
    if Path(SOCKET).exists():Path(SOCKET).unlink()
    unix=UnixServer(SOCKET,UnixHandler)
    os.chown(SOCKET,0,grp.getgrnam('gateway-operators').gr_gid);os.chmod(SOCKET,0o660)
    unix.serve_forever()
