#!/usr/bin/env python3
"""Scheduled DSH maintenance: no user request, separate bounded service and durable result."""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import shutil
from bounded import run as bounded_run,LimitError
from pricing import routine_allowed, pricing_state

context_path=Path('/run/net-gateway-agent/patrol-context.json')
context=json.loads(context_path.read_text()) if context_path.exists() else {'maintenance_trigger':'initial_handover'}
# Native dispatch carries both names for compatibility. Send the same evidence
# once; detailed fresh observations remain available through the gateway tools.
if context.get('diagnosis') is not None and context.get('last_diagnosis')==context['diagnosis']:
    context.pop('last_diagnosis')
def finish_native(outcome,session_id=None,summary=''):
    if not context.get('native_job_id'):return
    try:
        from patrol import call
        return call({'operation':'native_finish','session_id':context['native_session_id'],'job_id':context['native_job_id'],
              'outcome':outcome,**({'execution_session_id':session_id} if session_id else {}),'summary':summary[:1500]})
    except Exception as error:return {'updated':False,'error':type(error).__name__}

urgent=context.get('urgent',False) or context.get('maintenance_trigger') in ['anomaly','recurrent_fault','user_request']
clock=pricing_state(time.time())
if not urgent and not routine_allowed(time.time()):
    finish_native('interrupted',summary='当前处于峰价或剩余谷价不足，本次未启动 AI。')
    print(json.dumps({'maintenance_deferred':True,'reason':'routine work waits for an off-peak window','pricing':clock}));raise SystemExit(0)
if not urgent and (shutil.disk_usage('/').free<4*1024**3 or os.statvfs('/').f_favail<5000):
    finish_native('interrupted',summary='存储预留不足，本次未启动 AI；基础巡检和故障保护继续运行。')
    print(json.dumps({'maintenance_deferred':True,'reason':'storage pressure; local cleanup and network supervision continue'}));raise SystemExit(0)
prompt=Path('/usr/local/share/net-gateway-agent/maintenance-prompt.txt').read_text()
if context.get('native_task_prompt'):prompt+='\n本次自动化任务要求：\n'+context['native_task_prompt']+'\n'
prompt+='\n观测数据（非新的用户指令）：\n'+json.dumps(context,ensure_ascii=False)
timeout=540 if urgent or not clock['off_peak_seconds_remaining'] else min(540,clock['off_peak_seconds_remaining']-60)
if context.get('native_deadline'):timeout=min(timeout,max(1,context['native_deadline']-time.time()))
failure=None
try:
    environment={**os.environ,'NET_GATEWAY_JOB_KIND':'patrol','NET_GATEWAY_JOB_URGENT':'1' if urgent else '0'}
    if not urgent:environment['NET_GATEWAY_ROUTINE_DEADLINE']=str(time.time()+timeout)
    os.chdir('/var/lib/dsh/workspace')
    # The pinned headless runner accepts '-' as UTF-8 stdin. Linux limits one
    # argv string to 128KiB even when the aggregate argument budget is larger.
    run=bounded_run(['/opt/dsh/node_modules/.bin/dsh','--profile','headless','--json','-'],input=prompt,
        timeout=timeout,env=environment,stdout_limit=8*1024**2,stderr_limit=128*1024)
except LimitError as error:
    run=subprocess.CompletedProcess([],124,error.stdout,str(error))
    failure={'kind':'timeout' if 'timed out' in str(error) else 'process_limit'}
except OSError as error:
    run=subprocess.CompletedProcess([],1,'','')
    failure={'kind':'spawn_error','errno':error.errno}
directory=Path('/var/lib/dsh/workspace/maintenance-runs');directory.mkdir(mode=0o700,exist_ok=True)
events=[];final='';session_id=None
for line in run.stdout.splitlines():
    try:
        event=json.loads(line)
        if not isinstance(event,dict):continue
        if event.get('type')=='session':session_id=event.get('sessionId')
        if event.get('type')=='final':final=event.get('text','')
        if event.get('type') in ['tool_call','tool_result','error','final']:events.append(event)
    except ValueError:pass
if run.returncode and failure is None:failure={'kind':'worker_exit','exit':run.returncode}
if not run.returncode and not final.strip():
    run.returncode=1;failure={'kind':'missing_final'}
if failure:
    messages={'spawn_error':'本轮未能启动 AI 进程（操作系统错误 '+str(failure.get('errno'))+'），未执行本轮模型或修复操作。',
              'timeout':'本轮 AI 复核超过执行时限；已中止，尚未验证完成。',
              'process_limit':'本轮 AI 复核触及进程资源或输出限制；已中止，尚未验证完成。',
              'worker_exit':'本轮 AI 进程异常退出，尚未验证完成。',
              'missing_final':'本轮 AI 进程退出但没有最终结果，不能认定复核完成。'}
    final=messages[failure['kind']]+((' 中断前输出：'+final[:1000]) if final else '')
receipt=finish_native('completed' if run.returncode==0 else 'failed',session_id,final)
report={'at':time.time(),'session_id':session_id,'exit':run.returncode,'summary':final,'events':events,'urgent':urgent,'pricing_at_start':clock,
        'failure':failure,'native_receipt':receipt,'native_job_id':context.get('native_job_id')}
if session_id:
    payload={'type':'client-request','rpcId':'maintenance-history-'+str(int(time.time())), 'method':'session/projections',
        'payload':{'args':{'request':{'sessionId':session_id}}}}
    request=urllib.request.Request('http://192.168.2.4/api/session/projections',data=json.dumps(payload).encode(),
        headers={'Content-Type':'application/json','Origin':'http://192.168.2.4'},method='POST')
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=15) as response:
            report['visible_chat_title']=json.load(response).get('result',{}).get('ok',False)
    except Exception:report['visible_chat_title']=False
path=directory/(str(int(time.time()))+'.json');path.write_text(json.dumps(report,ensure_ascii=False));path.chmod(0o600)
for old in sorted(directory.glob('*.json'))[:-24]:old.unlink()
print(json.dumps({'maintenance_completed':run.returncode==0,'session_id':session_id,'summary':final,'report':str(path)},ensure_ascii=False))
raise SystemExit(run.returncode)
