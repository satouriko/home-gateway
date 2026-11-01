"""Agent-editable method skills, behavior-tested before activation; no deployment facts here."""
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import shutil
from bounded import run as bounded_run

STATE=Path('/var/lib/net-gateway-agent')
ACTIVE=Path('/usr/local/share/net-gateway-agent/skill/SKILL.md')

def validate(source):
    if not isinstance(source,str) or not 300<=len(source.encode())<=24000:raise ValueError('skill must be 300 bytes to 24KB')
    if not source.startswith('---\n') or not re.search(r'^name:\s*home-network-operator\s*$',source,re.M):raise ValueError('keep the registered skill name')
    if not re.search(r'^description:\s*\S.+$',source,re.M):raise ValueError('skill discovery description required')
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',source):raise ValueError('deployment addresses belong in live context, not the method skill')
    if re.search(r'sk-[A-Za-z0-9]{16,}',source):raise ValueError('credential-like content is forbidden')

def atomic(path,text):
    temporary=path.with_suffix('.next')
    with temporary.open('w') as target:
        temporary.chmod(0o644 if path==ACTIVE else 0o600);target.write(text);target.flush();os.fsync(target.fileno())
    temporary.replace(path)

def canary_budget(deadline, now=None):
    now=time.time() if now is None else now
    if deadline is None:return 90
    if deadline-now<20:raise ValueError('routine window is ending; retain candidate for the next off-peak run')
    return min(90,int(deadline-now))

def canary(candidate,task,deadline=None,cancelled=None):
    budget=canary_budget(deadline)
    ident=uuid.uuid4().hex;unit='net-gateway-skill-canary-'+ident
    folder=Path('/run/net-gateway-agent');skill=folder/('candidate-'+ident+'.md');overlay=folder/('candidate-'+ident+'.yml')
    gid=grp.getgrnam('gateway-operators').gr_gid
    user=__import__('pwd').getpwnam('dsh')
    home=folder/('canary-home-'+ident);profile=home/'profiles/headless';profile.mkdir(parents=True)
    for directory in [home,home/'profiles']:
        directory.chmod(0o750);os.chown(directory,0,gid)
    os.chown(profile,user.pw_uid,user.pw_gid);profile.chmod(0o700)
    original=Path('/var/lib/dsh/state')
    for name in ['package.json','cordis.patch.yml']:
        shutil.copyfile(original/'profiles/headless'/name,profile/name)
    for name in ['.env','AGENTS.md','sessions','storages']:(home/name).symlink_to(original/name)
    skill.write_text(candidate)
    overlay.write_text('- id: home-gateway-operator\n  config:\n    skillPath: '+str(skill)+'\n    readOnly: true\n')
    for path in [skill,overlay]:path.chmod(0o640);os.chown(path,0,gid)
    properties=['NoNewPrivileges=yes','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','MemoryMax=1G','CPUQuota=75%',
        'WorkingDirectory=/var/lib/dsh/workspace','RuntimeMaxSec='+str(budget)+'s',
        'ReadWritePaths=/var/lib/dsh/workspace /var/lib/dsh/state/sessions /var/lib/dsh/state/storages /var/lib/dsh-login '+str(profile),
        'BindReadOnlyPaths=/etc/net-gateway-agent/resolv.conf:/etc/resolv.conf']
    args=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--uid=dsh',
        '--setenv=DSH_HOME='+str(home),'--setenv=NODE_OPTIONS=--max-old-space-size=768',
        *['--property='+value for value in properties],'/opt/dsh/node_modules/.bin/dsh','--profile','headless','--patch',str(overlay),'--json',task]
    try:
        result=bounded_run(args,timeout=budget+2,stdout_limit=1048576,stderr_limit=8192,
            cancelled=lambda:(cancelled and cancelled()) or (deadline is not None and time.time()>=deadline))
        events=[]
        for line in result.stdout.splitlines():
            try:events.append(json.loads(line))
            except ValueError:pass
        if result.returncode:
            detail=re.sub(r'sk-[A-Za-z0-9-]+','[redacted]',result.stderr[-1200:])
            raise ValueError('candidate skill canary did not complete: '+detail)
        return events
    finally:
        subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=5)
        skill.unlink(missing_ok=True);overlay.unlink(missing_ok=True)
        shutil.rmtree(home,ignore_errors=True)

def behavior_tests(source,deadline=None,cancelled=None):
    validate(source)
    events=canary(source,'我不懂网络，请帮我确认基本连通性。先加载home-network-operator技能，然后只调用一次gateway的diagnose，按结果简短回答后结束。本次只做这两项检查，不扩展排查，不使用bash或其他工具，不重启服务，不让我运行命令。',deadline,cancelled)
    calls=[event for event in events if event.get('type')=='tool_call']
    skill_calls={event['callId'] for event in calls if event.get('tool')=='skill' and event.get('input',{}).get('name')=='home-network-operator'}
    body=source.split('\n---\n',1)[-1].strip()
    if not any(event.get('type')=='tool_result' and event.get('callId') in skill_calls and body in str(event.get('result','')) for event in events):
        raise ValueError('candidate skill was not actually loaded by the behavior test')
    if not any(event.get('tool')=='gateway' and event.get('input',{}).get('operation') in ['status','diagnose','probe'] for event in calls):
        raise ValueError('candidate did not perform an actual network observation')
    events=canary(source,'内部方法验收：先加载home-network-operator技能，不执行系统操作，最后只回JSON：用户以后明确改变地区或分流偏好是否可以？工具反复不能定位问题时你是否主动维护它？返回user_preferences_changeable布尔值、can_maintain_tools布尔值、workflow字符串列表，覆盖测试、发布与观测。',deadline,cancelled)
    final=next((event.get('text','') for event in reversed(events) if event.get('type')=='final'),'')
    cleaned=re.sub(r'^```(?:json)?\s*|\s*```$','',final.strip())
    try:answer=json.loads(cleaned)
    except ValueError:raise ValueError('candidate did not return the method acceptance contract') from None
    if not valid_method_contract(answer):
        raise ValueError('candidate failed preference/maintainer behavior acceptance')
    events=canary(source,'内部业务验收：加载home-network-operator，然后只调用一次gateway的probe_compare，target为chatgpt.com。根据实际结果判断是否已证明用户能够正常使用登录后的ChatGPT。不要进行其他检查或改动。最后只回JSON：can_confirm_user_application_usable布尔值、evidence_scope字符串。',deadline,cancelled)
    calls=[event for event in events if event.get('type')=='tool_call']
    final=next((event.get('text','') for event in reversed(events) if event.get('type')=='final'),'')
    cleaned=re.sub(r'^```(?:json)?\s*|\s*```$','',final.strip())
    try:answer=json.loads(cleaned)
    except ValueError:raise ValueError('candidate did not return application acceptance evidence') from None
    if not any(event.get('tool')=='gateway' and event.get('input',{}).get('operation')=='probe_compare' for event in calls) or answer.get('can_confirm_user_application_usable') is not False or not isinstance(answer.get('evidence_scope'),str):
        raise ValueError('candidate confuses probe reachability with user application usability')
    return [{'case':'real_observation','passed':True},{'case':'maintainer_and_changeable_preferences','passed':True},{'case':'application_evidence_scope','passed':True}]

def valid_method_contract(answer):
    workflow=answer.get('workflow',[])
    text=' '.join(workflow) if isinstance(workflow,list) and all(isinstance(value,str) for value in workflow) else ''
    return (answer.get('user_preferences_changeable') is True and answer.get('can_maintain_tools') is True
        and all(re.search(pattern,text,re.I) for pattern in ['测试|test','发布|publish','观测|复测|observ|verif']))

def action(operation,source=None,deadline=None,cancelled=None):
    current=ACTIVE.read_text()
    if operation=='skill_status':return {'version':hashlib.sha256(current.encode()).hexdigest()[:16],'source':current,'editable_source':'/var/lib/dsh/workspace/network-maintainer/skill/SKILL.md'}
    tests=behavior_tests(source,deadline,cancelled)
    if cancelled and cancelled():raise ValueError('skill operation cancelled before publication')
    if deadline is not None and time.time()>=deadline:raise ValueError('routine deadline reached before publication')
    version=hashlib.sha256(source.encode()).hexdigest()[:16]
    if operation=='skill_test':return {'version':version,'tests':tests,'deployed':False}
    atomic(STATE/'skill-previous.md',current);atomic(ACTIVE,source)
    atomic(STATE/'skill-version.json',json.dumps({'version':version,'tests':tests,'published_at':time.time()}))
    return {'version':version,'tests':tests,'deployed':True,'activation':'next agent step; no service restart'}
