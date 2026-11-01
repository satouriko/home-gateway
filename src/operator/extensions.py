"""Versioned agent-maintained tools, executed as a separate confined worker user."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
import uuid

STATE=Path('/var/lib/net-gateway-agent')

def validate_source(source):
    if not isinstance(source,str) or not 1<=len(source.encode())<=24000:raise ValueError('tool source exceeds 24KB budget')
    if re.search(r'sk-[A-Za-z0-9]{16,}',source):raise ValueError('credential-like content is not allowed in tool source')
    try:tree=ast.parse(source)
    except SyntaxError:raise ValueError('invalid Python source') from None
    if not any(isinstance(node,ast.FunctionDef) and node.name=='run' for node in tree.body):raise ValueError('define run(request)')

def execute(source,request):
    from bounded import run as bounded_run
    validate_source(source)
    unit='net-gateway-tool-'+uuid.uuid4().hex
    properties=['NoNewPrivileges=yes','ProtectSystem=strict','ProtectHome=yes','PrivateDevices=yes',
        'TemporaryFileSystem=/tmp:rw,size=32M','WorkingDirectory=/tmp',
        'InaccessiblePaths=/var/lib/dsh /etc/net-gateway /var/lib/net-gateway',
        'CapabilityBoundingSet=','MemoryMax=128M','TasksMax=16','CPUQuota=50%','RuntimeMaxSec=12s','LimitFSIZE=8M']
    args=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--service-type=exec',
        '--unit='+unit,'--uid=gateway-worker','--gid=gateway-operators',
        *['--property='+value for value in properties],'/usr/bin/python3','-I',str(Path(__file__).resolve()),'--worker']
    try:
        result=bounded_run(args,input=json.dumps({'source':source,'request':request}),
            timeout=17,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/var/empty'})
        if result.returncode:
            detail=re.sub(r'sk-[A-Za-z0-9-]+','[redacted]',result.stderr[-1800:])
            raise ValueError('tool failed in isolated worker: '+detail)
        if len(result.stdout)>32768:raise ValueError('tool output exceeds budget')
        output=json.loads(result.stdout)
        if not isinstance(output,dict):raise ValueError('tool must return a JSON object')
        return output
    except subprocess.TimeoutExpired:raise ValueError('tool execution timed out') from None
    finally:subprocess.run(['/usr/bin/systemctl','stop',unit],capture_output=True,timeout=5)

def write_json(path,data):
    temp=path.with_suffix('.next')
    with temp.open('w') as target:
        temp.chmod(0o600);json.dump(data,target,ensure_ascii=False);target.flush();os.fsync(target.fileno())
    temp.replace(path)

def action(operation,source=None,request=None):
    active=STATE/'tool-active.json'
    previous=STATE/'tool-previous.json'
    if operation=='tool_status':
        return {'active':True,**json.loads(active.read_text())} if active.exists() else {'active':False}
    if operation=='tool_run':
        if not active.exists():raise ValueError('no maintained tool module is installed')
        current=json.loads(active.read_text())
        try:return {'version':current['version'],'result':execute(current['source'],request or {'operation':'inspect'})}
        except Exception:
            if previous.exists():write_json(active,json.loads(previous.read_text()));previous.unlink()
            else:active.unlink(missing_ok=True)
            raise ValueError('tool failed; prior version restored or failed version disabled') from None
    validate_source(source)
    result=execute(source,{'operation':'self_test'})
    if result.get('ok') is not True or not isinstance(result.get('capabilities'),dict):raise ValueError('self_test must return ok=true and capabilities')
    inspect=execute(source,{'operation':'inspect'})
    if not isinstance(inspect.get('observations'),list):raise ValueError('inspect must return an observations list')
    record={'version':hashlib.sha256(source.encode()).hexdigest()[:16],'source':source,'capabilities':result['capabilities'],
        'tests':[{'case':'isolated_self_test','passed':True},{'case':'live_inspect','passed':True}], 'published_at':time.time()}
    if operation=='tool_test':return {key:value for key,value in record.items() if key!='source'}
    if active.exists():write_json(previous,json.loads(active.read_text()))
    write_json(active,record)
    return {'deployed':True,**{key:value for key,value in record.items() if key!='source'}}

if __name__=='__main__' and '--worker' in sys.argv:
    import pwd
    if os.geteuid() in [0,pwd.getpwnam('dsh').pw_uid]:raise RuntimeError('tool must use the separate worker identity')
    resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(2,2));resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
    signal.alarm(10)
    data=sys.stdin.read(65537)
    if len(data)>65536:raise ValueError('input budget exceeded')
    payload=json.loads(data);validate_source(payload['source'])
    scope={'__name__':'maintained_gateway_tool'}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(payload['source'],'<maintained-gateway-tool>','exec'),scope)
        output=scope['run'](payload['request'])
    print(json.dumps(output,ensure_ascii=False))
