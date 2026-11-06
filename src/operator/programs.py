"""Bounded pure diagnostic programs written by DSH, never privileged code."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time

STATE=Path('/var/lib/net-gateway-agent')
INPUT_LIMIT=512*1024

class InputError(ValueError):
    """Host observation failures must not invalidate a published program."""

def request_data(source,snapshot):
    try:data=json.dumps({'source':source,'snapshot':snapshot},ensure_ascii=False,allow_nan=False)
    except (ValueError,TypeError,RecursionError):raise InputError('diagnostic input must be finite JSON') from None
    if len(data.encode())>INPUT_LIMIT:raise InputError('diagnostic input exceeds byte budget')
    return data

FUNCTIONS={'len','min','max','sum','sorted','round','str','int','float','bool','list','dict','set','tuple','any','all','range','enumerate','zip','abs'}
ALLOWED=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,ast.If,ast.For,ast.Assign,ast.AugAssign,ast.Expr,
 ast.Call,ast.Name,ast.Load,ast.Store,ast.Constant,ast.Dict,ast.List,ast.Tuple,ast.Set,ast.Subscript,ast.Slice,ast.Attribute,
 ast.Compare,ast.Eq,ast.NotEq,ast.Lt,ast.LtE,ast.Gt,ast.GtE,ast.Is,ast.IsNot,ast.In,ast.NotIn,ast.BoolOp,ast.And,ast.Or,
 ast.UnaryOp,ast.Not,ast.USub,ast.UAdd,ast.BinOp,ast.Add,ast.Sub,ast.Mult,ast.Div,ast.FloorDiv,ast.Mod,ast.IfExp,
 ast.ListComp,ast.DictComp,ast.SetComp,ast.comprehension,ast.keyword)

def validate_source(source):
    if not isinstance(source,str) or not 1<=len(source)<=12000:raise ValueError('source must be at most 12000 characters')
    if re.search(r'sk-[A-Za-z0-9]{16,}',source):raise ValueError('credential-like source is rejected')
    try:tree=ast.parse(source)
    except SyntaxError:raise ValueError('invalid Python source') from None
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):raise ValueError('only def inspect(snapshot) is allowed')
    function=tree.body[0]
    if function.name!='inspect' or len(function.args.args)!=1 or function.args.defaults or function.decorator_list or function.returns or function.args.vararg or function.args.kwarg:
        raise ValueError('expected one plain inspect(snapshot) function')
    for node in ast.walk(tree):
        if not isinstance(node,ALLOWED):raise ValueError('unsupported construct: '+type(node).__name__)
        if isinstance(node,ast.Name) and node.id.startswith('_'):raise ValueError('private names are forbidden')
        if isinstance(node,ast.arg) and (node.arg.startswith('_') or node.annotation):raise ValueError('plain public arguments only')
        if isinstance(node,ast.Attribute) and node.attr not in {'get','items','keys','values'}:raise ValueError('only dictionary access methods are allowed')
        if isinstance(node,ast.Call):
            if isinstance(node.func,ast.Name) and node.func.id not in FUNCTIONS:raise ValueError('unsupported function')
            if not isinstance(node.func,(ast.Name,ast.Attribute)):raise ValueError('indirect calls are forbidden')
    return tree

def validate_output(output):
    if not isinstance(output,dict) or not {'summary','action','probe_domains'}<=set(output) or set(output)-{'summary','action','probe_domains','review_request'}:raise ValueError('return summary/action/probe_domains and optional review_request')
    review=output.get('review_request')
    if review is not None and (not isinstance(review,dict) or set(review)!={'fingerprint','reason'} or any(not isinstance(review.get(k),str) or not 1<=len(review[k])<=limit for k,limit in [('fingerprint',160),('reason',1000)])):
        raise ValueError('review_request requires a stable bounded fingerprint and evidence reason')
    if not isinstance(output['summary'],str) or len(output['summary'])>2000:raise ValueError('bounded summary required')
    if output['action'] not in ['none','recheck_nodes','refresh_subscription']:raise ValueError('unsupported advice')
    domains=output['probe_domains']
    if not isinstance(domains,list) or len(domains)>3:raise ValueError('at most three probe domains')
    for domain in domains:
        if not isinstance(domain,str) or len(domain)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):raise ValueError('plain public DNS hostname required')
    return output

def bounded_range(*args):
    result=range(*args)
    if len(result)>4096:raise ValueError('range budget exceeded')
    return result

def worker(source,snapshot):
    tree=validate_source(source)
    import builtins
    safe={name:getattr(builtins,name) for name in FUNCTIONS};safe['range']=bounded_range
    scope={'__builtins__':safe}
    exec(compile(tree,'<gateway-diagnostic>','exec'),scope)
    return validate_output(scope['inspect'](snapshot))

def evaluate(source,snapshot):
    from bounded import run as bounded_run
    validate_source(source)
    data=request_data(source,snapshot)
    args=[sys.executable,'-I',str(Path(__file__).resolve()),'--worker']
    if os.geteuid()==0:args=['/usr/sbin/runuser','-u','dsh','--',*args]
    result=bounded_run(args,input=data,timeout=4,
        env={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LANG':'C.UTF-8'})
    if result.returncode:raise ValueError('diagnostic failed in its resource-limited worker: '+result.stderr[-1200:])
    return validate_output(json.loads(result.stdout))

def fixed_tests(source):
    healthy={'checks':{'proxy_https':{'ok':True,'result':{'http_status':204,'elapsed_ms':100}},'mainland_https':{'ok':True,'result':{'http_status':200,'elapsed_ms':50}}},'history':[]}
    broken=json.loads(json.dumps(healthy));broken['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
    results=[]
    for name,snapshot,expected in [('healthy',healthy,'none'),('proxy_failure',broken,'recheck_nodes')]:
        result=evaluate(source,snapshot)
        if result['action']!=expected:raise ValueError('protected test failed: '+name)
        results.append({'case':name,'passed':True})
    client=json.loads(json.dumps(healthy));client['business_observations']={'issues':[{'kind':'recurring_client_failure','domain':'real.example.com','fingerprint':'fixture-client-failure','resolved':False}]}
    observed=evaluate(source,client)
    if not observed.get('review_request') or 'real.example.com' not in observed['probe_domains']:
        raise ValueError('protected client failure test requires unresolved review and real target')
    results.append({'case':'recurring_client_failure','passed':True})
    observed=json.loads(json.dumps(client));observed['history']=[{'at':999,'faults':[]}]
    observed['business_observations']['checked_at']=1000
    value=evaluate(source,observed)
    if not value.get('review_request') or 'real.example.com' not in value['probe_domains']:raise ValueError('new client evidence cannot be suppressed by healthy history')
    results.append({'case':'new_client_with_healthy_history','passed':True})
    from diagnostic_input import validate
    held=json.loads(json.dumps(client));row=held['business_observations']['issues'][0]
    row['incident']={'requires_attention':False,'status':'closed','priority':'normal','next_review_at':2000}
    held['business_observations']['checks']={row['domain']:{'result':{'paths':{'direct':{'transport_ok':None},'proxy':{'transport_ok':None}}}}}
    validate(evaluate(source,held),held);results.append({'case':'disposed_unknown_paths_not_due','passed':True})
    due=json.loads(json.dumps(held));due['business_observations']['issues'][0]['incident']['requires_attention']=True
    mixed=json.loads(json.dumps(held));fresh=json.loads(json.dumps(client['business_observations']['issues'][0]))
    fresh.update(domain='fresh.example.com',fingerprint='new-material-evidence',incident={'requires_attention':True,'new_evidence':True})
    mixed['business_observations']['issues'].append(fresh)
    for name,scenario,target in [('disposed_review_due',due,row['domain']),('new_evidence_beside_disposed',mixed,fresh['domain'])]:
        value=validate(evaluate(source,scenario),scenario)
        if not value.get('review_request') or target not in value['probe_domains']:raise ValueError('protected new/due client evidence test failed: '+name)
        results.append({'case':name,'passed':True})
    for name,new_evidence in [('held_prefix_new_target',True),('held_prefix_due_target',False)]:
        queued=json.loads(json.dumps(healthy))
        held_rows=[{'domain':'held'+str(i)+'.example.com','fingerprint':'held-'+str(i),'resolved':False,
                    'incident':{'requires_attention':False}} for i in range(3)]
        target={'domain':'later.example.com','fingerprint':'later','resolved':False,
                'incident':{'requires_attention':True,'new_evidence':new_evidence}}
        queued['business_observations']={'issues':held_rows+[target],'checks':{}}
        value=validate(evaluate(source,queued),queued)
        if target['domain'] not in value['probe_domains']:raise ValueError('protected target selection failed: '+name+'; filter eligible targets before the three-target limit')
        results.append({'case':name,'passed':True})
    return results

def write_json(path,data):
    temp=path.with_suffix('.next')
    with temp.open('w') as file:
        temp.chmod(0o600);json.dump(data,file,ensure_ascii=False);file.flush();os.fsync(file.fileno())
    temp.replace(path)

def program_action(operation,source=None,snapshot=None):
    active=STATE/'diagnostic-active.json'
    if operation=='program_status':
        if not active.exists():return {'active':False}
        current=json.loads(active.read_text())
        return {'active':True,'version':current['version'],'source':current['source'],'tests':current['tests'],'scope':'pure diagnostics only'}
    tests=fixed_tests(source)
    validation=None
    if snapshot is not None:
        from diagnostic_input import receipt
        validation=receipt(snapshot,evaluate(source,snapshot))
        tests.append({'case':'live_snapshot','passed':True})
    version=hashlib.sha256(source.encode()).hexdigest()[:16]
    if operation=='program_test':return {'tests':tests,'version':version,'deployed':False,'live_validation':validation}
    if active.exists():write_json(STATE/'diagnostic-previous.json',json.loads(active.read_text()))
    write_json(active,{'source':source,'version':version,'tests':tests,'published_at':time.time()})
    return {'tests':tests,'version':version,'deployed':True,'scope':'pure diagnostics only','live_validation':validation}

def inspect_active(snapshot):
    active=STATE/'diagnostic-active.json'
    if not active.exists():return {'active':False}
    current=json.loads(active.read_text())
    try:return {'active':True,'version':current['version'],'result':evaluate(current['source'],snapshot)}
    except InputError:
        return {'active':True,'version':current['version'],'input_unavailable':True,'maintenance_required':True,
                'input_error':'diagnostic_snapshot_unavailable'}
    except Exception:
        previous=STATE/'diagnostic-previous.json'
        if previous.exists():write_json(active,json.loads(previous.read_text()));previous.unlink()
        else:active.unlink(missing_ok=True)
        return {'active':False,'rolled_back':True,'failed_version':current['version']}

if __name__=='__main__' and '--worker' in sys.argv:
    resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(1,1));resource.setrlimit(resource.RLIMIT_FSIZE,(0,0));signal.alarm(3)
    data=sys.stdin.buffer.read(INPUT_LIMIT+1)
    if len(data)>INPUT_LIMIT:raise ValueError('input budget exceeded')
    request=json.loads(data)
    print(json.dumps(worker(request['source'],request['snapshot']),ensure_ascii=False))
