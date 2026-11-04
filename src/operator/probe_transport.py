"""Protected two-path HTTPS sampling in a disposable non-TUN Mihomo instance.

Household forwarding and groups are never reconfigured. The probe identity has
its own UID rule to the existing independent table. Credentials remain confined
to a short-lived private config, not returned to the model or exported.
"""
from contextlib import contextmanager
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

LOCK=threading.Lock()
CACHE={}
STATE=Path('/var/lib/net-gateway-agent')
WORK=Path('/run/net-gateway-agent/probes')
NODE_CACHE=Path('/var/lib/net-gateway')


def hostname(value):
    if not isinstance(value,str):raise ValueError('public DNS hostname required')
    name=value.lower().rstrip('.')
    if len(name)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',name):
        raise ValueError('public DNS hostname required')
    if name.rsplit('.',1)[-1] in ['lan','local','localhost','internal','home','test','invalid']:
        raise ValueError('local names are not probe targets')
    return name


def public_addresses(values):
    if not isinstance(values,list) or not 1<=len(values)<=16:raise ValueError('public address answer required')
    result=[]
    for value in values:
        address=ipaddress.ip_address(value)
        if not address.is_global:raise ValueError('probe DNS contains non-public address')
        if address.version==4 and str(address) not in result:result.append(str(address))
    if not result:raise ValueError('public IPv4 answer required')
    return result


def helper_config(target,addresses,node,direct_port,proxy_port,token):
    target=hostname(target);addresses=public_addresses(addresses)
    if not isinstance(node,dict) or not node.get('name') or node.get('type') in ['direct','reject'] or node.get('dialer-proxy'):
        raise ValueError('independent concrete proxy required')
    config={'mixed-port':0,'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule','log-level':'silent',
        'ipv6':False,'tun':{'enable':False},'dns':{'enable':False},'profile':{'store-selected':False},
        'authentication':['probe:'+token],'hosts':{target:addresses},'proxies':[node],
        'listeners':[{'name':'home-probe-direct','type':'http','listen':'127.0.0.1','port':direct_port,'proxy':'DIRECT'},
                     {'name':'home-probe-proxy','type':'http','listen':'127.0.0.1','port':proxy_port,'proxy':node['name']}],
        'rules':['MATCH,REJECT']}
    if 'provider_payload' in node:
        config['proxies']=[]
        config['proxy-providers']={'probe':{'type':'file','path':'provider.txt','filter':'^'+re.escape(node['name'])+'$','health-check':{'enable':False}}}
        config['proxy-groups']=[{'name':'ProbeProxy','type':'select','use':['probe'],'empty-fallback':'REJECT'}]
        config['listeners'][1]['proxy']='ProbeProxy'
    return config


def response_evidence(target,status,body,content_type,elapsed):
    markers={'www.baidu.com':'百度','www.google.com':'Google','github.com':'GitHub','www.youtube.com':'YouTube'}
    content_ok=None
    if status>=400:content_ok=False
    elif 200<=status<300 and target in markers:
        content_ok='text/html' in content_type and markers[target].lower() in body.decode('utf-8','replace').lower()
    business_error=None
    if status>=400:
        try:
            payload=json.loads(body[:32768]);error=payload.get('error',payload) if isinstance(payload,dict) else {}
            codes=[str(error.get(key,'')).lower() for key in ('code','type')] if isinstance(error,dict) else []
        except (ValueError,TypeError):codes=[]
        if any(code in ('unsupported_country_region_territory','unsupported_country','country_not_supported','region_not_supported') for code in codes):business_error='region_rejected'
        elif status==401:business_error='auth_required'
        elif status==429:business_error='rate_limited'
        elif status>=500:business_error='server_error'
    return {'transport_ok':True,'http_status':status,'elapsed_ms':elapsed,'content_ok':content_ok,'business_error_kind':business_error,
            'acceptance_scope':'HTTPS root response only; redirects are not followed'}


def request_https(target,port,token,path):
    start=time.monotonic();connection=http.client.HTTPSConnection('127.0.0.1',port,timeout=4,context=ssl.create_default_context())
    authorization=base64.b64encode(('probe:'+token).encode()).decode()
    connection.set_tunnel(target,443,headers={'Proxy-Authorization':'Basic '+authorization})
    try:
        connection.request('GET','/',headers={'Host':target,'User-Agent':'HomeNetwork-Probe/1','Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse();body=response.read(32768)
        result=response_evidence(target,response.status,body,response.getheader('Content-Type',''),round((time.monotonic()-start)*1000))
    except Exception as error:
        result={'transport_ok':False,'http_status':None,'elapsed_ms':round((time.monotonic()-start)*1000),'error_category':type(error).__name__}
    finally:connection.close()
    return {**result,'path':path,'path_verified':True,'origin':'synthetic_probe'}


def request_endpoint(target,port,token,path,endpoint,proxy_host='127.0.0.1',inspect=None):
    """One bounded CONNECT/TLS/HTTP exchange at the observed destination port."""
    from business_probe import endpoint_spec
    endpoint=endpoint_spec(endpoint)
    if endpoint is None or endpoint['network']!='tcp':return {'state':'unsupported_protocol','path_verified':False}
    start=time.monotonic();deadline=start+4;protocol=endpoint['application_protocol']
    connection=http.client.HTTPConnection(proxy_host,port,timeout=4);phase='probe_listener'
    result={'connect_ok':None,'tls_ok':None,'transport_ok':None,'proxy_tunnel_accepted':False,'target_dial_verified':False,
            'path':path,'path_verified':True,'origin':'synthetic_probe','application_verified':False}
    def remaining():
        value=deadline-time.monotonic()
        if value<=0:raise TimeoutError('endpoint deadline')
        return value
    headers={}
    if token:headers['Proxy-Authorization']='Basic '+base64.b64encode(('probe:'+token).encode()).decode()
    try:
        connection.set_tunnel(target,endpoint['port'],headers=headers)
        connection.sock=socket.create_connection((proxy_host,port),timeout=remaining())
        if inspect is not None:result['gateway_route']=inspect(connection.sock.getsockname(),target,endpoint)
        phase='target_connect';connection.sock.settimeout(remaining());connection._tunnel()
        # Mihomo acknowledges CONNECT before the outbound dial completes.
        # Acceptance of the local tunnel therefore proves no target reachability.
        result['proxy_tunnel_accepted']=True
        if protocol in ('tls','https'):
            phase='tls_handshake';connection.sock.settimeout(remaining())
            connection.sock=ssl.create_default_context().wrap_socket(connection.sock,server_hostname=target)
            result.update(tls_ok=True,connect_ok=True,transport_ok=True,target_dial_verified=True)
        if protocol in ('http','https'):
            phase='http_response';connection.sock.settimeout(remaining())
            connection.request('GET','/',headers={'Host':target,'User-Agent':'HomeNetwork-Probe/1','Connection':'close','Accept-Encoding':'identity'})
            response=connection.getresponse();connection.sock.settimeout(remaining()) if connection.sock else None
            result.update(connect_ok=True,target_dial_verified=True)
            body=response.read(32768)
            result.update(response_evidence(target,response.status,body,response.getheader('Content-Type',''),0))
        if protocol in ('tcp','unknown'):result['state']='target_dial_unverified'
    except Exception as error:
        result.update(transport_ok=False,error_category=type(error).__name__,failure_stage=phase)
        if phase=='probe_listener':result['path_verified']=False
    finally:connection.close()
    result['elapsed_ms']=round((time.monotonic()-start)*1000)
    return result


def select_node(api,config):
    proxies=api('/proxies').get('proxies',{});name='PROXY';seen=set()
    for _ in range(16):
        if name in seen:raise ValueError('cyclic proxy selection')
        seen.add(name);item=proxies.get(name,{})
        if item.get('now'):name=item['now'];continue
        break
    if name in ['DIRECT','REJECT','COMPATIBLE','PASS','GLOBAL']:raise ValueError('no concrete proxy selected')
    metadata=api('/providers/proxies').get('providers',{})
    for provider_name,provider in config.get('proxy-providers',{}).items():
        candidate=(NODE_CACHE/provider.get('path','')).resolve()
        if not candidate.is_relative_to(NODE_CACHE.resolve()) or not candidate.is_file() or candidate.stat().st_size>4*1024**2:continue
        if any(p.get('name')==name for p in metadata.get(provider_name,{}).get('proxies',[])):
            return {'name':name,'provider_payload':candidate.read_bytes()}
    raise ValueError('selected proxy configuration unavailable')


def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


@contextmanager
def helper(target,addresses,node,endpoint=None):
    identity=pwd.getpwnam('gateway-probe');WORK.mkdir(parents=True,exist_ok=True)
    directory=Path(tempfile.mkdtemp(prefix='probe-',dir=WORK));unit='net-gateway-probe-'+uuid.uuid4().hex
    direct_port=free_port();proxy_port=free_port()
    while proxy_port==direct_port:proxy_port=free_port()
    token=secrets.token_urlsafe(24)
    try:
        os.chown(directory,identity.pw_uid,identity.pw_gid);directory.chmod(0o700)
        config=directory/'config.json';config.write_text(json.dumps(helper_config(target,addresses,node,direct_port,proxy_port,token)))
        os.chown(config,identity.pw_uid,identity.pw_gid);config.chmod(0o600)
        if 'provider_payload' in node:
            payload=directory/'provider.txt';payload.write_bytes(node['provider_payload']);os.chown(payload,identity.pw_uid,identity.pw_gid);payload.chmod(0o600)
        properties=['NoNewPrivileges=yes','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','CapabilityBoundingSet=',
                    'ReadWritePaths='+str(directory),'MemoryMax=128M','CPUQuota=50%','TasksMax=32','RuntimeMaxSec=40s',
                    'InaccessiblePaths=/var/lib/dsh /var/lib/dsh-login /etc/net-gateway /var/lib/net-gateway']
        subprocess.run(['/usr/bin/systemd-run','--quiet','--collect','--service-type=exec','--unit='+unit,
            '--uid=gateway-probe','--gid=gateway-operators',*['--property='+x for x in properties],
            '/usr/local/bin/mihomo','-d',str(directory),'-f',str(config)],check=True,capture_output=True,timeout=6)
        deadline=time.monotonic()+4
        while True:
            try:
                with socket.create_connection(('127.0.0.1',proxy_port),timeout=.2):break
            except OSError:
                if time.monotonic()>=deadline:raise ValueError('protected probe listener did not start')
                time.sleep(.05)
        yield lambda domain,path:request_endpoint(domain,direct_port if path=='direct' else proxy_port,token,path,endpoint) if endpoint else request_https(domain,direct_port if path=='direct' else proxy_port,token,path)
    finally:
        subprocess.run(['/usr/bin/systemctl','stop',unit],capture_output=True,timeout=5)
        shutil.rmtree(directory,ignore_errors=True)


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()[:24]


def observe_identity(target,api,config_path):
    """Fresh policy/node/DNS identity without running either synthetic path."""
    target=hostname(target);answer=api('/dns/query?name='+target+'&type=A',timeout=4)
    addresses=public_addresses([row.get('data') for row in answer.get('Answer',[]) if row.get('type')==1])
    config=json.loads(Path(config_path).read_text());node=select_node(api,config)
    return {'node_id':hashlib.sha256(node['name'].encode()+node.get('provider_payload',b'')).hexdigest()[:24],
        'dns_fingerprint':_digest(sorted(addresses)),
        'config_identity':_digest({key:config.get(key) for key in ('mode','rules','dns','proxy-groups','proxy-providers')})}


def connection_proof(rows,source,target,endpoint,expected_path=None,exact_rule=False):
    """Attribute only this probe's held connection, never a household flow."""
    for row in rows:
        meta=row.get('metadata',{})
        if str(meta.get('sourceIP'))!=str(source[0]) or str(meta.get('sourcePort'))!=str(source[1]):continue
        if meta.get('host','').lower().rstrip('.')!=target or str(meta.get('destinationPort'))!=str(endpoint['port']):continue
        chains=row.get('chains',[])
        path='direct' if 'DIRECT' in chains else 'proxy' if chains and not any(x in chains for x in ['REJECT','PASS','COMPATIBLE']) else 'unknown'
        exact=str(row.get('rule','')).lower()=='domain' and row.get('rulePayload','').lower()==target
        return {'verified':path in ('direct','proxy') and (expected_path is None or path==expected_path) and (not exact_rule or exact),
                'path':path,'rule':str(row.get('rule',''))[:80],'rule_payload':str(row.get('rulePayload',''))[:253],
                'exact_rule':exact,'attribution':'own_probe_socket'}
    return {'verified':False,'path':'unknown','attribution':'own_probe_socket','reason':'connection_not_observed'}


def verify_route(target,endpoint,expected_path,api,config_path,exact_rule=True):
    from business_probe import endpoint_spec
    target=hostname(target);endpoint=endpoint_spec(endpoint)
    if endpoint is None or endpoint['network']!='tcp':return {'verified':False,'reason':'unsupported_endpoint','application_verified':False}
    config=json.loads(Path(config_path).read_text());port=config.get('mixed-port') or config.get('port')
    if type(port) is not int or not 1<=port<=65535:return {'verified':False,'reason':'gateway_http_listener_unavailable','application_verified':False}
    listener_host=config.get('bind-address','127.0.0.1')
    if listener_host in ('*','0.0.0.0','::',''):listener_host='127.0.0.1'
    # Gateway authentication is read privately; only one credential is used here.
    credentials=config.get('authentication',[]);token=None
    if credentials:return {'verified':False,'reason':'authenticated_gateway_listener_not_supported','application_verified':False}
    proof={};threads=[];stop=threading.Event()
    def inspect(source,domain,spec):
        def observe():
            deadline=time.monotonic()+2
            while not stop.is_set() and time.monotonic()<deadline:
                try:found=connection_proof(api('/connections',timeout=1).get('connections',[]),source,domain,spec,expected_path,exact_rule)
                except Exception:found={'verified':False,'reason':'controller_unavailable'}
                if found.get('attribution')=='own_probe_socket' and found.get('path') in ('direct','proxy'):
                    proof.update(found);return
                stop.wait(.05)
        thread=threading.Thread(target=observe,daemon=True);threads.append(thread);thread.start()
        return proof
    try:
        result=request_endpoint(target,port,token,expected_path or 'unknown',endpoint,proxy_host=listener_host,inspect=inspect)
        for thread in threads:thread.join(2.2)
    finally:stop.set()
    stage='http_response' if endpoint['application_protocol'] in ('http','https') else 'tls_handshake' if endpoint['application_protocol']=='tls' else 'tcp_connect'
    stage_ok=(result.get('connect_ok') is True if result.get('target_dial_verified') is True else None) if stage=='tcp_connect' else result.get('tls_ok') is True if stage=='tls_handshake' else result.get('transport_ok') is True and type(result.get('http_status')) is int
    status=result.get('http_status')
    acceptable=stage_ok is True and (stage!='http_response' or type(status) is int and 200<=status<400) and result.get('business_error_kind')!='region_rejected' and result.get('content_ok') is not False
    return {**proof,'verified':proof.get('verified') is True,'stage_ok':stage_ok,'acceptance_stage':stage,
            'endpoint_acceptable':acceptable,'http_status':status,'content_ok':result.get('content_ok'),'application_verified':False,'observed_at':time.time()}


def compare(target,api,config_path,now=None,endpoint=None,refresh=False):
    from business_probe import compare as classify,compare_endpoint,endpoint_spec
    target=hostname(target);now=time.time() if now is None else now
    with LOCK:
        spec=endpoint_spec(endpoint) if endpoint is not None else None
        if endpoint is not None and (spec is None or spec['network']!='tcp'):
            return compare_endpoint(target,endpoint,lambda *a,**k:None,now)
        answer=api('/dns/query?name='+target+'&type=A',timeout=4)
        addresses=public_addresses([row.get('data') for row in answer.get('Answer',[]) if row.get('type')==1])
        config=json.loads(Path(config_path).read_text());node=select_node(api,config)
        policy_id=_digest({key:config.get(key) for key in ('mode','rules','dns','proxy-groups','proxy-providers')})
        dns_id=_digest(sorted(addresses));node_id=hashlib.sha256(node['name'].encode()+node.get('provider_payload',b'')).hexdigest()[:24]
        key=(target,_digest(spec),policy_id,node_id,dns_id);previous=CACHE.get(key)
        if previous and 0<=now-previous['observed_at']<(15 if refresh else 180):return {**previous,'cached':True}
        with helper(target,addresses,node,endpoint=spec) as run_probe:
            result=compare_endpoint(target,spec,run_probe,now) if spec else classify(target,run_probe,now)
        gateway=verify_route(target,spec,None,api,config_path,exact_rule=False) if spec else None
        result.update(observed_at=now,origin='protected_synthetic_probe',node=node['name'],node_id=node_id,
          config_identity=policy_id,dns_fingerprint=dns_id,comparison_id=uuid.uuid4().hex,gateway_route=gateway,
          scope='protected gateway comparison; not a client application session',cached=False)
        CACHE[key]=result
        if len(CACHE)>32:CACHE.pop(next(iter(CACHE)))
        return result
