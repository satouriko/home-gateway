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
    return {'transport_ok':True,'http_status':status,'elapsed_ms':elapsed,'content_ok':content_ok,
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
def helper(target,addresses,node):
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
        yield lambda domain,path:request_https(domain,direct_port if path=='direct' else proxy_port,token,path)
    finally:
        subprocess.run(['/usr/bin/systemctl','stop',unit],capture_output=True,timeout=5)
        shutil.rmtree(directory,ignore_errors=True)


def compare(target,api,config_path,now=None):
    from business_probe import compare as classify
    target=hostname(target);now=time.time() if now is None else now
    with LOCK:
        previous=CACHE.get(target)
        if previous and now-previous['observed_at']<180:return {**previous,'cached':True}
        answer=api('/dns/query?name='+target+'&type=A',timeout=4)
        addresses=public_addresses([row.get('data') for row in answer.get('Answer',[]) if row.get('type')==1])
        config=json.loads(Path(config_path).read_text());node=select_node(api,config)
        with helper(target,addresses,node) as run_probe:
            result=classify(target,run_probe,now)
        result.update(observed_at=now,origin='synthetic_probe',node=node['name'],scope='protected gateway comparison; not a client application session',cached=False)
        CACHE[target]=result
        if len(CACHE)>32:CACHE.pop(next(iter(CACHE)))
        return result
