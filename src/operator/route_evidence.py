"""Private, bounded provenance for root probes and AI-interpreted public policy.

The model supplies references and interpretations, never raw trusted probe data
or a self-certified ``verified`` flag. Source integrity does not prove that an
arbitrary natural-language interpretation is true.
"""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import ssl
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from traffic import hostname
from user_policy import AUTO_CONTROL_DOMAINS

MAX_BYTES=2*1024*1024
MAX_SOURCE_BYTES=65536
MAX_RAW_HTML_BYTES=1024*1024
MAX_AGE=7*86400


def public_url(url,blocked_hosts=()):
    if not isinstance(url,str) or len(url)>1024 or any(ord(c)<33 for c in url):raise ValueError('public source URL required')
    try:
        parsed=urlsplit(url);domain=hostname(parsed.hostname)
        safe=parsed.scheme=='https' and parsed.port in (None,443) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and domain
    except ValueError:safe=False;domain=None
    if not safe or any(domain==host or domain.endswith('.'+host) for host in (*AUTO_CONTROL_DOMAINS,*blocked_hosts)):
        raise ValueError('public non-control HTTPS source without credentials or parameters required')
    return url,domain


class _Text(HTMLParser):
    NON_BODY_TAGS={'head','script','style','template','svg','canvas'}
    def __init__(self):super().__init__();self.parts=[];self.skip=0
    def handle_starttag(self,tag,attrs):
        if tag in self.NON_BODY_TAGS:self.skip+=1
    def handle_endtag(self,tag):
        if tag in self.NON_BODY_TAGS:self.skip=max(0,self.skip-1)
    def handle_data(self,data):
        if not self.skip:self.parts.append(data)


def fetch_public(url):
    """Bounded HTTPS fetch with public DNS pinning; no redirect or ambient auth."""
    _,domain=public_url(url);parsed=urlsplit(url)
    answers=socket.getaddrinfo(domain,443,type=socket.SOCK_STREAM)
    addresses=[]
    for family,_,_,_,address in answers:
        if not ipaddress.ip_address(address[0]).is_global:raise ValueError('public source resolved to a private address')
        if family==socket.AF_INET:addresses.append(address[0])
    if not addresses:raise ValueError('public source IPv4 address unavailable')
    connection=http.client.HTTPSConnection(domain,443,timeout=6,context=ssl.create_default_context())
    connection._create_connection=lambda address,timeout,source_address=None:socket.create_connection((addresses[0],443),timeout,source_address)
    try:
        connection.request('GET',parsed.path or '/',headers={'User-Agent':'HomeNetwork-PolicyEvidence/1','Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse()
        if response.status!=200:raise ValueError('source retrieval did not return HTTP 200')
        kind=response.getheader('Content-Type','').lower()
        if not any(x in kind for x in ('text/html','text/plain','application/json','text/markdown')):raise ValueError('unsupported public source type')
        raw_limit=MAX_RAW_HTML_BYTES if 'html' in kind else MAX_SOURCE_BYTES
        raw=response.read(raw_limit+1)
        if len(raw)>raw_limit:raise ValueError('raw source exceeds evidence byte limit')
        text=raw.decode('utf-8','replace')
        if 'html' in kind:
            parser=_Text();parser.feed(text);parser.close();text=' '.join(parser.parts)
        text=' '.join(text.split())
        if len(text.encode('utf-8'))>MAX_SOURCE_BYTES:raise ValueError('normalized source text exceeds evidence byte limit')
        return text
    finally:connection.close()


def _timestamp(value):
    return type(value) in (int,float) and math.isfinite(value) and value>=0


class EvidenceStore:
    def __init__(self,path=None):self.path=Path(path or '/var/lib/net-gateway-agent/route-evidence.json')

    @contextmanager
    def _locked(self,write=False):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        lock=self.path.with_suffix(self.path.suffix+'.lock')
        fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
        with os.fdopen(fd,'r+') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            if self.path.exists():
                if self.path.stat().st_size>MAX_BYTES:raise ValueError('evidence store size limit exceeded')
                state=json.loads(self.path.read_text())
                if state.get('version')!=1 or not isinstance(state.get('records'),dict):raise ValueError('invalid evidence store')
            else:state={'version':1,'records':{}}
            yield state
            if write:
                records=state['records']
                for kind,limit in [('comparison',128),('source',64),('requirement',64)]:
                    ordered=sorted((k for k,v in records.items() if v.get('kind')==kind),key=lambda k:records[k]['created_at'])
                    for key in ordered[:-limit]:del records[key]
                data=json.dumps(state,ensure_ascii=False,sort_keys=True).encode()
                # Source bodies are the largest optional entries. Eviction makes
                # dependent knowledge unusable until the AI refreshes sources.
                while len(data)>MAX_BYTES and records:
                    del records[min(records,key=lambda k:records[k]['created_at'])]
                    data=json.dumps(state,ensure_ascii=False,sort_keys=True).encode()
                fd,name=tempfile.mkstemp(prefix='.route-evidence-',dir=self.path.parent)
                try:
                    with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
                    os.replace(name,self.path)
                    directory=os.open(self.path.parent,os.O_RDONLY)
                    try:os.fsync(directory)
                    finally:os.close(directory)
                finally:
                    if os.path.exists(name):os.unlink(name)

    def record(self,comparison,policy_version,now=None):
        now=time.time() if now is None else now
        if not isinstance(comparison,dict) or not hostname(comparison.get('target')) or not isinstance(policy_version,str) or not policy_version:
            raise ValueError('root comparison and policy version required')
        identity=comparison.get('comparison_id');observed=comparison.get('observed_at')
        if not isinstance(identity,str) or len(identity)!=32 or not _timestamp(observed) or not 0<=now-observed<=MAX_AGE:
            raise ValueError('fresh root comparison identity required')
        payload=copy.deepcopy(comparison);payload.pop('cached',None)
        encoded=json.dumps(payload,sort_keys=True).encode()
        if len(encoded)>65536:raise ValueError('comparison size limit exceeded')
        digest=hashlib.sha256(encoded+policy_version.encode()).hexdigest()
        with self._locked(True) as state:
            for record in state['records'].values():
                if record['kind']=='comparison' and record['comparison_id']==identity:
                    if record['digest']!=digest:raise ValueError('comparison identity reused with different evidence')
                    return copy.deepcopy(record)
            record={**payload,'id':'cmp_'+uuid.uuid4().hex,'kind':'comparison','policy_version':policy_version,'created_at':now,'expires_at':observed+MAX_AGE,'digest':digest}
            state['records'][record['id']]=record
        return copy.deepcopy(record)

    def collect_source(self,url,fetch=None,now=None,blocked_hosts=()):
        url,domain=public_url(url,blocked_hosts);now=time.time() if now is None else now
        text=(fetch or fetch_public)(url)
        if not isinstance(text,str) or not 12<=len(text.encode())<=MAX_SOURCE_BYTES:raise ValueError('bounded actual source text required')
        record={'id':'src_'+uuid.uuid4().hex,'kind':'source','url':url,'source_host':domain,'retrieved_at':now,'created_at':now,'expires_at':now+MAX_AGE,
            'content_hash':hashlib.sha256(text.encode()).hexdigest(),'text':text,'collector':'trusted_source_fetch'}
        with self._locked(True) as state:state['records'][record['id']]=record
        return {key:value for key,value in record.items() if key!='text'}|{'excerpt':text[:1600]}

    def record_requirement(self,domain,required_path,source_ids,quotes,rationale,region_context,now=None,actor='dsh',ttl=MAX_AGE):
        domain=hostname(domain);now=time.time() if now is None else now
        if not domain or required_path not in ('direct','proxy') or not isinstance(source_ids,list) or not 1<=len(source_ids)<=4 or len(set(source_ids))!=len(source_ids):
            raise ValueError('exact domain, required path and source references required')
        if not isinstance(rationale,str) or not 12<=len(rationale)<=2000 or not isinstance(region_context,str) or not 2<=len(region_context)<=300:
            raise ValueError('bounded interpretation and current service region context required')
        if not isinstance(quotes,list) or not 1<=len(quotes)<=8 or type(ttl) not in (int,float) or not 60<=ttl<=MAX_AGE:
            raise ValueError('bounded source quotes and expiry required')
        with self._locked(True) as state:
            sources=[state['records'].get(key) for key in source_ids]
            if any(not item or item.get('kind')!='source' or not 0<=now-item['retrieved_at']<=MAX_AGE for item in sources):raise ValueError('fresh collected source references required')
            by_id={item['id']:item for item in sources};seen=set();clean=[]
            for item in quotes:
                if not isinstance(item,dict):raise ValueError('source quotation required')
                key=item.get('source_id');quote=item.get('quote')
                if key not in by_id or not isinstance(quote,str) or not 12<=len(quote)<=2000 or quote not in by_id[key]['text']:
                    raise ValueError('quotation does not match collected source')
                clean.append({'source_id':key,'quote':quote});seen.add(key)
            if seen!=set(source_ids):raise ValueError('each source needs a matching quotation')
            record={'id':'req_'+uuid.uuid4().hex,'kind':'requirement','domain':domain,'scope':'exact_domain','required_path':required_path,
                'source_ids':source_ids,'quotes':clean,'rationale':rationale,'region_context':region_context,'interpretation_owner':str(actor)[:80],
                'semantic_truth_proven':False,'provenance_checked':True,'created_at':now,'expires_at':min(now+ttl,*[source['expires_at'] for source in sources])}
            state['records'][record['id']]=record
        return copy.deepcopy(record)

    def get_many(self,ids,now=None):
        if not isinstance(ids,list) or len(ids)>32:raise ValueError('bounded evidence references required')
        now=time.time() if now is None else now
        with self._locked() as state:
            result=[]
            for key in ids:
                item=state['records'].get(key)
                if not item:raise ValueError('unknown evidence reference')
                item=copy.deepcopy(item);item['expired']=not item['created_at']<=now<=item['expires_at']
                if item['kind']=='requirement':
                    sources=[state['records'].get(ref) for ref in item['source_ids']]
                    item['references_available']=all(source and source.get('kind')=='source' and source['created_at']<=now<=source['expires_at'] for source in sources)
                result.append(item)
            return result

    def status(self,now=None,domain=None):
        now=time.time() if now is None else now
        if domain is not None and not hostname(domain):raise ValueError('exact public domain required')
        with self._locked() as state:
            records=list(state['records'].values());recent=[]
            for kind in ('requirement','comparison','source'):
                matching=[item for item in records if item['kind']==kind and (domain is None or item.get('domain',item.get('target'))==domain)]
                for item in sorted(matching,key=lambda row:row['created_at'],reverse=True)[:8]:
                    recent.append({key:item[key] for key in ('id','kind','domain','target','required_path','source_ids','url','created_at','expires_at') if key in item}|{'expired':not item['created_at']<=now<=item['expires_at']})
            return {kind+'s':sum(item['kind']==kind for item in records) for kind in ('source','requirement','comparison')}|{'private':True,'max_bytes':MAX_BYTES,'recent':recent}
