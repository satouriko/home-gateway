"""Durable incident ownership and dispositions, independent of severity or chat lifetime."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

STATE=Path('/var/lib/net-gateway-agent')
STATUSES={'open','working','verifying','blocked','closed'}
OUTCOMES={'fixed','not_a_problem','no_route_remedy','external_dependency'}


def finite(value):return type(value) in (int,float) and math.isfinite(value) and value>=0


def text(value,limit,name):
    if not isinstance(value,str) or not value.strip() or len(value)>limit:raise ValueError('bounded '+name+' required')
    if re.search(r'sk-[A-Za-z0-9]{16,}|-----BEGIN .*PRIVATE KEY',value):raise ValueError('credential-like content is not incident evidence')
    return value


def decision_facts(facts):
    # Monotone counters do not change the meaning of an existing disposition.
    # Viability, recovery, coverage, endpoint and impact evidence always do.
    return {k:v for k,v in facts.items() if k not in {'failure_count','last_seen','connections_seen','observed_bytes_lower_bound'}}


def validate_records(data):
    for field in ['cases','overflow_cases']:
        records=data.get(field,{})
        if not isinstance(records,dict) or len(records)>256:raise ValueError()
        for ident,case in records.items():
            if not isinstance(case,dict) or not isinstance(ident,str) or not re.fullmatch('case-[a-f0-9]{20}',ident) or case.get('id')!=ident:raise ValueError()
            if case.get('status') not in STATUSES or case.get('priority') not in ['urgent','normal'] or case.get('source_priority',case['priority']) not in ['urgent','normal']:raise ValueError()
            if type(case.get('revision')) is not int or case['revision']<1:raise ValueError()
            for key in ['created_at','updated_at','last_observed_at','next_review_at']:
                if not finite(case.get(key)):raise ValueError()
            text(case.get('key'),300,'case key');text(case.get('signature'),300,'signature')
            if not isinstance(case.get('facts'),dict) or len(json.dumps(case['facts'],allow_nan=False).encode())>4096:raise ValueError()
            if not isinstance(case.get('history'),list) or len(case['history'])>8 or any(not isinstance(e,dict) for e in case['history']):raise ValueError()
            if not isinstance(case.get('evidence'),list) or len(case['evidence'])>8 or any(not isinstance(e,str) or len(e)>160 for e in case['evidence']):raise ValueError()
            if type(case.get('network_restored')) is not bool:raise ValueError()
            if 'decided_at' in case and not finite(case['decided_at']):raise ValueError()
            if 'reopen_on_activity' in case and type(case['reopen_on_activity']) is not bool:raise ValueError()


class IncidentStore:
    def __init__(self,path=None,max_cases=128,max_overflow=128):
        self.path=Path(path) if path is not None else STATE/'incidents.json'
        if any(type(v) is not int or not 1<=v<=256 for v in [max_cases,max_overflow]):raise ValueError('bounded incident capacity required')
        self.max_cases=max_cases
        self.max_overflow=max_overflow

    @staticmethod
    def _reclaim(records,now):
        disposed=sorted((c for c in records.values() if c['status']=='closed' and c['priority']=='normal'
                         and c.get('outcome') in ['fixed','not_a_problem'] and c['last_observed_at']<now-72*3600),key=lambda c:c['updated_at'])
        if disposed:records.pop(disposed[0]['id'])
        return bool(disposed)

    @contextmanager
    def _state(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(str(self.path)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            try:
                fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd) as source:raw=source.read(4*1024**2+1)
                data=json.loads(raw)
                if len(raw.encode())>4*1024**2 or not isinstance(data,dict) or data.get('format')!=1 or not isinstance(data.get('cases'),dict):raise ValueError()
                validate_records(data)
            except FileNotFoundError:data={'format':1,'cases':{},'overflow_cases':{},'capacity_exceeded':False}
            except (ValueError,TypeError,OSError):raise ValueError('incident storage requires recovery') from None
            before=json.dumps(data,sort_keys=True,allow_nan=False)
            yield data
            encoded=json.dumps(data,ensure_ascii=False,sort_keys=True,allow_nan=False).encode()
            if json.dumps(data,sort_keys=True,allow_nan=False)==before:return
            if len(encoded)>4*1024**2:raise ValueError('incident storage exceeds its byte budget')
            fd,name=tempfile.mkstemp(prefix=self.path.name+'.',dir=self.path.parent)
            try:
                with os.fdopen(fd,'wb') as target:target.write(encoded);target.flush();os.fsync(target.fileno())
                os.replace(name,self.path)
                directory=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:Path(name).unlink(missing_ok=True)

    @staticmethod
    def _history(case,event):case['history']=[*case.get('history',[]),event][-8:]

    @staticmethod
    def _view(data):return copy.deepcopy({'cases':list(data['cases'].values()),'overflow_cases':list(data.get('overflow_cases',{}).values()),'capacity_exceeded':data.get('capacity_exceeded',False)})

    def observe(self,signals,now):
        if not finite(now) or not isinstance(signals,list):raise ValueError('valid observation time and signals required')
        if len(signals)>256:raise ValueError('incident observation batch exceeds budget; retry without dropping signals')
        with self._state() as data:
            overflow=data.setdefault('overflow_cases',{})
            for signal in signals:
                key=text(signal.get('key'),300,'signal key');signature=text(signal.get('signature'),300,'evidence signature')
                at=signal.get('observed_at',now)
                if not finite(at) or at>now+5:raise ValueError('valid signal timestamp required')
                facts=signal.get('facts',{})
                if not isinstance(facts,dict) or len(json.dumps(facts,allow_nan=False).encode())>4096:raise ValueError('bounded observation facts required')
                ident='case-'+hashlib.sha256(key.encode()).hexdigest()[:20]
                priority=signal.get('priority','urgent')
                if priority not in ['urgent','normal']:raise ValueError('valid incident priority required')
                case=data['cases'].get(ident) or overflow.get(ident)
                if case is None:
                    destination=data['cases']
                    if len(data['cases'])>=self.max_cases:
                        if not self._reclaim(data['cases'],now):
                            if len(overflow)>=self.max_overflow and not self._reclaim(overflow,now):raise ValueError('incident capacity exhausted; retain upstream evidence and retry')
                            data['capacity_exceeded']=True;destination=overflow
                    case={'id':ident,'key':key,'domain':signal.get('domain'),'revision':1,'signature':signature,
                          'status':'open','priority':priority,'source_priority':priority,'created_at':now,'updated_at':now,'last_observed_at':at,
                          'reason':'awaiting investigation','facts':copy.deepcopy(facts),'evidence':[],
                          'outcome':None,'network_restored':False,'next_review_at':now,'history':[]}
                    destination[ident]=case
                    self._history(case,{'at':now,'kind':'opened','signature':signature})
                    continue
                if at<case.get('last_observed_at',0):continue
                changed=signature!=case['signature']
                escalated=priority=='urgent' and case.get('source_priority',case['priority'])!='urgent'
                material=decision_facts(facts)!=decision_facts(case['facts'])
                recurrence=bool((case.get('reopen_on_activity') or case.get('outcome')=='fixed') and at>case.get('decided_at',now) and facts.get('current_failure') is True)
                reopen=changed or escalated or (material and case['status'] in ['closed','blocked']) or (case['status']=='closed' and recurrence)
                if reopen:
                    case.update(status='open',revision=case['revision']+1,next_review_at=now,outcome=None,
                                network_restored=False,updated_at=now,reason='new evidence requires disposition')
                    if priority=='urgent':case['priority']='urgent'
                    self._history(case,{'at':now,'kind':'evidence_changed' if changed else 'recurrence','signature':signature})
                elif material:case.update(revision=case['revision']+1,updated_at=now)
                case.update(signature=signature,source_priority=priority,last_observed_at=at,facts=copy.deepcopy(facts))
            return self._view(data)

    def list(self,now=None):
        with self._state() as data:return self._view(data)

    def get(self,ident):
        with self._state() as data:
            case=data['cases'].get(ident) or data.get('overflow_cases',{}).get(ident)
            if case is None:raise ValueError('incident not found')
            return copy.deepcopy(case)

    def decide(self,ident,revision,decision,actor,now):
        if not finite(now) or not isinstance(decision,dict):raise ValueError('valid decision required')
        actor=text(actor,100,'actor');status=decision.get('status')
        if status not in STATUSES:raise ValueError('valid incident status required')
        reason=text(decision.get('reason'),1000,'decision reason')
        evidence=decision.get('evidence')
        if not isinstance(evidence,list) or not 1<=len(evidence)<=8:raise ValueError('decision evidence required')
        evidence=[text(e,160,'evidence reference') for e in evidence]
        due=decision.get('next_review_at')
        if not finite(due) or not now<due<=now+7*86400:raise ValueError('finite future review time required')
        with self._state() as data:
            case=data['cases'].get(ident) or data.get('overflow_cases',{}).get(ident)
            if case is None:raise ValueError('incident not found')
            if type(revision) is not int or case['revision']!=revision:raise ValueError('incident revision changed; read current evidence')
            priority=decision.get('priority',case['priority'])
            if priority not in ['urgent','normal']:raise ValueError('valid priority required')
            if priority=='urgent' and status in ['working','verifying','blocked'] and due>now+900:
                raise ValueError('urgent work requires follow-up within fifteen minutes')
            outcome=decision.get('outcome') if status=='closed' else None
            if status=='closed' and outcome not in OUTCOMES:raise ValueError('explicit disposition outcome required')
            restored=outcome=='fixed'
            if restored and not (case['facts'].get('current_failure') is False and case['facts'].get('verified_recovery') is True):
                raise ValueError('network restoration needs current verification evidence')
            reopen=decision.get('reopen_on_activity',restored)
            if type(reopen) is not bool:raise ValueError('boolean recurrence policy required')
            if restored and not reopen:raise ValueError('verified fixes must retain recurrence detection')
            case.update(status=status,priority=priority,reason=reason,evidence=evidence,outcome=outcome,
                        network_restored=restored,next_review_at=due,updated_at=now,decided_at=now,
                        revision=revision+1,actor=actor,reopen_on_activity=reopen)
            self._history(case,{'at':now,'kind':'disposition','actor':actor,'status':status,'priority':priority,
                                'reason':reason,'evidence':evidence,'outcome':outcome,'next_review_at':due})
            return copy.deepcopy(case)

    def attention(self,now):
        if not finite(now):raise ValueError('valid review time required')
        view=self.list(now)
        return [case for case in view['cases']+view['overflow_cases'] if case['status']=='open' or case.get('next_review_at',0)<=now]
