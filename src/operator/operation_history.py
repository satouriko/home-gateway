"""Bounded repair facts and native receipts, independent of model narration."""
from contextlib import contextmanager
import copy
import fcntl
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
import uuid

OPERATIONS={'recheck_nodes','refresh_subscription','restart_gateway','restore_gateway','policy_apply','route_apply'}
STATUSES={'running','verified','completed','applied_unverified','pending_rollback','rejected','failed','interrupted','rolled_back'}
SESSION=re.compile(r'session-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
ERRORS={'ValueError','TimeoutError','TimeoutExpired','RuntimeError','OSError','PermissionError','ConnectionError','CalledProcessError'}

def valid_session(value):return isinstance(value,str) and SESSION.fullmatch(value) is not None
def ident(value):return isinstance(value,str) and re.fullmatch('[a-f0-9]{32}',value) is not None
def notice_id(sid,revision):return 'gateway-operations-'+sid[8:].replace('-','')+'-'+str(revision)

def owner(pid=None):
    pid=os.getpid() if pid is None else pid
    try:
        start=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
        return {'pid':pid,'start':start,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    except (OSError,IndexError):return None

def owner_alive(value):
    return isinstance(value,dict) and type(value.get('pid')) is int and value['pid']>0 and owner(value['pid'])==value


class OperationHistory:
    def __init__(self,path):self.path=Path(path)

    @contextmanager
    def _state(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(str(self.path)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            try:
                with self.path.open() as stream:raw=stream.read(256*1024+1)
                state=json.loads(raw)
                if len(raw.encode())>256*1024 or state.get('format')!=1 or type(state.get('sequence')) is not int or not 0<=state['sequence']<2**53 or not isinstance(state.get('delivered'),dict) or len(state['delivered'])>128 or not isinstance(state.get('records'),list) or len(state['records'])>128:raise ValueError()
                for r in state['records']:
                    if r.get('operation') not in OPERATIONS or r.get('status') not in STATUSES or not ident(r.get('id')) or type(r.get('sequence')) is not int or not 0<r['sequence']<=state['sequence'] or (r.get('session_id') is not None and not valid_session(r['session_id'])):raise ValueError()
                    if type(r.get('started_at')) not in (int,float) or not math.isfinite(r['started_at']) or r['started_at']<0:raise ValueError()
                if type(state.get('discarded_records')) is not int or state['discarded_records']<0:raise ValueError()
                if any(not valid_session(sid) or type(n) is not int or not 0<=n<=state['sequence'] for sid,n in state['delivered'].items()):raise ValueError()
            except FileNotFoundError:state={'format':1,'sequence':0,'records':[],'delivered':{},'discarded_records':0}
            except (ValueError,TypeError,AttributeError):raise ValueError('operation history requires recovery') from None
            before=json.dumps(state,sort_keys=True)
            for row in state['records']:
                if row['status']=='running' and (time.time()-row['started_at']>600 or (row.get('owner') is not None and not owner_alive(row['owner']))):
                    row.update(status='interrupted',finished_at=time.time())
            yield state
            if json.dumps(state,sort_keys=True)==before:return
            while len(state['records'])>128:
                index=next((i for i,r in enumerate(state['records']) if r['status']!='running'),None)
                if index is None:raise ValueError('operation history capacity exhausted')
                state['records'].pop(index);state['discarded_records']+=1
            live={r.get('session_id') for r in state['records']}
            state['delivered']={sid:n for sid,n in state['delivered'].items() if sid in live}
            data=json.dumps(state,sort_keys=True,allow_nan=False).encode()
            if len(data)>256*1024:raise ValueError('operation history byte budget exceeded')
            fd,name=tempfile.mkstemp(prefix='.operation-history-',dir=self.path.parent)
            try:
                with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
                os.replace(name,self.path)
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
            finally:Path(name).unlink(missing_ok=True)

    @staticmethod
    def _add(state,operation,sid,now,**fields):
        state['sequence']+=1
        row={'id':uuid.uuid4().hex,'sequence':state['sequence'],'operation':operation,'session_id':sid,
             'started_at':now,'status':'running','owner':owner(),**fields}
        state['records'].append(row);return row

    def begin(self,operation,session_id=None,now=None):
        if operation not in OPERATIONS or (session_id is not None and not valid_session(session_id)):raise ValueError('valid operation attribution required')
        with self._state() as state:return copy.deepcopy(self._add(state,operation,session_id,time.time() if now is None else now))

    def finish(self,record_id,result=None,error=None,transaction_id=None,now=None):
        with self._state() as state:
            row=next((r for r in state['records'] if r['id']==record_id),None)
            if row is None or row['status']!='running':return False
            row['finished_at']=time.time() if now is None else now
            if ident(transaction_id):row['transaction_id']=transaction_id
            if error is not None:
                row['error_code']=type(error).__name__ if type(error).__name__ in ERRORS else 'OperationError'
                row['status']='pending_rollback' if ident(transaction_id) else 'rejected' if isinstance(error,ValueError) else 'failed'
            else:
                result=result if isinstance(result,dict) else {}
                for key in ['verified_healthy','rollback_armed','applied']:
                    if type(result.get(key)) is bool:row[key]=result[key]
                row['status']='pending_rollback' if result.get('rollback_armed') else 'verified' if result.get('verified_healthy') is True else 'applied_unverified' if result.get('applied') else 'completed'
            return True

    def recovery(self,pending,now=None):
        with self._state() as state:
            sid=pending.get('session_id');sid=sid if valid_session(sid) else None
            parent=next((r for r in state['records'] if r['id']==pending.get('operation_record_id')),None)
            if parent:
                sid=parent.get('session_id')
                if parent['status']=='running':parent.update(status='interrupted',finished_at=time.time() if now is None else now)
            row=self._add(state,'restore_gateway',sid,time.time() if now is None else now,status='rolled_back',gateway_restarted=True,source='watchdog')
            if parent:row['related_id']=parent['id']
            return copy.deepcopy(row)

    def read(self):
        with self._state() as state:return copy.deepcopy(state)

    def notices(self):
        with self._state() as state:
            groups={}
            for row in state['records']:
                sid=row.get('session_id')
                if sid and row['sequence']>state['delivered'].get(sid,0):groups.setdefault(sid,[]).append(row)
            notices=[]
            for sid,rows in groups.items():
                if any(r['status']=='running' for r in rows):continue
                revision=max(r['sequence'] for r in rows)
                notices.append({'session_id':sid,'revision':revision,'notice_id':notice_id(sid,revision),'records':copy.deepcopy(rows)})
            return {'notices':notices[:16]}

    def acknowledge(self,sid,revision,message_id):
        if not valid_session(sid) or type(revision) is not int or message_id!=notice_id(sid,revision):return {'acknowledged':False}
        with self._state() as state:
            rows=[r for r in state['records'] if r.get('session_id')==sid and r['sequence']<=revision]
            if not rows or max(r['sequence'] for r in rows)!=revision or any(r['status']=='running' for r in rows):return {'acknowledged':False}
            state['delivered'][sid]=max(revision,state['delivered'].get(sid,0));return {'acknowledged':True}
