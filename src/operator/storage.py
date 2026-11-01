"""Conventional storage supervision. Model calls are unnecessary for routine retention."""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

STATE=Path('/var/lib/net-gateway-agent')
HOME=Path('/var/lib/dsh/state')
WORK=Path('/var/lib/dsh/workspace')
CONFIG=Path('/etc/net-gateway-agent/storage.json')
DEFAULT={'routine_min_free_bytes':4*1024**3,'critical_free_bytes':2*1024**3,
    'background_history_bytes':1024**3,'background_keep_recent':8,'duplicate_reports_keep':24,
    'scratch_bytes':128*1024**2,'reserve_bytes':128*1024**2,'single_file_bytes':64*1024**2,
    'user_chats':'never automatically delete','history_scope':'only registered background sessions, excluding live leases'}

def trim_checkpoints(state,keep=4):
    if (state/'pending.json').exists() or not (state/'checkpoints').exists():return
    with (state/'transaction.lock').open('a') as lease:
        try:fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:return
        if (state/'pending.json').exists():return
        current=(state/'known-good').resolve()
        directories=sorted([p for p in (state/'checkpoints').iterdir() if p.is_dir() and not p.is_symlink()],key=lambda p:p.stat().st_mtime,reverse=True)
        for directory in directories[keep:]:
            if directory.resolve()!=current:shutil.rmtree(directory)

def policy():return {**DEFAULT,**(json.loads(CONFIG.read_text()) if CONFIG.exists() else {})}

def size(path):
    total=0
    for root,dirs,files in os.walk(path,followlinks=False):
        for name in files:
            item=Path(root)/name
            try:
                info=item.lstat()
                if stat.S_ISREG(info.st_mode):total+=info.st_size
            except FileNotFoundError:pass
    return total

def trim_files(directory,keep=0,budget=0,older_than=None):
    if not directory.exists() or directory.is_symlink():return 0
    candidates=[]
    for item in directory.iterdir():
        try:
            info=item.lstat()
            if stat.S_ISREG(info.st_mode):candidates.append((info.st_mtime,item,info.st_size))
        except FileNotFoundError:pass
    candidates.sort(reverse=True);total=sum(row[2] for row in candidates);freed=0
    for index,(mtime,item,amount) in enumerate(candidates):
        if index<keep or (older_than is not None and mtime>=older_than):continue
        if budget and total<=budget:break
        try:item.unlink();freed+=amount;total-=amount
        except FileNotFoundError:pass
    return freed

def prune_background(sessions,registry,budget,keep):
    """Take the same POSIX session lease as DSH before deleting registered background data."""
    entries=[]
    for workspace in sessions.iterdir() if sessions.exists() else []:
        if not workspace.is_dir() or workspace.is_symlink():continue
        for directory in workspace.iterdir():
            record=registry.get(directory.name,{})
            if record.get('kind') not in ['patrol','canary'] or record.get('user_chat') or not re.fullmatch(r'session-[a-f0-9-]{36}',directory.name):continue
            if directory.is_symlink() or not directory.is_dir():continue
            entries.append((directory.stat().st_mtime,directory,size(directory)))
    entries.sort(reverse=True);total=sum(row[2] for row in entries);deleted=[]
    for _mtime,directory,amount in entries[max(keep,0):]:
        if total<=budget:break
        lock=directory/'session.lock'
        try:
            descriptor=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
            with os.fdopen(descriptor,'r+b') as lease:
                try:fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:continue
                shutil.rmtree(directory);total-=amount;deleted.append(directory.name)
        except (FileNotFoundError,OSError):continue
    return {'bytes':total,'removed':deleted,'over_budget':total>budget}

def main():
    p=policy();now=time.time();freed=0
    reserve=STATE/'emergency.reserve'
    if shutil.disk_usage('/').free<p['critical_free_bytes'] and reserve.exists():reserve.unlink()
    freed+=trim_files(WORK/'maintenance-runs',keep=p['duplicate_reports_keep'])
    freed+=trim_files(WORK/'.maintenance-tmp',budget=p['scratch_bytes'],older_than=now-86400)
    freed+=trim_files(HOME/'logs',keep=3,budget=16*1024**2)
    trim_checkpoints(STATE)
    for item in HOME.glob('operator-*.jsonl'):
        if not item.is_symlink() and item.stat().st_mtime<now-7*86400:freed+=item.stat().st_size;item.unlink()
    registry_path=STATE/'background-sessions.json'
    registry=json.loads(registry_path.read_text()) if registry_path.exists() else {}
    background=prune_background(HOME/'sessions',registry,p['background_history_bytes'],p['background_keep_recent'])
    free=shutil.disk_usage('/').free
    if free<p['critical_free_bytes']:
        if reserve.exists():reserve.unlink()
        freed+=trim_files(WORK/'.maintenance-tmp')
    elif free>p['routine_min_free_bytes']+p['reserve_bytes'] and not reserve.exists():
        with reserve.open('wb') as target:
            reserve.chmod(0o600);os.posix_fallocate(target.fileno(),0,p['reserve_bytes'])
    free=shutil.disk_usage('/').free;vfs=os.statvfs('/')
    scratch=size(WORK/'.maintenance-tmp')
    result={'checked_at':now,'free_bytes':free,'free_inodes':vfs.f_favail,'cleaned_bytes':freed,
        'background_history':background,'scratch_bytes':scratch,'pause_routine':free<p['routine_min_free_bytes'] or vfs.f_favail<5000 or background['over_budget'] or scratch>p['scratch_bytes'],
        'critical':free<p['critical_free_bytes'] or vfs.f_favail<1000,'emergency_reserve_present':reserve.exists(),'policy':p}
    temporary=STATE/'storage.next';temporary.write_text(json.dumps(result,ensure_ascii=False));temporary.chmod(0o600);temporary.replace(STATE/'storage.json')
    print(json.dumps({k:result[k] for k in ['free_bytes','free_inodes','pause_routine','critical','cleaned_bytes']}))

if __name__=='__main__':main()
