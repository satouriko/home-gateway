#!/usr/bin/env python3
"""Root-owned operator UID route, independent of the proxy's routing table."""
import json
import pwd
import subprocess

TABLE = '51889'
PRIORITY = '100'

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=8)

def apply():
    uid = pwd.getpwnam('dsh').pw_uid
    route = json.loads(run('ip','-j','route','get','192.168.2.1').stdout)[0]
    interface, source = route['dev'], route['prefsrc']
    rules = json.loads(run('ip','-j','rule','show').stdout)
    existing = [r for r in rules if r.get('priority') == int(PRIORITY)]
    if existing and not all(str(r.get('table')) == TABLE and (r.get('uidrange') in (f'{uid}-{uid}', {'start':uid,'end':uid}) or (r.get('uid_start'),r.get('uid_end'))==(uid,uid)) for r in existing):
        raise RuntimeError('reserved rule priority is occupied')
    run('ip','route','replace','table',TABLE,'192.168.2.0/24','dev',interface,'scope','link','src',source)
    run('ip','route','replace','table',TABLE,'default','via','192.168.2.1','dev',interface,'src',source)
    if not existing:
        run('ip','rule','add','priority',PRIORITY,'uidrange',f'{uid}-{uid}','lookup',TABLE)
    return {'uid':uid,'table':int(TABLE),'upstream':'192.168.2.1','interface':interface}

if __name__=='__main__':print(json.dumps(apply()))
