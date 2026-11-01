import json, runpy, sys
ns = runpy.run_path('/var/lib/dsh/workspace/network-maintainer/programs/patrol_inspect_candidate3.py')
inspect = ns['inspect']
DOMAIN = 'apd-pcdnwxstat.teg.tencent-cloud.net'
base_checks = {
 'gateway_dns_cn': {'ok':True,'result':{'rcode':0,'answer_count':3}},
 'gateway_dns_foreign': {'ok':True,'result':{'rcode':0,'answer_count':3}},
 'mainland_https': {'ok':True,'result':{'expected_health_status':True}},
 'proxy_https': {'ok':True,'result':{'expected_health_status':True}},
}
status_ok = {'services':{'net-gateway.service':{'ActiveState':'active'}}}
def snap(proxy_ok=True, faults=8, probe_error=True):
    checks = json.loads(json.dumps(base_checks))
    if not proxy_ok:
        checks['proxy_https']['ok'] = False
        checks['proxy_https']['result']['expected_health_status'] = False
    hist = []
    for i in range(12):
        has = i >= 12 - faults
        entry = {'faults':['client_business:'+DOMAIN] if has else []}
        if has: entry['faults_after_confirmation']=['client_business:'+DOMAIN]
        hist.append(entry)
    return {'checks':checks,'status':status_ok,'history':hist,
            'business_observations':{'issues':[{'domain':DOMAIN,'kind':'recurring_client_failure','fingerprint':'fp1'}],'checks':{}},
            'tracked_probes':{DOMAIN:{'error':'URLError','observed_at':1}},
            'quality_summary':{'preferred_pool':[{'alive':True},{'alive':True}]}}
# healthy
r = inspect({'checks':base_checks,'status':status_ok,'history':[],'business_observations':{'issues':[],'checks':{}},'quality_summary':{'preferred_pool':[{'alive':True}]}})
assert r['action']=='none' and 'review_request' not in r and r['probe_domains']==[], r
# proxy failure
r = inspect(snap(proxy_ok=False, faults=0))
assert r['action']=='recheck_nodes', r
# fresh client fault still escalates
r = inspect(snap(faults=1))
assert 'review_request' in r and DOMAIN in r['probe_domains'], r
# 5 rounds still escalates (below persistence threshold)
r = inspect(snap(faults=5))
assert 'review_request' in r, r
# 8 rounds persistent external: keep record, no repeated escalation, no wasted probe
r = inspect(snap())
assert 'review_request' not in r and r['probe_domains']==[] and '外部端点' in r['summary'], r
# persistent client fault plus fixed proxy failure must still escalate
r = inspect(snap(proxy_ok=False))
assert 'review_request' in r, r
print(json.dumps({'ok':True,'persistent':inspect(snap()),'fresh':inspect(snap(faults=1))}, ensure_ascii=False))
