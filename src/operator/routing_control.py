"""Privileged adapters for evidence-backed exact-domain transactions only."""
from contextlib import contextmanager
import json
import pwd
import time
import uuid


def positive_controls(diagnosis):
    checks=diagnosis.get('checks',{})
    direct=checks.get('mainland_https',{});proxy=checks.get('proxy_https',{})
    return {'direct':bool(direct.get('ok') and 200<=direct.get('result',{}).get('http_status',0)<400),
            'proxy':bool(proxy.get('ok') and proxy.get('result',{}).get('http_status')==204)}


class ProtectedAdapter:
    def __init__(self,gateway):self.g=gateway

    @contextmanager
    def transaction(self):
        descriptor=self.g.acquire_transaction()
        try:
            if (self.g.STATE/'pending.json').exists():raise ValueError('a previous transaction awaits protected recovery')
            yield
        finally:self.g.release_transaction(descriptor)

    def read(self):return json.loads(self.g.CONFIG.read_text()),self.g.current_policy()

    def identity(self,domain,endpoint):
        from probe_transport import observe_identity
        return observe_identity(domain,self.g.api,self.g.CONFIG)

    def validate(self,candidate,proposed):
        self.g.validate_baseline(candidate,pwd.getpwnam('dsh').pw_uid,proposed)
        temporary=self.g.CONFIG.with_suffix('.route-check.json')
        try:
            self.g.write_state(temporary,candidate)
            self.g.command('env','SAFE_PATHS=/etc/net-gateway','/usr/local/bin/mihomo','-t','-d','/var/lib/net-gateway','-f',str(temporary),timeout=25)
        finally:temporary.unlink(missing_ok=True)

    def arm(self,old_config,old_policy):
        pending=self.g.STATE/'pending.json'
        if pending.exists():raise ValueError('a previous transaction awaits protected recovery')
        self.g.checkpoint(old_config,old_policy)
        token=uuid.uuid4().hex
        self.g.write_state(pending,{'id':token,'operation':'route_apply','deadline':time.time()+90,'boot_id':self.g.boot_id()})
        return token

    def owns(self,token):
        try:pending=json.loads((self.g.STATE/'pending.json').read_text())
        except (OSError,ValueError):return False
        return pending.get('id')==token and pending.get('boot_id')==self.g.boot_id() and time.time()<pending.get('deadline',0)

    def write(self,candidate,proposed):
        self.g.write_state(self.g.STATE/'approved-policy.json',proposed)
        self.g.write_state(self.g.CONFIG,candidate)

    def reload(self):self.g.api('/configs','PUT',{'path':str(self.g.CONFIG)},timeout=25)

    def verify_target(self,domain,path,endpoint,exact_rule):
        from probe_transport import verify_route
        return verify_route(domain,endpoint,path,self.g.api,self.g.CONFIG,exact_rule=exact_rule)

    def verify_controls(self):
        diagnosis=self.g.diagnose()
        return {'verified_healthy':self.g.verification_healthy(diagnosis),'controls':positive_controls(diagnosis),'checked_at':time.time()}

    def commit(self,candidate,proposed,token):
        if not self.owns(token):raise ValueError('transaction ownership or recovery deadline changed')
        self.g.checkpoint(candidate,proposed)
        (self.g.STATE/'pending.json').unlink()
        import hashlib
        encoded=(json.dumps(proposed,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
        self.source_sync_version=hashlib.sha256(encoded).hexdigest()[:16]

    def rollback(self,token):
        if not self.owns(token):return False
        self.g.restore_gateway()
        (self.g.STATE/'pending.json').unlink(missing_ok=True)
        return True


def observed_endpoints(gateway,domain):
    traffic=gateway.traffic_status()
    if traffic.get('status')!='observed':return []
    return next((row.get('endpoints',[]) for row in traffic.get('domains',[]) if row.get('domain')==domain),[])


def operation(request,gateway):
    from route_evidence import EvidenceStore
    from adaptive_routing import evaluate_route
    from route_transaction import apply_route
    store=EvidenceStore(gateway.STATE/'route-evidence.json');op=request['operation']
    if op=='route_status':return store.status(domain=request.get('target'))
    if op=='route_get':return {'evidence':store.get_many(request['evidence_ids'])}
    if op=='route_source':
        config=json.loads(gateway.CONFIG.read_text())
        from urllib.parse import urlsplit
        blocked=[urlsplit(p.get('url','')).hostname for p in config.get('proxy-providers',{}).values()]
        return store.collect_source(request['url'],blocked_hosts=[host for host in blocked if host])
    if op=='route_requirement':
        return store.record_requirement(request['target'],request['path'],request['source_ids'],request['quotes'],request['rationale'],request['region_context'],actor=request['session_id'])
    if op=='route_evaluate':
        return evaluate_route(request['target'],request['path'],request['evidence_ids'],gateway.current_policy(),store,
            observed_endpoints=observed_endpoints(gateway,request['target']),business_requirement_evidence_ids=request.get('business_requirement_evidence_ids'))
    if op=='route_apply':
        proposal=request['proposal']
        adapter=ProtectedAdapter(gateway)
        result=apply_route(proposal,store,adapter,observed_endpoints=observed_endpoints(gateway,proposal.get('domain')))
        if result.get('applied'):result['source_sync_version']=adapter.source_sync_version
        return result
    raise ValueError('unknown protected route operation')
