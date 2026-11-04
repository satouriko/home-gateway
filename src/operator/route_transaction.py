"""CAS exact-domain policy changes under the broker's protected transaction.

The adapter owns durable recovery, filesystem privileges and gateway API access.
No candidate may checkpoint before real rule attribution and positive controls.
"""
import time

from adaptive_routing import evaluate_route
from user_policy import merge_preferences,render


def apply_route(proposal,store,adapter,now=None,observed_endpoints=None,operational_policy=None):
    allowed={'domain','path','expected_version','current_path','endpoint','evidence_ids','business_requirement_evidence_ids','evaluated_at'}
    if not isinstance(proposal,dict) or set(proposal)-allowed or not all(key in proposal for key in ('domain','path','expected_version','evidence_ids')):
        raise ValueError('bounded route proposal references required')
    now=time.time() if now is None else now
    def result(reason,**kwargs):
        return {'applied':False,'policy_changed':False,'verified_healthy':False,'rollback_armed':False,'rolled_back':False,
            'application_verified':False,'network_restored':False,'reason':reason,**kwargs}
    with adapter.transaction():
        old,approved=adapter.read()
        if approved.get('version')!=proposal['expected_version']:return result('policy_identity_changed')
        verdict=evaluate_route(proposal['domain'],proposal['path'],proposal['evidence_ids'],approved,store,now=now,
            observed_endpoints=observed_endpoints,operational_policy=operational_policy,
            business_requirement_evidence_ids=proposal.get('business_requirement_evidence_ids'))
        if verdict['action']!='apply':return result('strategy_recheck_rejected',evaluation=verdict)
        verified=verdict['proposal'];recent=max(store.get_many(verified['evidence_ids'],now=now),key=lambda row:row['observed_at'])
        identity=adapter.identity(verified['domain'],verified['endpoint'])
        if any(not identity.get(key) or identity[key]!=recent.get(key) for key in ('node_id','dns_fingerprint','config_identity')):
            return result('current_route_identity_changed')
        # Only this exact map delta is derived. No candidate config, endpoint,
        # strategy, region preference or broad suffix is accepted from the model.
        current=merge_preferences({},approved.get('preferences',{}))
        preferences=merge_preferences(current,{'adaptive_routes':{**current['adaptive_routes'],verified['domain']:verified['path']}})
        candidate,proposed=render(old,preferences,current)
        adapter.validate(candidate,proposed)
        token=adapter.arm(old,approved)
        try:
            if not adapter.owns(token):raise RuntimeError('transaction_ownership_lost')
            adapter.write(candidate,proposed);adapter.reload()
            target=adapter.verify_target(verified['domain'],verified['path'],verified['endpoint'],True)
            controls=adapter.verify_controls()
            if target.get('verified') is not True or target.get('stage_ok') is not True or target.get('exact_rule') is not True or target.get('attribution')!='own_probe_socket':
                raise RuntimeError('actual_rule_or_relevant_stage_not_verified')
            if verified['endpoint']['application_protocol'] in ('http','https'):
                status=target.get('http_status')
                if target.get('endpoint_acceptable') is not True or type(status) is not int or not 200<=status<400 or target.get('content_ok') is False:
                    raise RuntimeError('target_http_response_not_acceptable')
            if controls.get('verified_healthy') is not True:raise RuntimeError('positive_controls_failed')
            if not adapter.owns(token):raise RuntimeError('transaction_ownership_lost')
            adapter.commit(candidate,proposed,token)
            return result('exact_route_applied_and_transport_verified',applied=True,policy_changed=True,verified_healthy=True,
                target_verification=target,control_verification=controls,policy_version=proposed['version'],
                acceptance_scope='exact gateway rule and observed endpoint transport stage; real application acceptance remains unverified')
        except Exception as error:
            restored=False;armed=True
            if adapter.owns(token):
                try:
                    rollback=adapter.rollback(token)
                    restored=rollback is True or isinstance(rollback,dict) and rollback.get('restored') is True
                    armed=not restored
                except Exception:pass
            # An interrupted process leaves the durable root recovery token;
            # exception messages are not returned (may contain credentials).
            return result('route_change_not_verified',rolled_back=restored,rollback_armed=armed,error_category=type(error).__name__)
