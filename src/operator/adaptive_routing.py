"""Review exact-domain corrections against the CURRENT approved strategy.

This module is deliberately read-only. It reasons over root-collected references
and returns a proposal; the transaction re-evaluates it under the policy lock.
Public-source interpretation remains attributable to the AI, not certified by a
boolean that the AI itself supplied.
"""
import math
import time

from business_probe import endpoint_spec
from traffic import hostname
from user_policy import AUTO_CONTROL_DOMAINS,explicit_path,merge_preferences

DEFAULT_OPERATIONAL_POLICY={'min_rounds':2,'min_round_gap_seconds':60,'max_evidence_age_seconds':900,
    'max_observation_age_seconds':3600,'severe_latency_ms':2500,'latency_ratio':4,'latency_gap_ms':1000}


def evaluate_route(domain,path,evidence_ids,approved,store,now=None,operational_policy=None,
                   observed_endpoints=None,business_requirement_evidence_ids=None):
    now=time.time() if now is None else now;domain=hostname(domain)
    if not domain or path not in ('direct','proxy'):raise ValueError('exact public domain and path required')
    preferences=merge_preferences({},approved.get('preferences',{}));strategy=preferences['routing_strategy']
    tuning={**DEFAULT_OPERATIONAL_POLICY,**(operational_policy or {})}
    for key in DEFAULT_OPERATIONAL_POLICY:
        value=tuning[key]
        if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError('positive bounded operational thresholds required')
    if not 2<=tuning['min_rounds']<=8 or not 15<=tuning['min_round_gap_seconds']<=3600 or not 60<=tuning['max_evidence_age_seconds']<=3600:
        raise ValueError('independent recent comparison rounds required')
    def outcome(action,reason,**extra):
        return {'action':action,'reason':reason,'domain':domain,'requested_path':path,'policy_version':approved.get('version'),
            'strategy':strategy,'policy_changed':False,'application_verified':False,'network_restored':False,**extra}
    if preferences['mode']!='rule':return outcome('no_change','automatic_routes_disabled_by_mode')
    if explicit_path(domain,preferences):return outcome('no_change','explicit_user_route')
    protected=(*AUTO_CONTROL_DOMAINS,*tuning.get('protected_domains',()))
    if any(domain==host or domain.endswith('.'+host) for host in protected):return outcome('no_change','protected_control_domain')
    if not isinstance(evidence_ids,list) or len(evidence_ids)>8 or len(set(evidence_ids))<tuning['min_rounds']:
        return outcome('investigate','independent_rounds_required')
    try:rounds=store.get_many(evidence_ids,now=now)
    except ValueError:return outcome('investigate','unknown_comparison_reference')
    if any(row.get('kind')!='comparison' or row.get('target')!=domain or row.get('expired') or not 0<=now-row.get('observed_at',0)<=tuning['max_evidence_age_seconds'] for row in rounds):
        return outcome('investigate','stale_or_wrong_comparison')
    rounds=sorted(rounds,key=lambda row:row['observed_at'])
    if len({row.get('comparison_id') for row in rounds})!=len(rounds) or any(b['observed_at']-a['observed_at']<tuning['min_round_gap_seconds'] for a,b in zip(rounds,rounds[1:])):
        return outcome('investigate','independent_rounds_required')
    endpoints=[endpoint_spec(row.get('endpoint')) for row in rounds]
    endpoint=endpoints[0]
    if not endpoint or endpoint['network']!='tcp' or any(value!=endpoint for value in endpoints):return outcome('investigate','incomparable_or_unsupported_endpoint')
    observations=[item for item in (observed_endpoints or []) if endpoint_spec(item)==endpoint]
    if not any(type(item.get('last_failure_at')) in (int,float) and 0<=now-item['last_failure_at']<=tuning['max_observation_age_seconds'] for item in observations):
        return outcome('investigate','recent_actual_endpoint_failure_required')
    if any(row.get('policy_version')!=approved.get('version') for row in rounds):return outcome('investigate','policy_identity_changed')
    for key in ('node_id','dns_fingerprint','config_identity'):
        if not rounds[0].get(key) or len({row.get(key) for row in rounds})!=1:return outcome('investigate','comparison_identity_changed')
    if any(row.get('origin')!='protected_synthetic_probe' or row.get('state')!='observed' or row.get('path_identity_verified') is not True for row in rounds):
        return outcome('investigate','unverified_probe_paths')
    gateways=[row.get('gateway_route') or {} for row in rounds]
    if any(row.get('verified') is not True or row.get('path') not in ('direct','proxy') or row.get('attribution')!='own_probe_socket' for row in gateways):
        return outcome('investigate','actual_gateway_rule_unverified')
    if len({row['path'] for row in gateways})!=1:return outcome('investigate','current_gateway_path_changed')
    current=gateways[0]['path']
    requirements=[];ids=business_requirement_evidence_ids or []
    if ids:
        try:requirements=store.get_many(ids,now=now)
        except ValueError:return outcome('investigate','unknown_public_service_basis')
        if any(row.get('kind')!='requirement' or row.get('domain')!=domain or row.get('scope')!='exact_domain' or row.get('expired') or not row.get('references_available') or row.get('provenance_checked') is not True for row in requirements):
            return outcome('investigate','stale_or_unscoped_public_service_basis')
        if len({row['required_path'] for row in requirements})!=1:return outcome('investigate','conflicting_public_service_basis')
        required=requirements[0]['required_path']
        if required!=path:return outcome('investigate','requested_path_conflicts_with_public_service_basis')
        if required==current:return outcome('no_change','current_direction_matches_service_basis',next_action='investigate_node_upstream_or_application')
    elif strategy['require_public_service_basis'] or strategy['require_route_conflict']:
        return outcome('investigate','public_service_basis_required')
    if path==current:return outcome('no_change','already_uses_requested_path')
    if preferences['adaptive_routes'].get(domain)==path:return outcome('investigate','configured_route_not_observed')
    def counts(row,which):
        values=row.get('paths',{}).get(which,{})
        for key in ('sample_count','success_samples','failed_samples','region_rejected_samples','business_rejection_samples'):
            if type(values.get(key)) is not int or not 0<=values[key]<=3:return None
        if values['sample_count']!=3 or values['success_samples']+values['failed_samples']!=3 or values.get('path_verified') is not True:return None
        return values
    pairs=[(counts(row,current),counts(row,path)) for row in rounds]
    if any(a is None or b is None for a,b in pairs):return outcome('investigate','incomplete_stage_samples')
    if any(row.get('controls')!={'direct':True,'proxy':True} for row in rounds):return outcome('investigate','positive_controls_required')
    if all(a['failed_samples']>=2 and b['failed_samples']>=2 for a,b in pairs):
        return outcome('no_route_remedy','both_paths_fail_observed_endpoint',next_action='investigate_endpoint_upstream_or_service')
    if any(b['success_samples']!=3 or b['region_rejected_samples'] or b['business_rejection_samples'] for a,b in pairs):
        return outcome('investigate','required_path_not_demonstrably_usable')
    def degraded(a,b):
        if a['failed_samples']>=2 or a['region_rejected_samples']>=2:return True
        slow=a.get('median_elapsed_ms');fast=b.get('median_elapsed_ms')
        if type(slow) not in (int,float) or type(fast) not in (int,float) or fast<=0:return False
        if not math.isfinite(slow) or not math.isfinite(fast):return False
        return slow>=tuning['severe_latency_ms'] and slow>=fast*tuning['latency_ratio'] and slow-fast>=tuning['latency_gap_ms']
    serious=all(degraded(a,b) for a,b in pairs)
    if strategy['require_degraded_current'] and not serious:
        # A pure speed preference only becomes eligible if a future user changes
        # the authoritative strategy explicitly; the default does not allow it.
        if not strategy['allow_latency_only']:return outcome('no_change','current_path_not_persistently_severely_degraded')
        if not all(type(a.get('median_elapsed_ms')) in (int,float) and type(b.get('median_elapsed_ms')) in (int,float) and a['median_elapsed_ms']>=max(1,b['median_elapsed_ms'])*tuning['latency_ratio'] for a,b in pairs):
            return outcome('no_change','no_repeatable_material_latency_advantage')
    proposal={'domain':domain,'path':path,'expected_version':approved.get('version'),'current_path':current,'endpoint':endpoint,
        'evidence_ids':list(evidence_ids),'business_requirement_evidence_ids':list(ids),'evaluated_at':now}
    return outcome('apply','wrong_route_with_current_strategy_evidence',proposal=proposal,
        knowledge_scope='AI interpretation of collected public sources; source integrity checked, semantic truth not programmatically proven')
