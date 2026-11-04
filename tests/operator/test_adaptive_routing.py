import tempfile
import unittest
import uuid
from pathlib import Path

from adaptive_routing import evaluate_route
from business_probe import compare_endpoint
from route_evidence import EvidenceStore
from user_policy import merge_preferences
from probe_transport import response_evidence


class AdaptiveRoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=EvidenceStore(Path(self.tmp.name)/'evidence.json')
        self.approved={'version':'policy1','preferences':merge_preferences({},{})}
        self.endpoint={'network':'tcp','port':443,'application_protocol':'https','last_seen':1090,'last_failure_at':1080}
        self.domain='api.openai.com'

    def knowledge(self,path='proxy'):
        text='The documented service is unavailable from the current source region.'
        source=self.store.collect_source('https://help.example.com/supported-regions',fetch=lambda url:text,now=1000)
        return self.store.record_requirement(self.domain,path,[source['id']],[{'source_id':source['id'],'quote':text}],'The public availability policy requires this service to use the specified region path.','mainland China',now=1000)['id']

    def rounds(self,current='direct',bad='direct',region=False,both=False):
        refs=[]
        for i,at in enumerate((1000,1070)):
            paths={}
            for path in ('direct','proxy'):
                failed=3 if both or (path==bad and not region) else 0
                paths[path]={'sample_count':3,'success_samples':3-failed,'failed_samples':failed,'path_verified':True,
                    'region_rejected_samples':3 if path==bad and region else 0,'business_rejection_samples':3 if path==bad and region else 0,'median_elapsed_ms':80 if path==bad else 300}
            row={'target':self.domain,'comparison_id':uuid.uuid4().hex,'observed_at':at,'endpoint':{k:self.endpoint[k] for k in ('network','port','application_protocol')},
                'origin':'protected_synthetic_probe','state':'observed','node_id':'node1','dns_fingerprint':'dns1','config_identity':'config1','path_identity_verified':True,
                'gateway_route':{'verified':True,'path':current,'attribution':'own_probe_socket'},'paths':paths,'controls':{'direct':True,'proxy':True}}
            refs.append(self.store.record(row,'policy1',now=at)['id'])
        return refs

    def evaluate(self,refs,path='proxy',knowledge=None,**kwargs):
        return evaluate_route(self.domain,path,refs,self.approved,self.store,now=1100,observed_endpoints=[self.endpoint],business_requirement_evidence_ids=knowledge or [],**kwargs)

    def test_persistent_wrong_direction_with_public_basis_can_apply(self):
        result=self.evaluate(self.rounds(),knowledge=[self.knowledge()])
        self.assertEqual(result['action'],'apply');self.assertEqual(result['proposal']['expected_version'],'policy1')
        self.assertEqual(result['proposal']['domain'],self.domain);self.assertFalse(result['application_verified'])

    def test_openai_fast_direct_with_region_error_never_authorizes_direct(self):
        result=self.evaluate(self.rounds(current='proxy',bad='proxy'),path='direct',knowledge=[self.knowledge()])
        self.assertEqual(result['action'],'investigate');self.assertEqual(result['reason'],'requested_path_conflicts_with_public_service_basis')

    def test_current_direct_region_rejection_can_be_fixed_even_tls_works(self):
        self.assertEqual(self.evaluate(self.rounds(region=True),knowledge=[self.knowledge()])['action'],'apply')

    def test_correct_direction_poor_node_quality_is_not_route_change(self):
        result=self.evaluate(self.rounds(current='proxy',bad='proxy'),knowledge=[self.knowledge()])
        self.assertEqual(result['action'],'no_change');self.assertEqual(result['reason'],'current_direction_matches_service_basis')

    def test_unknown_public_basis_or_normal_but_slower_keeps_route(self):
        self.assertEqual(self.evaluate(self.rounds())['action'],'investigate')
        refs=self.rounds(bad=None)
        self.assertEqual(self.evaluate(refs,knowledge=[self.knowledge()])['action'],'no_change')

    def test_both_failed_is_not_restored_or_a_reason_to_switch(self):
        result=self.evaluate(self.rounds(both=True),knowledge=[self.knowledge()])
        self.assertEqual(result['action'],'no_route_remedy');self.assertFalse(result['network_restored'])

    def test_duplicate_cached_or_too_close_rounds_cannot_apply(self):
        refs=self.rounds()
        result=self.evaluate([refs[0],refs[0]],knowledge=[self.knowledge()])
        self.assertNotEqual(result['action'],'apply')
        self.assertNotEqual(self.evaluate(refs,knowledge=[self.knowledge()],operational_policy={'min_round_gap_seconds':100})['action'],'apply')

    def test_identity_changes_expiry_and_incomplete_route_proof_block_apply(self):
        for field,value in [('node_id','node2'),('dns_fingerprint','dns2'),('policy_version','policy2'),('gateway_route',{'verified':False,'path':'direct'})]:
            with self.subTest(field=field):
                refs=self.rounds();row=self.store.get_many([refs[-1]],now=1100)[0]
                # Root collector creates a new real round with the changed identity.
                row['comparison_id']=uuid.uuid4().hex;row[field]=value
                for k in ('id','kind','created_at','expires_at','expired','digest','policy_version'):row.pop(k,None)
                changed=self.store.record(row,'policy2' if field=='policy_version' else 'policy1',now=1070)['id']
                self.assertNotEqual(self.evaluate([refs[0],changed],knowledge=[self.knowledge()])['action'],'apply')

    def test_explicit_user_suffix_mode_and_survival_endpoints_win(self):
        refs=self.rounds();knowledge=[self.knowledge()]
        self.approved['preferences']['direct_domains']=['openai.com']
        self.assertEqual(self.evaluate(refs,knowledge=knowledge)['reason'],'explicit_user_route')
        self.approved['preferences']['direct_domains']=[];self.approved['preferences']['mode']='global'
        self.assertEqual(self.evaluate(refs,knowledge=knowledge)['reason'],'automatic_routes_disabled_by_mode')

    def test_latest_strategy_is_read_each_time_not_baked_into_skill(self):
        refs=self.rounds(bad=None);knowledge=[self.knowledge()]
        self.assertEqual(self.evaluate(refs,knowledge=knowledge)['action'],'no_change')
        self.approved['preferences']['routing_strategy']['require_degraded_current']=False
        self.assertEqual(self.evaluate(refs,knowledge=knowledge)['action'],'apply')

    def test_conflicting_public_interpretations_need_resolution(self):
        result=self.evaluate(self.rounds(),knowledge=[self.knowledge('proxy'),self.knowledge('direct')])
        self.assertEqual(result['reason'],'conflicting_public_service_basis')

    def test_stale_service_knowledge_and_missing_positive_control_never_apply(self):
        refs=self.rounds();knowledge=[self.knowledge()]
        self.assertNotEqual(evaluate_route(self.domain,'proxy',refs,self.approved,self.store,now=1000+8*86400,
            observed_endpoints=[self.endpoint],business_requirement_evidence_ids=knowledge)['action'],'apply')
        row=self.store.get_many([refs[-1]],now=1100)[0]
        row['comparison_id']=uuid.uuid4().hex;row['controls']={'direct':True,'proxy':False}
        for key in ('id','kind','created_at','expires_at','expired','digest','policy_version'):row.pop(key,None)
        changed=self.store.record(row,'policy1',now=1070)['id']
        self.assertEqual(self.evaluate([refs[0],changed],knowledge=knowledge)['reason'],'positive_controls_required')

    def test_real_probe_http_rejections_cannot_qualify_required_alternative(self):
        knowledge=[self.knowledge()]
        for status in (401,403,404,429,503):
            with self.subTest(status=status):
                refs=[]
                for at in (1000,1070):
                    def run_probe(target,path):
                        return {'connect_ok':path=='proxy','tls_ok':path=='proxy','transport_ok':path=='proxy',
                            'http_status':status if path=='proxy' else None,'path_verified':True,'elapsed_ms':30}
                    row=compare_endpoint(self.domain,self.endpoint,run_probe,at)
                    self.assertEqual(row['paths']['proxy']['success_samples'],3)
                    self.assertEqual(row['paths']['proxy']['business_rejection_samples'],3)
                    row.update(comparison_id=uuid.uuid4().hex,node_id='node1',dns_fingerprint='dns1',config_identity='config1',
                        gateway_route={'verified':True,'path':'direct','attribution':'own_probe_socket'},controls={'direct':True,'proxy':True})
                    refs.append(self.store.record(row,'policy1',now=at)['id'])
                result=self.evaluate(refs,knowledge=knowledge)
                self.assertEqual(result['action'],'investigate')
                self.assertEqual(result['reason'],'required_path_not_demonstrably_usable')

    def test_real_probe_success_with_public_basis_remains_eligible(self):
        refs=[]
        for at in (1000,1070):
            row=compare_endpoint(self.domain,self.endpoint,lambda target,path:{'connect_ok':path=='proxy','tls_ok':path=='proxy',
                'transport_ok':path=='proxy','http_status':200 if path=='proxy' else None,'path_verified':True,'elapsed_ms':40},at)
            row.update(comparison_id=uuid.uuid4().hex,node_id='node1',dns_fingerprint='dns1',config_identity='config1',
                gateway_route={'verified':True,'path':'direct','attribution':'own_probe_socket'},controls={'direct':True,'proxy':True})
            refs.append(self.store.record(row,'policy1',now=at)['id'])
        self.assertEqual(self.evaluate(refs,knowledge=[self.knowledge()])['action'],'apply')

    def test_real_http_200_with_known_wrong_content_cannot_qualify_alternative(self):
        self.domain='www.google.com';refs=[]
        for at in (1000,1070):
            def run_probe(target,path):
                return {'connect_ok':path=='proxy','tls_ok':path=='proxy','path_verified':True,
                    **(response_evidence(target,200,b'wrong page','text/html',30) if path=='proxy' else {'transport_ok':False})}
            row=compare_endpoint(self.domain,self.endpoint,run_probe,at)
            self.assertEqual(row['paths']['proxy']['success_samples'],3)
            self.assertEqual(row['paths']['proxy']['business_rejection_samples'],3)
            row.update(comparison_id=uuid.uuid4().hex,node_id='node1',dns_fingerprint='dns1',config_identity='config1',
                gateway_route={'verified':True,'path':'direct','attribution':'own_probe_socket'},controls={'direct':True,'proxy':True})
            refs.append(self.store.record(row,'policy1',now=at)['id'])
        self.assertEqual(self.evaluate(refs,knowledge=[self.knowledge()])['reason'],'required_path_not_demonstrably_usable')


if __name__=='__main__':unittest.main()
