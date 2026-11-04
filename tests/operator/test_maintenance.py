import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
from incidents import IncidentStore
import workflow
from test_broker import healthy_result

try:maintenance=importlib.import_module('maintenance')
except ModuleNotFoundError:maintenance=None


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(maintenance,'maintenance integration helper must exist')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name);self.now=1800000000
        self.state={};self.diagnosis=healthy_result()
        self.store=IncidentStore(self.directory/'incidents.json')
        self.source=(Path(__file__).parents[2]/'src/maintained/workflow.py').read_text()
    def policy(self,snapshot):
        return {'active':False,'version':'builtin','result':workflow.worker(self.source,snapshot),
                'failures':[],'maintenance_required':False}
    def issue(self,domain='real.example.com',**changes):
        return {'domain':domain,'kind':'recurring_client_failure','fingerprint':'legacy-'+domain,
                'resolved':False,'last_failure_at':self.now-10,'error_categories':['dial_timeout'],**changes}
    def observe(self,now=None,inspect=None):
        return maintenance.observe(self.state,self.diagnosis,self.now if now is None else now,
            preferences={'routing_strategy':'respect-current-intent'},directory=self.directory,inspect=inspect or self.policy)
    def decide(self,case,status='closed',outcome='no_route_remedy',due=600):
        return self.store.decide(case['id'],case['revision'],{'status':status,'outcome':outcome,
            'reason':'Both paths fail this endpoint while independent positive controls pass; review evidence again.',
            'evidence':['compare:current','controls:healthy'],'next_review_at':self.now+due},'session-investigator',self.now)
    def test_production_snapshot_runs_real_publisher_and_retains_controls_and_preferences(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        with patch.object(workflow,'STATE',self.directory):result=self.observe(inspect=workflow.inspect_active)
        self.assertFalse(result['workflow']['maintenance_required'])
        self.assertEqual(result['workflow']['result']['wake'],'urgent')
        self.assertEqual(result['path_health']['checks']['proxy_https']['ok'],True)
        self.assertEqual(result['routing']['preferences']['routing_strategy'],'respect-current-intent')
        self.assertTrue(result['cases'][0]['requires_attention'])
    def test_legacy_cases_migrate_once_and_counter_only_samples_preserve_real_disposition(self):
        old=self.issue(last_failure_at=self.now-86400,failure_count=40)
        self.state['business_observations']={'issues':[old],'checks':{}}
        first=self.observe();case=self.decide(first['cases'][0]);self.assertEqual(case['actor'],'session-investigator')
        self.state['business_observations']['issues'][0].update(failure_count=400,last_seen=self.now+10)
        result=self.observe(self.now+10)
        self.assertEqual(result['cases'][0]['status'],'closed');self.assertFalse(result['cases'][0]['requires_attention'])
        self.assertEqual(result['workflow']['result']['wake'],'none')
        self.assertTrue(result['migration_complete']);self.assertEqual(len(self.store.list()['cases']),1)
    def test_active_urgent_lease_avoids_duplicate_wake_but_expiry_requires_review(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        case=self.observe()['cases'][0];self.decide(case,status='working',due=120)
        active=self.observe(self.now+30)
        self.assertFalse(active['cases'][0]['requires_attention']);self.assertEqual(active['workflow']['result']['wake'],'none')
        expired=self.observe(self.now+121)
        self.assertTrue(expired['cases'][0]['requires_attention']);self.assertEqual(expired['workflow']['result']['wake'],'urgent')
    def test_material_evidence_reopens_a_disposed_case_without_synthetic_repair_claim(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        self.decide(self.observe()['cases'][0])
        self.diagnosis['business_observations']['issues'][0]['error_categories']=['connection_reset']
        self.diagnosis['business_observations']['issues'][0]['last_failure_at']=self.now+1
        result=self.observe(self.now+2)
        self.assertEqual(result['cases'][0]['status'],'open');self.assertFalse(result['cases'][0]['network_restored'])
        self.assertEqual(result['workflow']['result']['wake'],'urgent')
    def test_failed_repair_and_genuine_recurrence_after_verified_fix_require_attention(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        case=self.observe()['cases'][0];self.decide(case,status='working',due=600)
        self.diagnosis['business_observations']['issues'][0].update(repair_status='failed',last_failure_at=self.now+1)
        self.assertTrue(self.observe(self.now+2)['cases'][0]['requires_attention'])
        case=self.store.get(case['id']);facts={**case['facts'],'current_failure':False,'verified_recovery':True}
        self.store.observe([{'key':case['key'],'signature':'verified-recovery','observed_at':self.now+3,'facts':facts}],self.now+3)
        case=self.store.get(case['id'])
        self.store.decide(case['id'],case['revision'],{'status':'closed','outcome':'fixed','reason':'Relevant business verification passed',
            'evidence':['verify:business'],'next_review_at':self.now+500},'repair-session',self.now+4)
        self.diagnosis['business_observations']['issues'][0].update(repair_status='completed',last_failure_at=self.now+5)
        recurrence=self.observe(self.now+6)
        self.assertEqual(recurrence['cases'][0]['status'],'open');self.assertTrue(recurrence['cases'][0]['requires_attention'])
    def test_corrupt_incident_storage_retains_pending_input_and_retries_without_losing_it(self):
        path=self.directory/'incidents.json';path.write_text('{broken')
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe();self.assertIn('incident_storage',result['faults']);self.assertGreater(result['pending_signals'],0)
        pending=json.loads((self.directory/'maintenance-state.json').read_text());self.assertTrue(pending['pending'])
        self.assertEqual(path.read_text(),'{broken')
        path.unlink();self.diagnosis['business_observations']={'issues':[],'checks':{}}
        retried=self.observe(self.now+1)
        self.assertEqual(retried['pending_signals'],0);self.assertEqual(len(self.store.list()['cases']),1)
    def test_corrupt_workflow_is_explicit_fault_and_retains_signal_input(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe(inspect=lambda snapshot:{'result':{'wake':'none'}})
        self.assertIn('workflow_failure',result['faults']);self.assertGreater(result['pending_signals'],0)
        self.assertTrue(self.store.list()['cases'])
    def test_corrupt_maintenance_state_retains_multiple_inputs_until_recovery(self):
        path=self.directory/'maintenance-state.json';path.write_text('{damaged')
        for domain in ['first.example.com','second.example.com']:
            self.diagnosis['business_observations']={'issues':[self.issue(domain)],'checks':{}}
            self.assertIn('maintenance_storage',self.observe()['faults'])
        self.assertEqual(path.read_text(),'{damaged');path.unlink()
        self.diagnosis['business_observations']={'issues':[],'checks':{}}
        result=self.observe(self.now+1)
        self.assertEqual({case['domain'] for case in result['cases']},{'first.example.com','second.example.com'})
        self.assertEqual(result['pending_signals'],0)
    def test_structured_maintenance_corruption_is_reported_and_preserved(self):
        path=self.directory/'maintenance-state.json';raw='{"format":1,"pending":[],"migration_complete":"yes"}';path.write_text(raw)
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe();self.assertIn('maintenance_storage',result['faults']);self.assertEqual(path.read_text(),raw)
    def test_restored_trusted_path_supplies_verification_for_an_explicit_fixed_disposition(self):
        self.diagnosis['checks']['proxy_https']={'ok':False}
        first=self.observe();self.assertEqual(first['workflow']['result']['wake'],'urgent')
        self.diagnosis=healthy_result();recovered=self.observe(self.now+10)
        case=recovered['cases'][0]
        self.assertFalse(case['facts']['current_failure']);self.assertTrue(case['facts']['verified_recovery'])
        self.assertFalse(recovered['path_health']['hard_faults'])
    def test_more_than_store_capacity_retains_new_signal_for_later_retry(self):
        for offset in [0,128]:self.store.observe([{'key':'full:'+str(i),'signature':'stable','facts':{},'priority':'normal'}
            for i in range(offset,offset+128)],self.now-10)
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe()
        self.assertIn('incident_capacity',result['faults']);self.assertGreater(result['pending_signals'],0)
        self.assertEqual(result['total_cases'],256);self.assertEqual(len(result['cases']),128)
        data=json.loads((self.directory/'maintenance-state.json').read_text())
        self.assertTrue(any(signal.get('domain')=='real.example.com' for signal in data['pending']))
    def test_full_pending_queue_retains_recovery_input_when_admission_has_backpressure(self):
        old=[{'key':'pending:'+str(i),'signature':'stable','priority':'normal','observed_at':self.now-10,'facts':{}} for i in range(512)]
        recovery={'key':'recovery:one','signature':'new','priority':'urgent','observed_at':self.now-1,'facts':{}}
        (self.directory/'maintenance-state.json').write_text(json.dumps({'format':1,'migration_complete':True,'pending':old}))
        path=self.directory/'maintenance-pending-recovery.json';path.write_text(json.dumps({'format':1,'pending':[recovery]}))
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe();self.assertIn('pending_capacity',result['faults'])
        self.assertTrue(path.exists());self.assertEqual(json.loads(path.read_text())['pending'],[recovery])
    def test_case_capacity_prioritizes_urgent_attention_and_reports_overflow(self):
        signals=[{'key':'fixture:'+str(i),'signature':'stable','facts':{},'priority':'normal'} for i in range(128)]
        self.store.observe(signals,self.now-10)
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{}}
        result=self.observe()
        self.assertIn('incident_capacity',result['faults']);self.assertEqual(result['cases'][0]['priority'],'urgent')
        self.assertEqual(len(result['cases']),128);self.assertEqual(result['total_cases'],129)
        self.assertEqual(len(self.store.list()['overflow_cases']),1)
    def test_routing_hints_require_poor_current_business_path_and_conflicting_region_evidence(self):
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{'real.example.com':{'at':self.now,
            'result':{'paths':{'direct':{'transport_ok':True,'http_status':403},'proxy':{'transport_ok':True,'http_status':401}}}}}}
        result=self.observe();self.assertEqual(result['routing']['candidates'],[])
        self.assertEqual(result['workflow']['result']['route_candidates'],[])
    def test_root_collected_route_evidence_creates_an_executable_workflow_candidate(self):
        from route_evidence import EvidenceStore
        from user_policy import merge_preferences
        store=EvidenceStore(self.directory/'route-evidence.json');domain='real.example.com'
        endpoint={'network':'tcp','port':443,'application_protocol':'https'}
        policy={'version':'policy-current','preferences':merge_preferences({},{})}
        (self.directory/'approved-policy.json').write_text(json.dumps(policy))
        text='This public service requires the internationally available proxy route.'
        source=store.collect_source('https://help.example.com/regions',fetch=lambda url:text,now=self.now-200)
        requirement=store.record_requirement(domain,'proxy',[source['id']],[{'source_id':source['id'],'quote':text}],
            'Public service availability requires the proxy region path.','current mainland source region',now=self.now-180)
        refs=[]
        for at in [self.now-120,self.now-50]:
            paths={path:{'sample_count':3,'success_samples':0 if path=='direct' else 3,'failed_samples':3 if path=='direct' else 0,
                'region_rejected_samples':0,'business_rejection_samples':0,'path_verified':True,'median_elapsed_ms':300} for path in ['direct','proxy']}
            row={'target':domain,'comparison_id':uuid.uuid4().hex,'observed_at':at,'endpoint':endpoint,
                 'origin':'protected_synthetic_probe','state':'observed','node_id':'node-current','dns_fingerprint':'dns-current',
                 'config_identity':'config-current','path_identity_verified':True,'gateway_route':{'verified':True,'path':'direct','attribution':'own_probe_socket'},
                 'paths':paths,'controls':{'direct':True,'proxy':True}}
            refs.append(store.record(row,policy['version'],now=at)['id'])
        self.diagnosis['business_observations']={'issues':[self.issue()],'checks':{},'domains':[{'domain':domain,
            'last_seen':self.now,'last_failure_at':self.now-10,'endpoints':[{**endpoint,'last_failure_at':self.now-10}]}]}
        result=self.observe();candidates=result['routing']['candidates']
        self.assertEqual([c['domain'] for c in candidates],[domain])
        self.assertEqual(set(candidates[0]['evidence_ids']),set(refs))
        self.assertEqual(candidates[0]['business_requirement_evidence_ids'],[requirement['id']])
        self.assertEqual(result['workflow']['result']['route_candidates'],[domain])
        import patrol
        from adaptive_routing import evaluate_route
        self.state['business_observations']=self.diagnosis['business_observations']
        self.state['business_observations']['last_probe_at']=self.now
        calls=[]
        def protected(request):
            calls.append(request)
            return evaluate_route(request['target'],request['path'],request['evidence_ids'],policy,store,now=self.now,
                observed_endpoints=self.diagnosis['business_observations']['domains'][0]['endpoints'],
                business_requirement_evidence_ids=request['business_requirement_evidence_ids'])
        patrol.execute_workflow(self.state,self.diagnosis,result,self.now,request=protected)
        self.assertEqual([call['operation'] for call in calls],['route_evaluate'])
        second=self.observe()
        review=next(case for case in second['cases'] if case['key']=='route-review:'+domain)
        self.assertTrue(review['requires_attention']);self.assertEqual(review['facts']['action'],'apply')
        self.assertEqual(review['facts']['proposal']['expected_version'],'policy-current')
        self.assertEqual(second['workflow']['result']['wake'],'urgent');self.assertFalse(review['network_restored'])
    def test_model_supplied_routing_flags_cannot_create_a_root_candidate(self):
        self.diagnosis['business_observations']={'issues':[],'checks':{},'route_candidates':[{'domain':'fake.example.com',
            'current_path_bad':True,'current_route_conflicts':True,'business_basis':{'public':True,'required_path':'direct','evidence':['invented']}}]}
        self.assertEqual(self.observe()['routing']['candidates'],[])


if __name__=='__main__':unittest.main()
