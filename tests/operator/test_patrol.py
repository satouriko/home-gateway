import unittest
import copy
import io
import json
from pathlib import Path
import tempfile
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from patrol import should_run_ai, repair_choice, fault_signature, preempt_needed,audit_interval,urgent_ai_needed,fault_keys
from test_broker import healthy_result

class PatrolTests(unittest.TestCase):
    def test_diagnostic_input_fault_survives_confirmation_and_repair_verification(self):
        import patrol
        class Captured(Exception):pass
        for transition in ['confirmation','repair']:
            with self.subTest(transition=transition),tempfile.TemporaryDirectory() as folder:
                bad=healthy_result();bad['checks']['mainland_https']={'ok':False,'error':'timeout'}
                diagnoses=[bad,healthy_result()]
                def call(request):
                    if request['operation']=='diagnose':return copy.deepcopy(diagnoses.pop(0))
                    if request['operation']=='traffic_status':return {'status':'observed','domains':[]}
                    if request['operation']=='restore_gateway':return {'verification':healthy_result()}
                    if request['operation']=='quality':return {}
                    raise AssertionError(request)
                def capture(state,diagnosis,*args,**kwargs):
                    self.assertIn('diagnostic_input',diagnosis.get('maintenance_input_errors',[]))
                    raise Captured()
                with patch.object(patrol,'STATE',Path(folder)),patch.object(patrol,'call',side_effect=call),patch.object(patrol,'inspect_active',return_value={'active':True,'version':'good','input_unavailable':True}),patch.object(patrol,'repair_choice',return_value='restore_gateway' if transition=='repair' else None),patch.object(patrol.maintenance,'observe',side_effect=capture):
                    with self.assertRaises(Captured):patrol.main()

    def test_workflow_selected_target_controls_actual_endpoint_probes_and_shared_budget(self):
        import patrol
        now=1800000000;endpoint={'network':'tcp','port':5223,'application_protocol':'unknown'}
        for selected in ['first.example.com','second.example.com']:
            calls=[];state={'business_observations':{'checks':{},'issues':[],
                'domains':[{'domain':domain,'endpoints':[endpoint]} for domain in ['first.example.com','second.example.com']]}}
            upkeep={'workflow':{'result':{'probe_domains':[selected],'route_candidates':[]}},'routing':{'candidates':[]}}
            self.assertTrue(patrol.execute_workflow(state,healthy_result(),upkeep,now,request=lambda value:calls.append(value) or {'state':'observed'}))
            self.assertEqual(calls,[{'operation':'probe_compare','target':selected,'endpoint':endpoint}])
            self.assertEqual(state['business_observations']['checks'][selected]['at'],now)
            patrol.execute_workflow(state,healthy_result(),upkeep,now+10,request=lambda value:calls.append(value) or {})
            self.assertEqual(len(calls),1)
    def test_workflow_empty_or_unknown_endpoints_never_fall_back_to_https_443(self):
        import patrol
        for selected in [[],['unknown.example.com']]:
            calls=[];state={'business_observations':{'checks':{},'domains':[{'domain':'unknown.example.com'}]}}
            upkeep={'workflow':{'result':{'probe_domains':selected,'route_candidates':[]}},'routing':{'candidates':[]}}
            patrol.execute_workflow(state,healthy_result(),upkeep,1800000000,request=lambda value:calls.append(value) or {})
            self.assertEqual(calls,[])
            if selected:self.assertEqual(state['business_observations']['checks'][selected[0]]['result']['state'],'endpoint_unknown')
    def test_workflow_selected_root_candidate_is_revalidated_and_recorded_for_actual_ai_application(self):
        import patrol
        now=1800000000
        candidates=[{'domain':domain,'path':'proxy','evidence_ids':['cmp_a','cmp_b'],
            'business_requirement_evidence_ids':['req_actual']} for domain in ['first.example.com','second.example.com']]
        for selected in ['first.example.com','second.example.com']:
            calls=[];state={'business_observations':{'checks':{},'issues':[]}}
            upkeep={'workflow':{'result':{'probe_domains':[],'route_candidates':[selected]}},'routing':{'candidates':candidates}}
            patrol.execute_workflow(state,healthy_result(),upkeep,now,request=lambda value:calls.append(value) or
                {'action':'apply','proposal':{'domain':value['target'],'path':'proxy','expected_version':'policy-current'},'network_restored':False})
            self.assertEqual(calls,[{'operation':'route_evaluate','target':selected,'path':'proxy','evidence_ids':['cmp_a','cmp_b'],
                'business_requirement_evidence_ids':['req_actual']}])
            self.assertEqual(state['routing_reviews'][selected]['result']['action'],'apply')
            self.assertFalse(state['routing_reviews'][selected]['result']['network_restored'])
    def test_production_cycle_keeps_path_confidence_and_dispatches_case_progress_with_controls(self):
        import patrol
        import maintenance
        import workflow
        from business_watch import scan
        from incidents import IncidentStore
        for disposed in [False,True]:
            with self.subTest(disposed=disposed),tempfile.TemporaryDirectory() as folder:
                directory=Path(folder);now=1800000000;diagnosis=healthy_result();snapshots=[];commands=[]
                endpoint={'network':'tcp','port':5223,'application_protocol':'unknown'}
                observed={'status':'observed','domains':[{'domain':'real.example.com','last_seen':now,'last_failure_at':now-10,
                    'recurring_failure':True,'failure_count':5,'error_categories':['dial_timeout'],'endpoints':[endpoint]}]}
                business=scan(observed,{},lambda target,**kwargs:{},now,allow_probe=False);probe_calls=[]
                state={'business_observations':business,'healthy_samples':100,'confidence_program_version':'v',
                    'last_ai_at':now-1000,'last_routine_ai_at':now-10000,'last_independent_audit_at':now-100,
                    'diagnostic_program':{'active':True,'version':'v'}}
                source=(Path(__file__).parents[2]/'src/maintained/workflow.py').read_text()
                policy=lambda snapshot:{'active':False,'version':'builtin','maintenance_required':False,'failures':[],
                    'result':workflow.worker(source,snapshot)}
                first=maintenance.observe(state,{**diagnosis,'business_observations':business},now,directory=directory,inspect=policy)
                if disposed:
                    case=first['cases'][0];IncidentStore(directory/'incidents.json').decide(case['id'],case['revision'],
                        {'status':'closed','outcome':'no_route_remedy','priority':'normal','reason':'Both routes fail endpoint; independent controls pass',
                         'evidence':['compare:both-paths','controls:healthy'],'next_review_at':now+600},'investigator',now)
                (directory/'patrol.json').write_text(json.dumps(state));(directory/'native.json').write_text('{"session_id":"native","runs":[]}')
                def call(request):
                    if request['operation']=='diagnose':return copy.deepcopy(diagnosis)
                    if request['operation']=='traffic_status':return observed
                    if request['operation']=='quality':return {}
                    if request['operation']=='probe_compare':
                        probe_calls.append(request);return{'state':'observed','endpoint':request['endpoint'],
                            'paths':{'direct':{'transport_ok':False,'failed_samples':3,'success_samples':0},
                                     'proxy':{'transport_ok':False,'failed_samples':3,'success_samples':0}},'application_verified':False}
                    raise AssertionError(request)
                def command(args,**kwargs):commands.append(args);return SimpleNamespace(stdout='inactive' if args[1]=='is-active' else 'success',returncode=0)
                real_observe=maintenance.observe
                def upkeep(*args,**kwargs):return real_observe(*args,**{**kwargs,'directory':directory,'inspect':policy})
                def program(snapshot):snapshots.append(copy.deepcopy(snapshot));return{'active':True,'version':'v','result':{'action':'none','probe_domains':[]}}
                context=directory/'context.json'
                with patch.object(patrol,'STATE',directory),patch.object(patrol,'CONTEXT',context),patch.object(patrol.native,'STATE',directory),patch.object(patrol.native,'PATH',directory/'native.json'),patch.object(patrol.time,'time',return_value=now),patch.object(patrol,'call',side_effect=call),patch.object(patrol,'inspect_active',side_effect=program),patch.object(patrol.maintenance,'observe',side_effect=upkeep),patch.object(patrol.subprocess,'run',side_effect=command),patch.object(patrol,'save',side_effect=lambda p,v,group=None:p.write_text(json.dumps(v))),redirect_stdout(io.StringIO()):patrol.main()
                saved=json.loads((directory/'patrol.json').read_text())
                self.assertEqual(saved['healthy_samples'],101);self.assertEqual(saved['history'][-1]['faults'],[])
                self.assertEqual(snapshots[0]['observations'],snapshots[0]['business_observations'])
                self.assertEqual(any(args[1]=='start' for args in commands),not disposed)
                self.assertEqual(probe_calls,[] if disposed else [{'operation':'probe_compare','target':'real.example.com','endpoint':endpoint}])
                self.assertIn('maintenance',saved)
                if not disposed:
                    actual=json.loads(context.read_text());self.assertTrue(actual['urgent'])
                    self.assertTrue(actual['maintenance']['cases']);self.assertTrue(actual['maintenance']['path_health']['checks']['proxy_https']['ok'])
                    self.assertFalse(actual['maintenance']['cases'][0]['facts']['paths']['direct']['transport_ok'])
                    self.assertEqual(actual['maintenance']['cases'][0]['facts']['paths']['direct']['failed_samples'],3)
    def test_disposed_business_cases_do_not_poison_global_path_health(self):
        result=healthy_result();result['business_observations']={'issues':[{'domain':'old.example.com','resolved':False}]}
        self.assertEqual(fault_keys(result),[])
        self.assertFalse(urgent_ai_needed({},result,1800000000))
    def test_provider_and_cumulative_counts_do_not_change_fault_signature(self):
        result=healthy_result();result['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
        first=fault_signature(result);result['status']['provider_counts']={'pool':400}
        self.assertEqual(fault_signature(result),first)
    def test_due_urgent_case_rewakes_after_review_delay_while_active_lease_does_not(self):
        now=1800000000;result=healthy_result()
        case={'id':'case-fixture','revision':2,'status':'blocked','priority':'urgent','requires_attention':True,'next_review_at':now}
        result['maintenance']={'cases':[case],'faults':[],'next_check_seconds':120,'workflow':{'result':{'wake':'urgent'}}}
        self.assertTrue(urgent_ai_needed({},result,now))
        state={'last_ai_at':now,'last_ai_fingerprint':fault_signature(result)}
        self.assertFalse(urgent_ai_needed(state,result,now+10));self.assertTrue(urgent_ai_needed(state,result,now+120))
        case.update(status='working',requires_attention=False,next_review_at=now+600)
        result['maintenance']['workflow']['result']['wake']='none'
        self.assertFalse(urgent_ai_needed({},result,now+30))
    def test_real_path_fault_retains_urgency_but_an_owned_lease_prevents_a_duplicate_turn(self):
        now=1800000000;result=healthy_result();result['checks']['proxy_https']={'ok':False}
        case={'id':'case-owned-path','key':'path:proxy_https','revision':2,'status':'working','priority':'urgent',
              'requires_attention':False,'next_review_at':now+600}
        result['maintenance']={'cases':[case],'faults':[],'next_check_seconds':300,'workflow':{'result':{'wake':'urgent'}}}
        self.assertFalse(urgent_ai_needed({'last_ai_at':now},result,now+10))
        result['checks']['bootstrap_dns_api']={'ok':False}
        self.assertTrue(urgent_ai_needed({'last_ai_at':now},result,now+10))
        del result['checks']['bootstrap_dns_api'];case.update(status='closed')
        state={'last_ai_at':now,'last_ai_fingerprint':fault_signature(result)}
        self.assertTrue(urgent_ai_needed(state,result,now+300))
    @patch('patrol.routine_allowed',return_value=True)
    def test_workflow_normal_attention_uses_native_routine_budget_and_spacing(self,_allowed):
        now=1800000000;state={'last_ai_at':now-100,'last_routine_ai_at':now-8000,
            'diagnostic_program':{'active':True},'maintenance':{'workflow':{'result':{'wake':'routine'}}}}
        self.assertTrue(should_run_ai(state,healthy_result(),now))
        state['routine_run_times']=[now-15000]*6
        self.assertFalse(should_run_ai(state,healthy_result(),now))
        state['routine_run_times']=[];state['last_routine_ai_at']=now-100
        self.assertFalse(should_run_ai(state,healthy_result(),now))
    @patch('patrol.routine_allowed',return_value=True)
    def test_scheduled_0542_independent_audit_does_not_wait_until_0710_after_0109_urgent_turn(self,_allowed):
        from datetime import datetime,timezone
        stamp=lambda text:datetime.fromisoformat('2026-11-04T'+text+'+00:00').timestamp()
        now=stamp('05:42:00');result=healthy_result();result['checks']['proxy_https']={'ok':False}
        state={'last_ai_at':stamp('01:09:00'),'last_ai_kind':'anomaly','last_ai_fingerprint':fault_signature(result),
            'last_routine_ai_at':now-21600,'last_independent_audit_at':now-21600,'audit_rollup':{'samples':40},
            'diagnostic_program':{'active':True,'version':'v'},'audit_plan':{'interval_hours':6,'daily_budget':6,'expires_at':now+60,'for_program_version':'v'}}
        self.assertTrue(should_run_ai(state,result,now))
    def test_old_node_review_never_overwrites_a_new_program_failure(self):
        import patrol
        state={'review_request':{'fingerprint':'program-failed:new','reason':'worker failed'}}
        nodes={'review_due':True,'fingerprint':'node-pool:old','incident_history':[]}
        patrol.maybe_request_node_review(state,nodes,{'node-pool:old':100})
        self.assertEqual(state['review_request']['fingerprint'],'program-failed:new')
        patrol.maybe_request_node_review(state,{**nodes,'fingerprint':'node-pool:new'}, {})
        self.assertEqual(state['review_request']['fingerprint'],'program-failed:new')
        patrol.maybe_request_node_review(state,{**nodes,'fingerprint':'node-pool:new'},{'program-failed:new':100})
        self.assertEqual(state['review_request']['fingerprint'],'node-pool:new')
    def test_node_pool_incident_wakes_ai_even_when_coarse_https_probe_passes(self):
        result=healthy_result();result['node_observations']={'urgent':True,'fingerprint':'node-pool:first'}
        self.assertTrue(urgent_ai_needed({},result,1800000000))
        self.assertEqual(repair_choice(result),'recheck_nodes')
        first=fault_signature(result);state={'last_ai_fingerprint':first}
        self.assertFalse(urgent_ai_needed(state,result,1800000010))
        result['node_observations']['fingerprint']='node-pool:second'
        self.assertTrue(urgent_ai_needed(state,result,1800000020))
        result['node_observations']['urgent']=False
        self.assertFalse(urgent_ai_needed(state,result,1800000030))
    def test_restored_disabled_task_cannot_fall_back_to_legacy_routine_ai(self):
        state={'audit_plan':{'enabled':False},'last_ai_at':0}
        with patch('patrol.routine_allowed',return_value=True):
            self.assertFalse(should_run_ai(state,healthy_result(),1800000000))
            fault=healthy_result();fault['checks']['proxy_https']={'ok':False}
            self.assertTrue(should_run_ai(state,fault,1800000000))
    @patch('patrol.routine_allowed',return_value=True)
    def test_persistent_analyzed_fault_still_gets_a_budgeted_independent_second_look(self,_allowed):
        now=1800000000;result=healthy_result();result['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
        state={'last_ai_at':now-5*3600,'last_ai_fingerprint':fault_signature(result),'last_independent_audit_at':now-6*3600,'audit_rollup':{'samples':100}}
        self.assertFalse(urgent_ai_needed(state,result,now));self.assertTrue(should_run_ai(state,result,now))
        with patch('patrol.routine_allowed',return_value=False):self.assertFalse(should_run_ai(state,result,now))
    def test_new_install_trains_itself_without_a_user_request(self):
        self.assertTrue(should_run_ai({'last_ai_at':0},healthy_result(),100))
    @patch('patrol.routine_allowed',return_value=True)
    def test_healthy_checks_do_not_call_ai_each_time(self,_allowed):
        self.assertFalse(should_run_ai({'last_ai_at':100},healthy_result(),200))
        self.assertFalse(should_run_ai({'last_ai_at':100},healthy_result(),100+365*86400))
    def test_analyzed_unchanged_fault_is_not_rebilled_by_the_clock(self):
        result=healthy_result();result['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
        self.assertTrue(should_run_ai({'last_ai_at':100},result,200))
        state={'last_ai_at':100,'last_ai_fingerprint':fault_signature(result)}
        self.assertFalse(should_run_ai(state,result,200))
        self.assertFalse(should_run_ai(state,result,100+86400))
        self.assertTrue(should_run_ai({'last_ai_at':100},result,2000))
        self.assertEqual(repair_choice(result),'recheck_nodes')
    def test_new_fault_preempts_active_or_starting_routine(self):
        result=healthy_result();result['checks']['bootstrap_dns_api']={'ok':False}
        for job in ['active','activating']:
            self.assertTrue(preempt_needed({},result,job,{'urgent':False}))
            self.assertFalse(preempt_needed({},result,job,{'urgent':True}))
    @patch('patrol.routine_allowed',return_value=True)
    def test_actionable_review_is_deduplicated_and_has_daily_budget(self,_allowed):
        now=1800000000;state={'last_ai_at':now-1000,'review_request':{'fingerprint':'gap','reason':'missing measurement'}}
        self.assertTrue(should_run_ai(state,healthy_result(),now))
        state['last_routine_ai_at']=now-100
        self.assertFalse(should_run_ai(state,healthy_result(),now))
    @patch('patrol.routine_allowed',return_value=True)
    def test_independent_audit_checks_for_program_misses_without_high_frequency(self,_allowed):
        now=1800000000;state={'last_ai_at':now-8*86400,'last_independent_audit_at':now-8*86400,
            'audit_rollup':{'samples':200},'diagnostic_program':{'active':True,'version':'good'}}
        self.assertTrue(should_run_ai(state,healthy_result(),now))
        state['last_independent_audit_at']=now-3600
        self.assertFalse(should_run_ai(state,healthy_result(),now))
    def test_audit_confidence_and_model_policy_change_the_interval(self):
        now=1800000000;state={'program_started_at':now,'healthy_samples':8,'diagnostic_program':{'version':'v'}}
        self.assertEqual(audit_interval(state,now),4)
        state.update(program_started_at=now-4*86400,healthy_samples=1000)
        self.assertEqual(audit_interval(state,now),12)
        state.update(program_started_at=now-8*86400,healthy_samples=3000,successful_audits=3)
        self.assertEqual(audit_interval(state,now),24)
        state['audit_plan']={'interval_hours':2,'daily_budget':6,'expires_at':now+100,'for_program_version':'v'}
        self.assertEqual(audit_interval(state,now),4)
        state['audit_plan']['daily_budget']=12
        self.assertEqual(audit_interval(state,now),2)
        state.update(last_routine_ai_at=0,reviewed={'gap':now-3600})
        self.assertFalse(should_run_ai(state,healthy_result(),now))
    def test_routine_is_deferred_at_peak_but_new_fault_is_immediate(self):
        with patch('patrol.routine_allowed',return_value=False):
            self.assertFalse(should_run_ai({'last_ai_at':0},healthy_result(),100))
            result=healthy_result();result['checks']['proxy_https']={'ok':False}
            self.assertTrue(should_run_ai({'last_ai_at':99},result,100))
    def test_direct_policy_does_not_treat_expected_foreign_failure_as_incident(self):
        result=healthy_result();result['status']['policy']={'mode':'direct'};result['checks']['proxy_https']={'ok':False}
        self.assertIsNone(repair_choice(result))
    def test_target_business_denial_does_not_restart_healthy_network(self):
        result=healthy_result();result['business_target']={'http_status':403}
        self.assertIsNone(repair_choice(result))
    def test_gateway_inactive_is_handled_by_program_without_model(self):
        result=healthy_result();result['status']['services']['net-gateway.service']['ActiveState']='failed'
        self.assertEqual(repair_choice(result),'restore_gateway')

if __name__=='__main__':unittest.main()
