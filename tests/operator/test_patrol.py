import unittest
from unittest.mock import patch
from patrol import should_run_ai, repair_choice, fault_signature, preempt_needed,audit_interval,urgent_ai_needed
from test_broker import healthy_result

class PatrolTests(unittest.TestCase):
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
