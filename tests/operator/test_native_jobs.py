import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import native_jobs as native

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'native.json'
        self.now=1793490000
        self.state={'checked_at':self.now,'last_ai_at':self.now-20000,'last_routine_ai_at':self.now-20000,
                    'last_independent_audit_at':self.now-20000,'audit_rollup':{'samples':40},'diagnostic_program':{'active':True,'version':'v1'}}
        self.diagnosis={'status':{'services':{'net-gateway.service':{'ActiveState':'active'}}},'checks':{}}
        self.state['last_diagnosis']=self.diagnosis
        self.ledger={'session_id':'session-test','schedule_id':'schedule-test','runs':[],'retired':[]}
        self.write()
        prompt=self.path.parent/'prompt.txt';prompt.write_text('instructions')
        p=patch.object(native,'PROMPT',prompt);p.start();self.addCleanup(p.stop)
        for key,value in [('STATE',self.path.parent),('PATH',self.path)]:
            p=patch.object(native,key,value);p.start();self.addCleanup(p.stop)
        for key,value in [('routine_allowed',True),('storage_available',True),('emergency_active',False)]:
            p=patch.object(native,key,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(native,'pricing_state',return_value={'peak':False,'off_peak_seconds_remaining':10000});p.start();self.addCleanup(p.stop)
    def write(self):self.path.write_text(json.dumps(self.ledger))
    def admit(self):return native.admit('session-test',self.state,self.now)
    def test_healthy_due_audit_is_admitted_once_and_not_double_counted(self):
        first=self.admit();self.assertTrue(first['admitted']);self.assertEqual(first['deadline'],self.now+540)
        self.assertFalse(self.admit()['admitted'])
        self.assertEqual(len(json.loads(self.path.read_text())['runs']),1)
    def test_model_never_runs_for_peak_disk_emergency_or_stale_observations(self):
        for key,value in [('routine_allowed',False),('storage_available',False),('emergency_active',True)]:
            with self.subTest(key=key),patch.object(native,key,return_value=value):self.assertFalse(self.admit()['admitted'])
        self.state['checked_at']=self.now-901;self.assertFalse(self.admit()['admitted'])
        self.assertEqual(json.loads(self.path.read_text())['runs'],[])
    def test_other_native_tasks_are_unmanaged_and_retired_jobs_fail_closed(self):
        self.assertFalse(native.admit('user-session',self.state,self.now)['managed'])
        self.ledger['retired']=['old-session'];self.write()
        result=native.admit('old-session',self.state,self.now)
        self.assertTrue(result['managed']);self.assertFalse(result['admitted'])
    def test_successful_old_runs_are_included_in_budget_and_minimum_spacing(self):
        self.ledger['runs']=[{'id':str(i),'at':self.now-15000-i*500,'deadline':self.now-14000-i*500,'state':'completed','kind':'independent_audit','program_version':'v1'} for i in range(6)];self.write()
        self.assertFalse(self.admit()['admitted'])
        self.ledger['runs']=self.ledger['runs'][:1];self.ledger['runs'][0]['at']=self.now-500;self.write()
        self.assertFalse(self.admit()['admitted'])
    def test_unresolved_fault_is_handled_by_emergency_worker(self):
        self.diagnosis['checks']['proxy_https']={'ok':False}
        self.assertFalse(self.admit()['admitted'])
    def test_completion_requires_current_lease_and_cannot_renew_or_rewrite_expiry(self):
        lease=self.admit();self.assertFalse(native.finish('session-test','bad','completed',self.now+1)['updated'])
        self.assertTrue(native.finish('session-test',lease['id'],'completed',self.now+30)['updated'])
        self.assertFalse(native.finish('session-test',lease['id'],'failed',self.now+31)['updated'])
        later=native.admit('session-test',self.state,self.now+550);self.assertFalse(later['admitted'])
    def test_expired_lease_cannot_be_reported_as_success(self):
        lease=self.admit();result=native.finish('session-test',lease['id'],'completed',self.now+541)
        self.assertEqual(result['state'],'expired')
    def test_same_improvement_evidence_is_not_rebilled_after_success(self):
        self.state['review_request']={'fingerprint':'same-gap','reason':'coverage'}
        lease=self.admit();native.finish('session-test',lease['id'],'completed',self.now+1)
        self.state['checked_at']=self.now+7201
        self.assertFalse(native.admit('session-test',self.state,self.now+7201)['admitted'])
    def test_old_program_audits_do_not_inflate_new_program_confidence(self):
        ledger={'runs':[{'id':str(i),'at':self.now-3000-i,'deadline':self.now-2000,'state':'completed','kind':'independent_audit','program_version':'v0'} for i in range(3)]}
        effective=native.effective_state(self.state,ledger)
        self.assertEqual(effective['successful_audits'],0)
    def test_initial_integration_review_uses_normal_spacing_and_budget(self):
        self.state.update(last_ai_at=self.now-9000,last_routine_ai_at=self.now-9000,last_independent_audit_at=self.now-9000)
        self.assertFalse(self.admit()['admitted'])
        self.ledger['initial_review']=True;self.write()
        lease=self.admit();self.assertTrue(lease['admitted']);self.assertEqual(lease['kind'],'independent_audit')
        self.assertFalse(json.loads(self.path.read_text())['initial_review'])

    def test_deleted_task_stays_disabled_and_its_definition_is_retained(self):
        definition={'id':'schedule-test','kind':'every','title':'自定义','prompt':'检查我的网络','everySeconds':21600,'scheduledAt':'2026-11-02T00:00:00Z','status':'active'}
        native.observe(definition);native.observe(None)
        self.assertFalse(self.admit()['admitted'])
        plan=json.loads((self.path.parent/'audit-plan.json').read_text())
        self.assertFalse(plan['enabled']);self.assertEqual(plan['schedule']['prompt'],definition['prompt'])
    def test_native_edits_change_the_actual_interval_and_duplicate_occurrences_are_free(self):
        self.ledger['observed_task']={'kind':'every','everySeconds':21600};self.write()
        self.assertFalse(self.admit()['admitted'])
        self.state['last_independent_audit_at']=self.now-25000
        lease=native.admit('session-test',self.state,self.now,occurrence='same')
        self.assertTrue(lease['admitted']);native.finish('session-test',lease['id'],'completed',self.now+1)
        self.state['checked_at']=self.now+25000
        self.assertFalse(native.admit('session-test',self.state,self.now+25000,occurrence='same')['admitted'])
    def test_last_recurring_occurrence_uses_live_task_even_when_restore_preference_is_disabled(self):
        self.ledger['observed_task']={'kind':'every','everySeconds':14400,'status':'inactive'};self.write()
        self.state['audit_plan']={'enabled':False}
        self.assertTrue(self.admit()['admitted'])
    def test_dispatch_rechecks_emergency_under_shared_lock_and_preserves_urgent_context(self):
        lease=self.admit()
        with patch.object(native,'emergency_active',return_value=True),patch.object(native,'CONTEXT',self.path.parent/'context'):
            self.assertFalse(native.dispatch_job(lease)['admitted'])
            self.assertFalse(native.CONTEXT.exists())
    def test_headless_receipt_keeps_its_execution_identity_and_real_summary(self):
        lease=self.admit()
        native.finish('session-test',lease['id'],'completed',self.now+1,execution_session_id='worker-session',summary='检查通过')
        job=native.read()['runs'][-1]
        self.assertEqual(job['execution_session_id'],'worker-session');self.assertEqual(job['summary'],'检查通过')

    def test_task_restore_retires_schedule_identity_without_retiring_same_source_session(self):
        with patch.object(native,'publish_identity'):
            native.bind('session-test','replacement-task')
        ledger=native.read();self.assertIn('schedule-test',ledger['retired_schedule_ids']);self.assertNotIn('session-test',ledger['retired'])
    def test_cancelled_dispatch_never_writes_context_or_starts_service(self):
        lease=self.admit()
        with patch.object(native,'CONTEXT',self.path.parent/'context'),patch.object(native.time,'time',return_value=self.now),patch.object(native.subprocess,'run') as start:
            result=native.dispatch_job(lease,cancelled=lambda:True)
            self.assertFalse(result['admitted']);self.assertFalse(native.CONTEXT.exists());start.assert_not_called()

    def test_new_fault_preempts_native_work_and_leaves_emergency_path_free(self):
        lease=self.admit();self.diagnosis['checks']['proxy_https']={'ok':False}
        context=self.path.parent/'context.json';context.write_text(json.dumps({'native_job_id':lease['id'],'urgent':False}))
        with patch.object(native,'CONTEXT',context),patch.object(native.subprocess,'run') as stop:
            native.supervise(self.diagnosis,self.now+20)
            self.assertIn('stop',stop.call_args.args[0])
        self.assertFalse(native.check('session-test',lease['id'],self.now+21)['continue'])
        self.assertEqual(json.loads(self.path.read_text())['runs'][-1]['state'],'preempted')

if __name__=='__main__':unittest.main()
