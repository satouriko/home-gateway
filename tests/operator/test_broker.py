import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import broker

def healthy_result():
    return {'status':{'services':{'net-gateway.service':{'ActiveState':'active'}}},'checks':{
      'gateway_dns_cn':{'ok':True,'result':{'rcode':0,'answer_count':1}},
      'gateway_dns_foreign':{'ok':True,'result':{'rcode':0,'answer_count':1}},
      'bootstrap_dns_api':{'ok':True,'result':{'rcode':0,'answer_count':1}},
      'mainland_https':{'ok':True,'result':{'http_status':200}},
      'proxy_https':{'ok':True,'result':{'http_status':204,'expected_health_status':True}}}}

class RecoveryTests(unittest.TestCase):
    def test_integration_hold_keeps_pending_publications_without_restarting_a_skipped_service(self):
        with tempfile.TemporaryDirectory() as folder:
            hold=Path(folder)/'hold';hold.touch()
            with patch.object(broker,'SYNC_HOLD',hold,create=True),patch.object(broker,'command') as command:
                self.assertFalse(broker.dispatch_source_sync_once());command.assert_not_called()

    def test_successful_local_publications_request_sync_but_tests_and_unverified_policy_do_not(self):
        for operation,result,expected in [
            ('program_publish',{'deployed':True},True),('tool_publish',{'deployed':True},True),
            ('skill_publish',{'deployed':True},True),('audit_plan_set',{'interval_hours':4},True),
            ('policy_apply',{'verified_healthy':True,'rollback_armed':False},True),
            ('policy_apply',{'verified_healthy':False,'rollback_armed':True},False),
            ('program_test',{'deployed':False},False),('tool_test',{'deployed':False},False),
            ('skill_test',{'deployed':False},False),('policy_test',{'tested':True},False)]:
            with self.subTest(operation=operation,result=result),patch.object(broker,'dispatch',return_value=result),patch.object(broker,'queue_source_sync',return_value={'requested':True}) as queue:
                returned=broker.handle({'operation':operation})
                self.assertEqual(queue.called,expected)
                if expected:self.assertTrue(returned['source_control_sync']['requested'])
        with patch.object(broker,'dispatch',side_effect=ValueError('publication failed')),patch.object(broker,'queue_source_sync') as queue:
            with self.assertRaises(ValueError):broker.handle({'operation':'program_publish'})
            queue.assert_not_called()

    def test_sync_dispatch_failure_cannot_undo_a_successful_local_publication(self):
        with patch.object(broker,'dispatch',return_value={'deployed':True,'version':'published'}),patch.object(broker,'queue_source_sync',side_effect=OSError):
            result=broker.handle({'operation':'program_publish'})
            self.assertTrue(result['deployed']);self.assertFalse(result['source_control_sync']['requested'])

    def test_publish_queue_is_durable_and_detects_a_second_publication_during_push(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'SYNC_STATUS',Path(folder)/'status.json'),patch.object(broker,'start_sync_dispatcher'):
            broker.queue_source_sync('program_publish')
            request=json.loads((Path(folder)/'source-sync-request.json').read_text())
            self.assertTrue(broker.source_sync_pending())
            def first_push(*args,**kwargs):
                broker.queue_source_sync('skill_publish')
                (Path(folder)/'status.json').write_text(json.dumps({'acknowledged_request':request['id']}))
            with patch.object(broker,'command',side_effect=first_push):
                self.assertTrue(broker.dispatch_source_sync_once())
            latest=json.loads((Path(folder)/'source-sync-request.json').read_text())
            def second_push(*args,**kwargs):
                (Path(folder)/'status.json').write_text(json.dumps({'acknowledged_request':latest['id']}))
            with patch.object(broker,'command',side_effect=second_push):
                self.assertFalse(broker.dispatch_source_sync_once())
            self.assertFalse(broker.source_sync_pending())

    def test_failed_push_leaves_pending_request_without_a_busy_retry_loop(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'SYNC_STATUS',Path(folder)/'status.json'),patch.object(broker,'start_sync_dispatcher'):
            broker.queue_source_sync('tool_publish')
            with patch.object(broker,'command',side_effect=OSError):
                self.assertFalse(broker.dispatch_source_sync_once())
            self.assertTrue(broker.source_sync_pending())

    def test_source_control_context_is_current_and_excludes_private_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'status.json'
            path.write_text(json.dumps({'repository_url':'https://github.com/example/project','branch':'main',
                'result':'success','remote_commit':'a'*40,'last_success_at':123,'private_key':'must not enter model context'}))
            result=broker.source_control_status(path)
            self.assertTrue(result['available']);self.assertEqual(result['branch'],'main')
            self.assertEqual(result['remote_commit'],'a'*40);self.assertNotIn('private_key',result)
            path.write_text('broken')
            self.assertFalse(broker.source_control_status(path)['available'])

    def test_policy_metadata_recovers_current_preferences_instead_of_initial_defaults(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)):
            p=Path(folder);(p/'known-good').mkdir()
            expected={**broker.INSTALL_POLICY,'preferences':{'preferred_label':'日本'}}
            (p/'known-good/policy.json').write_text(json.dumps(expected))
            (p/'approved-policy.json').write_text('broken')
            self.assertEqual(broker.current_policy(),expected)
    def test_login_guard_replaces_a_symlink_without_touching_its_target(self):
        import os
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/'state';state.mkdir();login=Path(folder)/'login';login.mkdir()
            source=Path(folder)/'outside';source.write_text('untouched')
            credentials=login/'credentials.yaml';credentials.symlink_to(source)
            (state/'bootstrap-login.yaml').write_text('version: 1\nrecords: {}\n')
            with patch.object(broker,'STATE',state),patch.object(broker,'LOGIN',credentials),patch.object(broker.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())):
                broker.guard_login()
            self.assertFalse(credentials.is_symlink());self.assertEqual(source.read_text(),'untouched')
            self.assertEqual(len(list(login.glob('invalid-*'))),1)
    def test_login_guard_failure_cannot_block_network_recovery(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'boot_id',return_value='boot'),patch.object(broker,'restore_gateway') as restore,patch.object(broker,'guard_login',side_effect=PermissionError),patch.object(broker,'service',return_value={'ActiveState':'active'}),patch.object(broker,'agent_ready',return_value=True),patch('control_route.apply'),contextlib.redirect_stdout(io.StringIO()):
            (Path(folder)/'pending.json').write_text(json.dumps({'deadline':0,'boot_id':'boot'}))
            broker.watchdog();restore.assert_called_once()
    def test_transaction_lock_is_shared_with_another_process(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)):
            child=subprocess.Popen([sys.executable,'-c','import fcntl,sys,time;f=open(sys.argv[1],"a");fcntl.flock(f,fcntl.LOCK_EX);print("ready",flush=True);time.sleep(10)',str(Path(folder)/'transaction.lock')],stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'ready')
                with self.assertRaises(ValueError):broker.acquire_transaction()
                self.assertTrue(broker.LOCK.acquire(blocking=False));broker.LOCK.release()
            finally:child.terminate();child.wait();child.stdout.close()
    def test_running_service_with_broken_dns_is_not_healthy(self):
        result=healthy_result();result['checks']['gateway_dns_cn']['result']['answer_count']=0
        self.assertFalse(broker.verification_healthy(result))

    def test_running_service_with_proxy_failure_is_not_healthy(self):
        result=healthy_result();result['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
        self.assertFalse(broker.verification_healthy(result))

    def test_all_probes_healthy_is_accepted(self):self.assertTrue(broker.verification_healthy(healthy_result()))

    def test_repair_persists_the_same_final_verdict_returned_to_its_caller(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'command'),patch.object(broker,'boot_id',return_value='boot'),patch.object(broker,'diagnose',return_value=healthy_result()):
            returned=broker.repair('recheck_nodes')
            stored=json.loads((Path(folder)/'last-repair.json').read_text())
            self.assertTrue(returned['verified_healthy']);self.assertIs(stored.get('verified_healthy'),True)

    def test_failed_repair_remains_armed_and_cannot_extend_deadline(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(broker,'STATE',Path(folder)), patch.object(broker,'command'), patch.object(broker,'boot_id',return_value='boot'):
            result=healthy_result();result['checks']['proxy_https']={'ok':False,'error':'TimeoutError'}
            with patch.object(broker,'diagnose',return_value=result):
                report=broker.repair('recheck_nodes')
            self.assertFalse(report['verified_healthy'])
            pending=Path(folder)/'pending.json';before=pending.read_bytes()
            with self.assertRaises(ValueError):broker.repair('recheck_nodes')
            self.assertEqual(pending.read_bytes(),before)

    def test_expired_repair_recovers_without_model_or_broker_connection(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(broker,'STATE',Path(folder)), patch.object(broker,'boot_id',return_value='boot'), patch.object(broker,'restore_gateway') as restore, patch.object(broker,'service',return_value={'ActiveState':'active'}), patch.object(broker,'agent_ready',return_value=True), patch('control_route.apply'), contextlib.redirect_stdout(io.StringIO()):
            pending=Path(folder)/'pending.json';pending.write_text(json.dumps({'deadline':0,'boot_id':'boot'}))
            broker.watchdog()
            restore.assert_called_once();self.assertFalse(pending.exists())

    def test_unresponsive_agent_is_restarted_without_a_model(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(broker,'STATE',Path(folder)), patch.object(broker,'service',return_value={'ActiveState':'active'}), patch.object(broker,'agent_ready',return_value=False), patch.object(broker,'command') as command, patch('control_route.apply'), contextlib.redirect_stdout(io.StringIO()):
            broker.watchdog()
            self.assertIn(('systemctl','restart','dsh.service'),[call.args for call in command.call_args_list])

    def test_restore_validates_and_restores_checkpoint_policy_as_a_pair(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/'state';state.mkdir();config=Path(folder)/'config.json'
            saved={'rule-providers':{'proxy-domains':{'path':'old'}}}
            approved={'version':'old-approved'}
            (state/'known-good-config.json').write_text(json.dumps(saved))
            (state/'known-good-policy.json').write_text(json.dumps(approved))
            (state/'known-good-rules.yaml').write_text('payload: []')
            with patch.object(broker,'STATE',state),patch.object(broker,'CONFIG',config),patch.object(broker,'command'),patch.object(broker,'validate_baseline') as validate,patch.object(broker.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=999)):
                broker.restore_gateway()
                self.assertEqual(validate.call_args.args[2],approved)
                self.assertEqual(json.loads((state/'approved-policy.json').read_text()),approved)

    def test_failed_policy_change_keeps_old_checkpoint_and_arms_recovery(self):
        from test_user_policy import UserPolicyTests
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/'state';state.mkdir();(state/'known-good').mkdir()
            config=Path(folder)/'config.json';config.write_text(json.dumps(UserPolicyTests().fixture()))
            old={'mode':'rule','proxy_chain':['US_AUTO','OTHER_AUTO'],'region_providers':{'US_AUTO':'us','OTHER_AUTO':'other'},'default_rule':'MATCH,PROXY'}
            (state/'approved-policy.json').write_text(json.dumps(old))
            broken=healthy_result();broken['checks']['proxy_https']={'ok':False}
            with patch.object(broker,'STATE',state),patch.object(broker,'CONFIG',config),patch.object(broker,'command'),patch.object(broker,'api'),patch.object(broker,'diagnose',return_value=broken),patch.object(broker,'checkpoint') as checkpoint,patch.object(broker.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=999)):
                result=broker.policy_action('policy_apply',{'preferred_label':'日本','preferred_keywords':['日本']},{'id':'test-request','text':'更改地区偏好'})
            self.assertFalse(result['verified_healthy']);self.assertTrue(result['rollback_armed'])
            self.assertTrue((state/'pending.json').exists());checkpoint.assert_not_called()

if __name__=='__main__':unittest.main()
