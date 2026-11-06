from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import operation_history as history

SID='session-12345678-1234-1234-1234-123456789abc'


class OperationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=history.OperationHistory(Path(self.temp.name)/'operations.json')
        clock=patch.object(history.time,'time',return_value=1002);clock.start();self.addCleanup(clock.stop)

    def test_crashed_owner_releases_orphaned_operation_without_inventing_a_rollback(self):
        first=self.store.begin('recheck_nodes',SID,now=1000)
        with patch.object(history,'owner_alive',return_value=False):
            recovered=history.OperationHistory(self.store.path).read()['records'][0]
        self.assertEqual(recovered['status'],'interrupted');self.assertNotIn('gateway_restarted',recovered)
        second=self.store.begin('refresh_subscription',SID,now=1002)
        self.store.finish(second['id'],result={'verified_healthy':True},now=1003)
        notice=self.store.notices()['notices'][0]
        self.assertEqual([x['status'] for x in notice['records']],['interrupted','verified'])

    def test_live_owner_is_bounded_by_an_explicit_execution_lease(self):
        self.store.begin('recheck_nodes',SID,now=1000)
        with patch.object(history.time,'time',return_value=1601):
            self.assertEqual(self.store.read()['records'][0]['status'],'interrupted')

    def test_failed_attempt_and_watchdog_recovery_are_correlated_without_private_messages(self):
        item=self.store.begin('recheck_nodes',SID,now=1000)
        self.store.finish(item['id'],error=TimeoutError('private value must never be saved'),transaction_id='a'*32,now=1001)
        self.store.recovery({'id':'a'*32,'operation_record_id':item['id'],'session_id':SID},now=1100)
        records=self.store.read()['records']
        self.assertEqual(records[0]['status'],'pending_rollback');self.assertEqual(records[0]['error_code'],'TimeoutError')
        self.assertEqual(records[-1]['status'],'rolled_back');self.assertTrue(records[-1]['gateway_restarted'])
        self.assertEqual(records[-1]['related_id'],item['id']);self.assertNotIn('private',str(records))
        notice=self.store.notices()['notices'][0]
        self.assertEqual(len(notice['records']),2)
        self.assertFalse(self.store.acknowledge(SID,notice['revision'],'wrong')['acknowledged'])
        self.assertTrue(self.store.acknowledge(SID,notice['revision'],notice['notice_id'])['acknowledged'])
        self.assertEqual(self.store.notices()['notices'],[])

    def test_rejected_attempt_is_not_reported_as_verified_or_as_a_successful_change(self):
        item=self.store.begin('refresh_subscription',SID,now=1000)
        self.store.finish(item['id'],error=ValueError('private pending reason'),now=1001)
        row=self.store.read()['records'][0]
        self.assertEqual(row['status'],'rejected');self.assertNotIn('verified_healthy',row)

    def test_inflight_work_waits_for_completion_and_ack_cannot_skip_future_records(self):
        item=self.store.begin('recheck_nodes',SID,now=1000)
        self.assertEqual(self.store.notices()['notices'],[])
        self.assertFalse(self.store.acknowledge(SID,999,'gateway-operations-'+SID[8:].replace('-','')+'-999')['acknowledged'])
        self.store.finish(item['id'],result={'verified_healthy':True,'rollback_armed':False},now=1001)
        self.assertEqual(self.store.notices()['notices'][0]['records'][0]['status'],'verified')

    def test_retention_is_bounded_and_bad_state_is_not_silently_overwritten(self):
        for i in range(140):
            row=self.store.begin('recheck_nodes',None,now=1000+i)
            self.store.finish(row['id'],result={'verified_healthy':True},now=1001+i)
        self.assertLessEqual(len(self.store.read()['records']),128)
        self.assertLess(self.store.path.stat().st_size,256*1024)
        self.store.path.write_text('broken')
        with self.assertRaises(ValueError):self.store.read()
        self.assertEqual(self.store.path.read_text(),'broken')

    def test_structurally_incomplete_records_fail_as_recoverable_audit_errors(self):
        import json
        self.store.begin('recheck_nodes',SID,now=1000)
        data=json.loads(self.store.path.read_text());data['records'][0].pop('started_at')
        self.store.path.write_text(json.dumps(data));before=self.store.path.read_bytes()
        with self.assertRaises(ValueError):self.store.read()
        self.assertEqual(self.store.path.read_bytes(),before)


if __name__=='__main__':unittest.main()
