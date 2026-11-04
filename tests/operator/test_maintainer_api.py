import json
from pathlib import Path
import tempfile
import unittest
import threading
from unittest.mock import patch

import broker
from incidents import IncidentStore
from policy import validate_request
import probe_transport

SESSION='session-12345678-1234-1234-1234-123456789abc'
MESSAGE='fix(workflow): 按事件处理巡检故障\n\n旧流程丢失处理进度，需要记录修复结论。\n\n运维：按证据保存结论并安排复查。\n\n验证：通过事件回归测试。'


class MaintainerApiTests(unittest.TestCase):
    def test_interleaved_publishers_keep_their_own_versions_and_messages(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'start_sync_dispatcher'),patch.object(broker,'publication_secrets',return_value=[]):
            ready=threading.Event();newer=threading.Event();errors=[]
            def dispatch(request):
                if request['source']=='one':ready.set();newer.wait(2)
                else:ready.wait(2);newer.set()
                return {'deployed':True,'version':('1' if request['source']=='one' else '2')*16}
            def publish(which):
                try:broker.handle({'operation':'workflow_publish','source':which,'session_id':SESSION,'commit_message':MESSAGE.replace('巡检故障','巡检故障'+which)})
                except Exception as e:errors.append(e)
            with patch.object(broker,'dispatch',side_effect=dispatch),patch.object(broker,'publication_version',return_value='2'*16):
                threads=[threading.Thread(target=publish,args=(which,)) for which in ['one','two']]
                for thread in threads:thread.start()
                for thread in threads:thread.join(3)
            self.assertFalse(errors)
            records=broker.publication_registry().records()
            self.assertEqual({r['version'] for r in records},{'1'*16,'2'*16})
            by_version={r['version']:r['commit_message'] for r in records}
            self.assertIn('one',by_version['1'*16]);self.assertIn('two',by_version['2'*16])

    def test_invalid_publication_prose_is_rejected_before_local_mutation(self):
        with patch.object(broker,'dispatch') as dispatch:
            with self.assertRaises(ValueError):broker.handle({'operation':'workflow_publish','source':'candidate','commit_message':'bad'})
            dispatch.assert_not_called()

    def test_publish_queue_carries_exact_version_scoped_model_message(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'start_sync_dispatcher'),patch.object(broker,'publication_version',return_value='a'*16),patch.object(broker,'publication_secrets',return_value=[]):
            receipt=broker.queue_source_sync('workflow_publish',SESSION,MESSAGE)
            request=json.loads((Path(folder)/'source-sync-request.json').read_text())
            self.assertEqual(request['id'],receipt['request_id'])
            self.assertEqual(request['publications'][0]['commit_message'],MESSAGE)
            self.assertEqual(request['publications'][0]['version'],'a'*16)

    def test_incident_decision_is_durable_and_stale_decision_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker.time,'time',return_value=1000):
            store=IncidentStore(Path(folder)/'incidents.json')
            case=store.observe([{'key':'target:example.com','signature':'both-timeout','domain':'example.com','observed_at':999,'facts':{'current_failure':True}}],1000)['cases'][0]
            request={'operation':'incident_decide','id':case['id'],'revision':case['revision'],'session_id':SESSION,'decision':{'status':'blocked','reason':'both observed paths timeout; awaiting upstream change','evidence':['comparison:123'],'next_review_at':1100}}
            out=broker.dispatch(request)
            self.assertEqual(out['status'],'blocked');self.assertEqual(out['priority'],'urgent')
            self.assertEqual(broker.dispatch({'operation':'incident_get','id':case['id']})['reason'],out['reason'])
            with self.assertRaisesRegex(ValueError,'revision'):broker.dispatch(request)

    def test_workflow_and_targeted_evidence_requests_are_explicit_and_bounded(self):
        self.assertEqual(validate_request({'operation':'workflow_test','source':'def inspect(snapshot):\n return {}'})['source'],'def inspect(snapshot):\n return {}')
        for request in [
            {'operation':'evidence_detail','section':'shell'},
            {'operation':'evidence_detail','section':'observations','limit':1000},
            {'operation':'incident_get','id':'../../private'},
            {'operation':'incident_decide','id':'case-'+'a'*20,'revision':1,'session_id':SESSION,'decision':'bad'}]:
            with self.subTest(request=request),self.assertRaises(ValueError):validate_request(request)

    def test_context_compaction_and_detail_use_same_unabridged_source(self):
        full={'checked_at':1000,'observations':{'status':'observed','domains':[{'domain':f'site{i}.example.com','failure_count':0,'chains':['DIRECT']} for i in range(50)]}}
        with patch.object(broker,'context_full',return_value=full):
            compact=broker.context()
            ref=compact['observations']['detail_ref']['snapshot_ref']
            detail=broker.dispatch({'operation':'evidence_detail','section':'observations','target':'site49.example.com','snapshot_ref':ref})
            self.assertTrue(detail['requested_snapshot_matches'])
            self.assertIn('site49.example.com',json.dumps(detail))
            self.assertEqual(len(full['observations']['domains']),50)

    def test_cached_probe_reuses_original_controls_and_evidence_reference(self):
        comparison={'target':'example.com','comparison_id':'a'*32,'observed_at':1000,'cached':False}
        healthy={'checks':{'mainland_https':{'ok':True,'result':{'http_status':200}},'proxy_https':{'ok':True,'result':{'http_status':204}}}}
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)),patch.object(broker,'COMPARISON_RECORDS',{}),patch.object(broker,'diagnose',side_effect=[healthy,{'checks':{}}]) as diagnose,patch.object(broker,'current_policy',return_value={'version':'b'*16}),patch.object(probe_transport,'compare',side_effect=[comparison,{**comparison,'cached':True}]),patch('route_evidence.time.time',return_value=1000):
            first=broker.dispatch({'operation':'probe_compare','target':'example.com'})
            second=broker.dispatch({'operation':'probe_compare','target':'example.com'})
            self.assertEqual(first['evidence_id'],second['evidence_id'])
            self.assertEqual(second['controls'],{'direct':True,'proxy':True})
            self.assertTrue(second['cached']);self.assertEqual(diagnose.call_count,1)


if __name__=='__main__':unittest.main()
