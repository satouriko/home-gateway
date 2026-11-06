import copy
import json
from pathlib import Path
import tempfile
import unittest
from incidents import IncidentStore
import diagnostic_input


class DiagnosticInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.now=1000
        self.issue={'domain':'service.example.com','kind':'recurring_client_failure','resolved':False,
                    'fingerprint':'same','last_failure_at':900,'error_categories':['timeout']}
        self.snapshot={'status':{'checked_at':1000,'services':{'net-gateway.service':{'ActiveState':'active'}}},'checks':{},'history':[],
                       'business_observations':{'issues':[self.issue],'checks':{}}}
        from maintenance import _signals
        self.store=IncidentStore(self.root/'incidents.json')
        case=self.store.observe(_signals({},self.snapshot,1000,True),1000)['cases'][0]
        self.case=self.store.decide(case['id'],case['revision'],{'status':'closed','outcome':'external_dependency',
            'priority':'normal','reason':'Both observed paths fail; no safe routing remedy has been demonstrated.',
            'evidence':['compare:both'],'next_review_at':2000},'operator',1000)

    def test_annotation_honors_current_lease_without_removing_evidence(self):
        raw=copy.deepcopy(self.snapshot)
        result=diagnostic_input.annotate(self.snapshot,self.root,1100)
        row=result['business_observations']['issues'][0]
        self.assertFalse(row['incident']['requires_attention'])
        self.assertEqual(row['incident']['revision'],self.case['revision'])
        self.assertEqual(row['fingerprint'],'same');self.assertEqual(self.snapshot,raw)

    def test_due_review_and_material_new_evidence_remain_actionable(self):
        due=diagnostic_input.annotate(self.snapshot,self.root,2000)
        self.assertTrue(due['business_observations']['issues'][0]['incident']['requires_attention'])
        changed=copy.deepcopy(self.snapshot);changed['business_observations']['issues'][0]['error_categories']=['new_tls_failure']
        changed['business_observations']['issues'][0]['last_failure_at']=1050
        new=diagnostic_input.annotate(changed,self.root,1100)
        self.assertTrue(new['business_observations']['issues'][0]['incident']['requires_attention'])
        self.assertTrue(new['business_observations']['issues'][0]['incident']['new_evidence'])

    def test_counter_only_activity_does_not_override_an_external_wait(self):
        self.issue['last_failure_at']=1050;self.issue['failure_count']=999
        result=diagnostic_input.annotate(self.snapshot,self.root,1100)
        self.assertFalse(result['business_observations']['issues'][0]['incident']['requires_attention'])

    def test_old_patrol_cannot_override_a_newer_disposition_with_older_probe_facts(self):
        from maintenance import _signals
        newer=copy.deepcopy(self.snapshot)
        newer['checked_at']=1050
        newer['business_observations']['checks']={'service.example.com':{'at':1050,'result':{
            'paths':{'direct':{'transport_ok':False},'proxy':{'transport_ok':False}}}}}
        case=self.store.observe(_signals({},newer,1050,True),1050)['cases'][0]
        self.store.decide(case['id'],case['revision'],{'status':'closed','outcome':'external_dependency','priority':'normal',
            'reason':'Newer path evidence reviewed; retain the current external wait.', 'evidence':['compare:new'],'next_review_at':2000},'operator',1060)
        old=diagnostic_input.annotate(self.snapshot,self.root,1100)
        self.assertFalse(old['business_observations']['issues'][0]['incident']['requires_attention'])
        self.assertFalse(old['business_observations']['issues'][0]['incident']['new_evidence'])
        refreshed=copy.deepcopy(self.snapshot);refreshed['checked_at']=1100
        still_old=diagnostic_input.annotate(refreshed,self.root,1100)
        self.assertFalse(still_old['business_observations']['issues'][0]['incident']['new_evidence'])
        refreshed['business_observations']['issues'][0]['last_failure_at']=1090
        repeated=diagnostic_input.annotate(refreshed,self.root,1100)
        self.assertFalse(repeated['business_observations']['issues'][0]['incident']['new_evidence'])
        refreshed['business_observations']['issues'][0]['error_categories']=['new_tls_error']
        material=diagnostic_input.annotate(refreshed,self.root,1100)
        self.assertTrue(material['business_observations']['issues'][0]['incident']['new_evidence'])

    def test_missing_or_corrupt_case_state_never_invents_a_disposition(self):
        (self.root/'incidents.json').write_text('broken')
        result=diagnostic_input.annotate(self.snapshot,self.root,1100)
        self.assertFalse(result['incident_view']['available'])
        self.assertNotIn('incident',result['business_observations']['issues'][0])

    def test_live_input_requires_fresh_real_patrol_and_retains_current_case_revision(self):
        (self.root/'patrol.json').write_text(json.dumps({'checked_at':1000,'last_diagnosis':self.snapshot,'history':[]}))
        result=diagnostic_input.live(self.root,1100)
        self.assertEqual(result['business_observations']['issues'][0]['incident']['revision'],self.case['revision'])
        with self.assertRaisesRegex(ValueError,'fresh'):diagnostic_input.live(self.root,2001)

    def test_validation_rejects_premature_work_but_accepts_new_evidence(self):
        snapshot=diagnostic_input.annotate(self.snapshot,self.root,1100)
        bad={'summary':'check','action':'none','probe_domains':[],
             'review_request':{'fingerprint':'same','reason':'old client failure'}}
        with self.assertRaisesRegex(ValueError,'review deadline'):diagnostic_input.validate(bad,snapshot)
        bad.pop('review_request');bad['probe_domains']=['service.example.com']
        with self.assertRaisesRegex(ValueError,'review deadline'):diagnostic_input.validate(bad,snapshot)
        self.assertEqual(diagnostic_input.validate({'summary':'waiting','action':'none','probe_domains':[]},snapshot)['action'],'none')


if __name__=='__main__':unittest.main()
