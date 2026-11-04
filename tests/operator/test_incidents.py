import json
from pathlib import Path
import tempfile
import unittest

from incidents import IncidentStore


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.store=IncidentStore(Path(self.folder.name)/'cases.json')
        self.now=10000

    def signal(self,**extra):
        return {'key':'client:real.example.com','domain':'real.example.com','signature':'dns-unavailable',
                'observed_at':self.now,'priority':'urgent','facts':{'current_failure':True,'failure_count':4},**extra}

    def create(self):return self.store.observe([self.signal()],self.now)['cases'][0]

    def decide(self,case,**extra):
        return self.store.decide(case['id'],case['revision'],actor='test-agent',now=self.now,
            decision={'status':'blocked','reason':'Both paths were checked; local routing cannot repair this endpoint.',
                      'evidence':['comparison:1'],'next_review_at':self.now+600,**extra})

    def test_blocked_is_not_resolved_or_downgraded_and_becomes_due(self):
        case=self.decide(self.create())
        self.assertEqual(case['priority'],'urgent');self.assertEqual(case['status'],'blocked')
        self.assertFalse(case['network_restored'])
        self.assertEqual(self.store.attention(self.now),[])
        self.assertEqual(self.store.attention(self.now+601)[0]['id'],case['id'])

    def test_repeated_samples_preserve_the_agents_disposition_and_revision(self):
        case=self.decide(self.create())
        out=self.store.observe([self.signal(observed_at=self.now+10,facts={'current_failure':True,'failure_count':5})],self.now+10)['cases'][0]
        self.assertEqual(out['status'],'blocked');self.assertEqual(out['revision'],case['revision'])
        self.assertEqual(out['facts']['failure_count'],5)

    def test_changed_evidence_reopens_disposed_work_with_original_priority(self):
        case=self.decide(self.create(),status='closed',priority='urgent',outcome='no_route_remedy',next_review_at=self.now+600)
        changed=self.store.observe([self.signal(signature='one-route-now-works',observed_at=self.now+5)],self.now+5)['cases'][0]
        self.assertEqual(changed['id'],case['id']);self.assertEqual(changed['status'],'open')
        self.assertEqual(changed['priority'],'urgent');self.assertGreater(changed['revision'],case['revision'])

    def test_closing_no_routing_remedy_is_not_a_claim_of_network_repair(self):
        case=self.decide(self.create(),status='closed',priority='normal',outcome='no_route_remedy',next_review_at=self.now+3600)
        self.assertFalse(case['network_restored']);self.assertEqual(case['outcome'],'no_route_remedy')
        self.assertTrue(case['history'][-1]['evidence'])

    def test_active_work_has_a_finite_lease_and_is_resumed_after_expiry(self):
        case=self.decide(self.create(),status='working',next_review_at=self.now+300)
        self.assertEqual(self.store.attention(self.now+299),[])
        self.assertEqual(self.store.attention(self.now+301)[0]['id'],case['id'])

    def test_stale_decision_cannot_overwrite_a_new_observation(self):
        case=self.create();self.store.observe([self.signal(signature='new-failure-class')],self.now+1)
        with self.assertRaisesRegex(ValueError,'revision'):self.decide(case)
        self.assertEqual(self.store.list(self.now)['cases'][0]['status'],'open')

    def test_no_observations_never_delete_or_resolve_an_unfinished_case(self):
        case=self.create();out=self.store.observe([],self.now+86400)
        self.assertEqual(out['cases'][0]['id'],case['id']);self.assertEqual(out['cases'][0]['status'],'open')

    def test_closed_means_disposed_but_review_is_still_scheduled(self):
        case=self.decide(self.create(),status='closed',priority='normal',outcome='not_a_problem',next_review_at=self.now+3600)
        self.assertEqual(self.store.attention(self.now),[])
        self.assertEqual(self.store.attention(self.now+3601)[0]['id'],case['id'])

    def test_decisions_require_evidence_reason_and_finite_follow_up(self):
        for patch in [{'reason':''},{'evidence':[]},{'next_review_at':self.now-1},{'next_review_at':float('inf')}]:
            case=self.create()
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.decide(case,**patch)

    def test_corrupt_storage_is_reported_without_resetting_the_cases(self):
        self.store.path.write_text('{corrupt')
        with self.assertRaisesRegex(ValueError,'recovery'):self.store.list(self.now)
        self.assertEqual(self.store.path.read_text(),'{corrupt')

    def test_capacity_never_silently_evicts_unfinished_urgent_work(self):
        small=IncidentStore(self.store.path,max_cases=2)
        out=small.observe([self.signal(key='one'),self.signal(key='two'),self.signal(key='three')],self.now)
        self.assertEqual(len(out['cases']),2);self.assertTrue(out['capacity_exceeded'])
        self.assertEqual({x['key'] for x in out['cases']},{'one','two'})

    def test_capacity_keeps_urgent_disposed_cases_with_scheduled_follow_up(self):
        small=IncidentStore(self.store.path,max_cases=1)
        case=self.create();self.decide(case,status='closed',priority='urgent',outcome='no_route_remedy',next_review_at=self.now+600)
        out=small.observe([self.signal(key='new-case')],self.now+1)
        self.assertTrue(out['capacity_exceeded']);self.assertEqual(out['cases'][0]['id'],case['id'])

    def test_cannot_mark_the_network_fixed_without_verified_recovery(self):
        with self.assertRaisesRegex(ValueError,'verification'):
            self.decide(self.create(),status='closed',outcome='fixed',next_review_at=self.now+600)

    def test_new_urgency_reopens_a_normal_disposition(self):
        for signature in ['dns-unavailable','changed-condition']:
            store=IncidentStore(Path(self.folder.name)/(signature+'.json'))
            case=store.observe([self.signal(priority='normal')],self.now)['cases'][0]
            store.decide(case['id'],case['revision'],{'status':'closed','priority':'normal','outcome':'not_a_problem','reason':'previous normal evidence','evidence':['sample:1'],'next_review_at':self.now+3600},'agent',self.now)
            out=store.observe([self.signal(priority='urgent',signature=signature,observed_at=self.now+1)],self.now+1)['cases'][0]
            self.assertEqual(out['priority'],'urgent');self.assertEqual(out['status'],'open')

    def test_verified_fix_cannot_disable_recurrence(self):
        case=self.store.observe([self.signal(facts={'current_failure':False,'verified_recovery':True})],self.now)['cases'][0]
        with self.assertRaisesRegex(ValueError,'recurrence'):
            self.decide(case,status='closed',outcome='fixed',reopen_on_activity=False,next_review_at=self.now+600)
        fixed=self.decide(case,status='closed',outcome='fixed',next_review_at=self.now+600)
        again=self.store.observe([self.signal(observed_at=self.now+5)],self.now+5)['cases'][0]
        self.assertEqual(again['status'],'open');self.assertFalse(again['network_restored'])

    def test_oversized_batch_is_rejected_without_dropping_the_tail(self):
        with self.assertRaisesRegex(ValueError,'batch'):
            self.store.observe([self.signal()]*256+[self.signal(key='new-urgent')],self.now)
        self.assertEqual(self.store.list()['cases'],[])

    def test_capacity_retains_new_incident_evidence_in_attention(self):
        store=IncidentStore(self.store.path,max_cases=1)
        store.observe([self.signal(key='one'),self.signal(key='two')],self.now)
        self.assertEqual({c['key'] for c in store.attention(self.now)},{'one','two'})
        overflow=next(c for c in store.attention(self.now) if c['key']=='two')
        self.assertEqual(store.get(overflow['id'])['signature'],'dns-unavailable')

    def test_structured_corruption_requires_recovery(self):
        case=self.create();raw=json.loads(self.store.path.read_text());raw['cases'][case['id']]['status']='lost'
        self.store.path.write_text(json.dumps(raw));before=self.store.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'recovery'):self.store.attention(self.now)
        self.assertEqual(self.store.path.read_bytes(),before)

    def test_material_facts_invalidate_a_decision_even_when_signal_name_is_stable(self):
        case=self.create()
        self.store.observe([self.signal(facts={'current_failure':False,'verified_recovery':True})],self.now+1)
        with self.assertRaisesRegex(ValueError,'revision'):self.decide(case)

    def test_capacity_does_not_archive_a_normal_case_with_unfinished_follow_up(self):
        store=IncidentStore(self.store.path,max_cases=1)
        case=self.create();self.decide(case,status='closed',priority='normal',outcome='external_dependency',next_review_at=self.now+3600)
        result=store.observe([self.signal(key='another')],self.now+1)
        self.assertEqual(result['cases'][0]['id'],case['id']);self.assertTrue(result['capacity_exceeded'])

    def test_evidence_based_deescalation_is_not_undone_by_an_identical_source_sample(self):
        case=self.decide(self.create(),status='closed',priority='normal',outcome='no_route_remedy',next_review_at=self.now+3600)
        later=self.store.observe([self.signal(observed_at=self.now+5)],self.now+5)['cases'][0]
        self.assertEqual(later['status'],'closed');self.assertEqual(later['priority'],'normal')

    def test_old_disposed_overflow_records_release_room_for_new_urgent_work(self):
        store=IncidentStore(self.store.path,max_cases=1,max_overflow=2)
        store.observe([self.signal(key=k) for k in ['one','two','three']],self.now)
        for case in store.list()['overflow_cases']:
            store.decide(case['id'],case['revision'],{'status':'closed','priority':'normal','outcome':'not_a_problem','reason':'verified nonproblem','evidence':['ref:1'],'next_review_at':self.now+600},'agent',self.now)
        result=store.observe([self.signal(key='new-urgent',observed_at=self.now+73*3600)],self.now+73*3600)
        self.assertIn('new-urgent',{c['key'] for c in result['overflow_cases']})

    def test_invalid_decision_timestamp_requires_recovery_before_observation(self):
        case=self.create();raw=json.loads(self.store.path.read_text());raw['cases'][case['id']]['decided_at']='broken'
        self.store.path.write_text(json.dumps(raw));before=self.store.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'recovery'):self.store.observe([self.signal()],self.now+1)
        self.assertEqual(self.store.path.read_bytes(),before)

    def test_nonfixed_closure_requires_explicit_current_priority(self):
        case=self.create();before=self.store.path.read_bytes()
        for outcome in ['not_a_problem','no_route_remedy','external_dependency']:
            with self.subTest(outcome=outcome),self.assertRaisesRegex(ValueError,'explicit.*priority'):
                self.decide(case,status='closed',outcome=outcome)
            self.assertEqual(self.store.path.read_bytes(),before)

    def test_nonproblem_cannot_retain_current_urgent_priority(self):
        case=self.create()
        with self.assertRaisesRegex(ValueError,'not_a_problem.*normal'):
            self.decide(case,status='closed',outcome='not_a_problem',priority='urgent')
        self.assertEqual(self.store.get(case['id']),case)

    def test_closed_unresolved_urgency_keeps_the_fifteen_minute_bound(self):
        for outcome in ['no_route_remedy','external_dependency']:
            with self.subTest(outcome=outcome):
                case=self.create()
                with self.assertRaisesRegex(ValueError,'fifteen minutes'):
                    self.decide(case,status='closed',outcome=outcome,priority='urgent',next_review_at=self.now+901)
                decided=self.decide(case,status='closed',outcome=outcome,priority='urgent',next_review_at=self.now+900)
                self.assertEqual(self.store.attention(self.now+899),[])
                self.assertEqual(self.store.attention(self.now+900)[0]['id'],decided['id'])

    def test_verified_fixed_history_can_keep_urgent_with_a_long_review(self):
        case=self.store.observe([self.signal(facts={'current_failure':False,'verified_recovery':True})],self.now)['cases'][0]
        fixed=self.decide(case,status='closed',outcome='fixed',next_review_at=self.now+72*3600)
        self.assertEqual(fixed['priority'],'urgent');self.assertTrue(fixed['network_restored'])
        self.assertEqual(self.store.attention(self.now),[])

    def test_legacy_four_dispositions_require_read_only_triage_then_actor_cas(self):
        patterns=[('target','no_route_remedy',12),('benign-a','not_a_problem',72),
                  ('benign-b','not_a_problem',72),('upstream','external_dependency',24)]
        self.store.observe([self.signal(key=key) for key,_,_ in patterns],self.now)
        raw=json.loads(self.store.path.read_text())
        for key,outcome,hours in patterns:
            case=next(c for c in raw['cases'].values() if c['key']==key)
            case.update(status='closed',outcome=outcome,revision=2,decided_at=self.now,
                        next_review_at=self.now+hours*3600,actor='original-agent',
                        reason='original disposition',evidence=['original:1'],reopen_on_activity=False,
                        history=[{'kind':'disposition','actor':'original-agent','priority':'urgent','outcome':outcome}])
        self.store.path.write_text(json.dumps(raw));before=self.store.path.read_bytes()
        attention=self.store.attention(self.now+1)
        self.assertEqual({c['key'] for c in attention},{'target','benign-a','benign-b','upstream'})
        self.assertEqual(self.store.path.read_bytes(),before)
        # A bad original lease still needs triage when its remaining time falls below fifteen minutes.
        self.assertIn('target',{c['key'] for c in self.store.attention(self.now+12*3600-30)})
        for case in attention:
            corrected=self.decide(case,status='closed',outcome=case['outcome'],priority='normal',
                                  reason='Fresh evidence shows no urgent user impact; retain cheap review.',
                                  next_review_at=self.now+3600)
            self.assertEqual(corrected['revision'],3);self.assertEqual(corrected['source_priority'],'urgent')
            self.assertEqual(corrected['history'][0]['actor'],'original-agent')
            self.assertEqual(corrected['history'][-1]['actor'],'test-agent')
            self.assertFalse(corrected['network_restored'])
        self.assertEqual(self.store.attention(self.now+1),[])


if __name__=='__main__':unittest.main()
