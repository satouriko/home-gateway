import unittest
import hashlib
import json
import node_health as n


class NodeHealthTests(unittest.TestCase):
    def test_routing_strategy_and_exact_rules_do_not_reset_node_pool_identity(self):
        original={'preferences':{'mode':'rule','preferred_keywords':['美国'],'allow_other_regions':True}}
        changed={'preferences':{**original['preferences'],'adaptive_routes':{'example.com':'proxy'},'routing_strategy':{'allow_latency_only':False},'proxy_domains':['other.example.com']}}
        self.assertEqual(n.policy_id(original),n.policy_id(changed))
        changed['preferences']['preferred_keywords']=['日本']
        self.assertNotEqual(n.policy_id(original),n.policy_id(changed))

    def test_legacy_pool_incident_survives_first_new_format_sample(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False}]
        first=self.event(self.now-130,None,attempts)
        first['policy_id']=hashlib.sha256(json.dumps(self.policy['preferences'],sort_keys=True).encode()).hexdigest()[:16]
        before=first['incident_id']
        document=n.append({'recent_events':[first]},self.event(self.now,None,attempts),self.now)
        result=n.summarize(document,self.policy,self.now)
        self.assertTrue(result['urgent']);self.assertEqual(result['fingerprint'],'node-pool:'+before)

    def setUp(self):
        self.policy={'preferences':{'mode':'rule','allow_other_regions':True}}
        self.now=1800000000

    def event(self,at,region='US_AUTO',attempts=None):
        return n.event(at,region,attempts or [{'region':'US_AUTO','ok':True}],self.policy)

    def test_single_bad_node_or_transient_preferred_failure_does_not_buy_model_call(self):
        event=self.event(self.now,'OTHER_AUTO',[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False},{'region':'OTHER_AUTO','ok':True}])
        result=n.summarize({'recent_events':[event]},self.policy,self.now)
        self.assertFalse(result['urgent']);self.assertFalse(result['review_due'])

    def test_all_regions_failed_is_visible_to_emergency_worker(self):
        bad=self.event(self.now,None,[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False},{'region':'OTHER_AUTO','ok':False}])
        result=n.summarize({'recent_events':[bad]},self.policy,self.now)
        self.assertTrue(result['urgent']);self.assertEqual(result['state'],'unavailable')

    def test_sustained_preferred_failure_is_incident_even_if_other_region_works(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False},{'region':'OTHER_AUTO','ok':True}]
        events=[self.event(self.now-130,'OTHER_AUTO',attempts),self.event(self.now-60,'OTHER_AUTO',attempts),self.event(self.now,'OTHER_AUTO',attempts)]
        result=n.summarize({'recent_events':events},self.policy,self.now)
        self.assertTrue(result['urgent']);self.assertEqual(result['state'],'preferred_degraded')

    def test_recovered_significant_incident_keeps_review_evidence_not_active_fault(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False},{'region':'OTHER_AUTO','ok':True}]
        events=[self.event(self.now-200,'OTHER_AUTO',attempts),self.event(self.now-60,'OTHER_AUTO',attempts),self.event(self.now)]
        result=n.summarize({'recent_events':events},self.policy,self.now)
        self.assertFalse(result['urgent']);self.assertTrue(result['review_due'])

    def test_stale_and_other_policy_events_cannot_trigger_current_incident(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False}]
        bad=self.event(self.now-1000,None,attempts)
        self.assertFalse(n.summarize({'recent_events':[bad]},self.policy,self.now)['urgent'])
        bad=self.event(self.now,None,attempts)
        direct={'preferences':{'mode':'direct'}}
        self.assertFalse(n.summarize({'recent_events':[bad]},direct,self.now)['urgent'])

    def test_event_log_is_bounded_and_retains_failed_cycles_between_patrol_samples(self):
        document={}
        for index in range(200):document=n.append(document,self.event(self.now-199+index),self.now)
        self.assertLessEqual(len(document['recent_events']),64)

    def test_recovered_incident_survives_normal_cycle_churn_until_audit(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False}]
        document=n.append({},self.event(self.now-200,None,attempts),self.now-200)
        document=n.append(document,self.event(self.now-100),self.now-100)
        for index in range(100):document=n.append(document,self.event(self.now+index*35),self.now+index*35)
        result=n.summarize(document,self.policy,self.now+3500)
        self.assertFalse(result['urgent']);self.assertTrue(result['review_due'])
        self.assertEqual(len(result['incident_history']),1)

    def test_corrupt_optional_history_is_unknown_instead_of_breaking_diagnosis(self):
        for value in [{'recent_events':None},{'recent_events':'bad'},{'recent_events':[],'incident_history':None}]:
            self.assertFalse(n.summarize(value,self.policy,self.now)['urgent'])
        malformed={'recent_events':[{'at':self.now,'preferred_failed':True}], 'incident_history':[{'recovered_at':'invalid'}]}
        self.assertFalse(n.summarize(malformed,self.policy,self.now)['urgent'])
        self.assertLessEqual(len(n.append(malformed,self.event(self.now),self.now)['recent_events']),64)

    def test_observation_gap_does_not_count_as_continuous_degradation(self):
        attempts=[{'region':'US_AUTO','ok':False},{'region':'US_AUTO','ok':False},{'region':'OTHER_AUTO','ok':True}]
        events=[self.event(self.now-5*3600,'OTHER_AUTO',attempts),self.event(self.now,'OTHER_AUTO',attempts)]
        result=n.summarize({'recent_events':events},self.policy,self.now)
        self.assertFalse(result['urgent']);self.assertFalse(result['review_due'])
        document=n.append({},events[0],self.now-5*3600)
        document=n.append(document,events[1],self.now)
        result=n.summarize(document,self.policy,self.now)
        self.assertFalse(result['urgent'])


if __name__=='__main__':unittest.main()
