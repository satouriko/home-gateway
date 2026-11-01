import unittest
from business_watch import scan


class BusinessWatchTests(unittest.TestCase):
    def test_empty_or_stale_observations_never_select_synthetic_default_sites(self):
        calls=[]
        for status in ['observation_stale','observation_unavailable','insufficient_evidence']:
            result=scan({'status':status,'domains':[]},{},lambda target:calls.append(target),1000)
            self.assertEqual(calls,[])
            self.assertEqual(result['issues'],[])

    def test_selects_real_domain_and_does_not_turn_generic_homepage_403_into_user_fault(self):
        observed={'status':'observed','domains':[{'domain':'real.example.com','last_seen':1000,'failure_count':0,'chains':['node','PROXY']}]}
        calls=[]
        def probe(target):
            calls.append(target);return {'paths':{'proxy':{'business_ok':False,'http_ok':False,'application_state':'rejected'}},'issue_candidates':[{'kind':'recurring_path_failure'}]}
        result=scan(observed,{},probe,1000)
        self.assertEqual(calls,['real.example.com']);self.assertEqual(result['issues'],[])
        scan(observed,result,probe,1100)
        self.assertEqual(len(calls),1)

    def test_recurrent_client_failure_survives_synthetic_success_and_keeps_stable_fingerprint(self):
        observed={'status':'observed','domains':[{'domain':'real.example.com','last_seen':1000,'failure_count':4,'recurring_failure':True,'error_categories':['dial_timeout'],'chains':['node','PROXY']}]}
        result=scan(observed,{},lambda target:{'paths':{'proxy':{'transport_ok':True}}},1000)
        self.assertEqual(result['issues'][0]['domain'],'real.example.com')
        self.assertFalse(result['issues'][0]['resolved'])
        observed['domains'][0]['failure_count']=8
        after=scan(observed,result,lambda target:{},1200)
        self.assertEqual(after['issues'][0]['fingerprint'],result['issues'][0]['fingerprint'])
        stale=scan({'status':'observation_stale','domains':[]},result,lambda target:{},1300)
        self.assertEqual(stale['issues'],result['issues'])
        observed['domains'][0].update(last_seen=2800,recurring_failure=False)
        aged=scan(observed,result,lambda target:{'paths':{'proxy':{'transport_ok':True}}},2900)
        self.assertEqual(aged['issues'],result['issues'])


if __name__=='__main__':unittest.main()
