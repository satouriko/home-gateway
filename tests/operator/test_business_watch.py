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
        observed={'status':'observed','domains':[{'domain':'real.example.com','last_seen':1000,'failure_count':0,'chains':['node','PROXY'],
            'endpoints':[{'network':'tcp','port':443,'application_protocol':'https'}]}]}
        calls=[]
        def probe(target,endpoint=None):
            calls.append(target);return {'paths':{'proxy':{'business_ok':False,'http_ok':False,'application_state':'rejected'}},'issue_candidates':[{'kind':'recurring_path_failure'}]}
        result=scan(observed,{},probe,1000)
        self.assertEqual(calls,['real.example.com']);self.assertEqual(result['issues'],[])
        scan(observed,result,probe,1100)
        self.assertEqual(len(calls),1)

    def test_recurrent_client_failure_survives_synthetic_success_and_keeps_stable_fingerprint(self):
        observed={'status':'observed','domains':[{'domain':'real.example.com','last_seen':1000,'last_failure_at':1000,'failure_count':4,'recurring_failure':True,'error_categories':['dial_timeout'],'chains':['node','PROXY']}]}
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

    def test_recent_success_activity_cannot_refresh_archived_failure_time(self):
        observed={'status':'observed','domains':[{'domain':'old.example.com','last_seen':100000,'last_failure_at':1000,
            'failure_count':1000,'recurring_failure':True,'error_categories':['dial_timeout']}]}
        result=scan(observed,{},lambda target:{},100000)
        self.assertEqual(result['issues'],[])

    def test_new_failure_fingerprint_is_stable_across_days_and_counts(self):
        item={'domain':'real.example.com','last_seen':100000,'last_failure_at':100000,'failure_count':4,
              'recurring_failure':True,'error_categories':['dial_timeout']}
        first=scan({'status':'observed','domains':[item]}, {},lambda target:{},100000)
        item.update(last_seen=200000,last_failure_at=200000,failure_count=40)
        second=scan({'status':'observed','domains':[item]}, {},lambda target:{},200000)
        self.assertEqual(first['issues'][0]['fingerprint'],second['issues'][0]['fingerprint'])
        self.assertEqual(second['issues'][0]['last_failure_at'],200000)

    def test_actual_endpoint_is_forwarded_and_bounded_probe_failure_is_retained(self):
        calls=[];endpoint={'network':'udp','port':3478,'application_protocol':'unknown'}
        item={'domain':'voice.example.com','last_seen':1000,'last_failure_at':1000,'recurring_failure':True,'endpoints':[endpoint]}
        def probe(target,endpoint=None):calls.append((target,endpoint));return{'state':'unsupported_transport'}
        result=scan({'status':'observed','domains':[item]}, {},probe,1000)
        self.assertEqual(calls,[('voice.example.com',endpoint)])
        self.assertEqual(result['issues'][0]['endpoint'],endpoint)
    def test_normal_udp_and_non_https_tcp_keep_the_actual_observed_endpoint(self):
        for endpoint in [{'network':'udp','port':123,'application_protocol':'unknown'},
                         {'network':'tcp','port':5223,'application_protocol':'unknown'}]:
            calls=[]
            observed={'status':'observed','domains':[{'domain':'normal.example.com','last_seen':1000,'endpoints':[endpoint]}]}
            scan(observed,{},lambda target,endpoint=None:calls.append((target,endpoint)) or {},1000)
            self.assertEqual(calls,[('normal.example.com',endpoint)])
    def test_unknown_observed_endpoint_is_explicitly_not_probed(self):
        calls=[];observed={'status':'observed','domains':[{'domain':'unknown.example.com','last_seen':1000}]}
        result=scan(observed,{},lambda target,**kwargs:calls.append(target),1000)
        self.assertEqual(calls,[])
        self.assertEqual(result['checks']['unknown.example.com']['result']['state'],'endpoint_unknown')
    def test_mixed_endpoints_probe_the_failed_transport_and_rotate_multiple_failures(self):
        healthy={'network':'tcp','port':443,'application_protocol':'https','last_seen':1000,'last_failure_at':None}
        tcp={'network':'tcp','port':5223,'application_protocol':'unknown','last_seen':1000,'last_failure_at':990}
        udp={'network':'udp','port':443,'application_protocol':'quic','last_seen':1000,'last_failure_at':980}
        item={'domain':'mixed.example.com','last_seen':1000,'last_failure_at':990,'recurring_failure':True,'endpoints':[healthy,tcp,udp]}
        calls=[];probe=lambda target,endpoint=None:calls.append(endpoint) or {}
        first=scan({'status':'observed','domains':[item]}, {},probe,1000)
        self.assertEqual(calls,[{k:tcp[k] for k in ['network','port','application_protocol']}])
        item['last_seen']=2900
        scan({'status':'observed','domains':[item]}, first,probe,2900)
        self.assertEqual(calls[1],{k:udp[k] for k in ['network','port','application_protocol']})
    def test_full_business_backlog_rejects_new_batch_without_discarding_old_evidence(self):
        state={'issues':[{'domain':str(i)+'.example.com','resolved':False} for i in range(512)],'checks':{}}
        observed={'status':'observed','domains':[{'domain':'new.example.com','last_seen':1000,'last_failure_at':1000,'recurring_failure':True}]}
        with self.assertRaisesRegex(ValueError,'capacity'):scan(observed,state,lambda target:{},1000)
        self.assertEqual(len(state['issues']),512)


if __name__=='__main__':unittest.main()
