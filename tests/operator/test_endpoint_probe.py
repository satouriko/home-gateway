import unittest
import business_probe


class EndpointProbeTests(unittest.TestCase):
    def compare(self,*args,**kwargs):
        self.assertTrue(callable(getattr(business_probe,'compare_endpoint',None)))
        return business_probe.compare_endpoint(*args,**kwargs)

    def test_udp_target_is_explicitly_unsupported_without_tcp443_substitution(self):
        calls=[]
        result=self.compare('ntp.example.com',{'network':'udp','port':123,'application_protocol':'dns'},lambda *a,**k:calls.append(a),1000)
        self.assertEqual(result['state'],'unsupported_protocol');self.assertEqual(calls,[])
        self.assertEqual(result['endpoint']['port'],123)

    def test_tcp_probe_uses_the_observed_port_and_alternates_paths(self):
        calls=[]
        def probe(target,path):
            calls.append(path);return {'connect_ok':True,'target_dial_verified':True,'transport_ok':True,'elapsed_ms':20,'path_verified':True}
        result=self.compare('push.example.com',{'network':'tcp','port':5223,'application_protocol':'unknown'},probe,1000)
        self.assertEqual(calls,['direct','proxy']*3)
        self.assertEqual(result['acceptance_stage'],'tcp_connect')
        self.assertEqual(result['paths']['direct']['success_samples'],3)
        self.assertFalse(result['application_verified'])

    def test_http_rejection_is_not_a_network_failure_or_application_success(self):
        def probe(*args,**kwargs):return {'connect_ok':True,'tls_ok':True,'transport_ok':True,'http_status':403,'content_ok':False,'elapsed_ms':30,'path_verified':True}
        result=self.compare('api.example.com',{'network':'tcp','port':443,'application_protocol':'https'},probe,1000)
        for value in result['paths'].values():
            self.assertEqual(value['failed_samples'],0)
            self.assertEqual(value['business_rejection_samples'],3)
        self.assertFalse(result['application_verified'])

    def test_legacy_comparison_retains_network_failure_counts_separately(self):
        result=business_probe.compare('api.example.com',lambda *a,**k:{'transport_ok':True,'http_status':403,'content_ok':False,'path_verified':True},1000)
        self.assertEqual(result['paths']['direct'].get('transport_failed_samples'),0)

    def test_missing_port_and_unverified_path_cannot_establish_a_winner(self):
        result=self.compare('api.example.com',{'network':'tcp'},lambda *a,**k:{},1000)
        self.assertEqual(result['state'],'insufficient_endpoint_evidence')
        result=self.compare('api.example.com',{'network':'tcp','port':443,'application_protocol':'tls'},lambda *a,**k:{'tls_ok':True},1000)
        self.assertFalse(result['path_identity_verified'])

    def test_proxy_acceptance_without_target_dial_proof_is_not_success_or_failure(self):
        result=self.compare('push.example.com',{'network':'tcp','port':5223},lambda *a,**k:
            {'connect_ok':True,'proxy_tunnel_accepted':True,'path_verified':True,'target_dial_verified':False},1000)
        self.assertEqual(result['state'],'insufficient_target_dial_evidence')
        for values in result['paths'].values():
            self.assertEqual(values['unknown_samples'],3)
            self.assertEqual(values['success_samples'],0);self.assertEqual(values['failed_samples'],0)


if __name__=='__main__':unittest.main()
