from contextlib import contextmanager
import copy
import unittest

import test_adaptive_routing as fixtures
from route_transaction import apply_route


class Adapter:
    def __init__(self,approved):
        self.config={'mode':'rule','secret':'private fixture','tun':{'exclude-uid':[999]},'dns':{},
            'proxy-providers':{'us':{},'other':{}},'proxy-groups':[{'name':'PROXY'}]}
        self.approved=approved;self.calls=[];self.token=None;self.fail=None;self.locked=False
    @contextmanager
    def transaction(self):
        self.locked=True;self.calls.append('lock')
        try:yield
        finally:self.locked=False;self.calls.append('unlock')
    def read(self):
        assert self.locked;self.calls.append('read');return copy.deepcopy(self.config),copy.deepcopy(self.approved)
    def identity(self,*args):return {'node_id':'node1','dns_fingerprint':'dns1','config_identity':'config1'}
    def validate(self,*args):self.calls.append('validate')
    def arm(self,*args):self.old=(copy.deepcopy(self.config),copy.deepcopy(self.approved));self.token='token1';self.calls.append('arm');return self.token
    def write(self,candidate,proposed):self.calls.append('write');self.config=candidate;self.approved=proposed
    def reload(self):
        self.calls.append('reload')
        if self.fail=='reload':raise RuntimeError('fixture')
    def verify_target(self,*args):return {'verified':self.fail!='target','stage_ok':True,'endpoint_acceptable':True,'http_status':200,'attribution':'own_probe_socket','exact_rule':True}
    def verify_controls(self):return {'verified_healthy':self.fail!='controls'}
    def owns(self,token):return token==self.token
    def commit(self,*args):self.calls.append('commit');self.token=None
    def rollback(self,token):
        self.calls.append('rollback')
        if self.fail=='rollback':return False
        self.config,self.approved=self.old;self.token=None;return True


class RouteTransactionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AdaptiveRoutingTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.refs=f.rounds();self.knowledge=[f.knowledge()]
        self.proposal=f.evaluate(self.refs,knowledge=self.knowledge)['proposal'];self.adapter=Adapter(f.approved)

    def apply(self):
        return apply_route(self.proposal,self.fixture.store,self.adapter,now=1100,observed_endpoints=[self.fixture.endpoint])

    def test_lock_before_read_and_only_derived_exact_change_can_commit(self):
        self.proposal['endpoint']={'network':'tcp','port':1};self.proposal['current_path']='proxy'
        result=self.apply()
        self.assertTrue(result['applied']);self.assertFalse(result['application_verified'])
        self.assertEqual(self.adapter.calls[:2],['lock','read'])
        self.assertEqual(self.adapter.approved['preferences']['adaptive_routes'],{'api.openai.com':'proxy'})
        self.assertEqual(self.adapter.config['secret'],'private fixture');self.assertIn('commit',self.adapter.calls)

    def test_stale_policy_and_current_identity_fail_before_arming(self):
        self.adapter.approved={**self.adapter.approved,'version':'newer'}
        self.assertFalse(self.apply()['applied']);self.assertNotIn('arm',self.adapter.calls)
        self.adapter.approved=self.fixture.approved;self.adapter.identity=lambda *args:{'node_id':'changed'}
        self.assertFalse(self.apply()['applied']);self.assertNotIn('arm',self.adapter.calls)

    def test_reload_real_rule_or_controls_failure_rolls_back(self):
        for stage in ('reload','target','controls'):
            with self.subTest(stage=stage):
                self.adapter=Adapter(self.fixture.approved);self.adapter.fail=stage
                result=self.apply()
                self.assertFalse(result['applied']);self.assertTrue(result['rolled_back'])
                self.assertNotIn('commit',self.adapter.calls);self.assertNotIn('adaptive_routes',self.adapter.approved.get('bogus',{}))

    def test_failed_rollback_keeps_offline_recovery_armed(self):
        self.adapter.fail='rollback';self.adapter.verify_controls=lambda:{'verified_healthy':False}
        result=self.apply()
        self.assertTrue(result['rollback_armed']);self.assertFalse(result['verified_healthy'])

    def test_raw_config_and_uncollected_evidence_cannot_apply(self):
        self.proposal['config']={'rules':['MATCH,DIRECT']}
        with self.assertRaises(ValueError):self.apply()

    def test_http_rejection_after_reload_rolls_back_even_with_rule_and_controls(self):
        for status in (403,429,503):
            with self.subTest(status=status):
                self.adapter=Adapter(self.fixture.approved)
                self.adapter.verify_target=lambda *args:{'verified':True,'stage_ok':True,'endpoint_acceptable':False,
                    'http_status':status,'attribution':'own_probe_socket','exact_rule':True}
                result=self.apply()
                self.assertFalse(result['applied']);self.assertTrue(result['rolled_back'])
                self.assertNotIn('commit',self.adapter.calls)

    def test_http_receipt_needs_status_and_acceptance_not_only_transport(self):
        for proof in ({'endpoint_acceptable':True,'http_status':403},{'endpoint_acceptable':True},{'http_status':200},
                      {'endpoint_acceptable':True,'http_status':200,'content_ok':False}):
            with self.subTest(proof=proof):
                self.adapter=Adapter(self.fixture.approved)
                self.adapter.verify_target=lambda *args:{'verified':True,'stage_ok':True,'attribution':'own_probe_socket','exact_rule':True,**proof}
                self.assertTrue(self.apply()['rolled_back'])


if __name__=='__main__':unittest.main()
