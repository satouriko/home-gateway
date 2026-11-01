import copy
import unittest
from policy import validate_request, validate_baseline, recovery_due

class BoundaryTests(unittest.TestCase):
    def test_known_read_operation_is_accepted(self):
        self.assertEqual(validate_request({'operation':'status'}), {'operation':'status'})

    def test_shell_arguments_and_unknown_operations_are_rejected(self):
        for request in [{'operation':'shell','command':'id'}, {'operation':'status','command':'id'}, {'operation':'restart_dsh'}, {'operation':'choose_region','region':'DIRECT'}]:
            with self.subTest(request=request), self.assertRaises(ValueError): validate_request(request)

    def test_probe_accepts_domain_but_not_shell_or_credential_url(self):
        self.assertEqual(validate_request({'operation':'probe','target':'WWW.GOOGLE.COM'})['target'], 'www.google.com')
        for target in ['https://example.com/?token=secret', 'x;id', '../etc/passwd', 'localhost', '169.254.169.254', 'a'*260+'.com']:
            with self.subTest(target=target), self.assertRaises(ValueError): validate_request({'operation':'probe','target':target})

    def test_expired_transaction_recovers_without_an_agent(self):
        t={'deadline':120,'boot_id':'old'}
        self.assertFalse(recovery_due(t,119,'old'))
        self.assertTrue(recovery_due(t,120,'old'))
        self.assertTrue(recovery_due(t,100,'new'))
        self.assertFalse(recovery_due(None,100,'new'))

    def test_proxy_direct_fallback_is_rejected(self):
        c=self.config(); c['proxy-groups'][2]['proxies'].append('DIRECT')
        with self.assertRaises(ValueError): validate_baseline(c,999)

    def test_self_connection_exclusion_cannot_be_removed(self):
        c=self.config(); c['tun']['exclude-uid']=[]
        with self.assertRaises(ValueError): validate_baseline(c,999)

    def test_unapproved_default_direct_is_rejected(self):
        c=self.config();c['rules']=['MATCH,DIRECT']
        with self.assertRaises(ValueError):validate_baseline(c,999)

    def test_user_can_approve_different_region_and_fallback_preferences(self):
        c=self.config();c['proxy-groups'][0]['name']='JP_AUTO'
        c['proxy-groups'][0]['use']=['preferred']
        c['proxy-groups'][2]['proxies']=['JP_AUTO','OTHER_AUTO','DIRECT']
        approved={'mode':'rule','proxy_chain':['JP_AUTO','OTHER_AUTO','DIRECT'],
                  'region_providers':{'JP_AUTO':'preferred','OTHER_AUTO':'other'},'default_rule':'MATCH,PROXY'}
        self.assertIsNone(validate_baseline(c,999,approved))

    def test_model_lifeline_uses_uid_guard_not_a_permanent_business_domain_rule(self):
        c=self.config();c['rules']=['MATCH,PROXY']
        self.assertIsNone(validate_baseline(c,999))

    def test_valid_baseline_is_accepted(self):
        self.assertIsNone(validate_baseline(self.config(),999))

    @staticmethod
    def config():
        return {'mode':'rule','tun':{'exclude-uid':[999]},'rules':['DOMAIN-SUFFIX,deepseek.com,DIRECT','MATCH,PROXY'],
          'proxy-groups':[{'name':'US_AUTO','use':['us'],'empty-fallback':'REJECT'}, {'name':'OTHER_AUTO','use':['other'],'empty-fallback':'REJECT'},
                          {'name':'PROXY','proxies':['US_AUTO','OTHER_AUTO']} ]}

if __name__=='__main__':unittest.main()
