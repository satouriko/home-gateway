import copy
import unittest
from user_policy import merge_preferences,render


def config():
    return {'mode':'rule','secret':'test-fixture','tun':{'exclude-uid':[999]},'dns':{'nameserver-policy':{}},
      'proxy-providers':{'us':{'exclude-filter':'maintenance'},'other':{}},
      'proxy-groups':[{'name':'PROXY','proxies':['US_AUTO','OTHER_AUTO']}]}


class AdaptivePreferenceTests(unittest.TestCase):
    def test_exact_rule_and_dns_come_after_explicit_intent_before_geo_defaults(self):
        p=merge_preferences({}, {'adaptive_routes':{'cdn.example.com':'direct'},'proxy_domains':['manual.example.org']})
        candidate,approved=render(config(),p)
        rules=candidate['rules']
        self.assertIn('DOMAIN,cdn.example.com,DIRECT',rules)
        self.assertLess(rules.index('DOMAIN-SUFFIX,manual.example.org,PROXY'),rules.index('DOMAIN,cdn.example.com,DIRECT'))
        self.assertLess(rules.index('DOMAIN,cdn.example.com,DIRECT'),rules.index('GEOSITE,cn,DIRECT'))
        self.assertIn('cdn.example.com',candidate['dns']['nameserver-policy'])
        self.assertNotIn('+.cdn.example.com',candidate['dns']['nameserver-policy'])
        self.assertEqual(approved['proxy_chain'],['US_AUTO','OTHER_AUTO'])

    def test_new_explicit_suffix_intent_supersedes_old_automatic_rule(self):
        old=merge_preferences({}, {'adaptive_routes':{'api.example.com':'direct'}})
        current,_=render(config(),old)
        newer=merge_preferences(old,{'proxy_domains':['example.com']})
        candidate,approved=render(current,newer,old)
        self.assertNotIn('DOMAIN,api.example.com,DIRECT',candidate['rules'])
        self.assertNotIn('api.example.com',candidate['dns']['nameserver-policy'])

    def test_removing_automatic_rule_removes_only_its_managed_exact_dns(self):
        old=merge_preferences({}, {'adaptive_routes':{'api.example.com':'proxy'}})
        current,_=render(config(),old);current['dns']['nameserver-policy']['unrelated.example.org']=['server']
        candidate,_=render(current,merge_preferences(old,{'adaptive_routes':{}}),old)
        self.assertNotIn('api.example.com',candidate['dns']['nameserver-policy'])
        self.assertEqual(candidate['dns']['nameserver-policy']['unrelated.example.org'],['server'])

    def test_route_or_strategy_change_changes_policy_identity(self):
        _,a=render(config(),merge_preferences({},{}))
        _,b=render(config(),merge_preferences({}, {'adaptive_routes':{'api.example.com':'proxy'}}))
        self.assertNotEqual(a['version'],b['version'])
        self.assertTrue(a['preferences']['routing_strategy']['require_public_service_basis'])
        self.assertFalse(a['preferences']['routing_strategy']['allow_latency_only'])

    def test_automatic_routes_are_bounded_data_and_control_hosts_are_rejected(self):
        for value in [{'api.example.com':'REJECT'},{'*.example.com':'direct'},{'ai.lan':'direct'},{'api.deepseek.com':'proxy'},['example.com'],{'example.com,PROXY':'direct'}]:
            with self.subTest(value=value),self.assertRaises(ValueError):merge_preferences({}, {'adaptive_routes':value})

    def test_unrelated_privileged_configuration_is_preserved(self):
        before=config();candidate,_=render(before,merge_preferences({}, {'adaptive_routes':{'api.example.com':'proxy'}}))
        self.assertEqual(candidate['tun'],before['tun']);self.assertEqual(candidate['secret'],before['secret'])
        self.assertEqual(before,config())


if __name__=='__main__':unittest.main()
