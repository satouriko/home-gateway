import copy
import unittest
from user_policy import merge_preferences,render

class UserPolicyTests(unittest.TestCase):
    def fixture(self):
        return {'mode':'rule','secret':'private-controller-secret','tun':{'exclude-uid':[999]},'dns':{'nameserver-policy':{}},
            'proxy-providers':{'us':{'filter':'美国','exclude-filter':'故障|维护'},'other':{'exclude-filter':'故障|美国'}},
            'proxy-groups':[{'name':'US_AUTO','use':['us'],'empty-fallback':'REJECT'},{'name':'OTHER_AUTO','use':['other'],'empty-fallback':'REJECT'}, {'name':'PROXY','proxies':['US_AUTO','OTHER_AUTO']} ]}
    def test_user_preferences_can_change_without_changing_control_path(self):
        config=self.fixture();before=copy.deepcopy(config)
        preferences=merge_preferences({}, {'preferred_label':'日本','preferred_keywords':['日本','Japan'],'allow_proxy_direct_fallback':True})
        candidate,approved=render(config,preferences)
        self.assertIn('日本',candidate['proxy-providers']['us']['filter'])
        self.assertIn('DIRECT',candidate['proxy-groups'][2]['proxies'])
        self.assertEqual(candidate['tun'],before['tun']);self.assertEqual(candidate['secret'],before['secret'])
        self.assertEqual(approved['preferences']['preferred_label'],'日本')
        self.assertEqual(config,before)
    def test_privileged_settings_are_not_user_preference_fields(self):
        for patch in [{'tun':{}},{'secret':'x'},{'controller':'0.0.0.0'},{'allow_other_regions':'true'}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):merge_preferences({},patch)
    def test_domain_overrides_are_data_not_skill_text(self):
        preferences=merge_preferences({}, {'direct_domains':['example.org']})
        candidate,_=render(self.fixture(),preferences)
        self.assertIn('DOMAIN-SUFFIX,example.org,DIRECT',candidate['rules'])
    def test_removing_a_domain_override_also_removes_its_dns_policy(self):
        old=merge_preferences({}, {'direct_domains':['example.org']})
        config,_=render(self.fixture(),old)
        candidate,_=render(config,merge_preferences(old,{'direct_domains':[]}),old)
        self.assertNotIn('+.example.org',candidate['dns']['nameserver-policy'])

if __name__=='__main__':unittest.main()
