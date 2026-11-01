import unittest
import probe_transport as p


class ProtectedProbeTests(unittest.TestCase):
    def test_probe_instance_has_no_tun_subscription_or_direct_proxy_fallback(self):
        node={'name':'Actual US node','type':'ss','server':'node.example','port':443,'cipher':'aes-128-gcm','password':'test-fixture'}
        config=p.helper_config('example.com',['93.184.216.34'],node,18001,18002,'fixture')
        self.assertFalse(config['tun']['enable'])
        self.assertNotIn('proxy-providers',config)
        self.assertEqual([x['proxy'] for x in config['listeners']],['DIRECT',node['name']])
        self.assertTrue(all(x['listen']=='127.0.0.1' for x in config['listeners']))
        self.assertEqual(config['rules'],['MATCH,REJECT'])
        self.assertEqual(config['hosts']['example.com'],['93.184.216.34'])

    def test_dns_pinning_rejects_private_mixed_and_fake_addresses(self):
        for addresses in [['127.0.0.1'],['192.168.2.4'],['198.18.0.2'],['93.184.216.34','10.0.0.1'],[]]:
            with self.assertRaises(ValueError):p.public_addresses(addresses)
        self.assertEqual(p.public_addresses(['93.184.216.34']),['93.184.216.34'])

    def test_cached_native_subscription_uses_exact_leaf_filter_and_no_refresh(self):
        config=p.helper_config('example.com',['93.184.216.34'],{'name':'US (A)+','provider_payload':b'opaque native subscription'},18001,18002,'fixture')
        provider=config['proxy-providers']['probe']
        self.assertEqual(provider['type'],'file');self.assertNotIn('url',provider)
        import re
        self.assertIsNotNone(re.fullmatch(provider['filter'],'US (A)+'))
        self.assertIsNone(re.fullmatch(provider['filter'],'US Ax'))
        self.assertEqual(config['proxy-groups'][0]['empty-fallback'],'REJECT')
        self.assertNotIn('DIRECT',config['proxy-groups'][0].get('proxies',[]))

    def test_hostname_is_only_public_style_domain_no_url_or_literal(self):
        for target in ['localhost','ai.lan','api.local','127.0.0.1','https://example.com/a','-bad.example','a..com']:
            with self.assertRaises(ValueError):p.hostname(target)
        self.assertEqual(p.hostname('WWW.Baidu.com.'),'www.baidu.com')

    def test_redirect_response_is_not_followed_or_called_business_success(self):
        result=p.response_evidence('example.com',302,b'','text/html',12)
        self.assertEqual(result['http_status'],302)
        self.assertIsNone(result['content_ok'])
        self.assertEqual(result['acceptance_scope'],'HTTPS root response only; redirects are not followed')
        rejection=p.response_evidence('chatgpt.com',403,b'blocked','text/html',12)
        self.assertFalse(rejection['content_ok'])

    def test_expected_homepage_requires_marker(self):
        self.assertFalse(p.response_evidence('www.baidu.com',200,b'wrong page','text/html',12)['content_ok'])
        self.assertTrue(p.response_evidence('www.baidu.com',200,'<html>百度</html>'.encode(),'text/html',12)['content_ok'])


if __name__=='__main__':unittest.main()
