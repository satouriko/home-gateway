import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from route_evidence import EvidenceStore,fetch_public


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=EvidenceStore(Path(self.tmp.name)/'evidence.json')

    def source(self,text='This service is only available in the supported countries listed here.'):
        return self.store.collect_source('https://help.example.com/regions',fetch=lambda url:text,now=1000)

    def test_model_cannot_assert_source_verified_or_forge_a_quote(self):
        source=self.source()
        with self.assertRaises(ValueError):
            self.store.record_requirement('api.example.com','proxy',[source['id']],[{'source_id':source['id'],'quote':'China is not supported and must use proxy.'}],'regional service policy','mainland China',now=1001)
        with self.assertRaises(ValueError):
            self.store.record_requirement('api.example.com','proxy',['made-up'],[],'regional policy','mainland China',now=1001)

    def test_real_source_quotes_persist_with_interpretation_separate(self):
        text='This service is only available in the supported countries listed here.';source=self.source(text)
        requirement=self.store.record_requirement('api.example.com','proxy',[source['id']],[{'source_id':source['id'],'quote':text}],'The listed service regions exclude the current source region.','mainland China',now=1001)
        found=EvidenceStore(self.store.path).get_many([requirement['id']],now=1002)[0]
        self.assertEqual(found['required_path'],'proxy');self.assertEqual(found['domain'],'api.example.com')
        self.assertEqual(found['interpretation_owner'],'dsh');self.assertFalse(found['semantic_truth_proven'])
        self.assertFalse(found['expired']);self.assertEqual(self.store.path.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.store.status(now=1002,domain='api.example.com')['recent'][0]['id'],requirement['id'])
        self.assertTrue(self.store.get_many([requirement['id']],now=1001+8*86400)[0]['expired'])

    def test_unsafe_source_url_rejected_before_fetch(self):
        calls=[]
        from urllib.parse import urlunsplit
        authenticated=urlunsplit(('https','user:pass@example.com','/','',''))
        for url in ['http://help.example.com/a','https://127.0.0.1/a','https://ai.lan/','https://example.com/a?token=secret',authenticated,'https://api.deepseek.com/']:
            with self.assertRaises(ValueError):self.store.collect_source(url,fetch=lambda u:calls.append(u),now=1000)
        self.assertEqual(calls,[])

    def test_duplicate_cached_comparison_is_same_evidence_not_new_round(self):
        a={'target':'example.com','comparison_id':'a'*32,'observed_at':1000,'cached':False,'endpoint':{'network':'tcp','port':443},'paths':{}}
        first=self.store.record(a,'policy1',now=1000)
        again=self.store.record({**a,'cached':True},'policy1',now=1010)
        self.assertEqual(first['id'],again['id'])
        self.assertEqual(again['observed_at'],1000)
        with self.assertRaises(ValueError):self.store.record({**a,'target':'different.com'},'policy1',now=1010)

    def test_bounded_sources_and_requirements_are_not_public_backup(self):
        for i in range(80):
            self.store.collect_source('https://help.example.com/p'+str(i),fetch=lambda u:'public text '+u,now=1000+i)
        status=self.store.status(now=1100)
        self.assertLessEqual(status['sources'],64);self.assertLess(self.store.path.stat().st_size,2*1024*1024)
        self.assertNotIn('content',str(status))

    def test_public_dns_rebinding_answer_is_rejected_before_connection(self):
        import socket
        with patch('route_evidence.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.168.2.4',443))]),patch('route_evidence.http.client.HTTPSConnection') as connection:
            with self.assertRaises(ValueError):fetch_public('https://help.example.com/regions')
            connection.assert_not_called()

    def test_byte_ceiling_remains_bounded_with_large_source_documents(self):
        for i in range(36):
            self.store.collect_source('https://help.example.com/large'+str(i),fetch=lambda u:'x'*62000,now=1000+i)
        self.assertLessEqual(self.store.path.stat().st_size,2*1024*1024)
        self.assertLess(self.store.status(now=1100)['sources'],36)


if __name__=='__main__':unittest.main()
