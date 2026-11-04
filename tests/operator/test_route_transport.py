import contextlib
import json
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import probe_transport as p


class Tunnel(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.requests.append(self.rfile.readline().decode().strip())
        while self.rfile.readline() not in (b'\r\n', b''):
            pass
        self.wfile.write(b'HTTP/1.0 200 Connection established\r\n\r\n');self.wfile.flush()
        line=self.rfile.readline()
        if line.startswith(b'GET '):
            while self.rfile.readline() not in (b'\r\n',b''):
                pass
            self.wfile.write(b'HTTP/1.0 403 Forbidden\r\nContent-Length: 6\r\n\r\nDenied')


@contextlib.contextmanager
def tunnel():
    server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Tunnel);server.daemon_threads=True;server.requests=[]
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield server
    finally:server.shutdown();server.server_close();thread.join()


class RouteTransportTests(unittest.TestCase):
    def test_structured_region_error_is_business_evidence_not_transport_failure(self):
        body=b'{"error":{"code":"unsupported_country_region_territory","message":"private response data"}}'
        result=p.response_evidence('api.example.com',403,body,'application/json',30)
        self.assertTrue(result['transport_ok']);self.assertEqual(result['business_error_kind'],'region_rejected')
        self.assertNotIn('private response data',str(result))
        self.assertIsNone(p.response_evidence('api.example.com',403,b'Forbidden','text/plain',30)['business_error_kind'])

    def test_real_connect_uses_observed_port_and_keeps_403_separate(self):
        with tunnel() as server:
            result=p.request_endpoint('example.com',server.server_address[1],None,'direct',{'network':'tcp','port':8080,'application_protocol':'http'})
        self.assertEqual(len(server.requests),1);self.assertTrue(server.requests[0].startswith('CONNECT example.com:8080 HTTP/1.'))
        self.assertTrue(result['connect_ok']);self.assertTrue(result['transport_ok'])
        self.assertEqual(result['http_status'],403);self.assertFalse(result['application_verified'])

    def test_tcp_probe_does_not_send_http_to_unknown_application(self):
        with tunnel() as server:
            seen=[]
            result=p.request_endpoint('example.com',server.server_address[1],None,'proxy',{'network':'tcp','port':5223},inspect=lambda address,*args:seen.append(address) or {})
        self.assertIsNone(result['connect_ok']);self.assertIsNone(result['transport_ok']);self.assertEqual(len(seen),1)
        self.assertTrue(result['proxy_tunnel_accepted']);self.assertFalse(result['target_dial_verified'])
        self.assertEqual(result['state'],'target_dial_unverified')
        self.assertNotIn('http_status',result)

    def test_endpoint_and_dns_and_policy_identity_control_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.json';config.write_text(json.dumps({'rules':['MATCH,PROXY'],'dns':{}}))
            addresses=['93.184.216.34']
            api=lambda *args,**kwargs:{'Answer':[{'type':1,'data':x} for x in addresses]}
            @contextlib.contextmanager
            def helper(*args,**kwargs):
                yield lambda *a,**k:{'connect_ok':True,'target_dial_verified':True,'transport_ok':True,'path_verified':True,'elapsed_ms':12}
            p.CACHE.clear()
            with patch.object(p,'select_node',return_value={'name':'US fixture','provider_payload':b'private'}),patch.object(p,'helper',helper),patch.object(p,'verify_route',return_value={'verified':True,'path':'proxy'}):
                a=p.compare('example.com',api,config,now=1000,endpoint={'network':'tcp','port':5223})
                b=p.compare('example.com',api,config,now=1010,endpoint={'network':'tcp','port':5223})
                self.assertTrue(b['cached']);self.assertEqual(a['comparison_id'],b['comparison_id'])
                c=p.compare('example.com',api,config,now=1070,endpoint={'network':'tcp','port':5223},refresh=True)
                self.assertNotEqual(a['comparison_id'],c['comparison_id'])
                d=p.compare('example.com',api,config,now=1080,endpoint={'network':'tcp','port':443})
                self.assertNotEqual(d['comparison_id'],c['comparison_id'])
                addresses[:]=['1.1.1.1']
                e=p.compare('example.com',api,config,now=1090,endpoint={'network':'tcp','port':443})
                self.assertNotEqual(e['dns_fingerprint'],d['dns_fingerprint'])

    def test_gateway_rule_requires_exact_payload_and_own_socket(self):
        rows=[{'metadata':{'sourceIP':'127.0.0.1','sourcePort':'24001','destinationPort':'443','host':'example.com'},'chains':['DIRECT'],'rule':'Domain','rulePayload':'example.com'}]
        proof=p.connection_proof(rows,('127.0.0.1',24001),'example.com',{'network':'tcp','port':443},'direct',True)
        self.assertTrue(proof['verified'])
        rows[0]['metadata']['sourcePort']='24002'
        self.assertFalse(p.connection_proof(rows,('127.0.0.1',24001),'example.com',{'network':'tcp','port':443},'direct',True)['verified'])
        rows[0]['metadata']['sourcePort']='24001';rows[0]['rule']='DomainSuffix'
        self.assertFalse(p.connection_proof(rows,('127.0.0.1',24001),'example.com',{'network':'tcp','port':443},'direct',True)['verified'])

    def test_gateway_probe_uses_actual_lan_bound_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.json';config.write_text(json.dumps({'mixed-port':7890,'bind-address':'192.168.2.4'}))
            with patch.object(p,'request_endpoint',return_value={'connect_ok':True,'target_dial_verified':True}) as request:
                result=p.verify_route('example.com',{'network':'tcp','port':5223},'proxy',lambda *a,**k:{},config)
            self.assertEqual(request.call_args.kwargs['proxy_host'],'192.168.2.4')
            self.assertTrue(result['stage_ok']);self.assertFalse(result['verified'])

    def test_gateway_http_proof_distinguishes_response_from_acceptable_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.json';config.write_text(json.dumps({'mixed-port':7890,'bind-address':'192.168.2.4'}))
            endpoint={'network':'tcp','port':443,'application_protocol':'https'}
            api=lambda *a,**k:{'connections':[{'metadata':{'sourceIP':'192.168.2.4','sourcePort':'24001','destinationPort':'443','host':'example.com'},
                'chains':['DIRECT'],'rule':'Domain','rulePayload':'example.com'}]}
            for status in (200,302,401,403,429,503):
                with self.subTest(status=status):
                    def request(target,port,token,path,spec,proxy_host=None,inspect=None):
                        inspect(('192.168.2.4',24001),target,spec)
                        return {'connect_ok':True,'tls_ok':True,'transport_ok':True,'http_status':status}
                    with patch.object(p,'request_endpoint',request):
                        proof=p.verify_route('example.com',endpoint,'direct',api,config)
                    self.assertTrue(proof['verified']);self.assertTrue(proof['stage_ok'])
                    self.assertEqual(proof.get('endpoint_acceptable'),200<=status<400)
                    self.assertFalse(proof['application_verified'])

    def test_connect_accepting_proxy_without_target_dial_produces_only_unknown(self):
        from business_probe import compare_endpoint
        for protocol in ('tcp','unknown'):
            with self.subTest(protocol=protocol),tunnel() as server:
                endpoint={'network':'tcp','port':5223,'application_protocol':protocol}
                result=compare_endpoint('push.example.com',endpoint,
                    lambda target,path:p.request_endpoint(target,server.server_address[1],None,path,endpoint),1000)
                self.assertEqual(result['state'],'insufficient_target_dial_evidence')
                self.assertEqual(len(server.requests),6)
                for path in ('direct','proxy'):
                    self.assertEqual(result['paths'][path]['success_samples'],0)
                    self.assertEqual(result['paths'][path]['failed_samples'],0)
                    self.assertEqual(result['paths'][path]['unknown_samples'],3)

    def test_http_200_explicit_content_failure_cannot_pass_endpoint_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'config.json';config.write_text(json.dumps({'mixed-port':7890}))
            for content in (False,None,True):
                with self.subTest(content=content),patch.object(p,'request_endpoint',return_value={'connect_ok':True,'transport_ok':True,'http_status':200,'content_ok':content}):
                    proof=p.verify_route('example.com',{'network':'tcp','port':80,'application_protocol':'http'},'direct',lambda *a,**k:{},config)
                    self.assertEqual(proof['endpoint_acceptable'],content is not False)
                    self.assertFalse(proof['application_verified'])


if __name__=='__main__':unittest.main()
