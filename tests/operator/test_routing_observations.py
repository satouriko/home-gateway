import copy
import unittest
import traffic
import traffic_collector


def row(ident='tcp',network='tcp',port=443,chain=None,download=100):
    return {'id':ident,'start':'fixture','upload':0,'download':download,
      'metadata':{'sourceIP':'192.168.2.20','host':'api.example.com','network':network,'destinationPort':port},
      'chains':chain or ['US node','PROXY'],'rule':'Domain','rulePayload':'api.example.com'}


class EndpointObservationTests(unittest.TestCase):
    def test_warning_preserves_udp_port_path_and_actual_event_time(self):
        event=traffic_collector.parse_warning({'type':'warning','time':'2026-11-04T05:00:00Z',
          'payload':'[UDP] dial DIRECT (match Domain/ntp.example.com) 192.168.2.20:4567 --> ntp.example.com:123 error: timeout credential=PRIVATE'},1793772000,set())
        self.assertEqual((event.get('network'),event.get('port'),event.get('path')),('udp',123,'direct'))
        self.assertEqual(event['event_at'],1793772000-3600)
        self.assertNotIn('PRIVATE',str(event))

    def test_real_connections_keep_distinct_endpoints_and_route_deltas(self):
        state=traffic.update({},[row(),row('udp','udp',123,['DIRECT'])],1000,set())
        state=traffic.update(state,[row(download=160),row('udp','udp',123,['DIRECT'],130)],1001,set())
        domain=traffic.summary(state,1001)['domains'][0]
        self.assertIn('endpoints',domain)
        endpoints={(x['network'],x['port']):x for x in domain['endpoints']}
        self.assertEqual(endpoints['tcp',443]['paths']['proxy']['observed_bytes_lower_bound'],60)
        self.assertEqual(endpoints['udp',123]['paths']['direct']['observed_bytes_lower_bound'],30)
        self.assertEqual(endpoints['tcp',443]['application_protocol'],'unknown')

    def test_general_activity_does_not_advance_domain_failure_time(self):
        f={'domain':'api.example.com','sourceIP':'192.168.2.20','origin':'client','id':'first','at':1000,
           'event_at':990,'network':'tcp','port':443,'path':'proxy','error_category':'timeout'}
        state=traffic.record_failures({},[f],1000,set())
        state=traffic.update(state,[row()],2000,set())
        d=traffic.summary(state,2000)['domains'][0]
        self.assertEqual(d.get('last_failure_at'),990)
        self.assertEqual(d['last_seen'],2000)
        e=d['endpoints'][0]
        self.assertEqual(e['paths']['proxy']['last_failure_at'],990)

    def test_missing_endpoint_is_unknown_and_never_assumed_https(self):
        value=row();value['metadata'].pop('destinationPort')
        state=traffic.update({},[value],1000,set());d=traffic.summary(state,1000)['domains'][0]
        self.assertEqual(d.get('endpoints'),[])
        self.assertIsNone(d['last_failure_at'])

    def test_endpoint_capacity_and_expiry_are_bounded(self):
        state={}
        for n in range(600):state=traffic.update(state,[row(str(n),port=1000+n)],1000+n,set())
        self.assertIn('endpoints',state)
        self.assertLessEqual(len(state['endpoints']),512)
        state=traffic.update(state,[],1600+traffic.RETENTION_SECONDS,set())
        self.assertEqual(state['endpoints'],{})

    def test_invalid_port_does_not_create_a_false_endpoint(self):
        for value in [True,0,65536,'invalid']:
            state=traffic.update({},[row(port=value)],1000,set())
            self.assertEqual(traffic.summary(state,1000)['domains'][0].get('endpoints'),[])


if __name__=='__main__':unittest.main()
