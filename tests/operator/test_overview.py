import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone

try:
    import overview
except ImportError:
    overview = None

NOW = 2000000000
def iso(at): return datetime.fromtimestamp(at, timezone.utc).isoformat()

class OverviewTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(overview, 'overview adapter must exist')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.rules = ['IP-CIDR,192.168.0.0/16,DIRECT,no-resolve','IP-CIDR,10.0.0.0/8,DIRECT,no-resolve','IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
                      'DOMAIN,ai.lan,DIRECT','DOMAIN,ai.local,DIRECT','GEOSITE,private,DIRECT','GEOSITE,cn,DIRECT', 'GEOSITE,geolocation-!cn,PROXY', 'GEOIP,CN,DIRECT', 'MATCH,PROXY']
        self.config = self.state/'config.json'
        self.config.write_text(json.dumps({'secret':'private-controller', 'rules':self.rules,
            'proxy-providers':{'us':{'interval':21600,'filter':'(?i)(美国)','exclude-filter':'','url':'https://subscription.invalid/private-value'},'other':{'interval':21600,'exclude-filter':'(?i)(美国)'}},
            'proxy-groups':[{'name':'PROXY','proxies':['US_AUTO','OTHER_AUTO']}]}))
        self.preferences={'mode':'rule','mainland_direct':True,'preferred_label':'美国','preferred_keywords':['美国'],'allow_other_regions':True,'allow_proxy_direct_fallback':False}
        self.put('approved-policy.json', {'preferences':self.preferences})
        self.data = {
            '/configs':{'mode':'rule', 'authentication':['private-user:private-password']},
            '/proxies':{'proxies':{'PROXY':{'name':'PROXY','type':'Selector','now':'US_AUTO','all':['US_AUTO','OTHER_AUTO']},
                'GLOBAL':{'type':'Selector','now':'PROXY'},'US_AUTO':{'type':'URLTest','now':'California (美国) G03','alive':True}}},
            '/providers/proxies':{'providers':{'us':{'updatedAt':iso(NOW-90),'url':'private-source','proxies':[
                {'name':'California (美国) G03','type':'Shadowsocks','alive':True,'server':'private-server','password':'private-node-password',
                 'history':[{'time':iso(NOW-30),'delay':168}]}]},'other':{'updatedAt':iso(NOW-89),'proxies':[]}}},
            '/rules':{'rules':[{'type':'IPCIDR','payload':'192.168.0.0/16','proxy':'DIRECT'},{'type':'IPCIDR','payload':'10.0.0.0/8','proxy':'DIRECT'},{'type':'IPCIDR','payload':'172.16.0.0/12','proxy':'DIRECT'},
                {'type':'Domain','payload':'ai.lan','proxy':'DIRECT'},{'type':'Domain','payload':'ai.local','proxy':'DIRECT'},{'type':'GeoSite','payload':'private','proxy':'DIRECT'},
                {'type':'GeoSite','payload':'cn','proxy':'DIRECT'}, {'type':'GeoSite','payload':'geolocation-!cn','proxy':'PROXY'},
                {'type':'GeoIP','payload':'CN','proxy':'DIRECT'},{'type':'Match','payload':'','proxy':'PROXY'}]},
        }
        self.diagnosis = {'checked_at':NOW-30,'last_diagnosis':{'checks':{
            'gateway_dns_cn':{'ok':True,'result':{'rcode':0,'answer_count':1}},
            'gateway_dns_foreign':{'ok':True,'result':{'rcode':0,'answer_count':1}},
            'mainland_https':{'ok':True,'result':{'http_status':200}},
            'proxy_https':{'ok':True,'result':{'http_status':204}},
        }}}
        self.put('patrol.json',self.diagnosis)
        self.calls=[]; self.failed=set()
    def put(self,name,value): (self.state/name).write_text(json.dumps(value))
    def api(self,path,method='GET',data=None,timeout=15):
        self.assertEqual(method,'GET'); self.assertIsNone(data);self.assertLessEqual(timeout,2)
        self.calls.append(path)
        if path in self.failed: raise TimeoutError('credential-looking internal error must not escape')
        return copy.deepcopy(self.data[path])
    def snapshot(self): return overview.build_snapshot(self.api,self.state,self.config,NOW)
    def test_actual_provider_leaf_is_named_without_exposing_private_node_fields(self):
        result=self.snapshot()
        self.assertEqual(result['node']['name'],'California (美国) G03')
        self.assertEqual(result['node']['state'],'healthy');self.assertEqual(result['node']['delay_ms'],168)
        self.assertEqual(result['subscription']['interval_seconds'],21600)
        self.assertEqual(result['subscription']['updated_at'],NOW-89)
        encoded=json.dumps(result)
        for value in ['private-controller','private-source','private-server','private-node-password','private-password','subscription.invalid']:
            self.assertNotIn(value,encoded)
        self.assertEqual(set(self.calls),{'/configs','/proxies','/providers/proxies','/rules'})
    def test_global_and_direct_modes_follow_live_mode_instead_of_saved_rule_mode(self):
        self.data['/configs']['mode']='global'
        self.data['/proxies']['proxies']['GLOBAL']['now']='DIRECT'
        result=self.snapshot();self.assertEqual(result['node']['kind'],'direct');self.assertIsNone(result['node']['name'])
        self.assertIn('全局',result['routing']['summary'])
        self.data['/configs']['mode']='direct'
        result=self.snapshot();self.assertEqual(result['node']['kind'],'direct')
        self.assertEqual(next(c for c in result['health']['checks'] if c['id']=='proxy')['state'],'not_used')
    def test_cycles_and_missing_targets_are_unknown_not_arbitrary_node_choices(self):
        group=self.data['/proxies']['proxies']['US_AUTO']
        for name in ['PROXY','missing-node']:
            with self.subTest(name=name):
                group['now']=name;node=self.snapshot()['node']
                self.assertEqual(node['kind'],'unknown');self.assertIsNone(node['name']);self.assertEqual(node['state'],'unknown')
    def test_stale_future_and_missing_health_never_stay_green(self):
        for age in [601,-120,None]:
            with self.subTest(age=age):
                self.diagnosis['checked_at']=NOW-age if age is not None else None;self.put('patrol.json',self.diagnosis)
                result=self.snapshot();self.assertEqual(result['health']['state'],'unknown')
                self.assertTrue(all(c['state']=='unknown' for c in result['health']['checks']))
        self.diagnosis['checked_at']=NOW-30;self.diagnosis['last_diagnosis']['checks'].pop('mainland_https');self.put('patrol.json',self.diagnosis)
        self.assertEqual(self.snapshot()['health']['checks'][0]['state'],'unknown')
    def test_business_denial_is_unconfirmed_not_network_failure_and_timeouts_are_failures(self):
        self.diagnosis['last_diagnosis']['checks']['proxy_https']['result']['http_status']=403;self.put('patrol.json',self.diagnosis)
        self.assertEqual(self.snapshot()['health']['checks'][1]['state'],'unknown')
        self.diagnosis['last_diagnosis']['checks']['proxy_https']={'ok':False,'error':'TimeoutError'};self.put('patrol.json',self.diagnosis)
        self.assertEqual(self.snapshot()['health']['checks'][1]['state'],'unhealthy')
    def test_controller_failure_keeps_independent_health_and_hides_internal_errors(self):
        self.failed={'/configs','/proxies','/providers/proxies','/rules'}
        result=self.snapshot();self.assertEqual(result['node']['state'],'unknown')
        self.assertEqual(result['health']['state'],'healthy');self.assertNotIn('credential-looking',json.dumps(result))
    def test_live_rule_mismatch_and_extra_exit_are_reported_without_rule_dump(self):
        result=self.snapshot();self.assertTrue(result['routing']['consistent']);self.assertIn('中国大陆直连',result['routing']['summary'])
        self.data['/rules']['rules'][-1]['proxy']='DIRECT'
        result=self.snapshot();self.assertFalse(result['routing']['consistent']);self.assertIn('核对',result['routing']['summary'])
        self.data['/rules']['rules'][-1]['proxy']='SPECIAL'
        result=self.snapshot();self.assertTrue(result['routing']['multiple_exits'])
        self.assertNotIn('rules',result['routing'])
    def test_outdated_node_history_is_not_labeled_available(self):
        p=self.data['/providers/proxies']['providers']['us']['proxies'][0]
        p['history'][0]['time']=iso(NOW-900)
        self.assertEqual(self.snapshot()['node']['state'],'unknown')
    def test_pending_recovery_and_actual_terminal_receipts_take_precedence_over_routine_sampling(self):
        self.put('native-maintenance.json',{'runs':[{'state':'failed','at':NOW-20,'finished_at':NOW-10,'kind':'independent_audit','summary':'private raw conversation'}]})
        result=self.snapshot();self.assertEqual(result['activity']['state'],'failed');self.assertNotIn('private raw conversation',json.dumps(result))
        self.put('pending.json',{'operation':'recheck_nodes','deadline':NOW+60})
        self.assertEqual(self.snapshot()['activity']['state'],'verifying')
    def test_malformed_observation_file_degrades_only_its_section(self):
        (self.state/'patrol.json').write_text('{broken')
        result=self.snapshot();self.assertEqual(result['health']['state'],'unknown');self.assertEqual(result['node']['state'],'healthy')
    def test_wrong_shaped_partial_observations_do_not_break_the_whole_page(self):
        for value in [None,[], 'invalid']:
            with self.subTest(value=value):
                self.put('patrol.json',{'checked_at':NOW,'last_diagnosis':value})
                self.assertEqual(self.snapshot()['health']['state'],'unknown')
        self.data['/providers/proxies']['providers']['us']['proxies']=None
        self.data['/rules']['rules'][0]['extra']=None
        self.assertEqual(self.snapshot()['node']['state'],'unknown')
    def test_saved_mainland_and_region_filter_preferences_must_match_running_configuration(self):
        for patch in [{'mainland_direct':False,'preferred_label':'日本'},{'preferred_keywords':['日本'],'preferred_label':'日本'}]:
            with self.subTest(patch=patch):
                self.put('approved-policy.json',{'preferences':{**self.preferences,**patch}})
                result=self.snapshot();self.assertFalse(result['routing']['consistent']);self.assertIn('核对',result['routing']['summary'])
    def test_empty_keywords_use_the_real_single_pool_semantics_without_false_country_claims(self):
        self.put('approved-policy.json',{'preferences':{**self.preferences,'preferred_keywords':[]}})
        cfg=json.loads(self.config.read_text());cfg['proxy-providers']['us'].pop('filter');cfg['proxy-providers']['other']['exclude-filter']='';self.config.write_text(json.dumps(cfg))
        self.data['/proxies']['proxies']['PROXY']['all']=['US_AUTO']
        result=self.snapshot();self.assertTrue(result['routing']['consistent']);self.assertNotIn('美国节点',result['routing']['detail'])
    def test_malformed_terminal_state_and_ruleset_size_degrade_without_losing_node(self):
        self.put('native-maintenance.json',{'runs':[{'state':[],'at':NOW-10}]})
        rule={'type':'RuleSet','payload':'proxy-domains','proxy':'PROXY','size':None}
        self.data['/rules']['rules'].insert(5,rule)
        cfg=json.loads(self.config.read_text());cfg['rules'].insert(5,'RULE-SET,proxy-domains,PROXY');cfg['rule-providers']={'proxy-domains':{'type':'file','path':'proxy-domains.yaml'}};self.config.write_text(json.dumps(cfg))
        self.assertEqual(self.snapshot()['node']['name'],'California (美国) G03')
    def test_empty_dns_observation_is_unknown_and_explicit_failure_is_unhealthy(self):
        for value in [{},{'ok':True,'result':None}]:
            self.diagnosis['last_diagnosis']['checks']['gateway_dns_cn']=value;self.put('patrol.json',self.diagnosis)
            self.assertEqual(self.snapshot()['health']['checks'][2]['state'],'unknown')
    def test_repair_receipt_uses_durable_final_result_and_keeps_legacy_evidence_honest(self):
        old={'operation':'recheck_nodes','completed_at':NOW-5,'result':self.diagnosis['last_diagnosis']}
        self.put('last-repair.json',{**old,'verified_healthy':True})
        self.assertEqual(self.snapshot()['activity']['state'],'completed')
        self.put('last-repair.json',old)
        self.assertNotEqual(self.snapshot()['activity']['state'],'completed')
    def test_legacy_equivalent_filters_and_protected_domain_exception_preserve_valid_summary(self):
        cfg=json.loads(self.config.read_text())
        cfg['proxy-providers']['us']['filter']='(?i)(美[国])';cfg['proxy-providers']['other']['exclude-filter']='(?i)(美[国])'
        cfg['rules'].insert(5,'DOMAIN-SUFFIX,deepseek.com,DIRECT');self.config.write_text(json.dumps(cfg))
        self.data['/rules']['rules'].insert(5,{'type':'DomainSuffix','payload':'deepseek.com','proxy':'DIRECT'})
        self.assertTrue(self.snapshot()['routing']['consistent'])
    def test_actual_pool_membership_conflict_is_detected_even_with_matching_saved_filter_text(self):
        self.data['/providers/proxies']['providers']['other']['proxies']=[{'name':'California (美国) extra'}]
        self.assertFalse(self.snapshot()['routing']['consistent'])

class CacheTests(unittest.TestCase):
    def test_concurrent_readers_share_collection_then_refresh_after_expiry(self):
        self.assertIsNotNone(overview,'overview cache must exist')
        clock=[1];cache=overview.SnapshotCache(clock=lambda:clock[0]);calls=[];results=[]
        def loader():calls.append(1);time.sleep(.02);return {'value':len(calls)}
        threads=[threading.Thread(target=lambda:results.append(cache.get(loader))) for _ in range(6)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(calls),1);self.assertEqual(results,[{'value':1}]*6)
        clock[0]=22;self.assertEqual(cache.get(loader),{'value':2})

if __name__=='__main__':unittest.main()
