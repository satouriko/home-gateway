import copy
import json
import unittest

from evidence import diagnosis_summary, incident_summary, task_context, system_context, detail
from business_watch import scan
from business_probe import compare_endpoint


def production_sample():
    domains = [dict(domain=f'busy-{i}.example.com', last_seen=9000-i, failure_count=4,
                    recurring_failure=True, chains=['PROXY'], observed_bytes_lower_bound=900000,
                    rules=['GeoSite'], protocol='tcp', port=443, devices=['192.168.2.10'],
                    details='client sampled evidence ' * 100) for i in range(80)]
    domains += [dict(domain='normal-direct.example.com', last_seen=9001, failure_count=0,
                     chains=['DIRECT'], observed_bytes_lower_bound=5000),
                dict(domain='normal-proxy.example.com', last_seen=9002, failure_count=0,
                     chains=['PROXY'], observed_bytes_lower_bound=5000)]
    diagnosis = {'status': {'checked_at': 9003, 'services': {'net-gateway.service': {'ActiveState':'active'}},
                            'policy': {'revision': 'policy-v9', 'mode':'proxy'}},
                 'checks': {'gateway_dns_cn': {'ok':True,'result':{'rcode':0,'answer_count':2}},
                            'mainland_https': {'ok':True,'result':{'http_status':200,'business_ok':True}},
                            'proxy_https': {'ok':False,'error':'TimeoutError'}},
                 'business_observations': {'status':'observed','checked_at':9003,'domains':domains,
                    'issues':[{'domain':'busy-0.example.com','kind':'recurring_client_failure','resolved':False}],
                    'coverage': {'complete':False, 'gaps':['short_connections_absent']}}}
    incident = {'id':'case-one','domain':'busy-0.example.com','revision':3,'status':'blocked','priority':'urgent',
                'reason':'both routes failed; waiting upstream recovery','outcome':None,'network_restored':False,
                'next_review_at':9100,'updated_at':9000,'evidence':['probe:8000'],
                'facts': {'current_failure':True,'logged_in_application_verified':False},
                'history':[{'at':8999,'kind':'disposition','reason':'retained urgent; inspect upstream'}]}
    return {'observed_at':9003, 'urgent':True,'maintenance_trigger':'anomaly','native_job_id':'native-7',
            'native_session_id':'session-8','native_deadline':9500,'native_task_prompt':'already passed in prompt',
            'diagnosis':diagnosis,'last_diagnosis':copy.deepcopy(diagnosis),
            'incidents':{'cases':[incident],'overflow_cases':[],'capacity_exceeded':False},
            'history':[{'at':i,'faults':['proxy_https']} for i in range(100)],
            'recent_system_changes':[{'at':8990,'kind':'deployment','revision':'source-v4'}]}


def scanned_business_sample():
    endpoint={'network':'tcp','port':443,'application_protocol':'https'}
    observed={'status':'observed','domains':[{'domain':'app.example.com','last_seen':1000,
        'last_failure_at':1000,'failure_count':4,'recurring_failure':True,'error_categories':['timeout'],
        'chains':['PROXY'],'endpoints':[endpoint]}]}
    failed=scan(observed,{},lambda target,**kwargs:{'domain':target,'paths':{
        'proxy':{'transport_ok':True,'http_status':403,'business_ok':False,'application_state':'rejected'}}},1000)
    normal={'status':'observed','domains':[{'domain':'normal.example.com','last_seen':1700,
        'failure_count':0,'chains':['DIRECT'],'endpoints':[endpoint]}]}
    return scan(normal,failed,lambda target,**kwargs:{'domain':target,'paths':{
        'direct':{'transport_ok':True,'http_status':204,'business_ok':True,
                  'acceptance_scope':'fixed health endpoint','logged_in_application_verified':False}}},1700)


def sampled_business_fixture():
    business={'checked_at':2000,'coverage':{'complete':False,'gaps':['application_session_unverified']},
              'issues':[],'checks':{},'domains':[]}
    for i in range(6):
        domain=f'service-{i}.example.com'
        def probe(target,path):
            return {'transport_ok':True,'path_verified':True,'http_status':403 if i==0 and path=='direct' else 204,
                    'content_ok':False if i==0 and path=='direct' else True,
                    'business_error_kind':'region_rejected' if i==0 and path=='direct' else None,
                    'elapsed_ms':300 if path=='proxy' else 100}
        result=compare_endpoint(domain,{'network':'tcp','port':443,'application_protocol':'https'},probe,1900+i)
        result['report_checks']=[{'sample_report':'large detailed payload '*200}]*3
        business['checks'][domain]={'at':1900+i,'result':result}
        business['domains'].append({'domain':domain,'last_seen':1990+i,'chains':['DIRECT' if i%2 else 'PROXY']})
        if i==0:
            business['issues'].append({'domain':domain,'kind':'recurring_client_failure','resolved':False,
                'last_failure_at':1950,'facts':{'current_failure':True,'logged_in_application_verified':False},
                'progress':'waiting for upstream recovery','next_review_at':2100})
    return business


class EvidenceTests(unittest.TestCase):
    def test_disposition_counts_do_not_claim_unverified_targets_are_restored(self):
        records=[{'id':'fixed','status':'closed','priority':'urgent','outcome':'fixed','network_restored':True,'next_review_at':2000},
                 {'id':'outside','status':'closed','priority':'normal','outcome':'no_route_remedy','network_restored':False,'next_review_at':2000},
                 {'id':'active','status':'working','priority':'urgent','network_restored':False,'next_review_at':1100}]
        from evidence import _incidents
        result=_incidents(records,1000)
        self.assertEqual(result['urgent_count'],1)
        self.assertEqual(result['disposed_count'],2);self.assertEqual(result['verified_restored_count'],1)
        self.assertEqual(result['disposed_unverified_count'],1)

    def test_task_keeps_controls_incident_progress_identity_without_duplicate_large_records(self):
        raw=production_sample(); before=copy.deepcopy(raw); result=task_context(raw)
        self.assertEqual(raw,before)
        for key in ['urgent','maintenance_trigger','native_job_id','native_session_id','native_deadline']:
            self.assertEqual(result[key],raw[key])
        self.assertNotIn('last_diagnosis',result); self.assertNotIn('native_task_prompt',result)
        self.assertTrue(result['diagnosis']['checks']['gateway_dns_cn']['ok'])
        self.assertEqual(result['diagnosis']['checks']['mainland_https']['result']['http_status'],200)
        case=result['incidents']['cases'][0]
        self.assertEqual((case['status'],case['priority'],case['next_review_at']),('blocked','urgent',9100))
        self.assertIn('upstream',case['history'][-1]['reason'])
        self.assertFalse(case['network_restored'])
        self.assertLess(len(json.dumps(result).encode()),24*1024)
        self.assertEqual(result['recent_system_changes'][0]['revision'],'source-v4')

    def test_observation_sample_includes_normal_routes_and_failure_scope_with_explicit_gaps(self):
        result=diagnosis_summary(production_sample()['diagnosis'])['business_observations']
        names={row['domain'] for row in result['domains']}
        self.assertIn('busy-0.example.com',names)
        self.assertIn('normal-direct.example.com',names); self.assertIn('normal-proxy.example.com',names)
        self.assertGreater(result['more_count'],0)
        self.assertFalse(result['coverage']['complete'])
        self.assertIn('short_connections_absent',result['coverage']['gaps'])
        self.assertNotIn('business_ok',next(row for row in result['domains'] if row['domain']=='normal-direct.example.com'))

    def test_system_removes_duplicate_diagnosis_code_and_long_history_but_keeps_revisions(self):
        raw=production_sample(); full={'checked_at':9003,'observations':raw['diagnosis']['business_observations'],
             'maintenance_event':raw,'policy':{'revision':'policy-v9'},'source_control':{'head':'abc123','source':'code '*10000},
             'runtime_facts':{'observed_at':9000,'services':{'dsh.service':{'automatic_restart_count':0}}},
             'incidents':raw['incidents'],'recent_system_changes':raw['recent_system_changes']}
        result=system_context(full)
        self.assertNotIn('diagnosis',result['maintenance_event'])
        self.assertNotIn('source',result['source_control'])
        self.assertEqual(result['policy']['revision'],'policy-v9'); self.assertEqual(result['source_control']['head'],'abc123')
        self.assertEqual(result['runtime_facts']['services']['dsh.service']['automatic_restart_count'],0)
        self.assertLess(len(json.dumps(result).encode()),16*1024)

    def test_detail_is_targeted_nonmutating_and_ref_changes_with_new_evidence(self):
        state=production_sample(); before=copy.deepcopy(state)
        reference=diagnosis_summary(state['diagnosis'])['business_observations']['detail_ref']
        result=detail(state,'business_observations',target='normal-direct.example.com')
        self.assertEqual(result['snapshot_ref'],reference['snapshot_ref'])
        self.assertEqual(result['total_count'],1)
        self.assertEqual(result['items'][0]['domain'],'normal-direct.example.com')
        self.assertEqual(state,before)
        state['diagnosis']['business_observations']['domains'][-2]['last_seen']=9100
        self.assertNotEqual(detail(state,'business_observations')['snapshot_ref'],reference['snapshot_ref'])
        with self.assertRaises(ValueError):detail(state,'arbitrary_private_file')
        with self.assertRaises(ValueError):detail(state,'history',limit=10000)

    def test_missing_evidence_and_http_rejections_do_not_become_success(self):
        summary=diagnosis_summary({'checks':{'api':{'ok':True,'result':{'http_status':403,'business_ok':False}}}})
        self.assertFalse(summary['checks']['api']['result']['business_ok'])
        self.assertTrue(summary['evidence_gaps'])
        self.assertEqual(summary['business_observations']['status'],'unknown')
        self.assertEqual(detail({},'observations')['status'],'unknown')

    def test_controls_survive_a_large_target_failure_population(self):
        checks={f'target:{i}.example.com':{'ok':False,'error':'TimeoutError'} for i in range(50)}
        checks.update({'gateway_dns_cn':{'ok':True,'result':{'rcode':0}},
                       'mainland_https':{'ok':True,'result':{'http_status':200}},
                       'proxy_https':{'ok':True,'result':{'http_status':204}}})
        result=diagnosis_summary({'checks':checks})
        self.assertIn('gateway_dns_cn',result['checks'])
        self.assertIn('mainland_https',result['checks'])
        self.assertIn('proxy_https',result['checks'])
        self.assertGreater(result['checks_more_count'],0)

    def test_broker_maintenance_diagnosis_reference_resolves_against_unsummarized_context(self):
        event=production_sample();full={'maintenance_event':event}
        reference=system_context(full)['maintenance_event']['diagnosis_detail_ref']
        result=detail(full,'diagnosis')
        self.assertEqual(result['snapshot_ref'],reference['snapshot_ref'])
        self.assertEqual(result['items'][0]['checks']['gateway_dns_cn']['result']['rcode'],0)

    def test_maintenance_workflow_progress_and_independent_audit_survive_both_contexts(self):
        raw=production_sample()
        raw.update(audit_rollup={'normal_route_review_at':8900},storage={'pause_routine':False},
                   operational_workflow={'version':'wf-3','source':'protected_publisher'})
        raw['maintenance']={'cases':raw['incidents']['cases'],'requires_attention':True,
            'workflow':{'version':'wf-3'},'path_health':{'current':'degraded','disposed_cases_excluded':True},
            'observations':raw['diagnosis']['business_observations'],
            'routing':{'current_direction':'proxy','automatic_correction_authorized':False},
            'faults':['proxy_https'],'pending_signals':[{'kind':'upstream','urgent':True}],
            'next_check_seconds':60,'migration_complete':False}
        for result in [task_context(raw),system_context(raw)]:
            self.assertEqual(result['maintenance']['next_check_seconds'],60)
            self.assertFalse(result['maintenance']['migration_complete'])
            self.assertTrue(result['maintenance']['requires_attention'])
            self.assertEqual(result['maintenance']['cases'][0]['status'],'blocked')
            self.assertFalse(result['maintenance']['routing']['automatic_correction_authorized'])
            self.assertEqual(result['operational_workflow']['version'],'wf-3')
            self.assertEqual(result['operational_workflow']['source'],'protected_publisher')
        self.assertEqual(task_context(raw)['audit_rollup']['normal_route_review_at'],8900)
        self.assertIn('domains',system_context(raw)['maintenance']['observations'])
        compact=task_context(raw)
        self.assertEqual(compact['maintenance']['observations']['summary_in'],'diagnosis.business_observations')
        self.assertNotIn('history',compact['maintenance']['cases'][0])
        self.assertEqual(compact['incidents']['cases'][0]['history'][-1]['kind'],'disposition')
        reference=system_context(raw)['maintenance']['detail_ref']
        self.assertEqual(detail(raw,'maintenance')['snapshot_ref'],reference['snapshot_ref'])

    def test_real_business_scan_target_detail_preserves_issue_check_time_ref_and_nonmutation(self):
        business=scanned_business_sample()
        state={'business_observations':business};before=copy.deepcopy(state)
        result=detail(state,'business_observations','app.example.com')
        self.assertEqual(result['total_count'],1)
        row=result['items'][0]
        self.assertEqual(row['domain'],'app.example.com')
        self.assertEqual(row['issues'][0],business['issues'][0])
        self.assertEqual(row['issues'][0]['last_failure_at'],1000)
        self.assertEqual(row['check'],business['checks']['app.example.com'])
        self.assertEqual(row['check']['at'],1000)
        self.assertEqual(result['observed_at'],1700)
        reference=diagnosis_summary({'business_observations':business})['business_observations']['detail_ref']
        self.assertEqual(result['snapshot_ref'],reference['snapshot_ref'])
        self.assertEqual(state,before)
        business['checks']['app.example.com']['at']=1800
        self.assertNotEqual(detail(state,'business_observations')['snapshot_ref'],reference['snapshot_ref'])

    def test_real_business_scan_compact_summary_keeps_failure_and_normal_check_controls(self):
        business=scanned_business_sample()
        compact=diagnosis_summary({'business_observations':business})['business_observations']
        rows={row['domain']:row for row in compact['domains']}
        self.assertEqual(set(rows),{'app.example.com','normal.example.com'})
        self.assertFalse(rows['app.example.com']['issues'][0]['resolved'])
        self.assertFalse(rows['app.example.com']['check']['result']['paths']['proxy']['business_ok'])
        control=rows['normal.example.com']['check']
        self.assertEqual(control['at'],1700)
        self.assertFalse(control['result']['paths']['direct']['logged_in_application_verified'])
        self.assertEqual(compact['coverage'],business['coverage'])
        self.assertEqual(compact['total_count'],2)
        self.assertEqual(compact['more_count'],0)

    def test_real_business_scan_issue_without_check_and_unknown_target_keep_evidence_gaps(self):
        business=scan({'status':'observation_unavailable'},
            {'issues':[{'domain':'unprobed.example.com','resolved':False,'last_failure_at':900}]},
            lambda target:None,1000)
        business['evidence_gaps']=[{'domain':'unprobed.example.com','kind':'endpoint_unknown'}]
        result=detail({'business_observations':business},'business_observations','unprobed.example.com')
        self.assertEqual(result['items'][0]['issues'][0]['last_failure_at'],900)
        self.assertNotIn('check',result['items'][0])
        self.assertEqual(result['evidence_gaps'],business['evidence_gaps'])
        compact=diagnosis_summary({'business_observations':business})['business_observations']
        self.assertEqual(compact['evidence_gaps'],business['evidence_gaps'])
        missing=detail({'business_observations':business},'business_observations','absent.example.com')
        self.assertEqual(missing['status'],'not_found')
        self.assertTrue(missing['evidence_gaps'])
        self.assertEqual(missing['items'],[])

    def test_legacy_business_schema_and_large_retained_issue_population_keep_controls(self):
        business=scanned_business_sample();business.pop('domains',None)
        business['issues'] += [{'domain':f'pending-{i}.example.com','resolved':False,'last_failure_at':900}
                               for i in range(40)]
        before=copy.deepcopy(business)
        compact=diagnosis_summary({'business_observations':business})['business_observations']
        self.assertIn('normal.example.com',{row['domain'] for row in compact['domains']})
        self.assertGreater(compact['more_count'],0)
        result=detail({'business_observations':business},'business_observations','app.example.com')
        self.assertEqual(result['items'][0]['check']['at'],1000)
        self.assertFalse(result['items'][0]['issues'][0]['resolved'])
        self.assertEqual(business,before)

    def test_business_row_join_does_not_mutate_domain_embedded_issue_lists(self):
        issue={'domain':'app.example.com','resolved':False,'last_failure_at':1000}
        business={'domains':[{'domain':'app.example.com','issues':[]}],
                  'issues':[issue],'checks':{},'checked_at':1700}
        before=copy.deepcopy(business)
        diagnosis_summary({'business_observations':business})
        detail({'business_observations':business},'business_observations','app.example.com')
        self.assertEqual(business,before)

    def test_real_six_endpoint_checks_compact_aggregates_keep_full_detail_and_scope(self):
        business=sampled_business_fixture();before=copy.deepcopy(business)
        compact=system_context({'business_observations':business})['business_observations']
        self.assertLess(len(json.dumps(compact).encode()),8*1024)
        rows={row['domain']:row for row in compact['domains']}
        self.assertEqual(len(rows),6)
        issue=rows['service-0.example.com']['issues'][0]
        self.assertEqual(issue['progress'],'waiting for upstream recovery')
        self.assertTrue(issue['facts']['current_failure'])
        rejected=rows['service-0.example.com']['check']['result']['paths']['direct']
        self.assertEqual(rejected['sample_count'],3)
        self.assertEqual(rejected['business_rejection_samples'],3)
        self.assertEqual(rejected['region_rejected_samples'],3)
        self.assertEqual(rejected['median_elapsed_ms'],100)
        self.assertNotIn('samples',rejected)
        normal=rows['service-1.example.com']['check']['result']
        self.assertEqual(normal['acceptance_stage'],'http_response')
        self.assertFalse(normal['application_verified'])
        self.assertEqual(normal['paths']['direct']['success_samples'],3)
        self.assertNotIn('report_checks',normal)
        reference=rows['service-0.example.com']['detail_ref']
        fetched=detail({'business_observations':business},reference['section'],reference['target'])
        self.assertEqual(fetched['snapshot_ref'],reference['snapshot_ref'])
        original=fetched['items'][0]['check']
        self.assertEqual(original,business['checks']['service-0.example.com'])
        self.assertEqual(len(original['result']['paths']['direct']['samples']),3)
        self.assertEqual(business,before)

    def test_source_control_recent_publications_keep_two_metadata_receipts_and_full_detail(self):
        source={'available':True,'pending':True,'phase':'pending','error_code':'offline',
                'acknowledged_request':'request-4','remote_commit':'remote-proof',
                'recent_publications':[{'id':f'request-{i}','sequence':i,'status':'pending' if i==5 else 'confirmed',
                    'version':str(i),'updated_at':1000+i,'remote_commit':'proof-'+str(i),
                    'commit_message':'private-to-detail commit body '+('background '*500)} for i in range(6)]}
        before=copy.deepcopy(source);compact=system_context({'source_control':source})
        result=compact['source_control']
        self.assertEqual(len(result['recent_publications']),2)
        self.assertEqual([row['id'] for row in result['recent_publications']],['request-4','request-5'])
        self.assertEqual(result['recent_publications'][0]['remote_commit'],'proof-4')
        self.assertTrue(result['pending']);self.assertEqual(result['error_code'],'offline')
        self.assertEqual(result['acknowledged_request'],'request-4')
        self.assertEqual(result['publication_more_count'],4)
        self.assertEqual(result['publication_status_counts'],{'confirmed':5,'pending':1})
        self.assertNotIn('commit_message',result['recent_publications'][0])
        reference=compact['source_control_detail_ref']
        retrieved=detail({'source_control':source},reference['section'])
        self.assertEqual(retrieved['snapshot_ref'],reference['snapshot_ref'])
        self.assertEqual(retrieved['items'][0],source)
        self.assertEqual(source,before)

    def test_identical_native_schedule_has_one_summary_and_unequal_schedule_is_preserved(self):
        task={'kind':'every','everySeconds':14400,'scheduledAt':'2026-11-05T00:00:00Z','status':'active'}
        full={'audit_plan':{'interval_hours':4,'native_schedule':copy.deepcopy(task)},
              'native_automation':{'enabled':True,'task':task,'last_gate':{'admitted':False,'reason':'await next audit'}}}
        before=copy.deepcopy(full);compact=system_context(full)
        self.assertEqual(compact['audit_plan']['native_schedule'],{'summary_in':'native_automation.task'})
        self.assertEqual(compact['native_automation']['task'],task)
        self.assertEqual(compact['native_automation']['last_gate']['reason'],'await next audit')
        self.assertEqual(full,before)
        full['audit_plan']['native_schedule']['everySeconds']=7200
        changed=system_context(full)
        self.assertEqual(changed['audit_plan']['native_schedule']['everySeconds'],7200)
        self.assertEqual(changed['native_automation']['task']['everySeconds'],14400)

    def test_many_cases_report_remaining_urgent_work_and_retrieve_omitted_case(self):
        raw=production_sample(); template=raw['incidents']['cases'][0]
        raw['incidents']['cases']=[{**template,'id':f'case-{i}','next_review_at':9000+i} for i in range(40)]
        result=task_context(raw)['incidents']
        self.assertEqual(result['urgent_count'],40); self.assertGreater(result['more_count'],0)
        omitted='case-39'
        self.assertEqual(detail(raw,'incidents',omitted)['items'][0]['id'],omitted)
        self.assertEqual(incident_summary(template)['facts']['logged_in_application_verified'],False)


if __name__=='__main__':unittest.main()
