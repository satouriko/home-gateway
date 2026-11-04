# gateway-public-test: 1
"""Offline acceptance of exported effective sources, not historical candidates."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]


def evaluate(module, source, snapshot):
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'src/operator' / module), '--worker'],
                            input=json.dumps({'source': source, 'snapshot': snapshot}), text=True,
                            capture_output=True, timeout=6)
    if result.returncode:
        raise AssertionError('isolated public worker failed: ' + result.stderr[-1200:])
    return json.loads(result.stdout)


class ActiveDiagnosticTests(unittest.TestCase):
    def setUp(self):
        if not (ROOT / 'src/maintained/diagnostic.py').is_file():
            self.skipTest('no diagnostic publication in this snapshot')
        self.source = (ROOT / 'src/maintained/diagnostic.py').read_text()
        self.snapshot = {'checks': {
            'proxy_https': {'ok': True, 'result': {'http_status': 204, 'expected_health_status': True}},
            'mainland_https': {'ok': True, 'result': {'http_status': 200, 'expected_health_status': True}},
            'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
            'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}}},
            'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
            'history': [], 'business_observations': {'issues': [], 'checks': {}}}

    def result(self):
        return evaluate('programs.py', self.source, self.snapshot)

    def test_healthy_controls_do_not_trigger_repair(self):
        result = self.result()
        self.assertEqual(result['action'], 'none')
        self.assertEqual(result['probe_domains'], [])

    def test_missing_checks_remain_unknown(self):
        self.snapshot['checks'] = {}
        self.assertEqual(self.result()['action'], 'none')

    def test_real_fixed_proxy_fault_remains_actionable(self):
        self.snapshot['checks']['proxy_https'] = {'ok': False, 'error': 'TimeoutError'}
        self.assertEqual(self.result()['action'], 'recheck_nodes')

    def test_new_business_issue_without_path_evidence_requires_review(self):
        self.snapshot['business_observations']['issues'] = [{'domain': 'fresh.example.com',
            'fingerprint': 'public-fixture', 'kind': 'recurring_client_failure', 'resolved': False}]
        result = self.result()
        self.assertTrue(result.get('review_request'))
        self.assertIn('fresh.example.com', result['probe_domains'])

    def test_probe_value_error_does_not_invent_a_missing_dns_diagnosis(self):
        domain = 'probe.example.com'
        self.snapshot['business_observations'] = {
            'issues': [{'domain': domain, 'fingerprint': 'probe-unknown', 'resolved': False}],
            'checks': {domain: {'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}}}
        self.assertNotIn('没有可用的公共解析地址', self.result()['summary'])


class ActiveWorkflowTests(unittest.TestCase):
    def setUp(self):
        if not (ROOT / 'src/maintained/workflow.py').is_file():
            self.skipTest('no workflow source in this snapshot')
        self.source = (ROOT / 'src/maintained/workflow.py').read_text()
        self.snapshot = {'schema_version': 1, 'now': 1000,
            'path_health': {'hard_faults': [], 'checks': {}}, 'incidents': [],
            'observations': {'domains': []}, 'routing': {'candidates': []}, 'audit': {}}

    def result(self):
        return evaluate('workflow.py', self.source, self.snapshot)

    def case(self, **changes):
        case = {'id': 'public-fixture', 'status': 'open', 'priority': 'urgent',
                'reason': 'observed business failure', 'outcome': None, 'next_review_at': 1000,
                'facts': {'current_failure': True}, 'evidence': ['public:control'],
                'revision': 1, 'requires_attention': True}
        case.update(changes)
        self.snapshot['incidents'] = [case]

    def test_new_urgent_fault_is_never_suppressed_by_age_or_repetition(self):
        self.case()
        self.snapshot['audit'] = {'duplicate_count': 10000, 'daily_budget_remaining': 0}
        result = self.result()
        self.assertEqual(result['wake'], 'urgent')
        self.assertEqual(result['incident_ids'], ['public-fixture'])

    def test_blocked_case_keeps_priority_and_returns_when_review_is_due(self):
        self.case(status='blocked', requires_attention=False, next_review_at=1100)
        self.assertEqual(self.result()['wake'], 'none')
        self.case(status='blocked', requires_attention=True)
        self.assertEqual(self.result()['wake'], 'urgent')

    def test_failed_working_lease_retains_urgent_attention(self):
        self.case(status='working')
        self.assertEqual(self.result()['wake'], 'urgent')

    def test_disposed_target_cannot_corrupt_current_path_health(self):
        self.case(status='closed', requires_attention=False, next_review_at=1100, outcome='no_route_remedy')
        self.assertEqual(self.result()['wake'], 'none')
        self.snapshot['path_health']['hard_faults'] = ['proxy_https']
        self.assertEqual(self.result()['wake'], 'urgent')

    def test_faster_alternative_does_not_override_healthy_current_path(self):
        self.snapshot['routing']['candidates'] = [{'domain': 'healthy.example.com',
            'current_path_healthy': True, 'alternative_faster': True, 'needs_probe': True}]
        result = self.result()
        self.assertEqual(result['route_candidates'], [])
        self.assertEqual(result['wake'], 'none')

    def test_tls_or_http_4xx_does_not_prove_application_success(self):
        self.snapshot['routing']['candidates'] = [{'domain': 'app.example.com',
            'tls_ok': True, 'http_status': 403, 'business_outcome': 'unknown', 'needs_probe': True}]
        self.assertEqual(self.result()['route_candidates'], [])


class ActiveToolTests(unittest.TestCase):
    def test_exported_tool_self_test_uses_synthetic_inputs(self):
        # The surrounding exporter sandbox has no host network or private state.
        if not (ROOT / 'src/maintained/tool.py').is_file():
            self.skipTest('no tool publication in this snapshot')
        scope = runpy.run_path(str(ROOT / 'src/maintained/tool.py'))
        result = scope['run']({'operation': 'self_test'})
        self.assertIs(result['ok'], True)
        self.assertTrue(result.get('capabilities'))


if __name__ == '__main__':
    unittest.main()
