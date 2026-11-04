"""Operational workflow boundary, protected policy, and durable rollback tests."""
import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'src/operator/workflow.py'
MAINTAINED = MODULE.parent.parent / 'maintained/workflow.py'


def snapshot():
    return {'schema_version': 1, 'now': 1000, 'path_health': {'hard_faults': [], 'checks': {
        'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 100}},
        'mainland_https': {'ok': True, 'result': {'http_status': 200}}}},
        'incidents': [], 'observations': {'domains': []}, 'routing': {'candidates': []},
        'audit': {'node_count': 4, 'previous_node_count': 5},
        'checks': {'proxy_https': {'ok': True}}, 'history': [{'at': 999, 'node_count': 5}],
        'business_observations': {'issues': []}}


def case(ident='case-1', priority='urgent', status='open', attention=True, due=1000):
    return {'id': ident, 'status': status, 'priority': priority, 'reason': 'observed target failure',
        'outcome': None, 'next_review_at': due, 'facts': {'current_failure': True},
        'evidence': ['observation:1'], 'revision': 1, 'requires_attention': attention}


def constant(**changes):
    value = {'summary': 'bounded decision', 'wake': 'none', 'incident_ids': [],
             'probe_domains': [], 'route_candidates': [], 'next_check_seconds': 300}
    value.update(changes)
    return 'def inspect(snapshot):\n return ' + repr(value) + '\n'


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = None
        if MODULE.exists():
            spec = importlib.util.spec_from_file_location('workflow', MODULE)
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)

    def setUp(self):
        self.assertIsNotNone(self.module, 'workflow publisher must exist')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.patches = [patch.object(self.module, 'STATE', self.state), patch.object(self.module.os, 'geteuid', return_value=1000)]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def source(self):
        return MAINTAINED.read_text()

    def test_actual_isolated_evaluator_uses_explicit_schema(self):
        result = self.module.evaluate(constant(), snapshot())
        self.assertEqual(result['wake'], 'none')
        self.assertEqual(result['next_check_seconds'], 300)
        for missing in ['schema_version', 'path_health', 'incidents', 'observations', 'routing', 'audit']:
            broken = snapshot(); broken.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.module.evaluate(constant(), broken)

    def test_maintained_policy_preserves_severity_and_attention_lifecycle(self):
        scenarios = [('healthy', [], 'none', []), ('new urgent', [case()], 'urgent', ['case-1']),
            ('blocked not due', [case(status='blocked', attention=False, due=1100)], 'none', []),
            ('blocked due', [case(status='blocked')], 'urgent', ['case-1']),
            ('failed lease', [case(status='working')], 'urgent', ['case-1']),
            ('closed no review', [case(status='closed', attention=False, due=1100)], 'none', []),
            ('unknown business', [case(ident='case-unknown')], 'urgent', ['case-unknown']),
            ('normal due', [case(priority='normal')], 'routine', ['case-1'])]
        for name, incidents, wake, ids in scenarios:
            data = snapshot(); data['incidents'] = incidents
            with self.subTest(case=name):
                actual = self.module.evaluate(self.source(), data)
                self.assertEqual(actual['wake'], wake)
                self.assertEqual(actual['incident_ids'], ids)

    def test_hard_fault_guard_cannot_be_muted_by_source(self):
        data = snapshot(); data['path_health']['hard_faults'] = ['control_route']
        with self.assertRaisesRegex(ValueError, 'hard fault'):
            self.module.evaluate(constant(), data)
        self.assertEqual(self.module.evaluate(self.source(), data)['wake'], 'urgent')

    def test_urgent_case_cannot_be_dropped_or_downgraded(self):
        data = snapshot(); data['incidents'] = [case()]
        for source in [constant(wake='routine', incident_ids=['case-1']), constant(wake='urgent')]:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'urgent incident'):
                self.module.evaluate(source, data)

    def test_candidate_rotation_and_observed_domains_do_not_claim_application(self):
        data = snapshot(); data['observations']['domains'] = [{'domain': 'video.example.com', 'needs_probe': True}]
        data['routing']['candidates'] = [{'domain': 'one.example.com', 'needs_route_review': True}, {'domain': 'two.example.com', 'needs_route_review': True},
            {'domain': 'three.example.com', 'needs_route_review': True}, {'domain': 'four.example.com', 'needs_route_review': True}]
        first = self.module.evaluate(self.source(), data)
        data['now'] = 1300
        second = self.module.evaluate(self.source(), data)
        self.assertIn('video.example.com', first['probe_domains'])
        self.assertLessEqual(len(first['route_candidates']), 3)
        self.assertNotEqual(first['route_candidates'], second['route_candidates'])
        self.assertEqual(first['wake'], 'none')

    def test_rejects_io_secrets_unknown_cases_and_forbidden_outputs(self):
        for source in ["def inspect(s):\n return open('/etc/passwd').read()", "def inspect(s):\n return s.__class__",
                       "def inspect(s):\n return {'token':" + repr("sk-" + "a" * 24) + "}",
                       "def inspect(s):\n return {'token':" + repr("ghp_" + "a" * 26) + "}"]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.module.evaluate(source, snapshot())
        for changes in [{'incident_ids': ['unknown']}, {'route_candidates': ['localhost.local']},
                        {'probe_domains': ['169.254.169.254']}, {'shell': 'id'},
                        {'next_check_seconds': True}, {'probe_domains': ['x.example.com'] * 4}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.module.evaluate(constant(**changes), snapshot())

    def test_runtime_resource_budgets_stop_expansion(self):
        with self.assertRaises(ValueError):
            self.module.evaluate("def inspect(s):\n x = 'a' * 200000000\n return {}", snapshot())
        with self.assertRaises(ValueError):
            self.module.evaluate("def inspect(s):\n x = list(range(5000))\n return {}", snapshot())

    def test_protected_tests_reject_suppression_and_publish_is_side_effect_free_on_rejection(self):
        with self.assertRaises(ValueError):
            self.module.workflow_action('workflow_publish', constant())
        self.assertFalse((self.state / 'workflow-state.json').exists())
        names = {row['case'] for row in self.module.fixed_tests(self.source())}
        self.assertTrue({'healthy', 'urgent_new', 'urgent_blocked_not_due', 'urgent_blocked_due',
            'failed_working_lease', 'hard_fault', 'closed_not_due', 'unknown_business', 'missing_data'} <= names)

    def test_publication_versions_and_atomic_previous_rollback_are_exercised(self):
        source = self.source()
        tested = self.module.workflow_action('workflow_test', source)
        self.assertFalse(tested['deployed'])
        self.assertFalse((self.state / 'workflow-state.json').exists())
        first = self.module.workflow_action('workflow_publish', source)
        runtime_fault = source.replace('def inspect(snapshot):', "def inspect(snapshot):\n    crash = 1 / (0 if snapshot.get('audit', {}).get('runtime_crash') else 1)")
        second = self.module.workflow_action('workflow_publish', runtime_fault)
        self.assertNotEqual(first['version'], second['version'])
        current = self.module.workflow_action('workflow_status')
        self.assertEqual(current['version'], second['version'])
        data = snapshot(); data['audit']['runtime_crash'] = True
        actual = self.module.inspect_active(data)
        self.assertEqual(actual['result']['wake'], 'none')
        self.assertTrue(actual['rolled_back'])
        self.assertTrue(actual['maintenance_required'])
        self.assertEqual(actual['failed_version'], second['version'])
        self.assertEqual(actual['version'], first['version'])
        self.assertIn('ZeroDivisionError', actual['failures'][0]['error'])
        self.assertEqual(self.module.workflow_action('workflow_status')['version'], first['version'])

    def test_both_runtime_failures_keep_network_alarm_and_failure_identity(self):
        source = self.source()
        for tag in ['a', 'b']:
            crashing = source.replace('def inspect(snapshot):', "def inspect(snapshot):\n    crash = 1 / (0 if snapshot.get('audit', {}).get('runtime_crash') else 1)\n    tag = '" + tag + "'")
            self.module.workflow_action('workflow_publish', crashing)
        data = snapshot(); data['audit']['runtime_crash'] = True
        data['path_health']['hard_faults'] = ['proxy_https']
        actual = self.module.inspect_active(data)
        self.assertEqual(actual['result']['wake'], 'urgent')
        self.assertEqual(len(actual['failures']), 2)
        self.assertNotEqual(actual['failures'][0]['version'], actual['failures'][1]['version'])
        self.assertTrue(actual['maintenance_required'])
        self.assertTrue(actual['safe_fallback'])

    def test_invalid_output_rolls_back_and_missing_input_is_actionable(self):
        source = self.source()
        self.module.workflow_action('workflow_publish', source)
        invalid = source.replace('def inspect(snapshot):', "def inspect(snapshot):\n    if snapshot.get('audit', {}).get('runtime_bad'):\n        return {'summary': 'bad'}")
        self.module.workflow_action('workflow_publish', invalid)
        data = snapshot(); data['audit']['runtime_bad'] = True
        self.assertTrue(self.module.inspect_active(data)['rolled_back'])
        actual = self.module.inspect_active({})
        self.assertEqual(actual['result']['wake'], 'urgent')
        self.assertTrue(actual['maintenance_required'])

    def test_unpublished_status_reports_builtin_without_claiming_publication(self):
        result = self.module.workflow_action('workflow_status')
        self.assertFalse(result['active'])
        self.assertEqual(result['source'], self.source())
        self.assertEqual(self.module.inspect_active(snapshot())['result']['wake'], 'none')
        self.assertFalse((self.state / 'workflow-state.json').exists())

    def test_legacy_health_and_disposed_history_do_not_override_explicit_attention(self):
        data = snapshot()
        data['checks']['proxy_https']['ok'] = False
        data['business_observations']['issues'] = [{'kind': 'unknown', 'resolved': False}]
        data['incidents'] = [case(status='closed', attention=False, due=1200)]
        self.assertEqual(self.module.evaluate(self.source(), data)['wake'], 'none')

    def test_malformed_input_does_not_replace_a_valid_published_version(self):
        publication = self.module.workflow_action('workflow_publish', self.source())
        result = self.module.inspect_active({})
        self.assertEqual(result['result']['wake'], 'urgent')
        self.assertTrue(result['maintenance_required'])
        self.assertEqual(self.module.workflow_action('workflow_status')['version'], publication['version'])
        self.assertTrue(self.module.workflow_action('workflow_status')['active'])
        self.assertFalse(result.get('rolled_back', False))

    def test_corrupt_storage_returns_safe_decision_without_overwriting_evidence(self):
        path = self.state / 'workflow-state.json'
        path.write_text('broken state')
        data = snapshot(); data['path_health']['hard_faults'] = ['service']
        result = self.module.inspect_active(data)
        self.assertEqual(result['result']['wake'], 'urgent')
        self.assertTrue(result['maintenance_required'])
        self.assertEqual(result['failures'][-1]['version'], 'workflow-storage')
        self.assertEqual(path.read_text(), 'broken state')

    def test_worker_exceptions_do_not_echo_private_snapshot_values(self):
        data = snapshot(); data['audit']['private'] = 'private-value-that-must-not-be-logged'
        source = "def inspect(snapshot):\n return int(snapshot['audit']['private'])"
        with self.assertRaises(ValueError) as error:
            self.module.evaluate(source, data)
        self.assertIn('ValueError', str(error.exception))
        self.assertNotIn(data['audit']['private'], str(error.exception))

    def test_cpu_budget_terminates_nested_bounded_ranges(self):
        source = "def inspect(s):\n x = 0\n for a in range(4096):\n  for b in range(4096):\n   for c in range(4096):\n    x += 1\n return {}"
        with self.assertRaises(ValueError):
            self.module.evaluate(source, snapshot())

    def test_secret_values_cannot_escape_through_domain_advice(self):
        data = snapshot(); data['audit']['token'] = 'sk-' + 'abcdefghijklmnopqrstuvwxyz'
        source = "def inspect(s):\n return {'summary':'x','wake':'none','incident_ids':[],'probe_domains':[s['audit']['token'] + '.com'],'route_candidates':[],'next_check_seconds':300}"
        with self.assertRaises(ValueError):
            self.module.evaluate(source, data)

    def test_concurrent_process_publications_keep_a_complete_previous_version(self):
        code = "import json,sys; from pathlib import Path; import workflow; workflow.STATE=Path(sys.argv[1]); workflow.os.geteuid=lambda:1000; print(json.dumps(workflow.workflow_action('workflow_publish',sys.argv[2])))"
        processes = [subprocess.Popen([sys.executable, '-c', code, str(self.state), self.source() + '# ' + tag],
            env={**os.environ, 'PYTHONPATH': str(MODULE.parent)}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for tag in ['first', 'second']]
        results = []
        for process in processes:
            output, errors = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, errors)
            results.append(json.loads(output)['version'])
        data = json.loads((self.state / 'workflow-state.json').read_text())
        self.assertEqual({data['active']['version'], data['previous']['version']}, set(results))
        self.assertEqual(self.module.inspect_active(snapshot())['result']['wake'], 'none')
        self.assertEqual({path.name for path in self.state.iterdir()}, {'workflow-state.json', 'workflow-state.json.lock'})

    def test_urgent_attention_overflow_is_explicit_and_remains_actionable(self):
        data = snapshot(); data['incidents'] = [case(ident='case-' + str(index)) for index in range(17)]
        result = self.module.inspect_active(data)
        self.assertEqual(result['result']['wake'], 'urgent')
        self.assertTrue(result['maintenance_required'])
        self.assertTrue(result['safe_fallback'])
        self.assertIn('17', result['result']['summary'])
        self.assertEqual(len(result['result']['incident_ids']), 16)
        self.assertIn('overflow', result['failures'][0]['error'])

    def test_healthy_faster_and_region_denied_alternatives_are_not_route_reviews(self):
        data = snapshot()
        data['observations']['domains'] = [{'domain': 'api.openai.com', 'needs_probe': True}]
        data['routing']['candidates'] = [
            {'domain': 'healthy.example.com', 'needs_probe': True, 'current_path_healthy': True, 'alternative_faster': True},
            {'domain': 'api.openai.com', 'needs_probe': True, 'current_path_healthy': True,
             'alternative_faster': True, 'alternative_business_outcome': 'unsupported_region'}]
        result = self.module.evaluate(self.source(), data)
        self.assertEqual(result['route_candidates'], [])
        self.assertIn('api.openai.com', result['probe_domains'])
        self.assertEqual(result['wake'], 'none')
        with self.assertRaises(ValueError):
            self.module.evaluate(constant(route_candidates=['api.openai.com']), data)

    def test_unknown_operation_is_rejected_without_state_change(self):
        with self.assertRaises(ValueError):
            self.module.workflow_action('workflow_destroy', self.source())
        self.assertFalse((self.state / 'workflow-state.json').exists())


if __name__ == '__main__':
    unittest.main()
