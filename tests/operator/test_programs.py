import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
from programs import validate_source, validate_output,evaluate

class ProgramBoundaryTests(unittest.TestCase):
    def test_real_worker_accepts_bounded_observation_growth(self):
        source="def inspect(snapshot):\n return {'summary':'real child','action':'none','probe_domains':[]}\n"
        with patch('programs.os.geteuid',return_value=1000):
            self.assertEqual(evaluate(source,{'observations':{'sample':'a'*180000}})['summary'],'real child')

    def test_input_budget_failure_keeps_the_valid_published_program(self):
        import programs
        source="def inspect(snapshot):\n return {'summary':'ok','action':'none','probe_domains':[]}\n"
        with tempfile.TemporaryDirectory() as folder,patch.object(programs,'STATE',Path(folder)):
            active=Path(folder)/'diagnostic-active.json'
            active.write_text(json.dumps({'version':'good','source':source,'tests':[]}));before=active.read_bytes()
            result=programs.inspect_active({'observations':{'sample':'a'*(600*1024)}})
            self.assertTrue(result['active']);self.assertTrue(result['input_unavailable'])
            self.assertEqual(result['version'],'good');self.assertEqual(active.read_bytes(),before)
            self.assertNotIn('rolled_back',result)

    def test_publisher_rejects_health_only_program_that_misses_real_client_issue(self):
        import programs
        source="def inspect(s):\n return {'summary':'ok','action':'recheck_nodes' if s.get('checks',{}).get('proxy_https',{}).get('ok') is False else 'none','probe_domains':[]}"
        with patch('programs.os.geteuid',return_value=1000):
            with self.assertRaisesRegex(ValueError,'client'):programs.fixed_tests(source)
    def test_actual_isolated_python_process_runs_without_parent_import_paths(self):
        source="def inspect(snapshot):\n return {'summary':'real child','action':'none','probe_domains':[]}\n"
        with patch('programs.os.geteuid',return_value=1000):
            self.assertEqual(evaluate(source,{}),{'summary':'real child','action':'none','probe_domains':[]})
    def test_pure_snapshot_inspection_is_accepted(self):
        source="def inspect(snapshot):\n    checks = snapshot.get('checks', {})\n    return {'summary': str(len(checks)), 'action': 'none', 'probe_domains': []}\n"
        self.assertIsNotNone(validate_source(source))

    def test_import_io_introspection_and_unbounded_loops_are_rejected(self):
        for source in ["import os\ndef inspect(s): return {}", "def inspect(s):\n return open('/etc/passwd').read()", "def inspect(s):\n return s.__class__", "def inspect(s):\n while True: pass", "def inspect(s):\n return eval('1')", "def inspect(s):\n return inspect(s)"]:
            with self.subTest(source=source),self.assertRaises(ValueError):validate_source(source)

    def test_only_nondestructive_known_advice_is_accepted(self):
        result={'summary':'proxy failed','action':'recheck_nodes','probe_domains':['www.google.com']}
        self.assertEqual(validate_output(result),result)
        for action in ['DIRECT','restart_dsh','shell','restore_gateway']:
            with self.subTest(action=action),self.assertRaises(ValueError):validate_output({'summary':'x','action':action,'probe_domains':[]})

    def test_probe_budget_and_domain_validation_are_enforced(self):
        for domains in [['a.com']*4,['https://x.com?token=secret'],['169.254.169.254']]:
            with self.subTest(domains=domains),self.assertRaises(ValueError):validate_output({'summary':'x','action':'none','probe_domains':domains})

if __name__=='__main__':unittest.main()
