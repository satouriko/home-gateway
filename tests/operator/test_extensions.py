import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import extensions

class MaintainedToolTests(unittest.TestCase):
    def test_tool_test_acceptance_never_deploys_candidate(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(extensions,'STATE',Path(folder)):
            active=Path(folder)/'tool-active.json';original=json.dumps({'version':'good','source':'old'});active.write_text(original)
            metadata={'ok':True,'capabilities':{'inspect':'link'},'acceptance_cases':[{'request':{'operation':'inspect'},'expect':{'read_only':True}}]}
            with patch.object(extensions,'execute',side_effect=[metadata,{'observations':[]},{'read_only':True}]):
                result=extensions.action('tool_test','def run(request): return {}')
            self.assertEqual(active.read_text(),original)
            self.assertNotIn('deployed',result)
    def test_publication_requires_actual_declared_operation_acceptance(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(extensions,'STATE',Path(folder)):
            active=Path(folder)/'tool-active.json';active.write_text(json.dumps({'version':'good','source':'old'}))
            self_test={'ok':True,'capabilities':{'inspect':'link','compare_routes':'business comparison'}}
            with patch.object(extensions,'execute',side_effect=[self_test,{'observations':[]}]):
                with self.assertRaisesRegex(ValueError,'acceptance'):extensions.action('tool_publish','def run(request): return {}')
            self.assertEqual(json.loads(active.read_text())['version'],'good')

    def test_failed_new_operation_acceptance_preserves_active_source(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(extensions,'STATE',Path(folder)):
            active=Path(folder)/'tool-active.json';active.write_text(json.dumps({'version':'good','source':'old'}))
            metadata={'ok':True,'capabilities':{'compare_routes':'routes'},'acceptance_cases':[{'request':{'operation':'compare_routes'},'expect':{'acceptance_ok':True}}]}
            with patch.object(extensions,'execute',side_effect=[metadata,{'observations':[]},{'acceptance_ok':False}]):
                with self.assertRaisesRegex(ValueError,'acceptance'):extensions.action('tool_publish','def run(request): return {}')
            self.assertEqual(json.loads(active.read_text())['version'],'good')
    def test_failed_new_tool_does_not_replace_working_version(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(extensions,'STATE',Path(folder)):
            active=Path(folder)/'tool-active.json';active.write_text(json.dumps({'version':'good','source':'old'}))
            with patch.object(extensions,'execute',side_effect=ValueError('test failed')):
                with self.assertRaises(ValueError):extensions.action('tool_publish','def run(request): return {}')
            self.assertEqual(json.loads(active.read_text())['version'],'good')

    def test_runtime_error_restores_previous_tool_without_model_assistance(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(extensions,'STATE',Path(folder)):
            active=Path(folder)/'tool-active.json';active.write_text(json.dumps({'version':'bad','source':'bad'}))
            (Path(folder)/'tool-previous.json').write_text(json.dumps({'version':'good','source':'old'}))
            with patch.object(extensions,'execute',side_effect=ValueError('runtime failure')):
                with self.assertRaises(ValueError):extensions.action('tool_run')
            self.assertEqual(json.loads(active.read_text())['version'],'good')

if __name__=='__main__':unittest.main()
