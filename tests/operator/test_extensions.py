import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import extensions

class MaintainedToolTests(unittest.TestCase):
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
