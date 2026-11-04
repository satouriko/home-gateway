import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from routing_control import ProtectedAdapter,positive_controls


class AdapterTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.root=Path(folder.name);self.config=self.root/'config.json';self.config.write_text('{}')
        self.gateway=SimpleNamespace(STATE=self.root,CONFIG=self.config,write_state=lambda p,v:p.write_text(json.dumps(v)),
            checkpoint=Mock(),boot_id=lambda:'boot',api=Mock(),restore_gateway=Mock(),current_policy=lambda:{'version':'old'},
            diagnose=Mock(return_value={'checks':{}}),verification_healthy=Mock(return_value=True))
        self.adapter=ProtectedAdapter(self.gateway)

    def test_arming_retains_current_pair_and_cannot_replace_existing_transaction(self):
        token=self.adapter.arm({'rules':['old']},{'version':'old'})
        self.gateway.checkpoint.assert_called_once_with({'rules':['old']},{'version':'old'})
        self.assertTrue(self.adapter.owns(token))
        before=(self.root/'pending.json').read_bytes()
        with self.assertRaises(ValueError):self.adapter.arm({}, {})
        self.assertEqual((self.root/'pending.json').read_bytes(),before)

    def test_foreign_ownership_cannot_checkpoint_or_clear_recovery(self):
        token=self.adapter.arm({},{});self.gateway.checkpoint.reset_mock()
        (self.root/'pending.json').write_text(json.dumps({'id':'other','deadline':9999999999,'boot_id':'boot'}))
        with self.assertRaises(ValueError):self.adapter.commit({}, {},token)
        self.assertFalse(self.adapter.rollback(token));self.gateway.checkpoint.assert_not_called()
        self.gateway.restore_gateway.assert_not_called();self.assertTrue((self.root/'pending.json').exists())

    def test_failed_rollback_retains_independent_recovery_deadline(self):
        token=self.adapter.arm({},{});before=(self.root/'pending.json').read_bytes()
        self.gateway.restore_gateway.side_effect=OSError('failed')
        with self.assertRaises(OSError):self.adapter.rollback(token)
        self.assertEqual((self.root/'pending.json').read_bytes(),before)

    def test_positive_control_facts_cannot_infer_success_from_transport_only(self):
        self.assertEqual(positive_controls({'checks':{'mainland_https':{'ok':True,'result':{'http_status':200}},'proxy_https':{'ok':True,'result':{'http_status':403}}}}),{'direct':True,'proxy':False})
        self.assertEqual(positive_controls({'checks':{}}),{'direct':False,'proxy':False})


if __name__=='__main__':unittest.main()
