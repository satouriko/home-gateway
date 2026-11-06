import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import broker
from operation_history import OperationHistory
from policy import validate_request

SID='session-12345678-1234-1234-1234-123456789abc'


class OperationApiTests(unittest.TestCase):
    def test_repairs_accept_trusted_session_attribution_but_not_credentials(self):
        self.assertEqual(validate_request({'operation':'recheck_nodes','session_id':SID})['session_id'],SID)
        with self.assertRaises(ValueError):validate_request({'operation':'recheck_nodes','session_id':'private arbitrary text'})

    def test_envelope_records_a_timed_out_attempt_and_keeps_raw_errors_private(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)):
            def fail(_request):
                token={'id':'a'*32,'operation_record_id':broker.REQUEST.operation_record_id,'session_id':SID}
                (Path(folder)/'pending.json').write_text(json.dumps(token))
                raise TimeoutError('private transport detail')
            with patch.object(broker,'handle',side_effect=fail):reply=broker.envelope({'operation':'recheck_nodes','session_id':SID})
            self.assertFalse(reply['ok']);self.assertNotIn('private',reply['message'])
            records=OperationHistory(Path(folder)/'operation-history.json').read()['records']
            self.assertEqual(records[0]['status'],'pending_rollback');self.assertEqual(records[0]['session_id'],SID)

    def test_rejected_followup_does_not_claim_ownership_of_an_older_pending_repair(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(broker,'STATE',Path(folder)):
            (Path(folder)/'pending.json').write_text(json.dumps({'id':'a'*32,'operation_record_id':'b'*32}))
            with patch.object(broker,'handle',side_effect=ValueError('a previous repair is pending protected rollback')):
                broker.envelope({'operation':'refresh_subscription','session_id':SID})
            row=OperationHistory(Path(folder)/'operation-history.json').read()['records'][0]
            self.assertEqual(row['status'],'rejected');self.assertNotIn('transaction_id',row)


if __name__=='__main__':unittest.main()
