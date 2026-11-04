import json
from pathlib import Path
import tempfile
import unittest
from run_metrics import summarize


class MetricsTests(unittest.TestCase):
    def test_native_totals_are_used_without_inventing_repair_success_or_fees(self):
        sid='session-12345678-1234-1234-1234-123456789abc'
        with tempfile.TemporaryDirectory() as folder:
            row={'record':{'rows':{'tokenUsage':{'seq':72,'val':{'totals':{'uncachedInputTokens':100,'outputTokens':20,'cacheReadTokens':900,'cacheWriteTokens':0},'private':'not exported'}}}}}
            (Path(folder)/(sid+'.json')).write_text(json.dumps(row))
            result=summarize([{'type':'tool_call','tool':'gateway_incidents','input':{'operation':'decide'}},{'type':'tool_result','status':'completed'}],sid,folder)
            self.assertEqual(result['usage']['cacheReadTokens'],900);self.assertEqual(result['incident_decision_attempts'],1)
            self.assertIn('requires',result['repair_success']);self.assertNotIn('private',json.dumps(result));self.assertNotIn('fee',result)

    def test_missing_or_invalid_totals_are_unknown_not_free(self):
        with tempfile.TemporaryDirectory() as folder:
            result=summarize([],None,folder);self.assertFalse(result['usage']['available'])
            self.assertNotIn('outputTokens',result['usage'])


if __name__=='__main__':unittest.main()
