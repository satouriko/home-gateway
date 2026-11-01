import json
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor

from source_sync import SourceSyncRegistry, snapshot_versions


SESSION = 'session-12345678-1234-4234-8234-123456789abc'
OTHER = 'session-12345678-1234-4234-8234-123456789abd'
COMMIT = 'c' * 40


def confirmed(request, versions):
    return {'result': 'success', 'acknowledged_request': request['id'],
            'acknowledged_versions': versions, 'local_commit': COMMIT,
            'remote_commit': COMMIT, 'acknowledged_commit': COMMIT,
            'branch': 'main', 'expected_branch': 'main',
            'repository_url': 'https://github.com/example/home-gateway'}


def register_from_worker(path):
    return SourceSyncRegistry(path).register('program_publish', session_id=SESSION, version='a' * 16)['id']


class SourceSyncTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'receipts.json'
        self.registry = SourceSyncRegistry(self.path)

    def register(self, reason='program_publish', version='a' * 16, **kwargs):
        return self.registry.register(reason, session_id=SESSION, version=version, **kwargs)

    def test_snapshot_versions_hash_the_actual_exported_bytes(self):
        import hashlib
        files = {'src/maintained/diagnostic.py': b'program\n',
                 'src/maintained/tool.py': b'tool\n', 'src/dsh/skill/SKILL.md': b'skill\n',
                 'preferences/network-policy.json': b'{"mode":"rule"}\n',
                 'preferences/audit-plan.json': b'{"interval_hours":4}\n',
                 'private/state.json': b'never represented'}
        result = snapshot_versions(files)
        for reason, name in [('program_publish', 'src/maintained/diagnostic.py'),
                             ('tool_publish', 'src/maintained/tool.py'),
                             ('skill_publish', 'src/dsh/skill/SKILL.md'),
                             ('policy_apply', 'preferences/network-policy.json'),
                             ('audit_plan_set', 'preferences/audit-plan.json'),
                             ('audit_plan_enable', 'preferences/audit-plan.json'),
                             ('native_observe', 'preferences/audit-plan.json')]:
            self.assertEqual(result[reason], hashlib.sha256(files[name]).hexdigest()[:16])
        self.assertEqual(snapshot_versions({}), {})

    def test_per_request_identity_survives_latest_queue_supersession_and_restart(self):
        first = self.register(now=1)
        second = self.register('skill_publish', 'b' * 16, now=2)
        restarted = SourceSyncRegistry(self.path)
        self.assertEqual([r['id'] for r in restarted.records()], [first['id'], second['id']])
        self.assertTrue(restarted.pending())
        self.assertEqual(first['status'], 'pending')
        self.assertEqual(first['version'], 'a' * 16)

    def test_cross_process_registration_cannot_overwrite_another_publication(self):
        with ProcessPoolExecutor(max_workers=3) as pool:
            ids = list(pool.map(register_from_worker, [self.path] * 9))
        records = self.registry.records()
        self.assertEqual(len(set(ids)), 9)
        self.assertEqual({r['id'] for r in records}, set(ids))
        self.assertEqual([r['sequence'] for r in records], list(range(1, 10)))

    def test_corrupt_registry_is_not_silently_reset_and_private_records_stay_bounded(self):
        self.path.write_text('{corrupt')
        with self.assertRaisesRegex(ValueError, 'recovery'):
            self.register()
        self.assertEqual(self.path.read_text(), '{corrupt')

    def test_cumulative_push_confirms_only_requests_present_in_snapshot(self):
        first = self.register(now=1)
        second = self.register('skill_publish', 'b' * 16, now=2)
        third = self.register('tool_publish', 'd' * 16, now=3)
        self.registry.reconcile(confirmed(second, {'program_publish': first['version'], 'skill_publish': second['version']}), now=4)
        records = self.registry.records()
        self.assertEqual([r['status'] for r in records], ['success', 'success', 'pending'])
        self.assertEqual(records[0]['remote_commit'], COMMIT)
        self.assertEqual(records[0]['acknowledged_request'], second['id'])
        self.assertNotIn('remote_commit', records[2])

    def test_overwritten_version_is_explicitly_superseded_not_confirmed(self):
        first = self.register(now=1)
        second = self.register(version='b' * 16, now=2)
        self.registry.reconcile(confirmed(second, {'program_publish': second['version']}), now=3)
        old, current = self.registry.records()
        self.assertEqual(old['status'], 'superseded')
        self.assertEqual(old['superseded_by'], second['id'])
        self.assertNotIn('remote_commit', old)
        self.assertEqual(current['status'], 'success')
        self.assertFalse(self.registry.pending())

    def test_audit_change_reasons_share_one_underlying_artifact(self):
        old = self.register('audit_plan_set', 'a' * 16, now=1)
        latest = self.register('audit_plan_enable', 'b' * 16, now=2)
        self.registry.reconcile(confirmed(latest, {reason: latest['version'] for reason in
                                ('audit_plan_set', 'audit_plan_enable', 'native_observe')}))
        self.assertEqual(self.registry.records()[0]['status'], 'superseded')
        self.assertEqual(self.registry.records()[0]['superseded_by'], latest['id'])

    def test_missing_wrong_or_unverified_snapshot_never_becomes_success(self):
        record = self.register()
        for changes in ({'acknowledged_versions': {}}, {'acknowledged_versions': {'program_publish': 'b' * 16}},
                        {'remote_commit': 'd' * 40}, {'branch': 'feature'},
                        {'acknowledged_request': 'f' * 32}, {'repository_url': 'https://evil.invalid/a/b'}):
            with self.subTest(changes=changes):
                status = {**confirmed(record, {'program_publish': record['version']}), **changes}
                self.registry.reconcile(status)
                self.assertNotEqual(self.registry.records()[0]['status'], 'success')

    def test_hold_failed_retry_and_success_revision_notices_are_durable(self):
        record = self.register(now=1)
        self.registry.reconcile(held=True, now=2)
        held = self.registry.notices()['notices'][0]
        self.assertEqual(held['status'], 'held')
        self.registry.reconcile(held=True, now=3)
        self.assertEqual(self.registry.notices()['notices'][0]['revision'], held['revision'])
        self.registry.reconcile({'result': 'failed', 'attempted_request': record['id'],
                                 'error_code': 'push_rejected', 'stderr': 'PRIVATE'}, now=4)
        failed = self.registry.notices()['notices'][0]
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['error_code'], 'push_rejected')
        self.assertNotIn('PRIVATE', json.dumps(self.registry.records()))
        self.registry.reconcile(None, held=False, now=5)
        self.assertEqual(self.registry.records()[0]['status'], 'pending')
        self.registry.reconcile(confirmed(record, {'program_publish': record['version']}), now=6)
        self.assertEqual(self.registry.records()[0]['status'], 'success')

    def test_stale_failure_does_not_apply_to_newer_request_or_erase_success(self):
        first = self.register(now=1)
        self.registry.reconcile(confirmed(first, {'program_publish': first['version']}), now=2)
        self.register('skill_publish', 'b' * 16, now=3)
        self.registry.reconcile({'result': 'failed', 'attempted_request': first['id'], 'error_code': 'push_rejected'}, now=4)
        self.assertEqual([r['status'] for r in self.registry.records()], ['success', 'pending'])

    def test_acknowledgment_is_revision_session_and_message_scoped(self):
        self.register()
        notice = self.registry.notices()['notices'][0]
        for changes in ({'session_id': OTHER}, {'revision': notice['revision'] + 1}, {'message_id': 'arbitrary'}):
            args = dict(request_id=notice['id'], revision=notice['revision'], session_id=SESSION, message_id=notice['notice_id'])
            self.assertFalse(self.registry.acknowledge(**{**args, **changes})['acknowledged'])
        args = dict(request_id=notice['id'], revision=notice['revision'], session_id=SESSION, message_id=notice['notice_id'])
        self.assertTrue(self.registry.acknowledge(**args)['acknowledged'])
        self.assertEqual(SourceSyncRegistry(self.path).notices()['notices'], [])
        self.registry.reconcile(held=True)
        updated = self.registry.notices()['notices'][0]
        self.assertNotEqual(updated['notice_id'], notice['notice_id'])
        self.assertFalse(self.registry.acknowledge(**args)['acknowledged'])

    def test_notice_rotation_survives_restart_without_starving_busy_sessions_or_discarding_receipts(self):
        registered = [self.register() for _ in range(35)]
        first = self.registry.notices()
        self.assertEqual([r['id'] for r in first['notices']], [r['id'] for r in registered[:32]])
        # None of these deliveries were acknowledged: the next process must
        # still offer the later receipts before retrying the unavailable ones.
        restarted = SourceSyncRegistry(self.path)
        second = restarted.notices()
        self.assertEqual([r['id'] for r in second['notices'][:3]], [r['id'] for r in registered[32:]])
        self.assertEqual(second['pending'], 35)
        self.assertEqual(len(restarted.records()), 35)
        next_batch = restarted.notices(limit=4)
        self.assertEqual([r['id'] for r in next_batch['notices']], [r['id'] for r in registered[29:33]])

    def test_invalid_input_and_unbounded_private_errors_are_rejected_or_sanitized(self):
        for session in ('../private', 'session-../../x', 'session-1234', 's', 'session-' + 'g' * 36):
            with self.subTest(session=session), self.assertRaises(ValueError):
                self.registry.register('program_publish', session_id=session, version='a' * 16)
        with self.assertRaises(ValueError):
            self.registry.register('raw private operation', session_id=SESSION, version='a' * 16)
        record = self.register()
        self.registry.reconcile({'result': 'failed', 'attempted_request': record['id'],
                                 'error_code': 'token=SECRET\n/credentials/private'})
        self.assertEqual(self.registry.records()[0]['error_code'], 'sync_failed')

    def test_old_verified_receipt_still_confirms_when_newer_attempt_has_failed(self):
        first = self.register(now=1)
        newer = self.register('skill_publish', 'b' * 16, now=2)
        status = {**confirmed(first, {'program_publish': first['version']}),
                  'local_commit': 'd' * 40, 'result': 'failed',
                  'attempted_request': newer['id'], 'error_code': 'push_rejected'}
        self.registry.reconcile(status, now=3)
        self.assertEqual([r['status'] for r in self.registry.records()], ['success', 'failed'])

    def test_bound_prunes_only_finished_delivered_receipts_and_refuses_overflow(self):
        registry = SourceSyncRegistry(self.path, max_records=2)
        first = registry.register('program_publish', session_id=SESSION, version='a' * 16)
        second = registry.register('skill_publish', session_id=SESSION, version='b' * 16)
        with self.assertRaisesRegex(ValueError, 'capacity'):
            registry.register('tool_publish', session_id=SESSION, version='d' * 16)
        registry.reconcile(confirmed(first, {'program_publish': first['version']}))
        notice = registry.notices()['notices'][0]
        registry.acknowledge(notice['id'], notice['revision'], SESSION, notice['notice_id'])
        registry.register('tool_publish', session_id=SESSION, version='d' * 16)
        self.assertEqual(len(registry.records()), 2)
        self.assertEqual(registry.records()[0]['id'], second['id'])
        self.assertLess(self.path.stat().st_size, 16384)


if __name__ == '__main__':
    unittest.main()
