import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import os
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import backup
import restore
import test_backup


class RestoreTests(unittest.TestCase):
    def setUp(self):
        fixture = test_backup.PublicBackupTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.temp = Path(fixture.temp.name)
        self.repo = self.temp / 'repository'; self.repo.mkdir()
        backup.write_snapshot(self.repo, backup.collect(fixture.root))
        self.credentials = {'subscription_url': 'https://new-subscription.example/path', 'deepseek_api_key': 'replacement-api-value'}

    def test_restores_programs_and_preferences_with_fresh_credentials(self):
        target = self.temp / 'restored'
        restore.stage(self.repo, target, self.credentials, uid=1234)
        cfg = json.loads((target / 'etc/net-gateway/config.json').read_text())
        self.assertEqual(cfg['proxy-providers']['us']['url'], self.credentials['subscription_url'])
        self.assertIn('new-subscription.example', cfg['dns']['nameserver-policy'])
        self.assertNotIn('__SUBSCRIPTION_HOST__', cfg['dns']['nameserver-policy'])
        self.assertEqual(cfg['tun']['exclude-uid'], [1234])
        self.assertNotEqual(cfg['secret'], '__MIHOMO_SECRET__')
        self.assertEqual((target / 'var/lib/dsh/state/.env').read_text(), 'DEEPSEEK_API_KEY=replacement-api-value\n')
        self.assertEqual((target / 'var/lib/dsh-login/credentials.yaml').stat().st_mode & 0o777, 0o600)
        self.assertEqual((target / 'usr/local/share/net-gateway-agent/skill/SKILL.md').read_text(), 'current method skill')
        self.assertEqual(json.loads((target / 'var/lib/net-gateway-agent/diagnostic-active.json').read_text())['version'], 'first')

    def test_refuses_tampering_and_nonempty_destination_before_writing(self):
        target = self.temp / 'nonempty'; target.mkdir(); (target / 'keep').write_text('untouched')
        with self.assertRaises(ValueError): restore.stage(self.repo, target, self.credentials)
        (self.repo / 'config/mihomo.template.json').write_text('{}')
        fresh = self.temp / 'fresh'
        with self.assertRaises(ValueError): restore.stage(self.repo, fresh, self.credentials)
        self.assertFalse(fresh.exists())

    def test_rejects_manifest_path_escape_and_missing_credentials(self):
        manifest = self.repo / 'snapshot/manifest.json'
        data = json.loads(manifest.read_text()); data['files']['snapshot/files/etc/shadow'] = {'sha256': 'x', 'mode': 0o600}
        manifest.write_text(json.dumps(data))
        with self.assertRaises(ValueError): restore.stage(self.repo, self.temp / 'bad', self.credentials)
        with self.assertRaises(ValueError): restore.stage(self.repo, self.temp / 'empty', {})

    def test_restrictive_staging_umask_cannot_change_existing_system_directory_permissions(self):
        source = self.temp / 'source'; (source / 'etc').mkdir(parents=True)
        source.chmod(0o700); (source / 'etc').chmod(0o700)
        (source / 'etc/program.conf').write_text('configuration')
        target = self.temp / 'system'; (target / 'etc').mkdir(parents=True)
        target.chmod(0o755); (target / 'etc').chmod(0o755)
        previous = os.umask(0o077)
        try: restore.install_tree(source, target)
        finally: os.umask(previous)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual((target / 'etc').stat().st_mode & 0o777, 0o755)
        self.assertEqual((target / 'etc/program.conf').read_text(), 'configuration')

    def test_first_backup_after_restore_has_a_shared_transaction_lock(self):
        import fcntl
        target = self.temp / 'restored-first-boot'
        restore.stage(self.repo, target, self.credentials)
        with (target / 'var/lib/net-gateway-agent/transaction.lock').open('r') as lease:
            fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertTrue(backup.collect(target))

    def test_clean_install_requests_yaml_needed_by_credential_recovery(self):
        class StopAfterApt(Exception): pass
        requests = []
        def command(*args, **kwargs):
            requests.append(args)
            if args[:2] == ('apt-get', 'install'): raise StopAfterApt
        with patch.object(restore, 'command', side_effect=command):
            with self.assertRaises(StopAfterApt): restore.install_runtime(self.repo, {})
        installed = next(args for args in requests if args[:2] == ('apt-get', 'install'))
        self.assertIn('python3-yaml', installed)


if __name__ == '__main__': unittest.main()
