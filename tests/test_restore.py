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
    def test_workflow_and_route_preferences_roundtrip_without_private_history(self):
        import hashlib
        source = 'def inspect(snapshot): return {"wake": "none"}\n'
        version = hashlib.sha256(source.encode()).hexdigest()[:16]
        builtin = 'def inspect(snapshot): return {"wake": "urgent"}\n'
        self.fixture.put('/usr/local/share/net-gateway-agent/workflow.py', builtin)
        self.fixture.put('/var/lib/net-gateway-agent/workflow-state.json', json.dumps({
            'format': 1, 'active': {'source': source, 'version': version},
            'previous': {'source': 'private previous'}, 'last_failure': 'private failure'}))
        preferences = {'adaptive_routes': {'example.com': 'proxy'}, 'routing_strategy': {
            'require_degraded_current': True, 'require_public_service_basis': True,
            'require_route_conflict': True, 'allow_latency_only': False}}
        self.fixture.put('/var/lib/net-gateway-agent/approved-policy.json', json.dumps({'preferences': preferences}))
        backup.write_snapshot(self.repo, backup.collect(self.fixture.root))
        target = self.temp / 'workflow-restored'
        restore.stage(self.repo, target, self.credentials)
        state = json.loads((target / 'var/lib/net-gateway-agent/workflow-state.json').read_text())
        self.assertEqual(state['active']['version'], version)
        self.assertEqual(state['active']['source'], source)
        self.assertIsNone(state['previous'])
        self.assertNotIn('last_failure', state)
        self.assertEqual((target / 'usr/local/share/net-gateway-agent/workflow.py').read_text(), builtin)
        approved = json.loads((target / 'var/lib/net-gateway-agent/approved-policy.json').read_text())
        self.assertEqual(approved['preferences'], preferences)
        self.assertFalse((target / 'var/lib/net-gateway-agent/incidents.json').exists())

    def test_builtin_workflow_roundtrip_does_not_fabricate_an_active_publication(self):
        builtin = 'def inspect(snapshot): return {"wake": "urgent"}\n'
        self.fixture.put('/usr/local/share/net-gateway-agent/workflow.py', builtin)
        backup.write_snapshot(self.repo, backup.collect(self.fixture.root))
        target = self.temp / 'builtin-restored'
        restore.stage(self.repo, target, self.credentials)
        state = json.loads((target / 'var/lib/net-gateway-agent/workflow-state.json').read_text())
        self.assertIsNone(state['active'])
        self.assertIsNone(state['previous'])
        self.assertEqual((target / 'usr/local/share/net-gateway-agent/workflow.py').read_text(), builtin)

    def test_session_title_patch_license_and_provenance_survive_finite_restore(self):
        sources = {'session-list-title.patch': 'diff --git a/title.js b/title.js\n',
                   'title-provenance.json': '{"source":"pinned rc.5 packages"}\n',
                   'LICENSE.session-title': 'MIT fixture license\n'}
        for name, data in sources.items():
            self.fixture.put('/opt/dsh/patches/' + name, data)
        files = backup.collect(self.fixture.root)
        for name, data in sources.items():
            self.assertEqual(files['runtime/dsh/patches/' + name], data.encode())
        backup.write_snapshot(self.repo, files)
        target = self.temp / 'title-patch-restored'
        restore.stage(self.repo, target, self.credentials)
        for name, data in sources.items():
            self.assertEqual((target / 'opt/dsh/patches' / name).read_text(), data)

    def setUp(self):
        fixture = test_backup.PublicBackupTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture=fixture
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

    def test_deleted_native_task_definition_recovers_without_reenabling_or_restoring_history(self):
        plan={'interval_hours':6,'daily_budget':4,'enabled':False,
              'schedule':{'kind':'every','title':'家庭复核','prompt':'只读检查网络','everySeconds':21600},
              'session_id':'private-session','lastDelivery':{'private':'history'}}
        self.fixture.put('/var/lib/net-gateway-agent/audit-plan.json',json.dumps(plan))
        backup.write_snapshot(self.repo,backup.collect(self.fixture.root))
        stored=json.loads((self.repo/'preferences/audit-plan.json').read_text())
        self.assertNotIn('session_id',stored);self.assertNotIn('lastDelivery',stored)
        target=self.temp/'restored-task'
        restore.stage(self.repo,target,self.credentials)
        recovered=json.loads((target/'var/lib/net-gateway-agent/audit-plan.json').read_text())
        self.assertFalse(recovered['enabled']);self.assertEqual(recovered['schedule'],plan['schedule'])
        self.assertFalse((target/'var/lib/net-gateway-agent/native-maintenance.json').exists())

    def test_profile_plugins_resolve_from_locked_runtime_after_restore(self):
        root = self.temp / 'plugin-root'
        profile = root / 'var/lib/dsh/state/profiles/web'
        profile.mkdir(parents=True)
        (profile / 'package.json').write_text(json.dumps({'dependencies': {'dsh-web-mobile': '3.2.1'}}))
        package = root / 'opt/dsh/node_modules/dsh-web-mobile'
        package.mkdir(parents=True)
        (package / 'package.json').write_text('{"version":"3.2.1"}')
        previous=os.umask(0o077)
        try:restore.link_profile_plugins(root)
        finally:os.umask(previous)
        self.assertEqual((profile/'node_modules').stat().st_mode & 0o777,0o755)
        link = profile / 'node_modules/dsh-web-mobile'
        self.assertEqual(link.readlink(), Path('/opt/dsh/node_modules/dsh-web-mobile'))
        restore.link_profile_plugins(root)
        (package / 'package.json').write_text('{"version":"3.2.0"}')
        with self.assertRaises(ValueError): restore.link_profile_plugins(root)

    def test_protected_native_identity_directory_is_created_for_broker_sandbox(self):
        target=self.temp/'native-identity'
        restore.stage(self.repo,target,self.credentials)
        self.assertTrue((target/'var/lib/dsh/native-task-identity').is_dir())

    def test_overview_package_and_read_adapter_roundtrip_without_runtime_records(self):
        sources={
            '/usr/local/lib/net-gateway-agent/overview.py':'# readonly overview adapter',
            '/usr/local/share/net-gateway-agent/network-overview/package.json':'{"name":"home-network-overview"}',
            '/usr/local/share/net-gateway-agent/network-overview/index.mjs':'export function apply() {}',
            '/usr/local/share/net-gateway-agent/network-overview/client.js':'// native overview client',
        }
        for name,content in sources.items():self.fixture.put(name,content).chmod(0o640)
        self.fixture.put('/usr/local/share/net-gateway-agent/network-overview/private-log.json','private runtime record')
        files=backup.collect(self.fixture.root)
        self.assertIn('src/operator/overview.py',files)
        self.assertIn('src/dsh/network-overview/client.js',files)
        self.assertNotIn('private runtime record','\n'.join(v.decode() for v in files.values()))
        backup.write_snapshot(self.repo,files)
        target=self.temp/'overview-roundtrip';restore.stage(self.repo,target,self.credentials)
        for name,content in sources.items():
            recovered=target/name.lstrip('/')
            self.assertEqual(recovered.read_text(),content)
            if name.startswith('/usr/local/share/'):
                self.assertTrue(recovered.stat().st_mode&0o004,'public plugin code must be readable by replacement DSH user')
        self.assertFalse((target/'var/lib/dsh/state/.env').stat().st_mode&0o007)


if __name__ == '__main__': unittest.main()
