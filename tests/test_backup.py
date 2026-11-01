import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('backup', Path(__file__).parents[1] / 'backup.py')
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


class PublicBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'pi'
        self.put('/etc/net-gateway/config.json', json.dumps({
            'secret': 'controller-private-value',
            'proxy-providers': {'us': {'url': 'https://subscription.invalid/' + 'link/' + 'private-subscription', 'type': 'http'}},
            'dns': {'nameserver-policy': {'subscription.invalid': ['223.5.5.5']}},
            'tun': {'exclude-uid': [999]}, 'rules': ['MATCH,PROXY'],
        }))
        self.put('/var/lib/net-gateway-agent/approved-policy.json', json.dumps({'preferences': {'preferred_label': '美国'}}))
        self.put('/var/lib/dsh/state/.env', 'DEEPSEEK_API_KEY=' + 'sk-' + 'a' * 32)
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md', 'current method skill')
        self.put('/var/lib/net-gateway-agent/diagnostic-active.json', json.dumps({'source': 'def inspect(snapshot): return {}', 'version': 'first'}))

    def put(self, path, value):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
        return target

    def test_exports_active_sources_and_preferences_with_credential_placeholders(self):
        files = backup.collect(self.root)
        text = '\n'.join(v.decode() for v in files.values())
        self.assertIn('current method skill', text)
        self.assertIn('美国', text)
        self.assertIn('__SUBSCRIPTION_URL__', text)
        self.assertIn('__SUBSCRIPTION_HOST__', text)
        self.assertNotIn('controller-private-value', text)
        self.assertNotIn('private-subscription', text)
        self.assertNotIn('subscription.invalid', text)
        self.assertNotIn('sk-' + 'a' * 32, text)

    def test_ignores_logs_credentials_sessions_and_candidate_sources(self):
        self.put('/var/lib/dsh/state/sessions/private.json', 'private conversation')
        self.put('/var/lib/dsh/workspace/network-maintainer/tools/candidate.py', 'unpublished candidate')
        self.put('/var/lib/dsh-login/credentials.yaml', 'private login')
        files = backup.collect(self.root)
        text = '\n'.join(v.decode() for v in files.values())
        for forbidden in ['private conversation', 'unpublished candidate', 'private login']:
            self.assertNotIn(forbidden, text)

    def test_detects_a_new_active_program_and_repeated_export_is_identical(self):
        first = backup.collect(self.root)
        self.assertEqual(first, backup.collect(self.root))
        self.put('/var/lib/net-gateway-agent/diagnostic-active.json', json.dumps({'source': 'def inspect(snapshot): return {"new": True}', 'version': 'second'}))
        second = backup.collect(self.root)
        self.assertNotEqual(first, second)
        self.assertIn('second', second['snapshot/published/diagnostic-active.json'].decode())

    def test_rejects_symlinks_and_an_uncommitted_network_transaction(self):
        target = self.root / 'usr/local/share/net-gateway-agent/skill/SKILL.md'
        target.unlink()
        target.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): backup.collect(self.root)
        target.unlink(); target.write_text('safe')
        self.put('/var/lib/net-gateway-agent/pending.json', '{}')
        with self.assertRaises(ValueError): backup.collect(self.root)

    def test_rejects_a_secret_in_newly_published_code_and_authenticated_urls(self):
        for secret in ['sk-' + 'z' * 32, 'https://' + 'name:password@' + 'example.org/path', '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----']:
            with self.subTest(secret=secret[:12]), self.assertRaises(ValueError):
                backup.scan({'snapshot/code.py': secret.encode()})
        with self.assertRaises(ValueError): backup.scan({'x.py': b'previous-secret'}, ['previous-secret'])

    def test_rejects_unknown_provider_authentication_fields(self):
        p = self.root / 'etc/net-gateway/config.json'
        config = json.loads(p.read_text())
        config['proxy-providers']['us']['header'] = {'Authorization': ['Bearer ' + 'secret-provider-value']}
        p.write_text(json.dumps(config))
        with self.assertRaises(ValueError): backup.collect(self.root)

    def test_snapshot_replacement_removes_obsolete_files_but_preserves_repository(self):
        repo = Path(self.temp.name) / 'repo'
        repo.mkdir(); (repo / 'README.md').write_text('keep')
        backup.write_snapshot(repo, {'snapshot/old.py': b'old'})
        backup.write_snapshot(repo, {'snapshot/new.py': b'new'})
        self.assertFalse((repo / 'snapshot/old.py').exists())
        self.assertEqual((repo / 'snapshot/new.py').read_bytes(), b'new')
        self.assertEqual((repo / 'README.md').read_text(), 'keep')

    def test_rejects_additional_listener_credentials_before_public_export(self):
        path = self.root / 'etc/net-gateway/config.json'
        original = json.loads(path.read_text())
        for extra in [{'authentication': ['example-user:example-password']},
                      {'listeners': [{'name': 'socks', 'password': 'example-password'}]}]:
            with self.subTest(field=list(extra)[0]):
                path.write_text(json.dumps({**original, **extra}))
                with self.assertRaises(ValueError): backup.collect(self.root)

    def test_commits_only_changed_content_to_the_dedicated_remote_branch(self):
        folder = Path(self.temp.name)
        origin, repo = folder / 'origin.git', folder / 'working'
        def git(*args):
            return subprocess.run(['git', *map(str, args)], check=True, text=True, capture_output=True).stdout.strip()
        git('init', '--bare', origin)
        git('init', '-b', 'main', repo)
        git('-C', repo, 'config', 'user.name', 'Integration Test')
        git('-C', repo, 'config', 'user.email', 'test@example.invalid')
        (repo / 'README.md').write_text('initial project')
        git('-C', repo, 'add', '.'); git('-C', repo, 'commit', '-m', 'test: initialize project')
        initial = git('-C', repo, 'rev-parse', 'HEAD')
        git('-C', repo, 'remote', 'add', 'origin', origin)
        git('-C', repo, 'push', 'origin', 'main')
        git('-C', repo, 'switch', '-c', backup.BACKUP_BRANCH)
        args = [sys.executable, str(Path(__file__).parents[1] / 'backup.py'), '--root', str(self.root), '--repository', str(repo), '--push']
        subprocess.run(args, check=True, capture_output=True)
        deployed = git('--git-dir', origin, 'rev-parse', backup.BACKUP_BRANCH)
        self.assertNotEqual(initial, deployed)
        self.assertEqual(git('--git-dir', origin, 'rev-parse', 'main'), initial)
        subprocess.run(args, check=True, capture_output=True)
        self.assertEqual(git('--git-dir', origin, 'rev-parse', backup.BACKUP_BRANCH), deployed)


if __name__ == '__main__': unittest.main()
