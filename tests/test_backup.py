import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('backup', Path(__file__).parents[1] / 'backup.py')
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


class PublicBackupTests(unittest.TestCase):
    def test_git_auth_failure_exposes_safe_stage_without_private_diagnostics(self):
        failure=subprocess.CalledProcessError(128,['git'],stderr='Permission denied (publickey). private transport detail')
        with patch.object(backup.subprocess,'run',side_effect=failure):
            with self.assertRaises(backup.SyncError) as error:backup.git(Path('/repo'),'fetch','origin','main')
        self.assertEqual(str(error.exception),'git_auth_failed')
        self.assertEqual(error.exception.stage,'fetch');self.assertNotIn('private',str(error.exception))

    def test_git_transport_failure_does_not_masquerade_as_an_authentication_problem(self):
        failure=subprocess.CalledProcessError(128,['git'],stderr='Connection timed out: private endpoint')
        with patch.object(backup.subprocess,'run',side_effect=failure):
            with self.assertRaises(backup.SyncError) as error:backup.git(Path('/repo'),'push','origin','HEAD:main')
        self.assertEqual(str(error.exception),'git_transport_failed');self.assertEqual(error.exception.stage,'push')

    def test_real_commit_uses_writable_repository_when_system_temp_is_read_only(self):
        repo,args,git=self.publication_repo()
        before=git('-C',repo,'rev-parse','HEAD')
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md','updated public operational method')
        with patch('tempfile._get_default_tempdir',side_effect=FileNotFoundError('system temporary paths are read only')),patch('tempfile.tempdir',None):
            backup.execute(args)
        self.assertNotEqual(before,git('-C',repo,'rev-parse','HEAD'))
        self.assertEqual(git('-C',repo,'status','--porcelain'),'')

    def test_public_acceptance_can_run_with_only_repository_staging_writable(self):
        files={'tests/maintained/test_staging.py':b'# gateway-public-test: 1\nimport unittest\nclass T(unittest.TestCase):\n def test_true(self):self.assertTrue(True)\n'}
        with tempfile.TemporaryDirectory() as folder:
            with patch('tempfile._get_default_tempdir',side_effect=FileNotFoundError('system temporary paths are read only')),patch('tempfile.tempdir',None):
                result=backup.check_maintained_tests(files,temporary_root=Path(folder))
            self.assertEqual(result['tests_run'],1)
            self.assertEqual(list(Path(folder).iterdir()),[])

    def test_workflow_export_preserves_effective_source_and_excludes_private_lifecycle(self):
        import hashlib
        source = 'def inspect(snapshot): return {"wake": "none"}\n'
        version = hashlib.sha256(source.encode()).hexdigest()[:16]
        self.put('/usr/local/share/net-gateway-agent/workflow.py', 'def inspect(snapshot): return {}\n')
        self.put('/var/lib/net-gateway-agent/workflow-state.json', json.dumps({
            'format': 1, 'active': {'source': source, 'version': version, 'tests': ['private-case'], 'published_at': 55},
            'previous': {'source': 'private old source'}, 'last_failure': {'details': 'private failure'}}))
        for module in ['maintenance', 'incidents', 'workflow', 'evidence', 'runtime_facts',
                       'adaptive_routing', 'route_evidence', 'route_transaction', 'routing_control', 'commit_messages', 'run_metrics']:
            self.put(f'/usr/local/lib/net-gateway-agent/{module}.py', '# public ' + module)
        files = backup.collect(self.root)
        self.assertEqual(files['src/maintained/workflow.py'], source.encode())
        self.assertEqual(json.loads(files['snapshot/published/workflow-active.json']), {'version': version, 'active': True})
        self.assertEqual(files['src/maintained/workflow-default.py'], b'def inspect(snapshot): return {}\n')
        for module in ['maintenance', 'incidents', 'workflow', 'evidence', 'runtime_facts',
                       'adaptive_routing', 'route_evidence', 'route_transaction', 'routing_control', 'commit_messages', 'run_metrics']:
            self.assertIn(f'src/operator/{module}.py', files)
        text = '\n'.join(data.decode() for data in files.values())
        self.assertNotIn('private old source', text)
        self.assertNotIn('private failure', text)
        self.assertNotIn('private-case', text)
        builtin = self.root / 'usr/local/share/net-gateway-agent/workflow.py'
        builtin.unlink()
        with self.assertRaisesRegex(ValueError, 'workflow builtin'):
            backup.collect(self.root)
        self.put('/usr/local/share/net-gateway-agent/workflow.py', 'def inspect(snapshot): return {}\n')
        broken = json.loads((self.root / 'var/lib/net-gateway-agent/workflow-state.json').read_text())
        broken['active']['version'] = 'f' * 16
        self.put('/var/lib/net-gateway-agent/workflow-state.json', json.dumps(broken))
        with self.assertRaisesRegex(ValueError, 'workflow version'):
            backup.collect(self.root)

    def test_adaptive_preferences_export_without_private_evidence(self):
        preferences = {'adaptive_routes': {'example.com': 'direct'},
                       'routing_strategy': {'require_degraded_current': True, 'require_public_service_basis': True,
                                            'require_route_conflict': True, 'allow_latency_only': False}}
        self.put('/var/lib/net-gateway-agent/approved-policy.json', json.dumps({'preferences': preferences}))
        self.put('/var/lib/net-gateway-agent/route-evidence.json', 'private target observations')
        self.put('/var/lib/net-gateway-agent/incidents.json', 'private incident history')
        files = backup.collect(self.root)
        self.assertEqual(json.loads(files['preferences/network-policy.json'])['preferences'], preferences)
        self.assertNotIn('private target observations', '\n'.join(data.decode() for data in files.values()))
        self.assertNotIn('private incident history', '\n'.join(data.decode() for data in files.values()))
        for private in ({'adaptive_routes': {'example.com': {'path': 'direct', 'samples': ['private evidence']}}},
                        {'routing_strategy': {'private_comparisons': ['private evidence']}}):
            self.put('/var/lib/net-gateway-agent/approved-policy.json', json.dumps({'preferences': private}))
            with self.assertRaisesRegex(ValueError, 'routing preferences'):
                backup.collect(self.root)

    def test_nonportable_historical_tests_are_excluded_and_portable_tests_execute_exported_bytes(self):
        self.put('/var/lib/dsh/workspace/network-maintainer/tests/test_old.py',
                 "open('/var/lib/dsh/workspace/network-maintainer/programs/candidate.py').read()")
        self.put('/var/lib/dsh/workspace/network-maintainer/tests/test_public.py',
                 '# gateway-public-test: 1\nimport unittest\nfrom pathlib import Path\n'
                 'class SourceTests(unittest.TestCase):\n'
                 ' def test_actual_export(self):\n'
                 '  source = Path(__file__).resolve().parents[2] / "src/maintained/diagnostic.py"\n'
                 '  self.assertIn("def inspect", source.read_text())\n')
        files = backup.collect(self.root)
        self.assertNotIn('tests/maintained/test_old.py', files)
        self.assertIn('tests/maintained/test_public.py', files)
        receipt = json.loads(files['snapshot/maintained-tests.json'])
        self.assertEqual(receipt['excluded'][0]['reason'], 'nonportable_test')
        self.assertEqual(receipt['excluded'][0]['name'], 'test_old.py')
        result = backup.check_maintained_tests(files)
        self.assertEqual(result['tests_run'], 1)
        self.assertEqual(result['result'], 'passed')
        failing = dict(files)
        failing['src/maintained/diagnostic.py'] = b'no inspect function here'
        with self.assertRaisesRegex(ValueError, 'maintained_tests_failed'):
            backup.check_maintained_tests(failing)

    def test_failed_public_test_stops_real_export_before_commit_and_snapshot_replacement(self):
        repo, args, git = self.publication_repo()
        old_head = git('-C', repo, 'rev-parse', 'HEAD')
        self.put('/var/lib/dsh/workspace/network-maintainer/tests/test_bad.py',
                 '# gateway-public-test: 1\ndef test_regression():\n assert False, "real regression"\n')
        with self.assertRaisesRegex(ValueError, 'maintained_tests_failed'):
            backup.execute(args)
        self.assertEqual(git('-C', repo, 'rev-parse', 'HEAD'), old_head)
        self.assertFalse(git('-C', repo, 'status', '--porcelain'))

    def test_portable_test_sandbox_hides_host_files_and_network(self):
        secret = Path(self.temp.name) / 'host-only-fixture'
        secret.write_text('host data never mounted into test sandbox')
        source = ('# gateway-public-test: 1\nimport socket\nfrom pathlib import Path\n'
                  'def test_isolation():\n'
                  f' assert not Path({str(secret)!r}).exists()\n'
                  ' try:\n  socket.create_connection(("1.1.1.1", 443), timeout=0.1)\n'
                  ' except OSError:\n  pass\n'
                  ' else:\n  raise AssertionError("network unexpectedly available")\n')
        result = backup.check_maintained_tests({'tests/maintained/test_isolation.py': source.encode()})
        self.assertEqual(result['tests_run'], 1)

    def test_full_public_active_acceptance_runs_only_exported_source_bytes(self):
        repository = Path(__file__).resolve().parents[1]
        names = ['tests/maintained/test_active_sources.py', 'src/operator/programs.py',
                 'src/operator/workflow.py', 'src/operator/commit_messages.py', 'src/operator/bounded.py',
                 'src/maintained/diagnostic.py', 'src/maintained/tool.py', 'src/maintained/workflow.py']
        files = {name: (repository / name).read_bytes() for name in names}
        receipt = backup.check_maintained_tests(files)
        self.assertEqual(receipt['result'], 'passed')
        self.assertGreaterEqual(receipt['tests_run'], 11)

    def test_all_skipped_tests_are_not_reported_as_executed_acceptance(self):
        source = ('# gateway-public-test: 1\nimport unittest\n'
                  '@unittest.skip("unavailable fixture")\nclass Tests(unittest.TestCase):\n'
                  ' def test_required(self):\n  assert False\n')
        with self.assertRaisesRegex(ValueError, 'maintained_tests_failed'):
            backup.check_maintained_tests({'tests/maintained/test_skipped.py': source.encode()})

    def publication_repo(self):
        folder = Path(self.temp.name)
        origin, repo = folder / 'messages-origin.git', folder / 'messages-working'
        def git(*args):
            return subprocess.run(['git', *map(str, args)], check=True, text=True,
                                  capture_output=True).stdout.strip()
        git('init', '--bare', origin)
        git('init', '-b', 'main', repo)
        git('-C', repo, 'config', 'user.name', 'Integration Test')
        git('-C', repo, 'config', 'user.email', 'test@example.invalid')
        (repo / 'README.md').write_text('initial project')
        git('-C', repo, 'add', '.')
        git('-C', repo, 'commit', '-m', 'test: initialize project')
        git('-C', repo, 'remote', 'add', 'origin', origin)
        git('-C', repo, 'push', 'origin', 'main')
        args = SimpleNamespace(root=self.root, repository=repo, push=True)
        backup.execute(args)
        return repo, args, git

    @staticmethod
    def publication_message(subject):
        return f'fix(diagnostic): {subject}\n\n单目标失败曾误判全局故障，需要保留正常对照。\n\n诊断：增加正常对照。\n\n验证：诊断对照测试通过。'

    def test_model_messages_match_staged_bytes_and_superseded_versions_are_omitted(self):
        from source_sync import SourceSyncRegistry
        repo, args, git = self.publication_repo()
        registry = SourceSyncRegistry(Path(self.temp.name) / 'messages.json')
        old = registry.register('program_publish', version='a' * 16,
                                commit_message=self.publication_message('旧版本说明'))
        self.put('/var/lib/net-gateway-agent/diagnostic-active.json', json.dumps({
            'source': 'def inspect(snapshot): return {"controls": True}', 'version': 'new'}))
        versions = backup.snapshot_versions(backup.collect(self.root))
        current = registry.register('program_publish', version=versions['program_publish'],
                                    commit_message=self.publication_message('保留正常目标对照'))
        backup.execute(args, request=registry.request_descriptor(current['id']))
        message = git('-C', repo, 'log', '-1', '--format=%B')
        self.assertTrue(message.startswith('fix(diagnostic): 保留正常目标对照\n'))
        self.assertNotIn('旧版本说明', message)
        self.assertIn('src/maintained/diagnostic.py', message)
        self.assertIn(versions['program_publish'], message)
        self.assertIn('controls', git('-C', repo, 'show', 'HEAD:src/maintained/diagnostic.py'))
        committed = git('-C', repo, 'rev-parse', 'HEAD')
        backup.execute(args, request=registry.request_descriptor(current['id']))
        self.assertEqual(git('-C', repo, 'rev-parse', 'HEAD'), committed)

    def test_coalesced_publications_preserve_both_messages_and_actual_changed_scope(self):
        from source_sync import SourceSyncRegistry
        repo, args, git = self.publication_repo()
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md', 'new skill with controls')
        self.put('/var/lib/net-gateway-agent/diagnostic-active.json', json.dumps({
            'source': 'def inspect(snapshot): return {"coalesced": True}', 'version': 'coalesced'}))
        versions = backup.snapshot_versions(backup.collect(self.root))
        registry = SourceSyncRegistry(Path(self.temp.name) / 'messages.json')
        registry.register('program_publish', version=versions['program_publish'],
                          commit_message=self.publication_message('增加目标对照'))
        current = registry.register('skill_publish', version=versions['skill_publish'],
                                    commit_message=self.publication_message('补充诊断操作方法'))
        backup.execute(args, request=registry.request_descriptor(current['id']))
        message = git('-C', repo, 'log', '-1', '--format=%B')
        for expected in ('增加目标对照', '补充诊断操作方法', 'src/dsh/skill/SKILL.md',
                         'src/maintained/diagnostic.py'):
            self.assertIn(expected, message)

    def test_stale_metadata_falls_back_to_actual_scope_and_local_secrets_stop_commit(self):
        from source_sync import SourceSyncRegistry
        repo, args, git = self.publication_repo()
        registry = SourceSyncRegistry(Path(self.temp.name) / 'messages.json')
        current = registry.register('program_publish', version='a' * 16,
                                    commit_message=self.publication_message('不应出现的旧说明'))
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md', 'changed skill')
        backup.execute(args, request=registry.request_descriptor(current['id']))
        message = git('-C', repo, 'log', '-1', '--format=%B')
        self.assertNotIn('不应出现的旧说明', message)
        self.assertIn('src/dsh/skill/SKILL.md', message)
        old_head = git('-C', repo, 'rev-parse', 'HEAD')
        current = registry.register('skill_publish', version=backup.snapshot_versions(backup.collect(self.root))['skill_publish'],
                                    commit_message=self.publication_message('修复 controller-private-value'))
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md', 'must remain unpublished')
        with self.assertRaises(ValueError):
            backup.execute(args, request=registry.request_descriptor(current['id']))
        self.assertEqual(git('-C', repo, 'rev-parse', 'HEAD'), old_head)
        self.assertFalse(git('-C', repo, 'status', '--porcelain'))

    def test_git_filters_cannot_make_exported_version_claim_different_staged_bytes(self):
        repo, args, git = self.publication_repo()
        (repo / '.gitattributes').write_text('src/maintained/*.py text eol=lf\n')
        git('-C', repo, 'add', '.gitattributes')
        git('-C', repo, 'commit', '-m', 'test: normalize maintained source')
        git('-C', repo, 'push', 'origin', 'main')
        old_head = git('-C', repo, 'rev-parse', 'HEAD')
        self.put('/var/lib/net-gateway-agent/diagnostic-active.json', json.dumps({
            'source': 'def inspect(snapshot):\r\n    return {"filtered": True}\r\n', 'version': 'filtered'}))
        with self.assertRaisesRegex(backup.SyncError, 'publication_snapshot_mismatch'):
            backup.execute(args)
        self.assertEqual(git('-C', repo, 'rev-parse', 'HEAD'), old_head)

    def test_matching_metadata_for_unchanged_artifact_does_not_describe_other_changes(self):
        from source_sync import SourceSyncRegistry
        repo, args, git = self.publication_repo()
        version = backup.snapshot_versions(backup.collect(self.root))['program_publish']
        registry = SourceSyncRegistry(Path(self.temp.name) / 'messages.json')
        current = registry.register('program_publish', version=version,
                                    commit_message=self.publication_message('未改动的诊断说明'))
        self.put('/usr/local/share/net-gateway-agent/skill/SKILL.md', 'skill changed independently')
        backup.execute(args, request=registry.request_descriptor(current['id']))
        message = git('-C', repo, 'log', '-1', '--format=%B')
        self.assertNotIn('未改动的诊断说明', message)
        self.assertNotIn('src/maintained/diagnostic.py', message)
        self.assertIn('src/dsh/skill/SKILL.md', message)

    def test_repository_scan_ignores_installed_browser_dependencies_but_rejects_source_links(self):
        repo=Path(self.temp.name)/'scan';repo.mkdir()
        deps=Path(self.temp.name)/'deps';deps.mkdir();(deps/'fixture').write_text('sk-'+'z'*32)
        (repo/'node_modules').symlink_to(deps)
        backup.repository_scan(repo)
        (repo/'source.mjs').symlink_to(deps/'fixture')
        with self.assertRaises(ValueError):backup.repository_scan(repo)

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

    def test_commits_changed_content_to_main_and_skips_identical_exports(self):
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
        status = folder/'sync-status.json'
        request = folder/'request.json';request.write_text(json.dumps({'id':'a'*32}))
        args = [sys.executable, str(Path(__file__).parents[1] / 'backup.py'), '--root', str(self.root), '--repository', str(repo), '--push', '--status-file', str(status), '--request-file', str(request)]
        subprocess.run(args, check=True, capture_output=True)
        deployed = git('--git-dir', origin, 'rev-parse', 'main')
        self.assertNotEqual(initial, deployed)
        subprocess.run(args, check=True, capture_output=True)
        self.assertEqual(git('--git-dir', origin, 'rev-parse', 'main'), deployed)
        saved=json.loads(status.read_text())
        self.assertEqual(saved['branch'],'main');self.assertEqual(saved['remote_commit'],deployed)
        self.assertEqual(saved['acknowledged_request'],'a'*32)
        self.assertEqual(saved['result'],'success')
        git('-C',repo,'remote','set-url','origin',folder/'unreachable.git')
        request.write_text(json.dumps({'id':'b'*32}))
        failed=subprocess.run(args,capture_output=True)
        self.assertNotEqual(failed.returncode,0)
        rejected=json.loads(status.read_text())
        self.assertEqual(rejected['result'],'failed')
        self.assertEqual(rejected['remote_commit'],deployed)
        self.assertEqual(rejected['last_success_at'],saved['last_success_at'])
        self.assertEqual(rejected['acknowledged_request'],'a'*32)

    def test_remote_source_changes_stop_export_without_overwriting_local_project(self):
        folder = Path(self.temp.name); origin = folder/'remote.git'; local = folder/'local'; other = folder/'other'
        def git(*args):
            return subprocess.run(['git', *map(str,args)], check=True, capture_output=True, text=True).stdout.strip()
        git('init','--bare',origin);git('init','-b','main',local)
        git('-C',local,'config','user.name','Test');git('-C',local,'config','user.email','test@example.invalid')
        (local/'README.md').write_text('initial');git('-C',local,'add','.');git('-C',local,'commit','-m','test: initialize')
        git('-C',local,'remote','add','origin',origin);git('-C',local,'push','-u','origin','main')
        old = git('-C',local,'rev-parse','HEAD')
        git('clone','--branch','main',origin,other)
        git('-C',other,'config','user.name','Test');git('-C',other,'config','user.email','test@example.invalid')
        path=other/'src/operator/new.py';path.parent.mkdir(parents=True);path.write_text('upstream implementation')
        git('-C',other,'add','.');git('-C',other,'commit','-m','feat: update source');git('-C',other,'push')
        with self.assertRaises(ValueError): backup.prepare_sync(local)
        self.assertEqual(git('-C',local,'rev-parse','HEAD'),old)
        self.assertFalse((local/'src/operator/new.py').exists())


if __name__ == '__main__': unittest.main()
