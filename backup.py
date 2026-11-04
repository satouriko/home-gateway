#!/usr/bin/env python3
"""Finite public export. Never copy credentials, node caches or runtime history."""
import argparse
import ast
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/'src/operator'))
if Path('/usr/local/lib/net-gateway-agent').is_dir():sys.path.insert(0,'/usr/local/lib/net-gateway-agent')
from source_sync import MAX_BYTES, snapshot_versions, validate_request_descriptor
from commit_messages import build_commit_message
from bounded import run as bounded_run

CODE = ('user_policy.py patrol.py bounded.py policy.py extensions.py programs.py broker.py '
        'storage.py control_route.py ai_job.py credential_guard.mjs pricing.py skills.py native_jobs.py overview.py traffic.py traffic_collector.py business_probe.py business_watch.py probe_transport.py source_sync.py sandbox_runner.py node_health.py '
        'commit_messages.py maintenance.py incidents.py workflow.py evidence.py runtime_facts.py '
        'adaptive_routing.py route_evidence.py route_transaction.py routing_control.py run_metrics.py context_cache.py').split()
DOCS = ['CONTRACTS.md', 'identity.txt', 'operator.mjs', 'native-maintenance.mjs', 'broker-client.mjs', 'maintenance-prompt.txt', 'BACKGROUND.md', 'skill/SKILL.md',
        'sync-notices.mjs', 'routing-request.mjs', 'network-overview/package.json', 'network-overview/index.mjs', 'network-overview/client.js']
UNITS = ('net-gateway-control-route.service net-gateway-agent.service net-gateway-ai-patrol.service '
         'net-gateway-patrol.timer net-gateway-traffic.service dsh.service net-gateway.service net-gateway-maintain.service '
         'net-gateway-maintain.timer net-gateway-storage.service net-gateway-storage.timer '
         'net-gateway-watchdog.service net-gateway-watchdog.timer net-gateway-patrol.service '
         'dsh.service.d/storage.conf dsh.service.d/gateway-operator.conf '
         'net-gateway.service.d/operator-route.conf').split()
DIRECT = ([f'/usr/local/lib/net-gateway-agent/{n}' for n in CODE] +
          [f'/usr/local/share/net-gateway-agent/{n}' for n in DOCS] +
          [f'/etc/systemd/system/{n}' for n in UNITS] +
          ['/usr/local/bin/dsh', '/usr/local/bin/gateway-agent',
           '/usr/local/lib/net-gateway/gateway_maintain.py', '/usr/local/lib/net-gateway/network_setup.py',
           '/etc/net-gateway/proxy-domains.yaml', '/etc/net-gateway-agent/resolv.conf',
           '/etc/net-gateway-agent/pricing.json', '/etc/net-gateway-agent/storage.json',
           '/etc/systemd/journald.conf.d/80-net-gateway-bounds.conf',
           '/var/lib/dsh/lan-auto-login.mjs', '/var/lib/dsh/mobile-layout.mjs', '/var/lib/dsh/state/AGENTS.md',
           '/opt/dsh/package.json', '/opt/dsh/package-lock.json',
           '/usr/local/share/net-gateway-agent/workflow.py',
           '/usr/local/share/net-gateway-agent/tests/test_active_sources.py'] +
          [f'/opt/dsh/patches/{n}' for n in ['manifest.json','schedule-execution.patch','schedule-history-ui.patch',
                                            'LICENSE.schedule','LICENSE.schedule-ui','schedule-provenance.json','NOTICE.md',
                                            'session-list-title.patch','title-provenance.json','LICENSE.session-title']] +
          [f'/var/lib/dsh/state/profiles/{p}/{n}' for p in ['web', 'headless']
           for n in ['package.json', 'cordis.patch.yml']])
PLACEHOLDER_URL = '__SUBSCRIPTION_URL__'
SYNC_BRANCH = 'main'
PREFERENCE_KEYS = {'mode', 'preferred_label', 'preferred_keywords', 'allow_other_regions',
                   'allow_proxy_direct_fallback', 'mainland_direct', 'direct_domains',
                   'proxy_domains', 'excluded_keywords', 'adaptive_routes', 'routing_strategy'}
MANAGED_TREES = ['src', 'config', 'deploy', 'runtime', 'preferences', 'docs/operator',
                 'tests/maintained', 'snapshot']


def public_path(absolute):
    if absolute == '/usr/local/share/net-gateway-agent/workflow.py':
        return 'src/maintained/workflow-default.py'
    if absolute == '/usr/local/share/net-gateway-agent/tests/test_active_sources.py':
        return 'tests/maintained/test_active_sources.py'
    prefixes = {'/usr/local/lib/net-gateway-agent/': 'src/operator/',
                '/usr/local/lib/net-gateway/': 'src/gateway/',
                '/etc/systemd/system/': 'deploy/systemd/',
                '/var/lib/dsh/state/profiles/': 'config/dsh/', '/opt/dsh/': 'runtime/dsh/'}
    for prefix, target in prefixes.items():
        if absolute.startswith(prefix): return target + absolute.removeprefix(prefix)
    if absolute.startswith('/usr/local/share/net-gateway-agent/'):
        name = absolute.removeprefix('/usr/local/share/net-gateway-agent/')
        return ('docs/operator/' if name in ['BACKGROUND.md', 'CONTRACTS.md'] else 'src/dsh/') + name
    special = {'/usr/local/bin/dsh': 'deploy/bin/dsh', '/usr/local/bin/gateway-agent': 'deploy/bin/gateway-agent',
               '/etc/net-gateway/proxy-domains.yaml': 'config/proxy-domains.yaml',
               '/etc/systemd/journald.conf.d/80-net-gateway-bounds.conf': 'deploy/journald.conf',
               '/var/lib/dsh/lan-auto-login.mjs': 'src/dsh/lan-auto-login.mjs',
               '/var/lib/dsh/mobile-layout.mjs': 'src/dsh/mobile-layout.mjs',
               '/var/lib/dsh/state/AGENTS.md': 'src/dsh/AGENTS.md'}
    if absolute.startswith('/etc/net-gateway-agent/'): return 'config/' + Path(absolute).name
    return special[absolute]


SOURCE_MAP = {public_path(path): path for path in DIRECT}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def safe_read(root, absolute):
    path = root / absolute.lstrip('/')
    for part in [path, *path.parents]:
        if part == root.parent: break
        if part.is_symlink(): raise ValueError('symbolic link in export allowlist: ' + absolute)
    if not path.exists(): return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024**2:
        raise ValueError('unsupported export source: ' + absolute)
    return path.read_bytes()


def private_values(root, config):
    values = [config.get('secret', '')]
    for provider in config.get('proxy-providers', {}).values():
        url = provider.get('url', '')
        values.extend([url, urlsplit(url).hostname or ''])
    env = safe_read(root, '/var/lib/dsh/state/.env')
    if env:
        for line in env.decode().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                values.append(line.split('=', 1)[1].strip().strip('\"\''))
    return [v for v in values if isinstance(v, str) and len(v) >= 8]


def scan(files, forbidden=()):
    patterns = [r'sk-[A-Za-z0-9_-]{16,}', r'(?:ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}',
                r'-----BEGIN [A-Z ]*PRIVATE KEY-----', r'https?://[^\s/\"\']+:[^\s/\"\']+@',
                r'https?://[^\s/\"\']+/link/[A-Za-z0-9_-]{12,}',
                r'(?i)Bearer\s+[A-Za-z0-9_.-]{20,}']
    if sum(len(v) for v in files.values()) > 32 * 1024**2: raise ValueError('export size budget exceeded')
    for name, data in files.items():
        text = data.decode('utf-8')
        if any(re.search(pattern, text) for pattern in patterns) or any(value in text for value in forbidden):
            raise ValueError('sensitive content rejected in ' + name)


def public_config(config):
    config = json.loads(json.dumps(config))
    allowed = {'mixed-port', 'allow-lan', 'bind-address', 'mode', 'log-level', 'ipv6',
               'external-controller', 'secret', 'hosts', 'profile', 'tun', 'sniffer', 'dns',
               'proxy-providers', 'proxy-groups', 'rule-providers', 'rules', 'geodata-mode',
               'geodata-loader', 'geo-auto-update', 'geo-update-interval', 'geox-url'}
    if set(config) - allowed: raise ValueError('unknown Mihomo fields require review before public backup')
    def reject_auth(value, depth=0):
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {'username', 'password', 'token', 'access-token', 'api-key',
                                        'authorization', 'authentication', 'private-key', 'client-key'}:
                    raise ValueError('authentication material cannot be exported')
                if key == 'secret' and depth: raise ValueError('nested secret cannot be exported')
                reject_auth(item, depth+1)
        elif isinstance(value, list):
            for item in value: reject_auth(item, depth+1)
    reject_auth(config)
    if config.get('proxies'): raise ValueError('inline nodes must never be exported')
    config['secret'] = '__MIHOMO_SECRET__'
    hosts = set()
    for provider in config.get('proxy-providers', {}).values():
        if provider.get('type') != 'http': raise ValueError('unsupported provider type')
        # Explicitly refuse credentials supplied through headers instead of URLs.
        if set(provider.get('header', {})) - {'User-Agent'}:
            raise ValueError('provider authentication headers cannot be exported')
        if set(provider) - {'type', 'url', 'path', 'interval', 'proxy', 'size-limit', 'header',
                           'exclude-filter', 'health-check', 'filter'}:
            raise ValueError('unknown provider fields require review')
        hosts.add(urlsplit(provider['url']).hostname)
        provider['url'] = PLACEHOLDER_URL
    policies = config.get('dns', {}).get('nameserver-policy', {})
    for host in hosts:
        if host in policies: policies['__SUBSCRIPTION_HOST__'] = policies.pop(host)
    return config


def validate_public_preferences(preferences):
    if not isinstance(preferences, dict) or set(preferences) - PREFERENCE_KEYS:
        raise ValueError('unknown preference fields require review')
    routes = preferences.get('adaptive_routes', {})
    strategy = preferences.get('routing_strategy', {})
    strategy_keys = {'require_degraded_current', 'require_public_service_basis',
                     'require_route_conflict', 'allow_latency_only'}
    if (not isinstance(routes, dict) or len(routes) > 128 or
            any(not isinstance(domain, str) or len(domain) > 253 or
                re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', domain) is None or
                path not in ('direct', 'proxy') for domain, path in routes.items()) or
            not isinstance(strategy, dict) or set(strategy) - strategy_keys or
            any(type(value) is not bool for value in strategy.values())):
        raise ValueError('invalid public routing preferences')


def portable_test(data):
    """Opt in to active public sources; candidate history is never retargeted."""
    if data is None or len(data) > 65536: return False
    try:
        source = data.decode('utf-8')
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError): return False
    if '# gateway-public-test: 1' not in source.splitlines()[:8]: return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r'(?:/var/|/run/|/usr/local/|(?:^|/)programs/|patrol_inspect_candidate)', node.value):
                return False
    return True


MAINTAINED_TEST_RUNNER = r'''
import inspect, json, pathlib, resource, runpy, sys, unittest
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
sys.path.insert(0, '/repo/src/operator')
sys.path.insert(0, '/repo')
suite = unittest.TestSuite()
for path in sorted(pathlib.Path('/repo/tests/maintained').glob('test_*.py')):
    namespace = runpy.run_path(str(path), run_name='public_maintained_test')
    for name, value in namespace.items():
        if inspect.isclass(value) and issubclass(value, unittest.TestCase) and value is not unittest.TestCase:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(value))
        elif name.startswith('test_') and inspect.isfunction(value):
            suite.addTest(unittest.FunctionTestCase(value))
if suite.countTestCases() == 0:
    raise ValueError('portable tests must expose unittest cases or test_ functions')
result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
executed = result.testsRun - len(result.skipped)
passed = result.wasSuccessful() and executed > 0
print(json.dumps({'result': 'passed' if passed else 'failed', 'tests_run': executed,
                  'tests_skipped': len(result.skipped)}))
sys.exit(0 if passed else 1)
'''


def check_maintained_tests(files,temporary_root=None):
    """Execute exported bytes offline without exposing host credentials or state."""
    tests = {name: data for name, data in files.items() if name.startswith('tests/maintained/')}
    if not tests: return {'result': 'not_tested', 'tests_run': 0, 'reason': 'no_portable_tests'}
    if any(not portable_test(data) for data in tests.values()):
        raise ValueError('nonportable maintained test in snapshot')
    scan(files)
    runner = shutil.which('bwrap')
    if not runner: raise SyncError('maintained_test_sandbox_unavailable')
    # The production service exposes only its repository as writable. Keep
    # bounded acceptance staging there instead of depending on host /tmp.
    with tempfile.TemporaryDirectory(prefix='.export-tests-',dir=temporary_root) as temporary:
        repository = Path(temporary) / 'repo'; repository.mkdir()
        for name, data in files.items():
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('invalid maintained test source path')
            path = repository / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        command = [runner, '--unshare-all', '--die-with-parent', '--new-session',
                   '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
                   '--symlink', 'usr/lib', '/lib']
        if Path('/usr/lib64').exists(): command += ['--symlink', 'usr/lib64', '/lib64']
        command += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                    '--ro-bind', str(repository), '/repo', '--chdir', '/repo',
                    '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                    '--', '/usr/bin/python3', '-I', '-c', MAINTAINED_TEST_RUNNER]
        try:
            result = bounded_run(command, timeout=60, stdout_limit=32768, stderr_limit=32768)
        except (ValueError, OSError):
            raise SyncError('maintained_tests_failed') from None
        if result.returncode: raise SyncError('maintained_tests_failed')
        try: receipt = json.loads(result.stdout.splitlines()[-1])
        except (ValueError, IndexError): raise SyncError('maintained_tests_failed') from None
        if (not isinstance(receipt, dict) or receipt.get('result') != 'passed' or
                type(receipt.get('tests_run')) is not int or receipt['tests_run'] < 1):
            raise SyncError('maintained_tests_failed')
        return receipt


def collect(root):
    root = Path(root).resolve()
    if (root / 'var/lib/net-gateway-agent/pending.json').exists():
        raise ValueError('network transaction pending; retry after verification')
    raw = safe_read(root, '/etc/net-gateway/config.json')
    if raw is None: raise ValueError('gateway configuration missing')
    config = json.loads(raw)
    forbidden = private_values(root, config)
    files = {}
    modes = {}
    for absolute in DIRECT:
        data = safe_read(root, absolute)
        if data is not None:
            name = public_path(absolute)
            files[name] = data
            modes[name] = stat.S_IMODE((root / absolute.lstrip('/')).stat().st_mode)
    files['config/mihomo.template.json'] = encoded(public_config(config))
    approved = safe_read(root, '/var/lib/net-gateway-agent/approved-policy.json')
    if approved is None: raise ValueError('approved household preferences missing')
    approved = json.loads(approved)
    if set(approved) - {'mode', 'proxy_chain', 'region_providers', 'default_rule', 'scope',
                        'preferred_region', 'allow_proxy_direct_fallback', 'mainland_direct',
                        'preferences', 'version', 'preferred_label', 'pool_aliases'}:
        raise ValueError('unknown policy metadata requires review')
    validate_public_preferences(approved.get('preferences', {}))
    files['preferences/network-policy.json'] = encoded(approved)
    audit = safe_read(root, '/var/lib/net-gateway-agent/audit-plan.json')
    if audit:
        plan = json.loads(audit)
        files['preferences/audit-plan.json'] = encoded({k: plan[k] for k in ['interval_hours', 'daily_budget','enabled','schedule'] if k in plan})
    for name in ['diagnostic-active', 'tool-active']:
        data = safe_read(root, '/var/lib/net-gateway-agent/' + name + '.json')
        if data:
            data = json.loads(data)
            files['snapshot/published/' + name + '.json'] = encoded({'version': data['version']})
            source_name = 'diagnostic.py' if name == 'diagnostic-active' else 'tool.py'
            files['src/maintained/' + source_name] = data['source'].encode()
    workflow = safe_read(root, '/var/lib/net-gateway-agent/workflow-state.json')
    active = None
    if workflow:
        state = json.loads(workflow)
        if not isinstance(state, dict) or state.get('format') != 1:
            raise ValueError('invalid workflow state')
        active = state.get('active')
        if active is not None and (not isinstance(active, dict) or not isinstance(active.get('source'), str) or
                                  active.get('version') != hashlib.sha256(active['source'].encode()).hexdigest()[:16]):
            raise ValueError('workflow version integrity failed')
    source = active['source'].encode() if active else files.get('src/maintained/workflow-default.py')
    if active and 'src/maintained/workflow-default.py' not in files:
        raise ValueError('workflow builtin missing from finite export')
    if source:
        version = hashlib.sha256(source).hexdigest()[:16]
        files['src/maintained/workflow.py'] = source
        files['snapshot/published/workflow-active.json'] = encoded({'version': version, 'active': active is not None})
    tests = root / 'var/lib/dsh/workspace/network-maintainer/tests'
    included, excluded = [], []
    if tests.exists():
        paths = sorted(tests.glob('test_*.py'))
        if len(paths) > 128: raise ValueError('maintained test count budget exceeded')
        for path in paths:
            relative = '/' + str(path.relative_to(root))
            data = safe_read(root, relative)
            if not portable_test(data):
                excluded.append({'name': path.name, 'reason': 'nonportable_test'})
                continue
            name = 'tests/maintained/' + path.name
            if name in files and files[name] != data:
                raise ValueError('protected maintained test name conflict')
            files[name] = data
            included.append(path.name)
    files['snapshot/maintained-tests.json'] = encoded({'format': 1, 'collected': included,
                                                     'excluded': excluded, 'verification': 'not run during collection'})
    scan(files, forbidden)
    binary = root / 'usr/local/bin/mihomo'
    binary_hash = None
    if binary.exists():
        if binary.is_symlink(): raise ValueError('unexpected Mihomo binary link')
        with binary.open('rb') as stream: binary_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    manifest = {'format': 1, 'scope': 'programs and preferences only',
                'runtime': {'os': 'Debian 13 ARM64', 'node': '24.14.1', 'mihomo': '1.19.33',
                            'mihomo_sha256': binary_hash},
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(),
                                 'mode': modes.get(name, 0o600)} for name, data in sorted(files.items())}}
    files['snapshot/manifest.json'] = encoded(manifest)
    return files


def write_snapshot(repository, files):
    repository = Path(repository)
    scan(files)
    with tempfile.TemporaryDirectory(prefix='.export-', dir=repository) as temporary:
        temp = Path(temporary)
        for name, data in files.items():
            if not any(name.startswith(tree + '/') for tree in MANAGED_TREES) or '..' in Path(name).parts:
                raise ValueError('invalid snapshot path')
            target = temp / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        replaced = []
        try:
            for index, tree in enumerate(MANAGED_TREES):
                target = repository / tree
                if target.is_symlink(): raise ValueError('managed tree must be a directory')
                incoming = temp / tree
                if not incoming.exists(): incoming.mkdir(parents=True)
                old = temp / ('previous-' + str(index))
                if target.exists(): target.rename(old)
                replaced.append((target, old))
                target.parent.mkdir(parents=True, exist_ok=True)
                incoming.rename(target)
        except BaseException:
            for target, old in reversed(replaced):
                if target.exists(): shutil.rmtree(target)
                if old.exists(): old.rename(target)
            raise


def repository_scan(repository):
    files = {}
    for path in Path(repository).rglob('*'):
        relative = path.relative_to(repository)
        if any(x in {'.git', '__pycache__', 'node_modules'} or x.startswith('.export-') for x in relative.parts): continue
        if path.is_symlink(): raise ValueError('repository symlink rejected')
        if path.is_file(): files[str(relative)] = path.read_bytes()
    scan(files)


def git(repository, *args):
    stage = args[0] if args and args[0] in {'fetch', 'push', 'commit', 'add', 'merge'} else 'inspect'
    try:
        return subprocess.run(['git', '-C', str(repository), *args], check=True, capture_output=True,
                              text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise GitSyncError('git_transport_failed', stage) from None
    except subprocess.CalledProcessError as error:
        diagnostic = (error.stderr or '').lower()
        if any(text in diagnostic for text in ('permission denied (publickey)', 'authentication failed', 'could not read username')):
            reason = 'git_auth_failed'
        elif any(text in diagnostic for text in ('could not resolve host', 'could not resolve hostname')):
            reason = 'git_dns_failed'
        elif any(text in diagnostic for text in ('timed out', 'connection refused', 'connection reset', 'network is unreachable', 'connection closed')):
            reason = 'git_transport_failed'
        else:
            reason = 'git_push_failed' if stage == 'push' else 'git_operation_failed'
        # Do not carry private stderr, command arguments or credential URLs into
        # the operator's status/receipt. The original process error stays local.
        raise GitSyncError(reason, stage) from None


class SyncError(ValueError):
    """A safe reason code for the operator, without command output or credentials."""


class GitSyncError(SyncError):
    def __init__(self, reason, stage):
        super().__init__(reason)
        self.stage = stage


def verify_staged_snapshot(repository, files):
    """Git filters must not turn an exported version into different public bytes."""
    algorithm = git(repository, 'rev-parse', '--show-object-format').stdout.strip()
    if algorithm not in {'sha1', 'sha256'}: raise SyncError('publication_snapshot_mismatch')
    entries = git(repository, 'ls-files', '--stage', '-z').stdout
    indexed = {}
    for entry in entries.rstrip('\0').split('\0'):
        if not entry: continue
        header, name = entry.split('\t', 1)
        mode, digest, stage = header.split()
        if stage == '0' and mode in {'100644', '100755'}: indexed[name] = digest
    for name, data in files.items():
        digest = hashlib.new(algorithm, b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if indexed.get(name) != digest: raise SyncError('publication_snapshot_mismatch')


def prepare_sync(repository):
    if git(repository, 'branch', '--show-current').stdout.strip() != SYNC_BRANCH:
        raise SyncError('unexpected_branch')
    if git(repository, 'status', '--porcelain').stdout.strip():
        raise SyncError('uncommitted_repository_changes')
    git(repository, 'fetch', '--no-tags', 'origin', SYNC_BRANCH)
    remote = 'origin/' + SYNC_BRANCH
    def ancestor(left, right):
        return subprocess.run(['git', '-C', str(repository), 'merge-base', '--is-ancestor', left, right],
                              capture_output=True, timeout=10).returncode == 0
    if ancestor(remote, 'HEAD'): return
    if not ancestor('HEAD', remote): raise SyncError('diverged_history_requires_review')
    if git(repository, 'diff', '--name-only', 'HEAD', remote, '--', *MANAGED_TREES).stdout.strip():
        raise SyncError('remote_program_changes_require_deployment')
    # Documentation/project-only updates do not replace the deployed program.
    git(repository, 'merge', '--ff-only', remote)


def sync_status(path, repository, error=None, request_id=None, versions=None):
    if path is None: return
    previous = {}
    if path.exists():
        try: previous = json.loads(path.read_text())
        except ValueError: pass
    if not isinstance(previous, dict): previous = {}
    now = time.time()
    status = {key: previous[key] for key in ['last_success_at','remote_commit','acknowledged_request','acknowledged_versions','acknowledged_commit'] if key in previous}
    remote = git(repository, 'remote', 'get-url', 'origin').stdout.strip()
    match = re.fullmatch(r'(?:git@github\.com:|https://github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?', remote)
    status.update(repository_url='https://github.com/' + match.group(1) if match else None,
                  branch=git(repository, 'branch', '--show-current').stdout.strip(), expected_branch=SYNC_BRANCH,
                  result='failed' if error else 'success', last_attempt_at=now,
                  local_commit=git(repository, 'rev-parse', 'HEAD').stdout.strip(),
                  verification='last successful Git push',
                  attempted_request=request_id,
                  error_code=str(error) if isinstance(error, SyncError) else type(error).__name__ if error else None,
                  error_stage=error.stage if isinstance(error, GitSyncError) else None)
    if error is None:
        status.update(last_success_at=now, remote_commit=status['local_commit'])
        if request_id is not None: status['acknowledged_request']=request_id
        status.update(acknowledged_versions=versions or {},acknowledged_commit=status['local_commit'])
    temporary = path.with_suffix('.next')
    temporary.write_bytes(encoded(status)); temporary.chmod(0o600); temporary.replace(path)


def execute(args, request=None):
    if request is not None:
        request = validate_request_descriptor(request)
    with contextlib.ExitStack() as stack:
        if args.root.resolve() == Path('/'):
            if shutil.disk_usage('/').free < 4 * 1024**3: raise ValueError('preserve gateway free-space reserve')
            lock = stack.enter_context(open('/var/lib/net-gateway-agent/transaction.lock', 'r'))
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        files = collect(args.root)
        config = json.loads(safe_read(args.root.resolve(), '/etc/net-gateway/config.json'))
        forbidden = private_values(args.root.resolve(), config)
        if request is not None:
            # Check even stale prose: credentials must never reach queue output,
            # Git metadata or the repository when its artifact has been replaced.
            request = validate_request_descriptor(request, forbidden)
    test_receipt = check_maintained_tests(files,temporary_root=args.repository)
    history_size = sum(p.stat().st_size for p in (args.repository / '.git').rglob('*') if p.is_file())
    if history_size > 512 * 1024**2: raise ValueError('backup history size budget exceeded')
    if args.push: prepare_sync(args.repository)
    write_snapshot(args.repository, files)
    repository_scan(args.repository)
    if args.push:
        git(args.repository, 'add', '--', *MANAGED_TREES)
        verify_staged_snapshot(args.repository, files)
        changed = git(args.repository, 'diff', '--cached', '--name-only', '-z').stdout
        if changed:
            message = build_commit_message(snapshot_versions(files), changed.rstrip('\0').split('\0'), request, forbidden)
            scan({'commit-message.txt': message.encode()}, forbidden)
            # Show the complete reviewable message before the automatic push.
            print(message, flush=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='.export-commit-',dir=args.repository) as stream:
                stream.write(message); stream.flush()
                git(args.repository, 'commit', '-F', stream.name)
        # Push even with no new local change: the preceding push may have failed.
        git(args.repository, 'push', 'origin', 'HEAD:' + SYNC_BRANCH)
    print(json.dumps({'exported_files': len(files), 'pushed': args.push, 'maintained_tests': test_receipt}))
    return snapshot_versions(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'))
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--push', action='store_true')
    parser.add_argument('--status-file', type=Path)
    parser.add_argument('--request-file', type=Path)
    parser.add_argument('--check-maintained-tests', action='store_true', help='run only public portable tests in an offline sandbox')
    args = parser.parse_args()
    if args.check_maintained_tests:
        import restore
        _manifest, files = restore.verify(args.repository)
        print(json.dumps(check_maintained_tests(files,temporary_root=args.repository)))
        return
    request_id=None
    request=None
    try:
        if args.request_file is not None and args.request_file.exists():
            with args.request_file.open() as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw.encode()) > MAX_BYTES: raise SyncError('invalid_publication_request')
            request=json.loads(raw)
            request_id=request.get('id') if isinstance(request,dict) else None
            try: request=validate_request_descriptor(request)
            except ValueError: raise SyncError('invalid_publication_request') from None
        versions=execute(args,request=request)
    except Exception as error:
        if args.push: sync_status(args.status_file, args.repository, error,request_id=request_id)
        raise
    if args.push: sync_status(args.status_file, args.repository, request_id=request_id,versions=versions)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        # Do not print subprocess stderr: it can contain URLs or authentication material.
        print(json.dumps({'backup_failed': type(error).__name__}))
        raise SystemExit(1)
