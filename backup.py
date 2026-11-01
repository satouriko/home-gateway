#!/usr/bin/env python3
"""Finite public export. Never copy credentials, node caches or runtime history."""
import argparse
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
from urllib.parse import urlsplit

CODE = ('user_policy.py patrol.py bounded.py policy.py extensions.py programs.py broker.py '
        'storage.py control_route.py ai_job.py credential_guard.mjs pricing.py skills.py').split()
DOCS = ['CONTRACTS.md', 'identity.txt', 'operator.mjs', 'BACKGROUND.md', 'skill/SKILL.md']
UNITS = ('net-gateway-control-route.service net-gateway-agent.service net-gateway-ai-patrol.service '
         'net-gateway-patrol.timer dsh.service net-gateway.service net-gateway-maintain.service '
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
           '/var/lib/dsh/lan-auto-login.mjs', '/var/lib/dsh/state/AGENTS.md',
           '/opt/dsh/package.json', '/opt/dsh/package-lock.json'] +
          [f'/var/lib/dsh/state/profiles/{p}/{n}' for p in ['web', 'headless']
           for n in ['package.json', 'cordis.patch.yml']])
PLACEHOLDER_URL = '__SUBSCRIPTION_URL__'
BACKUP_BRANCH = 'backup/home'
PREFERENCE_KEYS = {'mode', 'preferred_label', 'preferred_keywords', 'allow_other_regions',
                   'allow_proxy_direct_fallback', 'mainland_direct', 'direct_domains',
                   'proxy_domains', 'excluded_keywords'}
MANAGED_TREES = ['src', 'config', 'deploy', 'runtime', 'preferences', 'docs/operator',
                 'tests/maintained', 'snapshot']


def public_path(absolute):
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
    if set(approved.get('preferences', {})) - PREFERENCE_KEYS:
        raise ValueError('unknown preference fields require review')
    files['preferences/network-policy.json'] = encoded(approved)
    audit = safe_read(root, '/var/lib/net-gateway-agent/audit-plan.json')
    if audit:
        plan = json.loads(audit)
        files['preferences/audit-plan.json'] = encoded({k: plan[k] for k in ['interval_hours', 'daily_budget']})
    for name in ['diagnostic-active', 'tool-active']:
        data = safe_read(root, '/var/lib/net-gateway-agent/' + name + '.json')
        if data:
            data = json.loads(data)
            files['snapshot/published/' + name + '.json'] = encoded({'version': data['version']})
            source_name = 'diagnostic.py' if name == 'diagnostic-active' else 'tool.py'
            files['src/maintained/' + source_name] = data['source'].encode()
    tests = root / 'var/lib/dsh/workspace/network-maintainer/tests'
    if tests.exists():
        for path in sorted(tests.glob('test_*.py')):
            relative = '/' + str(path.relative_to(root))
            files['tests/maintained/' + path.name] = safe_read(root, relative)
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
        if any(x in {'.git', '__pycache__'} or x.startswith('.export-') for x in relative.parts): continue
        if path.is_symlink(): raise ValueError('repository symlink rejected')
        if path.is_file(): files[str(relative)] = path.read_bytes()
    scan(files)


def git(repository, *args):
    return subprocess.run(['git', '-C', str(repository), *args], check=True, capture_output=True,
                          text=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'))
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--push', action='store_true')
    args = parser.parse_args()
    with contextlib.ExitStack() as stack:
        if args.root.resolve() == Path('/'):
            if shutil.disk_usage('/').free < 4 * 1024**3: raise ValueError('preserve gateway free-space reserve')
            lock = stack.enter_context(open('/var/lib/net-gateway-agent/transaction.lock', 'r'))
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        files = collect(args.root)
    history_size = sum(p.stat().st_size for p in (args.repository / '.git').rglob('*') if p.is_file())
    if history_size > 512 * 1024**2: raise ValueError('backup history size budget exceeded')
    write_snapshot(args.repository, files)
    repository_scan(args.repository)
    if args.push:
        if git(args.repository, 'branch', '--show-current').stdout.strip() != BACKUP_BRANCH:
            raise ValueError('automatic updates require the dedicated backup branch')
        git(args.repository, 'add', '--', *MANAGED_TREES)
        changed = git(args.repository, 'diff', '--cached', '--name-only').stdout.strip()
        if changed:
            git(args.repository, 'commit', '-F', str(Path(__file__).with_name('snapshot-commit.txt')))
        # Push even with no new local change: the preceding push may have failed.
        git(args.repository, 'push', 'origin', 'HEAD:' + BACKUP_BRANCH)
    print(json.dumps({'exported_files': len(files), 'pushed': args.push}))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        # Do not print subprocess stderr: it can contain URLs or authentication material.
        print(json.dumps({'backup_failed': type(error).__name__}))
        raise SystemExit(1)
