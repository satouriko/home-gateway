#!/usr/bin/env python3
"""Restore this program/preference snapshot; credentials must be supplied anew."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

import backup


def verify(repository):
    repository = Path(repository).resolve()
    manifest = json.loads((repository / 'snapshot/manifest.json').read_text())
    if manifest.get('format') != 1: raise ValueError('unsupported snapshot format')
    extra = {'config/mihomo.template.json', 'preferences/network-policy.json',
             'preferences/audit-plan.json', 'snapshot/published/diagnostic-active.json',
             'snapshot/published/tool-active.json', 'src/maintained/diagnostic.py', 'src/maintained/tool.py',
             'snapshot/published/workflow-active.json', 'src/maintained/workflow.py', 'snapshot/maintained-tests.json'}
    files = {}
    for name, record in manifest['files'].items():
        allowed = name in backup.SOURCE_MAP or name in extra
        if name.startswith('tests/maintained/'):
            allowed = Path(name).parent.as_posix() == 'tests/maintained' and Path(name).name.startswith('test_') and name.endswith('.py')
        if not allowed or '..' in Path(name).parts: raise ValueError('unexpected snapshot destination')
        data = backup.safe_read(repository, '/' + name)
        if data is None or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('snapshot content hash mismatch: ' + name)
        files[name] = data
    backup.scan(files)
    if 'preferences/network-policy.json' in files:
        backup.validate_public_preferences(json.loads(files['preferences/network-policy.json']).get('preferences', {}))
    workflow = files.get('snapshot/published/workflow-active.json')
    if workflow:
        published = json.loads(workflow)
        source = files.get('src/maintained/workflow.py')
        if (source is None or not isinstance(published, dict) or type(published.get('active')) is not bool or
                published.get('version') != hashlib.sha256(source).hexdigest()[:16]):
            raise ValueError('workflow version integrity failed')
        if 'src/maintained/workflow-default.py' not in files:
            raise ValueError('workflow builtin missing from finite export')
    return manifest, files


def check_credentials(credentials):
    if set(credentials) != {'subscription_url', 'deepseek_api_key'}: raise ValueError('supply subscription_url and deepseek_api_key only')
    url = urlsplit(credentials['subscription_url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('subscription must be an HTTPS URL without userinfo')
    if not isinstance(credentials['deepseek_api_key'], str) or not credentials['deepseek_api_key'].strip(): raise ValueError('API key required')
    if any(c in credentials['deepseek_api_key'] for c in '\r\n'): raise ValueError('invalid API key')


def stage(repository, destination, credentials, uid=999):
    check_credentials(credentials)
    manifest, files = verify(repository)
    destination = Path(destination)
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ValueError('restore staging directory must be empty')
    for parent in destination.parents:
        if parent.is_symlink(): raise ValueError('restore parent must not be a symlink')
    config = json.loads(files['config/mihomo.template.json'])
    config['secret'] = secrets.token_urlsafe(32)
    for provider in config['proxy-providers'].values():
        if provider['url'] != backup.PLACEHOLDER_URL: raise ValueError('subscription placeholder missing')
        provider['url'] = credentials['subscription_url']
    policies = config.get('dns', {}).get('nameserver-policy', {})
    if '__SUBSCRIPTION_HOST__' in policies:
        policies[urlsplit(credentials['subscription_url']).hostname] = policies.pop('__SUBSCRIPTION_HOST__')
    config.setdefault('tun', {})['exclude-uid'] = [uid]

    def write(absolute, data, mode=0o600):
        target = destination / absolute.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data); target.chmod(mode)

    for name, data in files.items():
        if name in backup.SOURCE_MAP:
            absolute = backup.SOURCE_MAP[name]
            mode = manifest['files'][name]['mode'] & 0o777
            if mode & 0o022: raise ValueError('unsafe program/configuration permissions')
            # Public exported modules must remain readable after UID/GID remapping.
            # Private state and credentials keep their separately assigned modes.
            if absolute.startswith('/usr/local/share/net-gateway-agent/'):
                mode |= 0o044
            write(absolute, data, mode)
        elif name.startswith('tests/maintained/'):
            write('/var/lib/dsh/workspace/network-maintainer/tests/' + Path(name).name, data)
    write('/etc/net-gateway/config.json', backup.encoded(config))
    approved = files['preferences/network-policy.json']
    for name, data in [('approved-policy.json', approved), ('known-good-policy.json', approved),
                       ('known-good-config.json', backup.encoded(config))]:
        write('/var/lib/net-gateway-agent/' + name, data)
    rules = files.get('config/proxy-domains.yaml', b'payload: []\n')
    write('/var/lib/net-gateway-agent/known-good-rules.yaml', rules)
    write('/var/lib/net-gateway-agent/transaction.lock', b'')
    for name in ['diagnostic-active', 'tool-active']:
        key = 'snapshot/published/' + name + '.json'
        if key in files:
            data = json.loads(files[key]); data['tests'] = []
            source_name = 'diagnostic.py' if name == 'diagnostic-active' else 'tool.py'
            data['source'] = files['src/maintained/' + source_name].decode()
            write('/var/lib/net-gateway-agent/' + name + '.json', backup.encoded(data))
            candidate = 'programs/patrol_inspect.py' if name == 'diagnostic-active' else 'tools/wireless_link.py'
            write('/var/lib/dsh/workspace/network-maintainer/' + candidate, data['source'].encode())
    skill = files.get('src/dsh/skill/SKILL.md')
    if skill: write('/var/lib/dsh/workspace/network-maintainer/skill/SKILL.md', skill)
    if 'snapshot/published/workflow-active.json' in files:
        published = json.loads(files['snapshot/published/workflow-active.json'])
        source = files['src/maintained/workflow.py'].decode()
        active = {'source': source, 'version': published['version'], 'tests': [], 'published_at': None} if published['active'] else None
        write('/var/lib/net-gateway-agent/workflow-state.json', backup.encoded({'format': 1, 'active': active, 'previous': None}))
        write('/var/lib/dsh/workspace/network-maintainer/programs/workflow.py', source.encode())
    if 'preferences/audit-plan.json' in files:
        plan = json.loads(files['preferences/audit-plan.json'])
        current = json.loads(files.get('snapshot/published/diagnostic-active.json', b'{}'))
        plan.update(reason='从已保存的维护偏好恢复', chosen_at=time.time(), expires_at=time.time()+7*86400,
                    for_program_version=current.get('version'))
        write('/var/lib/net-gateway-agent/audit-plan.json', backup.encoded(plan))
    write('/var/lib/dsh/state/.env', ('DEEPSEEK_API_KEY=' + credentials['deepseek_api_key'] + '\n').encode(), 0o640)
    empty_login = b'version: 1\nrefs: {}\nrecords: {}\n'
    for name in ['/var/lib/dsh-login/credentials.yaml', '/var/lib/dsh/state/.credentials.yaml',
                 '/var/lib/net-gateway-agent/bootstrap-login.yaml']:
        write(name, empty_login)
    for profile in ['web', 'headless']:
        write('/var/lib/dsh/state/profiles/' + profile + '/cordis.yml', b'')
    for name in ['sessions', 'storages', 'logs']:
        (destination / 'var/lib/dsh/state' / name).mkdir(parents=True, exist_ok=True)
    (destination / 'var/lib/dsh/workspace/.maintenance-tmp').mkdir(parents=True, exist_ok=True)
    (destination / 'var/lib/dsh/native-task-identity').mkdir(parents=True, exist_ok=True)
    (destination / 'var/lib/net-gateway/providers').mkdir(parents=True, exist_ok=True)
    return manifest


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=600, **kwargs)


def download(url, destination):
    request = urllib.request.Request(url, headers={'User-Agent': 'home-gateway-restore'})
    with urllib.request.urlopen(request, timeout=60) as response, open(destination, 'wb') as out:
        shutil.copyfileobj(response, out)


def install_runtime(repository, manifest):
    command('apt-get', 'update')
    command('apt-get', 'install', '-y', 'ca-certificates', 'python3', 'python3-yaml', 'bubblewrap', 'util-linux', 'iproute2', 'nftables', 'iw', 'zstd', 'git', 'openssh-client', 'xz-utils')
    version = manifest['runtime']['node']
    current = command('node', '--version').stdout.decode().strip() if shutil.which('node') else ''
    if current != 'v' + version:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); filename = f'node-v{version}-linux-arm64.tar.xz'
            base = f'https://nodejs.org/dist/v{version}/'
            download(base + filename, tmp / filename); download(base + 'SHASUMS256.txt', tmp / 'sha256')
            expected = next(line.split()[0] for line in (tmp / 'sha256').read_text().splitlines() if line.endswith('  ' + filename))
            if hashlib.sha256((tmp / filename).read_bytes()).hexdigest() != expected: raise ValueError('Node checksum failed')
            with tarfile.open(tmp / filename) as archive: archive.extractall(tmp, filter='data')
            target = Path('/usr/local/lib') / f'node-v{version}-linux-arm64'
            if not target.exists(): shutil.copytree(tmp / target.name, target)
            for binary in ['node', 'npm', 'npx']:
                link = Path('/usr/local/bin') / binary
                if link.is_symlink(): link.unlink()
                if not link.exists(): link.symlink_to(target / 'bin' / binary)
    Path('/opt/dsh').mkdir(parents=True, exist_ok=True)
    for name in ['package.json', 'package-lock.json']:
        shutil.copyfile(Path(repository) / 'runtime/dsh' / name, Path('/opt/dsh') / name)
    command('npm', 'ci', '--prefix', '/opt/dsh', '--ignore-scripts')
    command('python3', str(Path(repository) / 'tools/apply_dsh_patches.py'), '--runtime', '/opt/dsh',
            '--patches', str(Path(repository) / 'runtime/dsh/patches'))
    shutil.copytree(Path(repository) / 'runtime/dsh/patches', '/opt/dsh/patches', dirs_exist_ok=True)
    version = manifest['runtime']['mihomo']
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / 'mihomo.gz'
        download(f'https://github.com/MetaCubeX/mihomo/releases/download/v{version}/mihomo-linux-arm64-v{version}.gz', archive)
        binary = gzip.decompress(archive.read_bytes())
        if not manifest['runtime'].get('mihomo_sha256') or hashlib.sha256(binary).hexdigest() != manifest['runtime']['mihomo_sha256']:
            raise ValueError('Mihomo checksum failed')
        Path('/usr/local/bin/mihomo').write_bytes(binary); Path('/usr/local/bin/mihomo').chmod(0o755)


def install_tree(source, destination):
    source, destination = Path(source), Path(destination)
    if not destination.exists(): destination.mkdir(parents=True); destination.chmod(0o755)
    for item in sorted(source.rglob('*')):
        if item.is_symlink(): raise ValueError('restore source link rejected')
        target = destination / item.relative_to(source)
        if target.is_symlink(): raise ValueError('restore destination link rejected')
        if item.is_dir():
            if not target.exists(): target.mkdir(); target.chmod(0o755)
        else: shutil.copy2(item, target)


def link_profile_plugins(root=Path('/')):
    """Resolve profile dependencies through the one version-locked runtime."""
    root = Path(root)
    for profile in ['web', 'headless']:
        folder = root / 'var/lib/dsh/state/profiles' / profile
        package = folder / 'package.json'
        if not package.exists(): continue
        for name, version in json.loads(package.read_text()).get('dependencies', {}).items():
            if not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', name):
                raise ValueError('unsupported profile dependency')
            target = Path('/opt/dsh/node_modules') / name
            installed = json.loads((root / target.relative_to('/') / 'package.json').read_text())
            if installed['version'] != version: raise ValueError('profile dependency version mismatch: ' + name)
            modules=folder/'node_modules';modules.mkdir(exist_ok=True);modules.chmod(0o755)
            link = folder / 'node_modules' / name
            link.parent.mkdir(parents=True, exist_ok=True);link.parent.chmod(0o755)
            if link.is_symlink(): link.unlink()
            if link.exists(): raise ValueError('profile dependency destination is occupied')
            link.symlink_to(target)


def apply(repository, credentials):
    check_credentials(credentials)
    manifest, _files = verify(repository)
    if os.geteuid() != 0 or platform.machine() not in ['aarch64', 'arm64']:
        raise ValueError('apply requires root on the replacement ARM64 Pi')
    if Path('/etc/net-gateway/config.json').exists() or Path('/var/lib/dsh/state').exists():
        raise ValueError('apply requires a clean replacement system; existing deployment is protected')
    for args in [('groupadd', '--system', 'gateway-operators'), ('useradd', '--system', '--user-group', '--home-dir', '/var/lib/dsh', '--shell', '/usr/sbin/nologin', 'dsh'),
                 ('useradd', '--system', '--gid', 'gateway-operators', '--home-dir', '/var/empty', '--shell', '/usr/sbin/nologin', 'gateway-worker'),
                 ('useradd', '--system', '--gid', 'gateway-operators', '--home-dir', '/var/empty', '--shell', '/usr/sbin/nologin', 'gateway-probe')]:
        try:
            subprocess.run(['getent', 'group' if args[0] == 'groupadd' else 'passwd', args[-1]], check=True, capture_output=True)
        except subprocess.CalledProcessError: command(*args)
    command('usermod', '-a', '-G', 'gateway-operators', 'dsh')
    user = pwd.getpwnam('dsh')
    install_runtime(repository, manifest)
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / 'root'; stage(repository, staged, credentials, uid=user.pw_uid)
        install_tree(staged, '/')
    for path in ['/var/lib/dsh', '/var/lib/dsh/state', '/var/lib/dsh/state/profiles', '/var/lib/dsh/state/profiles/web', '/var/lib/dsh/state/profiles/headless','/var/lib/dsh/native-task-identity']:
        os.chown(path, 0, user.pw_gid); Path(path).chmod(0o750)
    for path in ['/var/lib/dsh/workspace', '/var/lib/dsh/state/sessions', '/var/lib/dsh/state/storages', '/var/lib/dsh/state/logs']:
        shutil.chown(path, user=user.pw_uid, group=user.pw_gid)
        for item in Path(path).rglob('*'): os.chown(item, user.pw_uid, user.pw_gid)
        Path(path).chmod(0o700)
    for item in Path('/var/lib/dsh/state').rglob('*'):
        if item.is_file() and 'profiles' in item.parts: os.chown(item, 0, user.pw_gid); item.chmod(0o640)
    for path in ['/var/lib/dsh/state/.env', '/var/lib/dsh/state/AGENTS.md', '/var/lib/dsh/lan-auto-login.mjs', '/var/lib/dsh/mobile-layout.mjs']:
        os.chown(path, 0, user.pw_gid)
    link_profile_plugins()
    for profile in ['web', 'headless']:
        path = Path('/var/lib/dsh/state/profiles') / profile / 'cordis.yml'; os.chown(path, user.pw_uid, user.pw_gid); path.chmod(0o600)
    os.chown('/var/lib/dsh-login', 0, user.pw_gid); Path('/var/lib/dsh-login').chmod(0o770)
    os.chown('/var/lib/dsh-login/credentials.yaml', user.pw_uid, user.pw_gid)
    Path('/var/lib/net-gateway-agent').chmod(0o700)
    config = json.loads(Path('/etc/net-gateway/config.json').read_text())
    for name, url in config.get('geox-url', {}).items():
        if name not in ['geoip', 'geosite'] or not url.startswith('https://github.com/MetaCubeX/meta-rules-dat/'):
            raise ValueError('unrecognized geodata source')
        download(url, Path('/var/lib/net-gateway') / ('GeoIP.dat' if name == 'geoip' else 'GeoSite.dat'))
    boot = Path('/boot/firmware/cmdline.txt')
    if boot.exists():
        options = boot.read_text().split()
        for value in ['cgroup_memory=1', 'cgroup_enable=memory']:
            if value not in options: options.append(value)
        boot.write_text(' '.join(options) + '\n')
    command('systemctl', 'daemon-reload')
    print('程序与偏好已恢复。重启后运行 sudo python3 restore.py --start 验证并启用服务。')


def start():
    if os.geteuid() != 0 or not Path('/etc/net-gateway/config.json').exists(): raise ValueError('replacement installation missing')
    if 'memory' not in Path('/sys/fs/cgroup/cgroup.controllers').read_text(): raise ValueError('reboot to enable memory control before starting')
    command('env', 'SAFE_PATHS=/etc/net-gateway', '/usr/local/bin/mihomo', '-t', '-d', '/var/lib/net-gateway', '-f', '/etc/net-gateway/config.json')
    command('systemctl', 'enable', '--now', 'net-gateway-control-route.service', 'net-gateway-agent.service', 'net-gateway.service', 'dsh.service',
            'net-gateway-traffic.service', 'net-gateway-maintain.timer', 'net-gateway-watchdog.timer', 'net-gateway-storage.timer', 'net-gateway-patrol.timer')
    result = json.loads(command('/usr/local/bin/gateway-agent', 'diagnose').stdout)
    print(json.dumps({'diagnose_ok': result.get('ok'), 'verification': result.get('result', {}).get('checks')}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parent)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--stage', type=Path); group.add_argument('--apply', action='store_true'); group.add_argument('--start', action='store_true')
    parser.add_argument('--credentials-file', help='Private JSON file, or - for stdin; never committed')
    args = parser.parse_args()
    if args.start: return start()
    if not args.credentials_file: raise ValueError('--credentials-file is required')
    credentials = json.load(sys.stdin) if args.credentials_file == '-' else json.loads(Path(args.credentials_file).read_text())
    if args.apply: apply(args.repository, credentials)
    else: stage(args.repository, args.stage, credentials); print('staged restore verified')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'restore_failed': type(error).__name__}))
        raise SystemExit(1)
