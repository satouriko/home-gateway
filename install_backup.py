#!/usr/bin/env python3
"""Install program-only automatic snapshots after authorizing the Pi deploy key."""
import os
from pathlib import Path
import shutil
import subprocess
import argparse
import re

BASE = Path('/var/lib/home-gateway-backup')
CONFIG = Path('/etc/home-gateway-backup')
CODE = Path('/usr/local/lib/home-gateway-backup')
REPOSITORY = 'git@github.com:satouriko/home-gateway.git'


def run(*args):
    subprocess.run(args, check=True, capture_output=True, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=REPOSITORY)
    args = parser.parse_args()
    if not re.fullmatch(r'git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', args.repository):
        raise SystemExit('use a GitHub SSH repository URL')
    if os.geteuid() != 0: raise SystemExit('run as root on the Pi')
    if not (CONFIG / 'id_ed25519').is_file(): raise SystemExit('authorize a repository-scoped deploy key first')
    for folder in [BASE, CONFIG, CODE]: folder.mkdir(parents=True, exist_ok=True); folder.chmod(0o700)
    # Opening append preserves the inode used by the broker/watchdog flock.
    with Path('/var/lib/net-gateway-agent/transaction.lock').open('a'): pass
    (CONFIG / 'id_ed25519').chmod(0o600)
    shutil.copyfile(Path(__file__).with_name('github_known_hosts'), CONFIG / 'known_hosts')
    (CONFIG / 'ssh_config').write_text('''Host github.com
  HostName ssh.github.com
  Port 443
  User git
  IdentityFile /etc/home-gateway-backup/id_ed25519
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile /etc/home-gateway-backup/known_hosts
  HostKeyAlias github.com
  ConnectTimeout 10
''')
    os.environ['GIT_SSH_COMMAND'] = '/usr/bin/ssh -F /etc/home-gateway-backup/ssh_config'
    repo = BASE / 'repository'
    if not repo.exists():
        run('git', 'clone', '--branch', 'main', args.repository, str(repo))
    repo.chmod(0o700)
    run('git', '-C', str(repo), 'config', 'user.name', 'Home Gateway Backup')
    run('git', '-C', str(repo), 'config', 'user.email', 'home-gateway-backup@users.noreply.github.com')
    for name in ['backup.py', 'snapshot-commit.txt']:
        shutil.copyfile(Path(__file__).with_name(name), CODE / name); (CODE / name).chmod(0o600)
    Path('/etc/systemd/system/home-gateway-backup.service').write_text('''[Unit]
Description=Public program and preference backup (no credentials or history)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/home-gateway-backup/backup.py --repository /var/lib/home-gateway-backup/repository --push --status-file /var/lib/home-gateway-backup/status.json --request-file /var/lib/net-gateway-agent/source-sync-request.json
Environment="GIT_SSH_COMMAND=/usr/bin/ssh -F /etc/home-gateway-backup/ssh_config"
Environment=GIT_TERMINAL_PROMPT=0
TimeoutStartSec=150
MemoryMax=192M
CPUQuota=25%
Nice=15
TasksMax=40
LimitFSIZE=32M
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/home-gateway-backup
''')
    Path('/etc/systemd/system/home-gateway-backup.timer').write_text('''[Unit]
Description=Synchronize published programs and household preferences
[Timer]
OnBootSec=5min
OnUnitInactiveSec=15min
AccuracySec=30s
[Install]
WantedBy=timers.target
''')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'home-gateway-backup.timer')
    print('automatic program/preference backup installed')


if __name__ == '__main__': main()
