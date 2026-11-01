#!/usr/bin/env python3
"""Run portable checks without root privileges, network changes or model calls."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import backup
import restore


def main():
    for tests in ['tests', 'tests/operator']:
        environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src/operator')}
        subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', tests, '-q'],
                       cwd=ROOT, env=environment, check=True)
    restore.verify(ROOT)
    backup.repository_scan(ROOT)
    if shutil.which('node'):
        for path in (ROOT / 'src').rglob('*.mjs'):
            subprocess.run(['node', '--check', str(path)], check=True)
    print('Tests, snapshot integrity, public-content scan and available JavaScript syntax checks passed.')


if __name__ == '__main__': main()
