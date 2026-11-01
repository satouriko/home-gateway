"""Regression test for the diagnostic worker entry point.

A deployed runtime update once imported `bounded` at module top-level in
programs.py.  The worker is started with `python3 -I programs.py --worker`,
which does not put the script directory on sys.path, so every evaluation
died with ModuleNotFoundError and the active program was rolled back.
This test runs the real deployed worker exactly as evaluate() does, so a
reintroduced import/path regression fails here before publish.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = Path('/usr/local/lib/net-gateway-agent/programs.py')
SOURCE = ROOT / 'programs' / 'patrol_inspect.py'
CONTEXT = Path('/run/net-gateway-agent/patrol-context.json')

HEALTHY = {
    'status': {'services': {'net-gateway.service': {'ActiveState': 'active'}}},
    'checks': {
        'proxy_https': {'ok': True, 'result': {'http_status': 204, 'elapsed_ms': 300, 'expected_health_status': True}},
        'mainland_https': {'ok': True, 'result': {'http_status': 200, 'elapsed_ms': 90, 'expected_health_status': True}},
        'gateway_dns_cn': {'ok': True, 'result': {'rcode': 0, 'answer_count': 3}},
        'gateway_dns_foreign': {'ok': True, 'result': {'rcode': 0, 'answer_count': 8}},
    },
    'history': [],
}

BROKEN = json.loads(json.dumps(HEALTHY))
BROKEN['checks']['proxy_https'] = {'ok': False, 'error': 'TimeoutError'}


def run_worker(snapshot):
    payload = json.dumps({'source': SOURCE.read_text(), 'snapshot': snapshot})
    return subprocess.run(
        [sys.executable, '-I', str(WORKER), '--worker'],
        input=payload, text=True, capture_output=True,
        env={'PATH': '/usr/bin:/bin', 'HOME': '/var/empty', 'LANG': 'C.UTF-8'},
        timeout=10,
    )


def check(name, snapshot, expected_action):
    proc = run_worker(snapshot)
    assert proc.returncode == 0, '%s: worker exit %s: %s' % (name, proc.returncode, proc.stderr[-500:])
    output = json.loads(proc.stdout)
    assert set(output) == {'summary', 'action', 'probe_domains'}, '%s: bad keys %s' % (name, set(output))
    assert output['action'] == expected_action, '%s: action %s != %s' % (name, output['action'], expected_action)
    assert isinstance(output['summary'], str) and output['summary'], '%s: empty summary' % name
    return output


def scenario(name, mutate, expected_action, expect_terms=()):
    snapshot = json.loads(json.dumps(HEALTHY))
    mutate(snapshot)
    output = check(name, snapshot, expected_action)
    for term in expect_terms:
        assert term in output['summary'], '%s: summary missing %r: %s' % (name, term, output['summary'])
    return output


def main():
    check('healthy', HEALTHY, 'none')
    check('proxy_failure', BROKEN, 'recheck_nodes')
    # Branches that normal healthy data rarely exercises: they must stay
    # conservative and must not crash the real worker.
    scenario('missing_checks', lambda snap: snap.update(checks={}), 'none', ('缺失',))
    scenario(
        'service_down',
        lambda snap: snap['status']['services']['net-gateway.service'].update(ActiveState='failed'),
        'none', ('服务',),
    )
    scenario(
        'sustained_latency',
        lambda snap: snap.update(history=[{'proxy_ms': 430}] * 4 + [{'proxy_ms': 1300}] * 4),
        'recheck_nodes', ('时延',),
    )
    scenario(
        'all_pool_dead',
        lambda snap: snap.update(quality_summary={'preferred_pool': [
            {'name': 'A', 'alive': False}, {'name': 'B', 'alive': False}]}),
        'refresh_subscription', ('全部不可用',),
    )
    scenario(
        'partial_pool_dead',
        lambda snap: snap.update(quality_summary={'preferred_pool': [
            {'name': 'A', 'alive': True}, {'name': 'B', 'alive': False}]}),
        'none', ('1/2',),
    )
    if CONTEXT.exists():
        context = json.loads(CONTEXT.read_text())
        snapshot = {**context['diagnosis'], 'history': context.get('history', [])[-24:]}
        output = check('real_context', snapshot, 'none')
        print('real_context:', output['action'], output['summary'])
    print('ALL PASS')


if __name__ == '__main__':
    main()
