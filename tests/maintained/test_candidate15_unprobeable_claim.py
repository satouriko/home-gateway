"""回归：probe_unavailable 原因未确认时，巡检程序不得断言“没有可用的公共解析地址”。

背景：business_watch 把探测异常记为 state=probe_unavailable/error_category=ValueError；
probe_transport 的 ValueError 同时覆盖名称不存在、解析失败、应答数超出 1..16 上限、
应答含非公网地址等多种原因，单凭该错误不能得出“解析不存在”。v15 起改为“原因未确认”。
"""
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'programs' / 'patrol_inspect_candidate15.py'


def _snapshot(issues, checks):
    return {
        'checks': {
            'proxy_https': {'ok': True, 'result': {'expected_health_status': True}},
            'mainland_https': {'ok': True, 'result': {'expected_health_status': True}},
        },
        'history': [],
        'business_observations': {'checked_at': 1793767320, 'issues': issues, 'checks': checks},
    }


def _run(snapshot):
    code = (
        "import json,sys;ns={};exec(compile(open(sys.argv[1]).read(),'<c>','exec'),ns);"
        "print(json.dumps(ns['inspect'](json.loads(sys.stdin.read())),ensure_ascii=False))"
    )
    out = subprocess.run([sys.executable, '-c', code, str(SOURCE)], input=json.dumps(snapshot),
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_value_error_not_reported_as_missing_dns():
    result = _run(_snapshot(
        [{'domain': 'a.example', 'kind': 'recurring_client_failure', 'fingerprint': 'f1', 'resolved': False}],
        {'a.example': {'at': 1793767000, 'result': {'state': 'probe_unavailable', 'error_category': 'ValueError'}}},
    ))
    assert '没有可用的公共解析地址' not in result['summary']
    assert '原因未确认' in result['summary']
    assert result['action'] == 'none'
    assert result.get('review_request') is None
    assert result['probe_domains'] == []


def test_unresolved_endpoint_without_path_evidence_still_requests_review():
    result = _run(_snapshot(
        [{'domain': 'real.example.com', 'kind': 'recurring_client_failure', 'fingerprint': 'f2', 'resolved': False}],
        {},
    ))
    assert result.get('review_request'), result
    assert 'real.example.com' in result['probe_domains']
