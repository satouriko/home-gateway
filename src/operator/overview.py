"""Finite, read-only presentation of existing gateway observations."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import copy
import json
import math
from pathlib import Path
import re
import shutil
import threading
import time

MAX_AGE = 600


class SnapshotCache:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.value = None
        self.expires = 0

    def get(self, loader):
        with self.lock:
            if self.value is None or self.clock() >= self.expires:
                self.value = loader()
                self.expires = self.clock() + 20
            return copy.deepcopy(self.value)


CACHE = SnapshotCache()


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def obj(value):
    return value if isinstance(value, dict) else {}


def seq(value):
    return value if isinstance(value, list) else []


def timestamp(value):
    if number(value):
        return value if value > 0 else None
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def fresh(value, now):
    return number(value) and -60 <= now-value <= MAX_AGE


def read_json(path):
    try:
        if path.is_symlink() or path.stat().st_size > 2*1024**2:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def label(value, limit=256):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return None
    if re.search(r'https?://|\bsk-[A-Za-z0-9_-]{16,}|[\x00-\x1f]', value):
        return None
    return value.strip()


def resolve_node(mode, proxies, providers, now):
    unknown = {'kind':'unknown', 'name':None, 'state':'unknown', 'checked_at':None, 'delay_ms':None}
    if mode == 'direct':
        return {**unknown, 'kind':'direct', 'state':'not_used'}
    if mode not in ['rule', 'global']:
        return unknown
    records = dict(proxies)
    for provider in providers.values():
        if not isinstance(provider, dict):
            continue
        for item in seq(provider.get('proxies'))[:1000]:
            if isinstance(item, dict) and isinstance(item.get('name'), str):
                records.setdefault(item['name'], item)
    name = 'GLOBAL' if mode == 'global' else 'PROXY'
    visited = set()
    broken = False
    for _ in range(16):
        if name == 'DIRECT':
            return {**unknown, 'kind':'direct', 'state':'not_used'}
        if name in ['REJECT', 'REJECT-DROP']:
            return {**unknown, 'kind':'blocked', 'state':'unhealthy'}
        if not isinstance(name, str) or name in visited:
            return unknown
        visited.add(name)
        record = records.get(name)
        if not isinstance(record, dict):
            return unknown
        broken = broken or record.get('alive') is False
        if 'now' in record:
            name = record['now']
            continue
        if record.get('type') in ['Selector', 'URLTest', 'Fallback', 'LoadBalance'] or not label(name):
            return unknown
        rows = [(timestamp(row.get('time')), row.get('delay')) for row in seq(record.get('history'))[-64:] if isinstance(row, dict)]
        rows = [(at, delay) for at, delay in rows if at is not None]
        at, delay = max(rows, default=(None, None), key=lambda row:row[0])
        valid_delay = number(delay) and 0 < delay < 120000
        state = 'unknown'
        if fresh(at, now):
            if broken or record.get('alive') is False or delay == 0:
                state = 'unhealthy'
            elif record.get('alive') is True and valid_delay:
                state = 'healthy'
        return {'kind':'proxy', 'name':name, 'state':state, 'checked_at':at,
                'delay_ms':round(delay) if state == 'healthy' else None}
    return unknown


def rule_key(kind, payload, target):
    kind = re.sub(r'[^A-Za-z0-9]', '', str(kind)).upper()
    if kind in ['GEOIP', 'GEOSITE']:
        payload = str(payload).lower()
    return kind, str(payload), str(target)


def pool_evidence(providers, wanted, chain):
    """Check the complete observed pools, including legacy regex spellings."""
    spec = obj(obj(wanted.get('proxy-providers')).get('us'))
    try:
        include = re.compile(spec['filter']) if spec.get('filter') else None
        exclude = re.compile(spec['exclude-filter']) if spec.get('exclude-filter') else None
    except (re.error, TypeError):
        return None
    seen = 0
    for name in ['us', 'other'] if chain and 'OTHER_AUTO' in chain else ['us']:
        provider = obj(providers.get(name))
        for item in seq(provider.get('proxies'))[:1000]:
            node_name = obj(item).get('name')
            if not isinstance(node_name, str):return False
            seen += 1
            preferred = include is None or include.search(node_name) is not None
            if (preferred != (name == 'us')) or (exclude and exclude.search(node_name)):
                return False
    return True if seen else None


def routing_summary(mode, config, rules, proxies, policy, providers):
    from user_policy import render
    result = {'mode':mode, 'consistent':False, 'multiple_exits':False,
              'summary':'分流状态待更新', 'detail':'暂时无法读取实际运行规则。'}
    preferences = policy.get('preferences', {})
    preferences = preferences if isinstance(preferences, dict) else {}
    if mode in ['direct', 'global']:
        return {**result, 'consistent':preferences.get('mode') == mode,
                'summary':'当前为直连模式' if mode == 'direct' else '当前为全局代理模式',
                'detail':'不使用规则分流。' if preferences.get('mode') == mode else '实际运行模式与保存偏好不同，待核对。'}
    if mode != 'rule' or not isinstance(rules, list) or len(rules) > 500:
        return result
    live = [rule_key(r.get('type'), r.get('payload', ''), r.get('proxy')) for r in rules
            if isinstance(r, dict) and not obj(r.get('extra')).get('disabled')]
    def keys(values):
        result = []
        for raw in seq(values)[:501]:
            parts = raw.split(',') if isinstance(raw, str) else []
            if len(parts) >= 2:
                result.append(rule_key(parts[0], '' if len(parts) == 2 else parts[1], parts[1] if len(parts) == 2 else parts[2]))
        return result
    try:
        wanted, _ = render(config, preferences)
    except (ValueError, KeyError, TypeError, AttributeError):
        wanted = {}
    expected = keys(wanted.get('rules'))
    multiple = any(r[2] not in ['DIRECT', 'REJECT', 'REJECT-DROP', 'PROXY'] for r in live)
    result['multiple_exits'] = multiple
    chain = next((g.get('proxies') for g in seq(wanted.get('proxy-groups')) if isinstance(g, dict) and g.get('name') == 'PROXY'), None)
    actual_chain = obj(proxies.get('PROXY')).get('all')
    filters_match = all((obj(obj(config.get('proxy-providers')).get(name)).get(field) or '') ==
                        (obj(obj(wanted.get('proxy-providers')).get(name)).get(field) or '')
                        for name in ['us', 'other'] for field in ['filter', 'exclude-filter'])
    evidence = pool_evidence(providers, wanted, chain)
    extra = [rule for rule in live if rule not in expected]
    extra_domains = all(rule[0] in ['DOMAIN', 'DOMAINSUFFIX'] and rule[2] in ['DIRECT', 'PROXY'] and
                        len(rule[1]) <= 253 and re.fullmatch(r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}', rule[1]) for rule in extra)
    required = [rule for rule in live if rule in expected]
    consistent = bool(live and live == keys(config.get('rules')) and required == expected and extra_domains and
                      evidence is not False and (filters_match or evidence is True) and
                      preferences.get('mode') == mode and actual_chain == chain)
    result['consistent'] = consistent
    if not consistent:
        result.update(summary='分流配置待核对', detail='实际规则或代理顺序与保存偏好不同。')
        return result
    cn = {r[2] for r in live if r[0] in ['GEOSITE', 'GEOIP'] and r[1] == 'cn'}
    foreign = any(r == ('GEOSITE', 'geolocation-!cn', 'PROXY') for r in live)
    unmatched = any(r == ('MATCH', '', 'PROXY') for r in live)
    if cn == {'DIRECT'} and foreign and unmatched:
        result['summary'] = '中国大陆直连，其余走代理'
    elif cn == {'PROXY'} and foreign and unmatched:
        result['summary'] = '中国大陆及其他地区均走代理'
    else:
        result['summary'] = '按当前规则决定直连或代理'
    # A user-defined pool label is not evidence of a physical exit country.
    detail = '首选节点均不可用时，才启用其他地区。' if chain and 'OTHER_AUTO' in chain else '使用首选节点组，不启用其他地区备用。'
    if multiple:
        detail += '部分流量有独立出口。'
    elif extra or any(preferences.get(k) for k in ['direct_domains', 'proxy_domains']) or any(r.get('type') == 'RuleSet' and number(r.get('size')) and r['size'] > 0 for r in rules if isinstance(r, dict)):
        detail += '含自定义例外。'
    result['detail'] = detail
    return result


def health_summary(patrol, node, now):
    at = timestamp(patrol.get('checked_at'))
    observations = obj(patrol.get('last_diagnosis')).get('checks', {})
    observations = observations if isinstance(observations, dict) else {}
    def web(name, expected):
        value = observations.get(name)
        if not isinstance(value, dict):return 'unknown'
        if value.get('ok') is False:return 'unhealthy'
        code = obj(value.get('result')).get('http_status')
        return 'healthy' if value.get('ok') is True and number(code) and expected(code) else 'unknown'
    domestic = web('mainland_https', lambda code:200 <= code < 400)
    proxy = 'not_used' if node['kind'] == 'direct' else web('proxy_https', lambda code:code == 204)
    dns = []
    for name in (['gateway_dns_cn'] if node['kind'] == 'direct' else ['gateway_dns_cn', 'gateway_dns_foreign']):
        value = observations.get(name)
        result = obj(obj(value).get('result'))
        count = result.get('answer_count')
        code = result.get('rcode')
        if obj(value).get('ok') is False:
            dns.append('unhealthy')
        elif obj(value).get('ok') is not True or not number(code) or not number(count) or not 0 <= code <= 15 or not 0 <= count <= 65535:
            dns.append('unknown')
        else:
            dns.append('healthy' if code == 0 and count > 0 else 'unhealthy')
    dns = 'unhealthy' if 'unhealthy' in dns else 'unknown' if 'unknown' in dns else 'healthy'
    items = [{'id':key, 'label':text, 'state':state if fresh(at, now) or state == 'not_used' else 'unknown'}
             for key, text, state in [('domestic', '国内', domestic), ('proxy', '代理', proxy), ('dns', 'DNS', dns)]]
    states = [item['state'] for item in items]
    state = 'unhealthy' if 'unhealthy' in states else 'unknown' if 'unknown' in states else 'healthy'
    return {'checked_at':at, 'state':state, 'checks':items}


def latest_activity(state, subscription, patrol, now):
    pending = read_json(state/'pending.json')
    if pending:
        return {'at':None, 'state':'verifying', 'summary':'正在验证修复结果，未通过将自动回退。'}
    events = []
    at = subscription['updated_at']
    if at is not None:
        events.append({'at':at, 'state':'completed', 'summary':'节点订阅已更新。'})
    native = read_json(state/'native-maintenance.json')
    summaries = {'running':'AI 复核正在进行。', 'completed':'AI 复核已完成。', 'failed':'AI 复核未完成。',
                 'interrupted':'AI 复核已中断。', 'expired':'AI 复核已超时。', 'preempted':'常规复核已让位给故障处理。'}
    for run in seq(native.get('runs'))[-48:]:
        if not isinstance(run, dict) or run.get('kind') == 'deployment_validation' or not isinstance(run.get('state'), str) or run.get('state') not in summaries:continue
        at = timestamp(run.get('finished_at')) or timestamp(run.get('at'))
        if at is not None:events.append({'at':at, 'state':run['state'], 'summary':summaries[run['state']]})
    gate = obj(native.get('last_gate'))
    if gate.get('reason') == 'waiting for off-peak budget':
        events.append({'at':timestamp(gate.get('at')), 'state':'deferred', 'summary':'常规 AI 复核等待谷价，程序巡检继续运行。'})
    repair = read_json(state/'last-repair.json')
    if repair.get('operation') in ['recheck_nodes', 'refresh_subscription', 'restart_gateway', 'restore_gateway']:
        success = repair.get('verified_healthy') is True
        legacy = 'verified_healthy' not in repair
        events.append({'at':timestamp(repair.get('completed_at')), 'state':'completed' if success else 'observed' if legacy else 'unconfirmed',
                       'summary':'自动修复已通过最终验收。' if success else '已执行自动修复，旧记录未保存最终验收结果。' if legacy else '自动修复未通过最终验收。'})
    events = [e for e in events if e['at'] is not None and e['at'] <= now+60]
    if events:return max(events, key=lambda e:e['at'])
    return {'at':timestamp(patrol.get('checked_at')), 'state':'observed', 'summary':'程序检查已完成。' if patrol.get('checked_at') else '暂无自动处理记录。'}


def build_snapshot(api, state, config_path, now=None):
    now = time.time() if now is None else now
    state = Path(state)
    def fetch(path):
        try:
            value = api(path, timeout=2)
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}
    paths = ['/configs', '/proxies', '/providers/proxies', '/rules']
    with ThreadPoolExecutor(max_workers=4) as pool:
        data = dict(zip(paths, pool.map(fetch, paths)))
    config = read_json(Path(config_path))
    patrol = read_json(state/'patrol.json')
    policy = read_json(state/'approved-policy.json')
    mode = data['/configs'].get('mode')
    mode = mode.lower() if isinstance(mode, str) and mode.lower() in ['rule', 'global', 'direct'] else None
    proxies = data['/proxies'].get('proxies', {})
    providers = data['/providers/proxies'].get('providers', {})
    proxies = proxies if isinstance(proxies, dict) else {}
    providers = providers if isinstance(providers, dict) else {}
    node = resolve_node(mode, proxies, providers, now)
    updates = [timestamp(p.get('updatedAt')) for p in providers.values() if isinstance(p, dict)]
    updates = [at for at in updates if at is not None and at <= now+60]
    intervals = [p.get('interval') for p in obj(config.get('proxy-providers')).values() if isinstance(p, dict)]
    interval = intervals[0] if intervals and all(number(v) and v > 0 and v == intervals[0] for v in intervals) else None
    subscription = {'updated_at':max(updates, default=None), 'interval_seconds':interval}
    try:temperature = int(Path('/sys/class/thermal/thermal_zone0/temp').read_text())/1000
    except (OSError, ValueError):temperature = None
    return {'observed_at':now, 'node':node,
            'routing':routing_summary(mode, config, data['/rules'].get('rules'), proxies, policy, providers),
            'health':health_summary(patrol, node, now),
            'activity':latest_activity(state, subscription, patrol, now), 'subscription':subscription,
            'device':{'temperature_celsius':temperature, 'free_disk_bytes':shutil.disk_usage('/').free}}
