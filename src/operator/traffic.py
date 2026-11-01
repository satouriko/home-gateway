"""Bounded private observations of household connections, never browsing history.

Bytes are a lower bound: the first sight of a connection establishes a baseline.
Snapshots cannot establish that short, failed, or hostless connections were healthy.
Persist this state privately; it contains client IP addresses and observed domains.
"""
import hashlib
import ipaddress
import math
import re


RETENTION_SECONDS = 72 * 3600
BASELINE_SECONDS = 5 * 60
MAX_DOMAINS = 256
MAX_DEVICES = 128
MAX_CONNECTIONS = 4096
MAX_FAILURE_EVENTS = 1024
MAX_INPUT_ROWS = 16384
RECENT_SECONDS = 6 * 3600
_HOURLY_COUNTERS = ('upload', 'download', 'connections', 'failures')
_MAX_COUNTER = (1 << 63) - 1
_ERROR_CATEGORIES = {'timeout', 'dns', 'refused', 'reset', 'tls', 'unreachable', 'proxy', 'other'}
_GAPS = ['short_or_failed_connections_may_be_absent', 'hostless_connections_not_attributed',
         'first_snapshot_bytes_not_counted', 'sampled_not_complete_accounting']


def hostname(value):
    """Normalize a public DNS name without resolving it or accepting URLs/IPs."""
    if not isinstance(value, str) or not value or len(value) > 254 or value != value.strip():
        return None
    if any(ord(char) < 33 for char in value):
        return None
    try:
        name = value.rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return None
    if len(name) > 253 or len(name.split('.')) < 2:
        return None
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    if name.rsplit('.', 1)[-1].isdigit():
        return None
    if name.rsplit('.', 1)[-1] in {'local', 'localhost', 'lan', 'home', 'internal', 'invalid', 'test', 'onion'}:
        return None
    if name.endswith(('.home.arpa', '.in-addr.arpa', '.ip6.arpa')):
        return None
    return name


def _time(value):
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else 0
    except (TypeError, ValueError, OverflowError):
        return 0


def _counter(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    if not 0 <= value <= _MAX_COUNTER or not math.isfinite(value):
        return None
    return int(value)


def _source(value, local_addresses):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast or address.is_reserved:
        return None
    return None if str(address) in local_addresses else str(address)


def _locals(addresses):
    result = set()
    for value in list(addresses or ())[:256]:
        try:
            address = ipaddress.ip_address(str(value).split('/', 1)[0])
            result.add(str(address))
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                result.add(str(address.ipv4_mapped))
        except ValueError:
            continue
    return result


def _digest(*values):
    return hashlib.sha256('\0'.join(str(value)[:512] for value in values).encode()).hexdigest()[:24]


def _prune(state, now):
    if not isinstance(state, dict) or state.get('version') != 1:
        state = {'version': 1, 'domains': {}, 'devices': {}, 'connections': {}, 'failure_events': {},
                 'snapshot_count': 0, 'dropped_observations': 0}
    cutoff = now - RETENTION_SECONDS
    oldest_hour = int(now // 3600) - 71
    for name, limit in (('domains', MAX_DOMAINS), ('devices', MAX_DEVICES)):
        records = state[name]
        for key, record in list(records.items()):
            if record['last_seen'] < cutoff:
                del records[key]
                continue
            # Four fixed-position integers keep a saturated 72-hour record small.
            record['hours'] = {hour: [values.get(key, 0) for key in _HOURLY_COUNTERS] if isinstance(values, dict) else values
                               for hour, values in record['hours'].items() if int(hour) >= oldest_hour}
            if name == 'domains':
                record['failure_times'] = [at for at in record.get('failure_times', []) if at >= cutoff][-16:]
        if len(records) > limit:
            state[name] = dict(sorted(records.items(), key=lambda pair: pair[1]['last_seen'], reverse=True)[:limit])
    state['connections'] = {key: value for key, value in state['connections'].items()
                            if value['last_seen'] >= now - BASELINE_SECONDS and value['domain'] in state['domains']}
    state['connections'] = dict(list(state['connections'].items())[-MAX_CONNECTIONS:])
    state['failure_events'] = {key: at for key, at in state['failure_events'].items() if at >= cutoff}
    state['failure_events'] = dict(list(state['failure_events'].items())[-MAX_FAILURE_EVENTS:])
    return state


def _recent_failure_times(record, now):
    return [at for at in record.get('failure_times', []) if now - 30 * 60 <= at <= now]


def _failure_priority(record, now):
    times = _recent_failure_times(record, now)
    recurring = len(times) >= 3 and max(times) - min(times) >= 60
    return recurring, bool(times), len(times), max(times, default=0), record['last_seen']


def _make_domain_room(state, now, failure):
    """Prefer current evidence while preserving failures through snapshot churn."""
    choices = [(name, record) for name, record in state['domains'].items()
               if failure or not _recent_failure_times(record, now)]
    if not choices:
        # Ordinary traffic cannot displace the evidence needed to establish a
        # recurring fault. Incoming failures can still use the bounded capacity.
        state['dropped_observations'] = min(_MAX_COUNTER, state['dropped_observations'] + 1)
        state['domain_capacity_drops'] = min(_MAX_COUNTER, state.get('domain_capacity_drops', 0) + 1)
        return False
    name, record = min(choices, key=lambda pair: (_failure_priority(pair[1], now), pair[0]))
    del state['domains'][name]
    state['domain_evictions'] = min(_MAX_COUNTER, state.get('domain_evictions', 0) + 1)
    if record.get('failure_times'):
        state['failure_domain_evictions'] = min(_MAX_COUNTER, state.get('failure_domain_evictions', 0) + 1)
    if _failure_priority(record, now)[0]:
        state['recurring_issue_evictions'] = min(_MAX_COUNTER, state.get('recurring_issue_evictions', 0) + 1)
    return True


def _record(state, domain, source, now, *, failure=False, reference_now=None):
    if domain not in state['domains']:
        if len(state['domains']) >= MAX_DOMAINS and not _make_domain_room(
                state, now if reference_now is None else reference_now, failure):
            return None, None
        state['domains'][domain] = {'first_seen': now, 'last_seen': now, 'hours': {}, 'devices': [],
                                   'rules': [], 'chains': [], 'failure_times': [], 'error_categories': []}
    record = state['domains'][domain]
    record['first_seen'] = min(record['first_seen'], now)
    record['last_seen'] = max(record['last_seen'], now)
    if source not in record['devices'] and len(record['devices']) < 16:
        record['devices'].append(source)
    device = state['devices'].get(source)
    if device is None and len(state['devices']) < MAX_DEVICES:
        device = state['devices'][source] = {'first_seen': now, 'last_seen': now, 'hours': {}}
    if device is not None:
        device['first_seen'] = min(device['first_seen'], now)
        device['last_seen'] = max(device['last_seen'], now)
    return record, device


def _increment(record, now, **values):
    if record is None:
        return
    hour = str(int(now // 3600))
    counters = record['hours'].setdefault(hour, [0, 0, 0, 0])
    for index, name in enumerate(_HOURLY_COUNTERS):
        counters[index] = min(_MAX_COUNTER, counters[index] + values.get(name, 0))


def _failure_update(state, failures, now, local_addresses):
    for failure in (failures or [])[:MAX_INPUT_ROWS]:
        if not isinstance(failure, dict) or failure.get('origin') != 'client':
            continue
        domain = hostname(failure.get('domain', failure.get('host')))
        source = _source(failure.get('sourceIP'), local_addresses)
        at = _time(failure.get('at', now))
        if not domain or not source or at < now - RETENTION_SECONDS or at > now + 5:
            continue
        category = failure.get('error_category', failure.get('kind', 'other'))
        category = category if isinstance(category, str) and category in _ERROR_CATEGORIES else 'other'
        key = _digest(source, domain, failure.get('id', failure.get('event_id', (at, category))))
        if key in state['failure_events']:
            continue
        if len(state['failure_events']) >= MAX_FAILURE_EVENTS:
            # Keep accepting current failures when a busy stream fills the cache.
            # IDs are a bounded duplicate filter, not an exhaustive event history.
            del state['failure_events'][next(iter(state['failure_events']))]
            state['failure_dedup_evictions'] = min(_MAX_COUNTER, state.get('failure_dedup_evictions', 0) + 1)
        record, device = _record(state, domain, source, at, failure=True, reference_now=now)
        if record is None:
            continue
        state['failure_events'][key] = at
        _increment(record, at, failures=1)
        _increment(device, at, failures=1)
        record['failure_times'] = sorted(set(record['failure_times'] + [at]))[-16:]
        if category not in record['error_categories']:
            record['error_categories'].append(category)


def update(state, connections, now, local_addresses, failures=None):
    """Merge an active-connection snapshot; never count baseline cumulative bytes."""
    now = _time(now)
    state = _prune(state, now)
    local_addresses = _locals(local_addresses)
    if now < state.get('updated_at', 0):
        return state
    state['updated_at'] = now
    state['snapshot_count'] = min(_MAX_COUNTER, state['snapshot_count'] + 1)
    rows = connections.get('connections', []) if isinstance(connections, dict) else connections
    rows = rows if isinstance(rows, list) else []
    for connection in rows[:MAX_INPUT_ROWS]:
        if not isinstance(connection, dict) or connection.get('synthetic'):
            continue
        metadata = connection.get('metadata', {})
        if not isinstance(metadata, dict) or metadata.get('synthetic') or metadata.get('origin') in ('control', 'probe', 'synthetic'):
            continue
        if str(metadata.get('inboundName', '')).startswith(('net-gateway-probe', 'maintainer-probe')):
            continue
        domain = hostname(metadata.get('host'))
        source = _source(metadata.get('sourceIP'), local_addresses)
        if not domain or not source:
            continue
        record, device = _record(state, domain, source, now)
        if record is None:
            continue
        for field in ('rule', 'chains'):
            values = connection.get(field, []) if field == 'chains' else [connection.get(field)]
            if not isinstance(values, list):
                continue
            target = record['chains' if field == 'chains' else 'rules']
            for value in values[:4]:
                if isinstance(value, str) and value and value[:128] not in target and len(target) < 4:
                    target.append(value[:128])
        identifier = connection.get('id')
        upload, download = _counter(connection.get('upload')), _counter(connection.get('download'))
        if not isinstance(identifier, (str, int)) or upload is None or download is None:
            continue
        key = _digest(identifier, connection.get('start', ''), domain, source)
        previous = state['connections'].get(key)
        if previous is None and len(state['connections']) >= MAX_CONNECTIONS:
            state['dropped_observations'] += 1
            continue
        up = upload - previous['upload'] if previous and upload >= previous['upload'] else 0
        down = download - previous['download'] if previous and download >= previous['download'] else 0
        _increment(record, now, upload=up, download=down, connections=int(previous is None))
        _increment(device, now, upload=up, download=down, connections=int(previous is None))
        state['connections'][key] = {'domain': domain, 'source': source, 'upload': upload, 'download': download, 'last_seen': now}
    if len(rows) > MAX_INPUT_ROWS:
        state['dropped_observations'] += len(rows) - MAX_INPUT_ROWS
    _failure_update(state, failures, now, local_addresses)
    return state


def record_failures(state, failures, now, local_addresses):
    """Merge sanitized warning events, excluding control/probe or unscoped logs."""
    now = _time(now)
    state = _prune(state, now)
    _failure_update(state, failures, now, _locals(local_addresses))
    state['updated_at'] = max(state.get('updated_at', 0), now)
    return state


def _totals(record, now):
    oldest_hour = int(now // 3600) - 71
    totals = {'upload': 0, 'download': 0, 'connections': 0, 'failures': 0}
    for hour, values in record['hours'].items():
        if oldest_hour <= int(hour) <= int(now // 3600):
            for index, key in enumerate(_HOURLY_COUNTERS):
                totals[key] += values.get(key, 0) if isinstance(values, dict) else values[index]
    return totals


def _domain_summary(domain, record, now):
    totals = _totals(record, now)
    failure_times = _recent_failure_times(record, now)
    recurring = len(failure_times) >= 3 and max(failure_times) - min(failure_times) >= 60
    return {'domain': domain, 'last_seen': record['last_seen'], 'device_count': len(record['devices']),
            'device_addresses': list(record['devices']), 'device_address_limit': 16,
            'observed_upload_bytes': totals['upload'], 'observed_download_bytes': totals['download'],
            'observed_bytes_lower_bound': totals['upload'] + totals['download'],
            'connections_seen': totals['connections'], 'failure_count': totals['failures'],
            'recurring_failure': recurring, 'error_categories': record['error_categories'],
            'rules': record['rules'], 'chains': record['chains']}


def _domains(state, now):
    if not isinstance(state, dict) or state.get('version') != 1:
        return []
    records = [_domain_summary(name, record, now) for name, record in state['domains'].items()
               if now - RETENTION_SECONDS <= record['last_seen'] <= now]
    return sorted(records, key=lambda item: (item['recurring_failure'], item['failure_count'],
                                            item['observed_bytes_lower_bound'], item['last_seen'], item['domain']), reverse=True)


def summary(state, now):
    """Return a small private summary with explicit evidence and coverage limits."""
    now = _time(now)
    domains = _domains(state, now)
    devices = []
    for address, record in state.get('devices', {}).items():
        if not now - RETENTION_SECONDS <= record['last_seen'] <= now:
            continue
        totals = _totals(record, now)
        devices.append({'address': address, 'last_seen': record['last_seen'],
                        'observed_bytes_lower_bound': totals['upload'] + totals['download'],
                        'failure_count': totals['failures']})
    devices.sort(key=lambda item: (item['observed_bytes_lower_bound'], item['last_seen']), reverse=True)
    issues = [{'kind': 'recurring_client_failure', 'domain': item['domain'], 'failure_count': item['failure_count'],
               'error_categories': item['error_categories'], 'action': 'investigate'}
              for item in domains if item['recurring_failure']]
    coverage = {'complete': False, 'gaps': list(_GAPS),
                'snapshot_count': state.get('snapshot_count', 0),
                'dropped_observations': state.get('dropped_observations', 0),
                'failure_dedup_evictions': state.get('failure_dedup_evictions', 0),
                'domain_evictions': state.get('domain_evictions', 0),
                'failure_domain_evictions': state.get('failure_domain_evictions', 0),
                'recurring_issue_evictions': state.get('recurring_issue_evictions', 0),
                'domain_capacity_drops': state.get('domain_capacity_drops', 0)}
    status = 'observed' if domains else 'insufficient_evidence'
    collector = state.get('collector')
    if isinstance(collector, dict):
        last_success = collector.get('last_success_at', collector.get('last_success', 0))
        # Allow the two-minute persistence interval; older files are stale.
        active = bool(last_success and 0 <= now - last_success <= 2 * 120 + 10
                      and not collector.get('snapshot_error_category'))
        coverage.update(last_success=last_success, sampling_active=active,
                        last_success_at=last_success,
                        failure_stream_available=collector.get('stream_available') is True and active,
                        last_stream_event=collector.get('last_stream_event', 0),
                        snapshot_error_category=collector.get('snapshot_error_category'),
                        disk_write_deferred=collector.get('disk_write_deferred', False),
                        failure_events_dropped=collector.get('failure_events_dropped', 0))
        if not active:
            status = 'collection_stale'
    return {'origin': 'mihomo_client_observations', 'scope': 'household_clients', 'retention_hours': 72,
            'status': status, 'coverage': coverage,
            'observed_bytes_lower_bound': sum(item['observed_bytes_lower_bound'] for item in domains),
            'domain_count': len(domains), 'device_count': len(devices),
            'failure_count': sum(item['failure_count'] for item in domains),
            'domains': domains[:16], 'devices': devices[:16], 'issues': issues[:16]}


def candidates(state, now, limit=3):
    """Choose domains seen within six hours, prioritizing repeated client faults."""
    try:
        limit = max(0, min(3, int(limit)))
    except (ValueError, TypeError, OverflowError):
        limit = 3
    now = _time(now)
    return [item['domain'] for item in _domains(state, now) if item['last_seen'] >= now - RECENT_SECONDS][:limit]
