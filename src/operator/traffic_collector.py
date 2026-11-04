#!/usr/bin/env python3
"""Small root-only Mihomo observer; no AI calls, routing writes or raw log history."""
from collections import deque
from datetime import datetime,timezone,timedelta
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import select
import socket
import stat
import tempfile
import threading
import time
import urllib.request

from bounded import run
import traffic


STATE = Path('/var/lib/net-gateway-agent/traffic.json')
CONFIG = Path('/etc/net-gateway/config.json')
POLL_SECONDS = 2
PERSIST_SECONDS = 120
MAX_STATE_BYTES = 2 * 1024 ** 2
MAX_RESPONSE_BYTES = 4 * 1024 ** 2
MAX_LOG_BYTES = 8192
MIN_FREE_BYTES = 4 * 1024 ** 3
_HOUSEHOLD_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                            ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
_DIAL_ERROR = re.compile(r'\[(?P<network>TCP|UDP)\].*?\bdial\b.*?'
                         r'(?P<source>\[[0-9a-fA-F:]+\]|[0-9.]+):[0-9]{1,5}\s+-->\s+'
                         r'(?P<domain>[A-Za-z0-9._-]{1,254}):(?P<port>[0-9]{1,5})\s+error:\s*(?P<error>.*)')


def _household(value):
    try:
        address = ipaddress.ip_address(str(value).strip('[]'))
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address) if any(address.version == network.version and address in network for network in _HOUSEHOLD_NETWORKS) else None
    except ValueError:
        return None


def parse_warning(event, now, local_addresses):
    """Extract a client dial failure; discard all message text immediately.

    Some Mihomo versions omit event timestamps. Those events deduplicate by a
    minute bucket, giving only a conservative lower bound on repeated failures.
    """
    if local_addresses is None:
        return None
    if isinstance(event, str):
        if len(event.encode('utf-8')) > MAX_LOG_BYTES:
            return None
        try:
            event = json.loads(event)
        except ValueError:
            return None
    if not isinstance(event, dict) or event.get('type', event.get('level')) not in ('warning', 'warn', 'error'):
        return None
    payload = event.get('payload', event.get('message'))
    if not isinstance(payload, str) or len(payload.encode('utf-8')) > MAX_LOG_BYTES:
        return None
    match = _DIAL_ERROR.search(payload)
    if not match:
        return None
    source = _household(match['source'])
    domain = traffic.hostname(match['domain'])
    if not source or not domain or source in local_addresses:
        return None
    error = match['error'].lower()
    category = 'other'
    for name, fragments in (('timeout', ('timeout', 'timed out', 'deadline')),
                            ('dns', ('no such host', 'dns', 'name resolution')),
                            ('refused', ('refused',)), ('reset', ('reset', 'broken pipe')),
                            ('tls', ('tls', 'certificate', 'handshake')),
                            ('unreachable', ('unreachable', 'no route'))):
        if any(fragment in error for fragment in fragments):
            category = name
            break
    timestamp = event.get('time', event.get('timestamp'))
    timestamp = str(timestamp)[:128] if isinstance(timestamp, (str, int, float)) else str(int(now // 60))
    if re.fullmatch(r'\d{2}:\d{2}:\d{2}',timestamp):timestamp=time.strftime('%Y-%m-%d',time.gmtime(now+8*3600))+'T'+timestamp
    identifier = hashlib.sha256((timestamp + '\0' + payload).encode()).hexdigest()[:32]
    route=re.search(r'\bdial\s+(DIRECT|PROXY|US_AUTO|OTHER_AUTO)\s+\(match',payload)
    path='direct' if route and route[1]=='DIRECT' else 'proxy' if route else 'unknown'
    port=int(match['port'])
    if not 1<=port<=65535:return None
    result={'domain': domain, 'sourceIP': source, 'error_category': category,
            'origin': 'client', 'id': identifier, 'at': now,'network':match['network'].lower(),
            'port':port,'path':path,'application_protocol':'unknown'}
    raw=event.get('time',event.get('timestamp'))
    try:
        if isinstance(raw,str):
            instant=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
            if instant.tzinfo is None:instant=instant.replace(tzinfo=timezone(timedelta(hours=8)))
            result['event_at']=instant.timestamp()
        elif type(raw) in (int,float):result['event_at']=raw/1000 if raw>1e11 else raw
    except (ValueError,OverflowError):pass
    return result


def interface_addresses(payload):
    """Read the Pi's interface addresses, never neighbors or client identities."""
    addresses = {'127.0.0.1', '::1'}
    if not isinstance(payload, list):
        return addresses
    for interface in payload[:128]:
        if not isinstance(interface, dict):
            continue
        for info in interface.get('addr_info', [])[:128]:
            try:
                addresses.add(str(ipaddress.ip_address(info['local'])))
            except (TypeError, KeyError, ValueError):
                continue
    return addresses


def discover_local_addresses():
    result = run(['ip', '-j', 'address', 'show'], timeout=5, stdout_limit=262144, stderr_limit=8192)
    addresses = interface_addresses(json.loads(result.stdout))
    if len(addresses) <= 2:
        raise ValueError('local interface discovery unavailable')
    return addresses


def _load(path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES:
            return {}
        value = json.loads(path.read_text())
        if value.get('version') != 1 or any(not isinstance(value.get(name), dict) for name in ('domains', 'devices', 'connections', 'failure_events')):
            return {}
        # Prune old data on restart before accepting another snapshot.
        traffic.summary(value, time.time())
        return value
    except (OSError, ValueError, TypeError, AttributeError, KeyError, IndexError):
        return {}


def cleanup_stale_temporaries(path, now):
    """Remove only old regular files from this collector's atomic-write prefix."""
    try:
        for index, temporary in enumerate(path.parent.glob('.' + path.name + '.*')):
            if index >= 128:
                break
            info = temporary.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and now - info.st_mtime > 600:
                temporary.unlink(missing_ok=True)
    except OSError:
        pass


class Collector:
    def __init__(self, path=STATE, local_addresses=None, disk_usage=shutil.disk_usage):
        self.path = Path(path)
        cleanup_stale_temporaries(self.path, time.time())
        self.local_addresses = local_addresses
        self.disk_usage = disk_usage
        self.state = _load(self.path)
        self.metadata = self.state.setdefault('collector', {})
        self.metadata.update(poll_seconds=POLL_SECONDS, persist_seconds=PERSIST_SECONDS,
                             stream_available=False, disk_write_deferred=False)
        self.last_persist_attempt = None
        self.last_payload = None
        self.events = deque(maxlen=512)
        self.stream = {'stream_available': False, 'last_stream_event': 0, 'failure_events_dropped': 0}
        self.lock = threading.Lock()

    def observe(self, connections, now):
        if self.local_addresses is None:
            self.snapshot_failed(now, 'local_addresses_unavailable')
            return
        if not isinstance(connections, dict) or not isinstance(connections.get('connections'), list):
            raise ValueError('invalid controller snapshot')
        rows = connections['connections']
        rows = [row for row in rows[:traffic.MAX_INPUT_ROWS] if isinstance(row, dict)
                and isinstance(row.get('metadata'), dict) and _household(row['metadata'].get('sourceIP'))]
        with self.lock:
            events = list(self.events)
            self.events.clear()
            self.metadata.update(self.stream)
        self.state = traffic.update(self.state, rows, now, self.local_addresses, failures=events)
        self.state['collector'] = self.metadata
        self.metadata.update(last_success=now, last_success_at=now, last_snapshot_attempt=now, snapshot_error_category=None)

    def snapshot_failed(self, now, category='unavailable'):
        self.metadata.update(last_snapshot_attempt=now, snapshot_error_category=category)
        # A snapshot outage does not prevent collecting trustworthy warning events.
        with self.lock:
            events = list(self.events)
            self.events.clear()
            self.metadata.update(self.stream)
        if events and self.local_addresses is not None:
            self.state = traffic.record_failures(self.state, events, now, self.local_addresses)
        self.state['collector'] = self.metadata

    def warning(self, event, now):
        failure = parse_warning(event, now, self.local_addresses)
        if failure is None:
            return
        with self.lock:
            if len(self.events) == self.events.maxlen:
                self.stream['failure_events_dropped'] += 1
            self.events.append(failure)
            self.stream['last_stream_event'] = now

    def persist(self, now):
        if self.last_persist_attempt is not None and now - self.last_persist_attempt < PERSIST_SECONDS:
            return False
        self.last_persist_attempt = now
        try:
            if self.disk_usage(self.path.parent).free < MIN_FREE_BYTES:
                self.metadata['disk_write_deferred'] = True
                return False
            self.metadata['disk_write_deferred'] = False
            self.metadata.pop('persist_error_category', None)
            payload = json.dumps(self.state, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
            if len(payload) > MAX_STATE_BYTES:
                self.metadata['disk_write_deferred'] = True
                self.metadata['persist_error_category'] = 'state_byte_budget'
                return False
            if payload == self.last_payload:
                return False
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(prefix='.' + self.path.name + '.', dir=self.path.parent, delete=False) as target:
                    temporary = Path(target.name)
                    os.fchmod(target.fileno(), 0o600)
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
                temporary.replace(self.path)
                descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self.last_payload = payload
                return True
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError):
            self.metadata['disk_write_deferred'] = True
            return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def controller_request(path, timeout=5):
    if CONFIG.stat().st_size > MAX_RESPONSE_BYTES:
        raise ValueError('controller configuration budget')
    config = json.loads(CONFIG.read_text())
    secret = config.get('secret')
    if not isinstance(secret, str) or not 0 < len(secret) <= 512:
        raise ValueError('controller authentication unavailable')
    request = urllib.request.Request('http://127.0.0.1:9090' + path,
                                     headers={'Authorization': 'Bearer ' + secret, 'Accept': 'application/json'})
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open(request, timeout=timeout)


def _exact(stream,count):
    result=b''
    while len(result)<count:
        chunk=stream.read(count-len(result))
        if not chunk:raise ValueError('truncated local log frame')
        result+=chunk
    return result


def read_log_frame(stream):
    first,second=_exact(stream,2)
    if not first&128 or second&128:raise ValueError('unsupported local log frame')
    size=second&127
    if size==126:size=int.from_bytes(_exact(stream,2),'big')
    elif size==127:size=int.from_bytes(_exact(stream,8),'big')
    opcode=first&15
    if size>MAX_LOG_BYTES or opcode not in [1,8,9,10]:raise ValueError('local log frame exceeds contract')
    if opcode in [8,9,10] and size>125:raise ValueError('invalid local control frame')
    return opcode,_exact(stream,size)


def _log_worker(collector, stop):
    while not stop.is_set():
        try:
            # HTTP streaming does not flush quiet response headers. A native
            # WebSocket completes immediately and remains subscribed when idle.
            config=json.loads(CONFIG.read_text());secret=config['secret']
            if not isinstance(secret,str) or not 0<len(secret)<=512 or '\r' in secret or '\n' in secret:raise ValueError('controller credential unavailable')
            key=base64.b64encode(os.urandom(16)).decode()
            with socket.create_connection(('127.0.0.1',9090),timeout=5) as connection,connection.makefile('rb',buffering=0) as stream:
                request=('GET /logs?level=warning&format=structured HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\nAuthorization: Bearer '+secret+'\r\n\r\n').encode()
                connection.sendall(request)
                status=stream.readline(4097);headers={};total=len(status)
                while True:
                    line=stream.readline(4097);total+=len(line)
                    if not line or total>8192:raise ValueError('local upgrade headers exceed contract')
                    if line==b'\r\n':break
                    name,value=line.decode('ascii').split(':',1);headers[name.lower()]=value.strip()
                accepted=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                if not status.startswith(b'HTTP/1.1 101 ') or headers.get('sec-websocket-accept')!=accepted:raise ValueError('local warning upgrade rejected')
                with collector.lock:
                    collector.stream['stream_available'] = True
                while not stop.is_set():
                    if not select.select([connection],[],[],1)[0]:continue
                    opcode,payload=read_log_frame(stream)
                    if opcode==8:break
                    if opcode==9:
                        mask=os.urandom(4);connection.sendall(bytes([138,128|len(payload)])+mask+bytes(value^mask[index%4] for index,value in enumerate(payload)))
                    if opcode==1:collector.warning(payload.decode('utf-8',errors='replace'),time.time())
        except Exception:
            pass  # Never print controller errors: they can embed authentication data.
        finally:
            with collector.lock:
                collector.stream['stream_available'] = False
        stop.wait(10)


def main():
    collector = Collector()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    signal.signal(signal.SIGINT, lambda signum, frame: stop.set())
    threading.Thread(target=_log_worker, args=(collector, stop), daemon=True, name='client-warning-observer').start()
    address_refresh = 0
    while not stop.is_set():
        started = time.monotonic()
        now = time.time()
        if now >= address_refresh:
            try:
                collector.local_addresses = discover_local_addresses()
                address_refresh = now + 300
            except Exception:
                collector.local_addresses = None
                address_refresh = now + 10
        interval = POLL_SECONDS
        try:
            if collector.local_addresses is None:
                raise ValueError('local interface discovery unavailable')
            with controller_request('/connections') as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ValueError('snapshot response budget')
            collector.observe(json.loads(payload), now)
        except Exception:
            collector.snapshot_failed(now)
            interval = 10
        collector.persist(now)
        stop.wait(max(0, interval - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
