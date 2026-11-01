"""Read-only observation of the gateway's own wireless link.

This module exists because earlier diagnostics conflated the maintainer's
independent control path with the household business path, and because the
existing toolset had no wireless-link observation.  It reads link-layer
state only: connection state, signal in dBm and negotiated rx/tx bitrates.

Design rules:
  * never perform speed tests or downloads;
  * never emit SSID or BSSID (household identifiers are dropped during
    parsing, even though ``iw`` output contains them);
  * never turn signal strength into a throughput-ceiling claim.  Signal and
    negotiated rates are link-layer facts, not measured throughput.

``run({"operation": "self_test"})`` runs real assertions against realistic
``iw dev <if> link`` fixtures.  ``run({"operation": "inspect"})`` performs a
bounded, read-only query and returns an ``observations`` list.
"""

import concurrent.futures
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request

_IW_CANDIDATES = ("/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "/bin/iw")

_CONNECTED_RE = re.compile(r"^\s*Connected to .*?\(on (\S+)\)", re.M)
_DISCONNECTED_RE = re.compile(r"^\s*Not connected\.?\s*$", re.M)
_SIGNAL_RE = re.compile(r"^\s*signal:\s*(-?\d+)\s*dBm", re.M)
_RX_RE = re.compile(r"^\s*rx bitrate:\s*([\d.]+)\s*MBit/s", re.M)
_TX_RE = re.compile(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", re.M)
_FREQ_RE = re.compile(r"^\s*freq:\s*([\d.]+)", re.M)

_NOTES = [
    "链路层只读观测，未做下载测速，不代表吞吐上限。",
    "本工具在隔离工作进程内只读观测链路，未执行代理或直连测速。",
    "输出已移除网络标识与接入点标识。",
]

NORMAL_FIXTURE = """Connected to 02:00:00:00:00:01 (on wlan0)
\tSSID: ExampleNetwork
\tfreq: 5220.0
\tRX: 161510122 bytes (221076 packets)
\tTX: 158743850 bytes (221850 packets)
\tsignal: -72 dBm
\trx bitrate: 175.5 MBit/s
\ttx bitrate: 195.0 MBit/s
\tbss flags: short-preamble short-slot-time
\tdtim period: 1
\tbeacon int: 100
"""

DISCONNECTED_FIXTURE = "Not connected.\n"

PARTIAL_FIXTURE = """Connected to 02:00:00:00:00:01 (on wlan0)
\tSSID: lab-net
\tfreq: 2412.0
"""


def _number(regex, raw, cast=float):
    match = regex.search(raw)
    return cast(match.group(1)) if match else None


def parse_iw_link(text, interface=None):
    """Parse ``iw dev <if> link`` text into a redacted observation dict."""
    raw = text or ""
    connected = _CONNECTED_RE.search(raw)
    if interface is None and connected:
        interface = connected.group(1)

    if _DISCONNECTED_RE.search(raw):
        return {"kind": "wireless_link", "interface": interface, "state": "disconnected"}

    if connected:
        observation = {
            "kind": "wireless_link",
            "interface": interface,
            "state": "connected",
            "signal_dbm": _number(_SIGNAL_RE, raw, int),
            "rx_bitrate_mbps": _number(_RX_RE, raw),
            "tx_bitrate_mbps": _number(_TX_RE, raw),
            "frequency_mhz": _number(_FREQ_RE, raw),
        }
        missing = [
            name
            for name in ("signal_dbm", "rx_bitrate_mbps", "tx_bitrate_mbps", "frequency_mhz")
            if observation[name] is None
        ]
        if missing:
            observation["missing_fields"] = missing
        return observation

    return {
        "kind": "wireless_link",
        "interface": interface,
        "state": "unknown",
        "missing_fields": ["state"],
    }


def _iw_path():
    for path in _IW_CANDIDATES:
        if os.access(path, os.X_OK):
            return path
    return shutil.which("iw")


def _wireless_interfaces():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    found = []
    for name in names:
        if name == "lo":
            continue
        if os.path.isdir(os.path.join("/sys/class/net", name, "wireless")):
            found.append(name)
    return found


def _result(ok, observations, error=None):
    result = {
        "ok": ok,
        "operation": "inspect",
        "read_only": True,
        "observations": observations,
        "notes": list(_NOTES),
    }
    if error:
        result["error"] = error
    return result


def inspect_wireless(interface=None):
    iw = _iw_path()
    if not iw:
        return _result(
            False,
            [{"kind": "wireless_link", "state": "unavailable", "error": "iw_not_available"}],
            "iw_not_available",
        )

    interfaces = [interface] if interface else _wireless_interfaces()
    if not interfaces:
        return _result(
            False,
            [{"kind": "wireless_link", "state": "unavailable", "error": "no_wireless_interface"}],
            "no_wireless_interface",
        )
    target = interfaces[0]

    try:
        proc = subprocess.run(
            [iw, "dev", target, "link"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _result(
            False,
            [{"kind": "wireless_link", "interface": target, "state": "unavailable", "error": type(exc).__name__}],
            "iw_query_failed",
        )

    if proc.returncode != 0:
        return _result(
            False,
            [
                {
                    "kind": "wireless_link",
                    "interface": target,
                    "state": "unavailable",
                    "error": "iw_exit_%d" % proc.returncode,
                }
            ],
            "iw_query_failed",
        )

    return _result(True, [parse_iw_link(proc.stdout, target)])


# Protected root probes own path identity, DNS pinning and content checks.
# Tool candidates never read proxy credentials or infer routing from exit IPs.
import socket


def _protected_compare(domain):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(40)
        connection.connect('/run/net-gateway-agent/control.sock')
        connection.sendall(json.dumps({'operation':'probe_compare','target':domain}).encode()+b'\n')
        response=json.loads(connection.makefile('rb').readline(131073))
    if response.get('ok') is not True:
        return {'target':domain,'state':'probe_unavailable','reason':'protected comparison unavailable; not a healthy result'}
    return response['result']


def _valid_target(domain):
    return isinstance(domain,str) and len(domain)<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain) is not None


def compare_routes(request):
    domains=request.get('domains')
    if not isinstance(domains,list) or not 1<=len(domains)<=2 or not all(_valid_target(x) for x in domains):
        return {'ok':False,'observations':[],'reason':'provide one or two real observed public domain names'}
    observations=[]
    for domain in domains:
        try:observations.append(_protected_compare(domain))
        except Exception:observations.append({'target':domain,'state':'probe_unavailable'})
    verified=all(x.get('path_identity_verified') is True for x in observations)
    acceptance=verified and all(any(v.get('usable') is True for v in x.get('paths',{}).values()) for x in observations)
    return {'ok':True,'operation':'compare_routes','origin':'synthetic_probe','observations':observations,
            'path_identity_verified':verified,'acceptance_ok':acceptance,'policy_changed':False,
            'scope':'protected HTTPS root comparisons; not real client application sessions',
            'summary':'comparison evidence collected' if verified else 'comparison unavailable; task remains unverified'}


def self_test():
    assert parse_iw_link(NORMAL_FIXTURE,'wlan0')['state']=='connected'
    assert parse_iw_link(DISCONNECTED_FIXTURE,'wlan0')['state']=='disconnected'
    observed=parse_iw_link(NORMAL_FIXTURE,'wlan0')
    assert 'SSID' not in json.dumps(observed) and '02:00:00' not in json.dumps(observed)
    assert _valid_target('www.baidu.com')
    assert not _valid_target('https://example.com/private?key=value')
    assert compare_routes({'domains':[]})['ok'] is False
    return {'ok':True,'capabilities':{'inspect':'read-only wireless link observations','compare_routes':'protected direct versus concrete proxy comparison with layered application evidence'},
            'acceptance_cases':[{'request':{'operation':'inspect'},'expect':{'read_only':True}},
                                {'request':{'operation':'compare_routes','domains':['www.baidu.com']},'expect':{'acceptance_ok':True}}]}


def run(request):
    operation=(request or {}).get('operation','inspect')
    if operation=='self_test':return self_test()
    if operation=='inspect':return inspect_wireless((request or {}).get('interface'))
    if operation=='compare_routes':return compare_routes(request)
    return {'ok':False,'observations':[],'reason':'unknown operation'}
