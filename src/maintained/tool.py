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

import json
import os
import re
import shutil
import subprocess

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

NORMAL_FIXTURE = """Connected to 8c:5a:c1:f9:53:80 (on wlan0)
\tSSID: CMCC-2xTD
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

PARTIAL_FIXTURE = """Connected to 8c:5a:c1:f9:53:80 (on wlan0)
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


def self_test():
    failures = []
    checks = 0

    def expect(condition, message):
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(message)

    link = parse_iw_link(NORMAL_FIXTURE)
    expect(link["state"] == "connected", "normal output must parse as connected")
    expect(link["interface"] == "wlan0", "normal output must report interface")
    expect(link["signal_dbm"] == -72, "normal output must keep signal dBm")
    expect(link["rx_bitrate_mbps"] == 175.5, "normal output must keep rx bitrate")
    expect(link["tx_bitrate_mbps"] == 195.0, "normal output must keep tx bitrate")
    expect(link["frequency_mhz"] == 5220.0, "normal output must keep frequency")
    expect("missing_fields" not in link, "complete output must not report gaps")

    leaked = json.dumps(link).lower()
    expect("cmcc-2xtd" not in leaked, "SSID must not appear in observation")
    expect("8c:5a:c1:f9:53:80" not in leaked, "BSSID must not appear in observation")
    expect('"ssid"' not in leaked and '"bssid"' not in leaked, "identifier keys must be absent")
    expect("throughput" not in leaked and "bandwidth" not in leaked, "observation must not claim throughput")

    down = parse_iw_link(DISCONNECTED_FIXTURE)
    expect(down["state"] == "disconnected", "disconnected output must parse as disconnected")
    expect("signal_dbm" not in down, "disconnected output must not invent signal")
    expect("ssid" not in json.dumps(down).lower(), "disconnected output must not leak identifiers")

    partial = parse_iw_link(PARTIAL_FIXTURE)
    expect(partial["state"] == "connected", "partial output must still parse as connected")
    expect(partial["signal_dbm"] is None, "absent signal must stay None, not guessed")
    expect(partial["rx_bitrate_mbps"] is None, "absent rx bitrate must stay None")
    expect(partial["tx_bitrate_mbps"] is None, "absent tx bitrate must stay None")
    expect("signal_dbm" in partial.get("missing_fields", []), "partial output must report missing signal")
    expect("rx_bitrate_mbps" in partial.get("missing_fields", []), "partial output must report missing rates")
    expect("8c:5a:c1:f9:53:80" not in json.dumps(partial), "partial output must not leak BSSID")

    if failures:
        return {"ok": False, "assertions": checks, "failures": failures}

    return {
        "ok": True,
        "assertions": checks,
        "capabilities": {
            "self_test": "真实断言覆盖已连接、断连、字段缺失的 iw link 输出，并校验标识不泄露",
            "inspect": "只读读取无线连接状态、信号 dBm、收发协商速率与频点；不测速、不以信号推断吞吐上限",
        },
    }


def run(request):
    operation = (request or {}).get("operation", "inspect")
    if operation == "self_test":
        return self_test()
    if operation == "inspect":
        target = (request or {}).get("interface")
        return inspect_wireless(target)
    return {
        "ok": False,
        "error": "unknown_operation",
        "operations": ["self_test", "inspect"],
    }
