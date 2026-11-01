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


# ---------------------------------------------------------------------------
# route comparison: direct egress vs the Mihomo rule path, per domain.
#
# Evidence layers: direct = this host's own direct egress (not a client
# device); mihomo = https through 192.168.2.4:7890 using the CURRENT rules,
# so a domain ruled DIRECT is tested direct too.  Latency is path evidence
# only, never a bandwidth claim.  Read-only; suggestions need user approval.

PROXY = "http://192.168.2.4:7890"
ROUTE_TIMEOUT = 2.0
MAX_ROUTE_DOMAINS = 5
_TLS = ssl.create_default_context()

ROUTE_DEFAULT_DOMAINS = [
    "www.google.com",
    "www.youtube.com",
    "github.com",
    "chatgpt.com",
    "www.baidu.com",
]

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_SLOW_RATIO = 2.0
_SLOW_DELTA_MS = 300
_SLOW_MIN_MS = 500

_ROUTE_NOTES = [
    "mihomo 侧走 192.168.2.4:7890 的现有规则，不强制指定代理节点；规则为直连的域名实际也测直连。",
    "direct 侧是网关主机自身的直连出口，不是家中手机/电脑的客户端路径。",
    "先核对两条路径的出口 IP：相同说明本机直连也被透明代理接管，此时不比较直连与代理，也不据此判断分流。",
    "时延只用于两条路径的相对比较，不代表带宽上限，也不因单次结果断言根因。",
    "工具只读，不修改策略、规则、节点或凭据；建议需用户确认后才可由策略工具应用。",
]

_EGRESS_URL = "http://ip-api.com/json/?fields=status,query"


def _valid_domain(value):
    if not isinstance(value, str):
        return None
    domain = value.strip().lower()
    if not _DOMAIN_RE.match(domain) or ".." in domain or domain.startswith("-"):
        return None
    return domain


def _fetch_route(domain, use_proxy, timeout=ROUTE_TIMEOUT):
    url = "https://" + domain + "/"
    handlers = [urllib.request.HTTPSHandler(context=_TLS)]
    if use_proxy:
        handlers.append(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    opener = urllib.request.build_opener(*handlers)
    start = time.monotonic()
    try:
        with opener.open(url, timeout=timeout) as response:
            response.read(64)
            status = response.status
        return {
            "ok": True,
            "http_status": status,
            "elapsed_ms": round((time.monotonic() - start) * 1000),
        }
    except urllib.error.HTTPError as error:
        return {
            "ok": True,
            "http_status": error.code,
            "elapsed_ms": round((time.monotonic() - start) * 1000),
        }
    except Exception as error:  # noqa: BLE001 - classify transport failures
        return {
            "ok": False,
            "error": type(error).__name__,
            "elapsed_ms": round((time.monotonic() - start) * 1000),
        }


def classify_route(direct, mihomo):
    """Return (verdict, suggestion) from two normalized probe results."""
    d_ok = direct.get("ok") is True
    m_ok = mihomo.get("ok") is True
    d_ms = direct.get("elapsed_ms")
    m_ms = mihomo.get("elapsed_ms")

    if not d_ok and not m_ok:
        return "both_fail", "insufficient_evidence"
    if not d_ok and m_ok:
        return "needs_proxy", "proxy_domains"
    if d_ok and not m_ok:
        return "rules_path_fails", "investigate"
    if not isinstance(d_ms, (int, float)) or not isinstance(m_ms, (int, float)):
        return "inconclusive", "insufficient_evidence"
    if d_ms < 1 or m_ms < 1:
        return "inconclusive", "insufficient_evidence"
    if m_ms >= _SLOW_MIN_MS and m_ms >= d_ms * _SLOW_RATIO + _SLOW_DELTA_MS:
        return "proxy_slower", "direct_domains"
    return "ok", "keep"


def _route_evidence(direct, mihomo):
    def part(name, result):
        if result.get("ok") is True:
            return "%s %sms/HTTP%s" % (name, result.get("elapsed_ms"), result.get("http_status"))
        return "%s失败(%s)" % (name, result.get("error", "error"))

    return part("直连", direct) + "，" + part("当前规则", mihomo)


def _egress_ip(use_proxy):
    handlers = [urllib.request.HTTPHandler()]
    if use_proxy:
        handlers.append(urllib.request.ProxyHandler({"http": PROXY}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(_EGRESS_URL, timeout=ROUTE_TIMEOUT) as response:
            data = json.loads(response.read(512).decode("utf-8", "replace"))
        return data.get("query") if data.get("status") == "success" else None
    except Exception:  # noqa: BLE001 - identity check is best effort
        return None


def _comparison_allowed(direct_ip, mihomo_ip):
    """Two paths are distinguishable only when both report different exits."""
    return bool(direct_ip and mihomo_ip and direct_ip != mihomo_ip)


def _current_verdict(result):
    return "current_path_ok" if result.get("ok") is True else "current_path_unreachable"


def _probe_current_path(domains):
    """Reachability on the rules path only; makes no direct/proxy claim."""
    observations = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {domain: pool.submit(_fetch_route, domain, True) for domain in domains}
        for domain in domains:
            result = futures[domain].result()
            if result.get("ok") is True:
                evidence = "当前规则 %sms/HTTP%s" % (result.get("elapsed_ms"), result.get("http_status"))
            else:
                evidence = "当前规则失败(%s)" % result.get("error", "error")
            observations.append(
                {
                    "kind": "current_path",
                    "domain": domain,
                    "mihomo": result,
                    "verdict": _current_verdict(result),
                    "suggestion": "investigate" if result.get("ok") is not True else "keep",
                    "evidence": evidence,
                }
            )
    return observations


def _compare_route_domains(domains):
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for domain in domains:
            tasks[(domain, "direct")] = pool.submit(_fetch_route, domain, False)
            tasks[(domain, "mihomo")] = pool.submit(_fetch_route, domain, True)
        results = {}
        for (domain, leg), future in tasks.items():
            results.setdefault(domain, {})[leg] = future.result()

    observations = []
    confirm = []
    for domain in domains:
        direct = results[domain]["direct"]
        mihomo = results[domain]["mihomo"]
        verdict, suggestion = classify_route(direct, mihomo)
        if verdict in ("proxy_slower", "needs_proxy", "rules_path_fails"):
            confirm.append(domain)
        observations.append(
            {
                "kind": "route_compare",
                "domain": domain,
                "direct": direct,
                "mihomo": mihomo,
                "verdict": verdict,
                "suggestion": suggestion,
                "evidence": _route_evidence(direct, mihomo),
            }
        )

    if confirm:
        by_domain = {item["domain"]: item for item in observations}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            checks = {}
            for domain in confirm:
                use_proxy = by_domain[domain]["suggestion"] != "direct_domains"
                checks[domain] = (use_proxy, pool.submit(_fetch_route, domain, use_proxy))
            for domain, (use_proxy, future) in checks.items():
                item = by_domain[domain]
                if use_proxy:
                    item["confirm_mihomo"] = future.result()
                else:
                    item["confirm_direct"] = future.result()

    return observations


def compare_routes(request):
    raw = (request or {}).get("domains")
    if raw is None:
        raw = ROUTE_DEFAULT_DOMAINS
    if not isinstance(raw, list):
        return {"ok": False, "error": "domains_must_be_list"}
    domains = []
    for value in raw[:MAX_ROUTE_DOMAINS]:
        domain = _valid_domain(value)
        if domain is None:
            return {"ok": False, "error": "invalid_domain", "value": str(value)[:64]}
        if domain not in domains:
            domains.append(domain)
    if not domains:
        return {"ok": False, "error": "no_domains"}

    direct_ip = _egress_ip(False)
    mihomo_ip = _egress_ip(True)
    egress = {"direct": direct_ip, "mihomo": mihomo_ip}
    if not _comparison_allowed(direct_ip, mihomo_ip):
        if direct_ip is None or mihomo_ip is None:
            reason = "外网出口身份获取失败"
        else:
            reason = "本机直连与代理走同一出口，没有独立直连基线"
        observations = _probe_current_path(domains)
        alerts = [item for item in observations if item["verdict"] == "current_path_unreachable"]
        summary = "%s；仅检查当前规则路径：%d个域名中%d个不可达" % (reason, len(observations), len(alerts))
        return {
            "ok": True,
            "operation": "compare_routes",
            "read_only": True,
            "domains": domains,
            "comparison_valid": False,
            "egress": {**egress, "reason": reason},
            "observations": observations,
            "alerts": [
                {
                    "domain": item["domain"],
                    "verdict": item["verdict"],
                    "suggestion": item["suggestion"],
                    "evidence": item["evidence"],
                }
                for item in alerts
            ],
            "summary": summary,
            "notes": list(_ROUTE_NOTES),
        }

    observations = _compare_route_domains(domains)
    alerts = [item for item in observations if item["verdict"] != "ok"]
    if not alerts:
        summary = "已比较%d个域名的直连与当前规则路径，未发现明显错配" % len(observations)
    else:
        parts = ["%s:%s" % (item["domain"], item["verdict"]) for item in alerts]
        summary = "发现%d个待关注项（%s）" % (len(alerts), "、".join(parts))

    return {
        "ok": True,
        "operation": "compare_routes",
        "read_only": True,
        "domains": domains,
        "comparison_valid": True,
        "egress": egress,
        "observations": observations,
        "alerts": [
            {
                "domain": item["domain"],
                "verdict": item["verdict"],
                "suggestion": item["suggestion"],
                "evidence": item["evidence"],
            }
            for item in alerts
        ],
        "summary": summary,
        "notes": list(_ROUTE_NOTES),
    }


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

    ok = {"ok": True, "http_status": 200, "elapsed_ms": 100}
    slow = {"ok": True, "http_status": 200, "elapsed_ms": 900}
    fast = {"ok": True, "http_status": 200, "elapsed_ms": 120}
    fail = {"ok": False, "error": "TimeoutError", "elapsed_ms": 2000}
    expect(classify_route(ok, slow) == ("proxy_slower", "direct_domains"), "slow proxy must be flagged")
    expect(classify_route(fast, {"ok": True, "http_status": 200, "elapsed_ms": 260}) == ("ok", "keep"), "small delta must stay ok")
    expect(classify_route(fail, ok) == ("needs_proxy", "proxy_domains"), "direct failure with working mihomo needs proxy")
    expect(classify_route(ok, fail) == ("rules_path_fails", "investigate"), "mihomo failure with direct works needs investigation")
    expect(classify_route(fail, fail) == ("both_fail", "insufficient_evidence"), "both failing must not guess")
    expect(classify_route({"ok": True}, {"ok": True}) == ("inconclusive", "insufficient_evidence"), "missing latency is inconclusive")
    expect(classify_route({"ok": True, "elapsed_ms": 0}, ok) == ("inconclusive", "insufficient_evidence"), "zero latency is inconclusive")
    boundary = {"ok": True, "http_status": 200, "elapsed_ms": 200}
    expect(classify_route(boundary, {"ok": True, "http_status": 200, "elapsed_ms": 700})[0] == "proxy_slower", "ratio+delta boundary must flag")
    expect(classify_route(boundary, {"ok": True, "http_status": 200, "elapsed_ms": 699})[0] == "ok", "just below boundary must stay ok")
    expect(_valid_domain("www.google.com") == "www.google.com", "plain domain must validate")
    expect(_valid_domain("https://www.google.com") is None, "url must not validate")
    expect(_valid_domain("user:pass@example.com") is None, "credential-like value must not validate")
    expect(_valid_domain("a..b") is None, "empty label must not validate")
    expect(_valid_domain(None) is None, "non-string must not validate")
    expect("secret" not in json.dumps(_ROUTE_NOTES).lower(), "route notes must not mention credentials")
    expect(_comparison_allowed("1.1.1.1", "2.2.2.2") is True, "different exits allow comparison")
    expect(_comparison_allowed("1.1.1.1", "1.1.1.1") is False, "same exit must block comparison")
    expect(_comparison_allowed(None, "1.1.1.1") is False, "missing exit must block comparison")
    expect(_current_verdict({"ok": True, "http_status": 204}) == "current_path_ok", "reachable current path must be ok")
    expect(_current_verdict({"ok": False, "error": "TimeoutError"}) == "current_path_unreachable", "failed current path must be flagged")

    if failures:
        return {"ok": False, "assertions": checks, "failures": failures}

    return {
        "ok": True,
        "assertions": checks,
        "capabilities": {
            "self_test": "真实断言覆盖已连接、断连、字段缺失的 iw link 输出，并校验标识不泄露；另覆盖路由比较分类、阈值边界与域名校验。",
            "inspect": "只读读取无线连接状态、信号 dBm、收发协商速率与频点；不测速、不以信号推断吞吐上限。",
            "route_compare": "先核对直连与代理出口；仅当出口不同才对最多5个域名比较路径并复测可疑项；出口相同或未知时明确报告无法区分，不做分流结论。",
        },
    }


def run(request):
    operation = (request or {}).get("operation", "inspect")
    if operation == "self_test":
        return self_test()
    if operation == "compare_routes":
        return compare_routes(request)
    if operation == "inspect":
        if (request or {}).get("mode") == "routes":
            return compare_routes(request)
        target = (request or {}).get("interface")
        return inspect_wireless(target)
    return {
        "ok": False,
        "error": "unknown_operation",
        "operations": ["self_test", "inspect", "compare_routes"],
    }
