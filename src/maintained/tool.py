"""Explain and measure endpoint reachability from the maintainer control path.

Why this exists: the protected business probe sometimes records
``{"state": "probe_unavailable", "error_category": "ValueError"}`` for the very
domains real clients keep failing on (e.g. apd-pcdnwxstat.teg.tencent-cloud.net,
a.v.smtcdns.com).  That single token cannot tell apart three very different
situations:

  * the name does not resolve at all (DNS / retired endpoint),
  * the name resolves to more than the probe transport's 16-answer cap,
  * the name resolves and the endpoint is simply unreachable from this WAN.

Without that split the same "unresolved" ticket can be re-read as "client link
fault" or as "probe bug" for days.  This tool resolves the name, reports the
answer set composition, states whether the protected probe would refuse it, and
then tries a bounded TCP + TLS handshake to at most three addresses.

Evidence boundaries (never collapse them):
  * this runs on the maintainer control path (independent UID route, no Mihomo
    data plane).  It is NOT a household client path and NOT the proxy path.
  * a failed handshake here means "unreachable from this WAN egress", never
    "unreachable everywhere".
  * a successful handshake is transport evidence only: an application can still
    reject the request (401/403/404 are business answers, not link failures).
  * latency here is path evidence, never a bandwidth claim.

The tool is read-only: no policy, rule, node, credential or engine changes.
``run({"operation": "self_test"})`` asserts the classifiers on synthetic input.
``run({"operation": "inspect", "domains": [...]})`` performs at most 5 domains
and 3 addresses each, with a 2 s per-attempt budget.
"""

import ipaddress
import re
import socket
import ssl
import time

TIMEOUT = 2.0
MAX_DOMAINS = 5
MAX_ADDRESSES = 3
# Mirrors the protected probe transport's own bound: more answers than this and
# the probe refuses the target before any packet is sent.
PROBE_ANSWER_CAP = 16
ALLOWED_PORTS = (443,)
DEFAULT_DOMAINS = ["www.baidu.com"]
_NAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_TLS = ssl.create_default_context()


def _valid_domain(value):
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    if "://" in name or "/" in name or "@" in name or ":" in name:
        return None
    if _NAME.match(name) is None:
        return None
    return name


def _pick_addresses(addresses):
    """Keep global addresses only, deterministically ordered and bounded."""
    kept = []
    dropped = []
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            dropped.append(raw)
            continue
        if not address.is_global:
            dropped.append(str(address))
            continue
        if str(address) not in kept:
            kept.append(str(address))
    return sorted(kept)[:MAX_ADDRESSES], sorted(set(dropped))


def _resolve(domain):
    """Return (addresses, detail). detail tells DNS failure apart from empty."""
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        return [], {"dns_state": "unresolved", "dns_error": error.errno}
    except Exception as error:  # pragma: no cover - defensive
        return [], {"dns_state": "unresolved", "dns_error": type(error).__name__}
    seen = []
    for info in infos:
        host = info[4][0]
        if host not in seen:
            seen.append(host)
    if not seen:
        return [], {"dns_state": "empty"}
    return seen, {"dns_state": "resolved"}


def _handshake(address, domain, port):
    """Bounded TCP connect plus TLS handshake with SNI; never raises."""
    started = time.monotonic()
    try:
        raw = socket.create_connection((address, port), timeout=TIMEOUT)
    except Exception as error:
        return {"address": address, "tcp_ok": False, "tcp_ms": None,
                "tls_ok": False, "tls_ms": None, "error": type(error).__name__}
    tcp_ms = round((time.monotonic() - started) * 1000.0, 1)
    try:
        with _TLS.wrap_socket(raw, server_hostname=domain) as tls:
            tls_ms = round((time.monotonic() - started) * 1000.0, 1)
            return {"address": address, "tcp_ok": True, "tcp_ms": tcp_ms,
                    "tls_ok": bool(tls.session), "tls_ms": tls_ms, "error": None}
    except Exception as error:
        return {"address": address, "tcp_ok": True, "tcp_ms": tcp_ms,
                "tls_ok": False, "tls_ms": None, "error": type(error).__name__}
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _summarize(resolution, picked, samples):
    """Turn the raw facts into one stable verdict plus an explicit cause."""
    if resolution.get("dns_state") == "unresolved":
        return "dns_unresolved"
    if resolution.get("dns_state") == "empty" or not picked:
        return "no_public_address"
    if not samples:
        return "not_measured"
    if any(item.get("tcp_ok") for item in samples):
        return "tcp_reachable"
    return "endpoint_unreachable_from_control_path"


def _probe_refusal(resolution, answer_count):
    """Why the protected probe would answer probe_unavailable/ValueError."""
    if resolution.get("dns_state") != "resolved":
        return resolution.get("dns_state")
    if answer_count > PROBE_ANSWER_CAP:
        return "answer_cap_exceeded"
    return None


def inspect_endpoint(request):
    request = request if isinstance(request, dict) else {}
    raw = request.get("domains")
    if raw is None:
        raw = list(DEFAULT_DOMAINS)
    if not isinstance(raw, list) or not raw:
        return {"ok": False, "error": "domains_required", "observations": []}
    domains = []
    for item in raw:
        name = _valid_domain(item)
        if name is None:
            return {"ok": False, "error": "invalid_domain", "value": str(item)[:120], "observations": []}
        if name not in domains:
            domains.append(name)
    if len(domains) > MAX_DOMAINS:
        return {"ok": False, "error": "too_many_domains", "limit": MAX_DOMAINS, "observations": []}

    observations = []
    for domain in domains:
        addresses, resolution = _resolve(domain)
        picked, dropped = _pick_addresses(addresses)
        samples = [_handshake(address, domain, 443) for address in picked]
        verdict = _summarize(resolution, picked, samples)
        refusal = _probe_refusal(resolution, len(addresses))
        if verdict == "dns_unresolved":
            note = "name does not resolve here; the protected probe cannot measure it either"
        elif verdict == "no_public_address":
            note = "no global unicast address to test; probe input would be rejected"
        elif verdict == "tcp_reachable":
            note = "transport reaches the endpoint from the control path; application answers are separate evidence"
        elif verdict == "endpoint_unreachable_from_control_path":
            note = "no handshake from this WAN egress; says nothing about other networks or the proxy path"
        else:
            note = "not measured"
        if refusal == "answer_cap_exceeded":
            note = note + "; answer set exceeds the probe transport cap of %d" % PROBE_ANSWER_CAP
        observations.append({
            "domain": domain,
            "verdict": verdict,
            "note": note,
            "answer_count": len(addresses),
            "probe_refusal": refusal,
            "probe_answer_cap": PROBE_ANSWER_CAP,
            "tested": samples,
            "dropped_addresses": dropped,
            "route": "maintainer control path (independent UID route, no Mihomo data plane)",
            "scope": "TCP/TLS handshake only; not a client application session",
        })

    return {
        "ok": True,
        "observed_at": round(time.time(), 3),
        "domain_limit": MAX_DOMAINS,
        "address_limit": MAX_ADDRESSES,
        "timeout_seconds": TIMEOUT,
        "observations": observations,
    }


def self_test():
    checks = []

    def check(name, condition):
        checks.append({"case": name, "passed": bool(condition)})

    check("accepts_dns_name", _valid_domain("a.v.smtcdns.com") == "a.v.smtcdns.com")
    check("lowercases_and_trims", _valid_domain("  WWW.Baidu.COM. ") == "www.baidu.com")
    check("rejects_url", _valid_domain("https://a.v.smtcdns.com/") is None)
    check("rejects_credentials", _valid_domain("user:pw@a.v.smtcdns.com") is None)
    check("rejects_ip_literal", _valid_domain("1.2.3.4") is None)
    check("rejects_single_label", _valid_domain("localhost") is None)

    picked, dropped = _pick_addresses([
        "192.168.1.1", "10.0.0.1", "2409:8c54:870:187::1",
        "112.60.24.11", "112.60.22.23", "111.32.207.88", "112.60.24.39",
    ])
    check("caps_addresses", len(picked) == MAX_ADDRESSES)
    check("filters_private", "192.168.1.1" not in picked and "10.0.0.1" not in picked)
    check("keeps_global_sorted", picked == sorted(picked) and "112.60.22.23" in picked)
    check("reports_dropped", "192.168.1.1" in dropped and "10.0.0.1" in dropped)
    check("dedupes", _pick_addresses(["1.1.1.1", "1.1.1.1"])[0] == ["1.1.1.1"])

    check("cap_boundary_ok", _probe_refusal({"dns_state": "resolved"}, PROBE_ANSWER_CAP) is None)
    check("cap_exceeded", _probe_refusal({"dns_state": "resolved"}, PROBE_ANSWER_CAP + 1) == "answer_cap_exceeded")
    check("unresolved_reason", _probe_refusal({"dns_state": "unresolved"}, 0) == "unresolved")

    check("verdict_unresolved",
          _summarize({"dns_state": "unresolved"}, [], []) == "dns_unresolved")
    check("verdict_no_address",
          _summarize({"dns_state": "resolved"}, [], []) == "no_public_address")
    check("verdict_unreachable",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": False}, {"tcp_ok": False}]) == "endpoint_unreachable_from_control_path")
    check("verdict_reachable",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": False}, {"tcp_ok": True}]) == "tcp_reachable")
    check("verdict_not_measured",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"], []) == "not_measured")

    check("port_policy_declared", ALLOWED_PORTS == (443,))
    check("inspect_rejects_bad_input",
          inspect_endpoint({"domains": ["http://x/"]}).get("error") == "invalid_domain")
    check("inspect_defaults_domains",
          inspect_endpoint({"domains": []}).get("error") == "domains_required")
    check("inspect_always_has_observations",
          isinstance(inspect_endpoint({"domains": ["http://x/"]}).get("observations"), list))

    passed = sum(1 for item in checks if item["passed"])
    return {
        "ok": passed == len(checks),
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "capabilities": {
            "inspect": "max 5 domains, 3 global addresses each, TCP+TLS 443 handshake, 2.0s per attempt",
        },
        "acceptance_cases": [
            {"request": {"operation": "inspect", "domains": ["www.baidu.com"]}, "expect": {"ok": True}},
        ],
        "contract": {
            "self_test": "域名/地址/端口/裁定分类器的行为断言，含探测传输 16 条应答上限边界；不依赖网络。",
            "inspect": "最多5个域名、每个最多3个全球地址，控制路径 TCP+TLS 握手；说明受保护探测为何返回 probe_unavailable。",
        },
    }


def run(request):
    request = request if isinstance(request, dict) else {}
    operation = request.get("operation", "inspect")
    if operation == "self_test":
        return self_test()
    if operation == "inspect":
        return inspect_endpoint(request)
    return {"ok": False, "error": "unknown_operation",
            "operations": ["self_test", "inspect"]}
