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

Positive control (added 2026-11-04): a per-run handshake to a domain already
known healthy from this path.  Without it a failed target handshake has two
opposite readings -- "this endpoint refuses the probe's TLS" or "this whole
path cannot do TLS right now" -- that look identical in a single sample.  With
the control, a target failure is reported as endpoint-specific only when the
control itself completed; when the control also fails the target verdict says
so instead of implying the endpoint is at fault.

Evidence boundaries (never collapse them):
  * this runs on the maintainer control path (independent UID route, no Mihomo
    data plane).  It is NOT a household client path and NOT the proxy path.
  * a failed handshake here means "no TLS from this WAN egress", never
    "unreachable everywhere".
  * a successful handshake is transport evidence only: an application can still
    reject the request (401/403/404 are business answers, not link failures).
  * a target that refuses the probe's TLS while real clients keep transferring
    bytes is a probe-method limit (e.g. HTTP/3-only or non-HTTPS service), not
    a link fault; this tool reports the two facts apart, it does not merge them.
  * latency here is path evidence, never a bandwidth claim.

The tool is read-only: no policy, rule, node, credential or engine changes.
``run({"operation": "self_test"})`` asserts the classifiers on synthetic input.
``run({"operation": "inspect", "domains": [...]})`` performs at most 5 domains
and 3 addresses each, with a 2 s per-attempt budget, plus one control handshake.
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
# A sub-5 ms TCP connect to a public unicast address cannot be the real endpoint:
# something local answers the SYN.  Observed 2026-11-03 on a dead CDN domain
# (0.3-0.4 ms connects, every TLS handshake timing out), so a fast connect alone
# must not be reported as reachability.
IMPLAUSIBLE_CONNECT_MS = 5.0
ALLOWED_PORTS = (443,)
# Known-healthy mainland endpoint: the fixed gateway check reaches it with HTTP
# 200, so a completed TLS handshake here proves this path can still do TLS.
CONTROL_DOMAIN = "www.baidu.com"
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


def _control_probe(domain=CONTROL_DOMAIN):
    """One bounded handshake to a known-healthy domain on this same path."""
    addresses, resolution = _resolve(domain)
    picked, _dropped = _pick_addresses(addresses)
    if not picked:
        return {"domain": domain, "dns_state": resolution.get("dns_state"),
                "tls_ok": False, "tcp_ok": False, "tcp_ms": None,
                "error": "no_public_address"}
    sample = _handshake(picked[0], domain, 443)
    return {"domain": domain, "dns_state": resolution.get("dns_state"),
            "address": picked[0], "tcp_ok": sample.get("tcp_ok"),
            "tcp_ms": sample.get("tcp_ms"), "tls_ok": sample.get("tls_ok"),
            "error": sample.get("error")}


def _summarize(resolution, picked, samples, control=None):
    """Turn the raw facts into one stable verdict.

    TCP connect success is not enough: a local SYN answer looks identical to a
    reachable endpoint in a few tenths of a millisecond.  Only a completed TLS
    handshake (the transport the probe and clients actually need) is treated
    as reachability.

    The control decides how to read a target failure:
      * control handshake completed -> the path can do TLS, so the target
        specifically failed it (``tls_rejected_target_only``);
      * control handshake failed or absent -> the target failure cannot be
        pinned on the endpoint, so the older conservative verdicts are kept.
    """
    if resolution.get("dns_state") == "unresolved":
        return "dns_unresolved"
    if resolution.get("dns_state") == "empty" or not picked:
        return "no_public_address"
    if not samples:
        return "not_measured"
    if any(item.get("tls_ok") for item in samples):
        return "tls_reachable"
    if isinstance(control, dict) and control.get("tls_ok") is True:
        return "tls_rejected_target_only"
    connects = [item for item in samples if item.get("tcp_ok")]
    if connects:
        timed = [item["tcp_ms"] for item in connects if isinstance(item.get("tcp_ms"), float)]
        if timed and min(timed) < IMPLAUSIBLE_CONNECT_MS:
            return "connect_intercepted_no_tls"
        return "tcp_only_no_tls"
    return "endpoint_unreachable_from_control_path"


def _probe_refusal(resolution, answer_count):
    """Why the protected probe would answer probe_unavailable/ValueError."""
    if resolution.get("dns_state") != "resolved":
        return resolution.get("dns_state")
    if answer_count > PROBE_ANSWER_CAP:
        return "answer_cap_exceeded"
    return None


def _verdict_note(verdict, control):
    control_ok = isinstance(control, dict) and control.get("tls_ok") is True
    control_domain = (control or {}).get("domain", CONTROL_DOMAIN)
    if verdict == "dns_unresolved":
        note = "name does not resolve here; the protected probe cannot measure it either"
    elif verdict == "no_public_address":
        note = "no global unicast address to test; probe input would be rejected"
    elif verdict == "tls_reachable":
        note = "TLS handshake completed from the control path; application answers are separate evidence"
    elif verdict == "tls_rejected_target_only":
        note = ("control TLS to %s completed on this path, but this endpoint did not complete "
                "the probe's TLS handshake; it may refuse plain TLS, require HTTP/3, or not "
                "serve HTTPS. An HTTPS probe is not a valid health signal for it, and this is "
                "not evidence of a link fault" % control_domain)
    elif verdict == "connect_intercepted_no_tls":
        note = "TCP connects in well under a millisecond but no TLS handshake completes; a local SYN answer is likely, so the endpoint is not proven reachable"
    elif verdict == "tcp_only_no_tls":
        note = "TCP connects but no TLS handshake completes; endpoint reachability is not proven"
    elif verdict == "endpoint_unreachable_from_control_path":
        note = "no handshake from this WAN egress; says nothing about other networks or the proxy path"
    else:
        note = "not measured"
    if isinstance(control, dict) and control.get("tls_ok") is not True:
        note = note + ("; control handshake to %s also failed, so this result cannot be "
                       "attributed to the endpoint alone" % control_domain)
    return note


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

    control = _control_probe()
    observations = []
    for domain in domains:
        addresses, resolution = _resolve(domain)
        picked, dropped = _pick_addresses(addresses)
        samples = [_handshake(address, domain, 443) for address in picked]
        verdict = _summarize(resolution, picked, samples, control)
        refusal = _probe_refusal(resolution, len(addresses))
        note = _verdict_note(verdict, control)
        if refusal == "answer_cap_exceeded":
            note = note + "; answer set exceeds the probe transport cap of %d" % PROBE_ANSWER_CAP
        evidence = ["control tls_ok=%s" % (control.get("tls_ok"),),
                    "target tls_ok=%s" % (any(item.get("tls_ok") for item in samples),)]
        observations.append({
            "domain": domain,
            "verdict": verdict,
            "note": note,
            "answer_count": len(addresses),
            "probe_refusal": refusal,
            "probe_answer_cap": PROBE_ANSWER_CAP,
            "tested": samples,
            "evidence": evidence,
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
        "control": control,
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
    check("verdict_tls_reachable",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": False}, {"tcp_ok": True, "tls_ok": True}]) == "tls_reachable")
    check("verdict_fast_connect_is_not_reachability",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": True, "tcp_ms": 0.3, "tls_ok": False}]) == "connect_intercepted_no_tls")
    check("verdict_plausible_tcp_without_tls",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": True, "tcp_ms": 40.0, "tls_ok": False}]) == "tcp_only_no_tls")
    check("verdict_not_measured",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"], []) == "not_measured")

    # Positive-control regressions: the same raw target sample must be read
    # differently depending on whether the control path could do TLS.
    fast_fail = [{"tcp_ok": True, "tcp_ms": 0.3, "tls_ok": False}]
    check("verdict_target_only_when_control_ok",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"], fast_fail,
                     {"domain": "www.baidu.com", "tls_ok": True}) == "tls_rejected_target_only")
    check("verdict_keeps_conservative_when_control_down",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"], fast_fail,
                     {"domain": "www.baidu.com", "tls_ok": False}) == "connect_intercepted_no_tls")
    check("verdict_keeps_conservative_without_control",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"], fast_fail) == "connect_intercepted_no_tls")
    check("note_names_control_success",
          "control TLS to www.baidu.com completed" in
          _verdict_note("tls_rejected_target_only", {"domain": "www.baidu.com", "tls_ok": True}))
    check("note_flags_unusable_control",
          "cannot be attributed to the endpoint alone" in
          _verdict_note("connect_intercepted_no_tls", {"domain": "www.baidu.com", "tls_ok": False}))
    check("tls_reachable_not_relabelled_by_control",
          _summarize({"dns_state": "resolved"}, ["1.1.1.1"],
                     [{"tcp_ok": True, "tls_ok": True}],
                     {"domain": "www.baidu.com", "tls_ok": True}) == "tls_reachable")

    check("port_policy_declared", ALLOWED_PORTS == (443,))
    check("control_domain_is_plain_name", _valid_domain(CONTROL_DOMAIN) == CONTROL_DOMAIN)
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
            "inspect": "max 5 domains, 3 global addresses each, TCP+TLS 443 handshake, 2.0s per attempt, plus one positive-control handshake",
        },
        "acceptance_cases": [
            {"request": {"operation": "inspect", "domains": ["www.baidu.com"]}, "expect": {"ok": True}},
        ],
        "contract": {
            "self_test": "域名/地址/端口/裁定分类器的行为断言，含探测传输 16 条应答上限边界与正对照对同一目标样本的双向解释；不依赖网络。",
            "inspect": "最多5个域名、每个最多3个全球地址，控制路径 TCP+TLS 握手，先做一次已知健康域名的正对照；说明受保护探测为何 probe_unavailable，并把端点特定失败与整条路径无法握手区分开。",
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
