"""Explain endpoint reachability from the control path.

Why a protected probe says probe_unavailable/ValueError matters: NXDOMAIN
(name absent), EAI_AGAIN (resolver failed; existence unproven), an answer set
over the probe cap, and an unreachable endpoint need opposite conclusions.

Evidence is control-path only: not a client session, not the proxy path; a
failed handshake means unreachable from this WAN egress only; transport
success is not application success; latency is not bandwidth.
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


def _classify_dns_error(errno):
    """EAI_* -> evidence state; NXDOMAIN and EAI_AGAIN must never share a label."""
    if errno == socket.EAI_NONAME:
        return "nxdomain"
    if errno == socket.EAI_AGAIN:
        return "resolver_temporary"
    return "unresolved"


def _resolve(domain):
    """Return (addresses, detail). detail tells DNS failure apart from empty."""
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        return [], {"dns_state": _classify_dns_error(error.errno), "dns_error": error.errno}
    except Exception as error:  # pragma: no cover - defensive
        return [], {"dns_state": "resolver_error", "dns_error": type(error).__name__}
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
    """Turn the raw facts into one stable verdict plus an explicit cause.

    TCP connect success is not enough: a local SYN answer looks identical to a
    reachable endpoint in a few tenths of a millisecond.  Only a completed TLS
    handshake (the transport the probe and clients actually need) is treated
    as reachability; a fast connect with no handshake is named as suspected
    interception instead of a passing path.
    """
    dns_state = resolution.get("dns_state")
    if dns_state == "nxdomain":
        return "dns_nxdomain"
    if dns_state == "resolver_temporary":
        return "dns_tempfail"
    if dns_state == "unresolved":
        return "dns_unresolved"
    if resolution.get("dns_state") == "empty" or not picked:
        return "no_public_address"
    if not samples:
        return "not_measured"
    if any(item.get("tls_ok") for item in samples):
        return "tls_reachable"
    connects = [item for item in samples if item.get("tcp_ok")]
    if connects:
        fastest = min(item["tcp_ms"] for item in connects if isinstance(item.get("tcp_ms"), float))
        if fastest < IMPLAUSIBLE_CONNECT_MS:
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
        if verdict == "dns_nxdomain":
            note = "name answers NXDOMAIN; not a resolver/proxy/node fault, though the client app may still be misconfigured"
        elif verdict == "dns_tempfail":
            note = "temporary resolver failure (EAI_AGAIN); existence unproven, rule out a resolver/upstream problem"
        elif verdict == "dns_unresolved":
            note = "name does not resolve here; the protected probe cannot measure it either; NXDOMAIN and a temporary resolver failure are not yet distinguished"
        elif verdict == "no_public_address":
            note = "no global unicast address to test; probe input would be rejected"
        elif verdict == "tls_reachable":
            note = "TLS handshake completed from the control path; application answers are separate evidence"
        elif verdict == "connect_intercepted_no_tls":
            note = "TCP connects in well under a millisecond but no TLS handshake completes; a local SYN answer is likely, so the endpoint is not proven reachable"
        elif verdict == "tcp_only_no_tls":
            note = "TCP connects but no TLS handshake completes; endpoint reachability is not proven"
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
    check("classify_nxdomain", _classify_dns_error(socket.EAI_NONAME) == "nxdomain")
    check("classify_tempfail", _classify_dns_error(socket.EAI_AGAIN) == "resolver_temporary")
    check("verdict_nxdomain", _summarize({"dns_state": "nxdomain"}, [], []) == "dns_nxdomain")
    check("verdict_tempfail",
          _summarize({"dns_state": "resolver_temporary"}, [], []) == "dns_tempfail")
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

    check("port_policy_declared", ALLOWED_PORTS == (443,))
    check("inspect_rejects_bad_input",
          inspect_endpoint({"domains": ["http://x/"]}).get("error") == "invalid_domain")
    check("inspect_defaults_domains",
          inspect_endpoint({"domains": []}).get("error") == "domains_required")
    check("inspect_always_has_observations",
          isinstance(inspect_endpoint({"domains": ["http://x/"]}).get("observations"), list))

    # --- protected-trigger mirrors: regression assertions for the repeat-call ---
    on = {"status": {"services": {"net-gateway.service": {"ActiveState": "active"}}}}
    healthy = dict(on, checks={"mainland_https": {"ok": True, "result": {"expected_health_status": True}}})
    bookkeeping = dict(on, checks={}, business_observations={"issues": [
        {"domain": "a.example", "resolved": False},
        {"domain": "b.example", "resolved": True},
    ]})
    check("trigger_healthy_no_faults", _trigger_faults(healthy) == [])
    check("trigger_counts_only_unresolved",
          _trigger_faults(bookkeeping) == ["client_business:a.example"])

    stable = _trigger_signature(bookkeeping, _trigger_faults(bookkeeping))
    check("trigger_signature_stable",
          stable == _trigger_signature(bookkeeping, _trigger_faults(bookkeeping)))
    moved = dict(bookkeeping, status={"services": on["status"]["services"],
                                      "provider_counts": {"us": 13, "other": 70}})
    check("trigger_provider_counts_changes_signature",
          _trigger_signature(moved, _trigger_faults(moved)) != stable)
    check("trigger_audit_calls_provider_change_duplicate",
          audit_trigger({"diagnosis": moved, "state": {
              "last_ai_fingerprint": "older", "previous": bookkeeping}}).get("verdict")
          == "duplicate_provider_counts_change")

    broken = dict(on, checks={"proxy_https": {"ok": False, "result": {"expected_health_status": False}}},
                  business_observations=bookkeeping["business_observations"])
    broken_signature = _trigger_signature(broken, _trigger_faults(broken))
    check("trigger_audit_calls_new_fault_new_evidence",
          audit_trigger({"diagnosis": broken, "state": {
              "last_ai_fingerprint": "older", "previous": bookkeeping}}).get("verdict")
          == "new_or_changed_fault")
    check("trigger_audit_calls_recovery_echo",
          audit_trigger({"diagnosis": bookkeeping, "state": {
              "last_ai_fingerprint": broken_signature, "previous": broken}}).get("verdict")
          == "recovery_echo")
    check("trigger_same_signature_no_review",
          audit_trigger({"diagnosis": bookkeeping,
                         "state": {"last_ai_fingerprint": stable}}).get("review_trigger") is False)
    check("trigger_audit_requires_diagnosis",
          audit_trigger({}).get("error") == "diagnosis_required")
    direct = dict(on, status={"services": on["status"]["services"], "policy": {"mode": "direct"}},
                  checks={"proxy_https": {"ok": False, "result": {}}})
    check("trigger_direct_mode_skips_proxy_checks", _trigger_faults(direct) == [])
    check("trigger_run_dispatch",
          run({"operation": "audit_trigger", "diagnosis": healthy}).get("verdict") == "healthy_no_trigger")

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


# --- protected-trigger audit (read-only mirror) ------------------------------
# Mirrors deployed patrol.py: fault_keys() (unresolved client_business issues,
# node-pool urgent, service, disk, fixed checks), fault_signature() (sha256 of
# faults + evidence + provider_counts) and urgent_ai_needed() (faults and
# signature != last). A transient fixed-path failure changes the signature and
# its recovery changes it again; business_watch never marks issues resolved, so
# those keys stay in fault_keys() and every provider_counts change re-triggers.
FIXED_CHECK_SKIP_DIRECT = ("gateway_dns_foreign", "proxy_https")


def _trigger_faults(diagnosis):
    diagnosis = diagnosis if isinstance(diagnosis, dict) else {}
    faults = []
    business = diagnosis.get("business_observations") or {}
    for issue in business.get("issues") or []:
        if isinstance(issue, dict) and issue.get("resolved") is False:
            faults.append("client_business:" + str(issue.get("domain") or "unknown"))
    status = diagnosis.get("status") or {}
    direct = (status.get("policy") or {}).get("mode") == "direct"
    nodes = diagnosis.get("node_observations") or {}
    if not direct and nodes.get("urgent") is True:
        faults.append("proxy_node_pool")
    gateway = (status.get("services") or {}).get("net-gateway.service") or {}
    if gateway.get("ActiveState") != "active":
        faults.append("gateway_service")
    if (status.get("storage") or {}).get("critical"):
        faults.append("disk_space")
    checks = diagnosis.get("checks") or {}
    for name in checks:
        if direct and name in FIXED_CHECK_SKIP_DIRECT:
            continue
        item = checks.get(name) or {}
        result = item.get("result") or {}
        count = result.get("answer_count", 0)
        if (item.get("ok") is not True
                or ("rcode" in result and (result.get("rcode") != 0 or count < 1))
                or result.get("expected_health_status") is False):
            faults.append(name)
    return sorted(set(faults))


def _evidence_row(diagnosis, name):
    item = (diagnosis.get("checks") or {}).get(name) or {}
    result = item.get("result") or {}
    return {
        "rcode": result.get("rcode"),
        "http_status": result.get("http_status"),
        "expected_health_status": result.get("expected_health_status"),
        "error": item.get("error"),
    }


def _trigger_signature(diagnosis, faults):
    import hashlib
    import json
    evidence = {name: _evidence_row(diagnosis, name) for name in faults}
    if "proxy_node_pool" in faults:
        evidence["proxy_node_pool"]["incident"] = (diagnosis.get("node_observations") or {}).get("fingerprint")
    payload = {
        "faults": faults,
        "evidence": evidence,
        "provider_counts": (diagnosis.get("status") or {}).get("provider_counts") or {},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:20]


def _fault_groups(faults):
    groups = {"client_business": [], "fixed_path": [], "node_pool": [], "service_or_storage": []}
    for name in faults:
        if name.startswith("client_business:"):
            groups["client_business"].append(name)
        elif name == "proxy_node_pool":
            groups["node_pool"].append(name)
        elif name in ("gateway_service", "disk_space"):
            groups["service_or_storage"].append(name)
        else:
            groups["fixed_path"].append(name)
    return groups


def audit_trigger(request):
    """Say whether a new dispatch would be new evidence or a repeat."""
    diagnosis = request.get("diagnosis")
    if not isinstance(diagnosis, dict):
        return {"ok": False, "error": "diagnosis_required", "observations": []}
    state = request.get("state") or {}
    previous = state.get("previous") if isinstance(state.get("previous"), dict) else None
    faults = _trigger_faults(diagnosis)
    signature = _trigger_signature(diagnosis, faults)
    last = state.get("last_ai_fingerprint")
    review_trigger = bool(faults) and signature != last
    verdict = "healthy_no_trigger"
    deltas = {"added_faults": [], "removed_faults": [], "changed_evidence": [],
              "provider_counts_changed": False, "previous_signature": None}
    if faults:
        verdict = "same_signature_as_last_ai" if not review_trigger else "signature_changed_no_previous"
    if faults and review_trigger and previous is not None:
        prev_faults = _trigger_faults(previous)
        added = [name for name in faults if name not in prev_faults]
        removed = [name for name in prev_faults if name not in faults]
        changed = [name for name in faults
                   if name in prev_faults and _evidence_row(diagnosis, name) != _evidence_row(previous, name)]
        prev_counts = (previous.get("status") or {}).get("provider_counts") or {}
        counts = (diagnosis.get("status") or {}).get("provider_counts") or {}
        counts_changed = prev_counts != counts
        deltas = {"added_faults": added, "removed_faults": removed, "changed_evidence": changed,
                  "provider_counts_changed": counts_changed,
                  "previous_signature": _trigger_signature(previous, prev_faults)}
        if added:
            verdict = "new_or_changed_fault"
        elif counts_changed:
            verdict = "duplicate_provider_counts_change"
        elif changed:
            verdict = "changed_evidence"
        elif removed:
            removed_groups = _fault_groups(removed)
            if removed_groups["fixed_path"] and not _fault_groups(faults)["fixed_path"]:
                verdict = "recovery_echo"
            else:
                verdict = "duplicate_business_bookkeeping"

    notes = {
        "healthy_no_trigger": "no fault key; no emergency call justified",
        "same_signature_as_last_ai": "same signature as the last dispatch; a repeat adds no evidence",
        "signature_changed_no_previous": "signature differs from the last dispatch, but no prior snapshot was supplied",
        "duplicate_provider_counts_change": "only provider_counts differ; same failing paths, so bookkeeping not new evidence",
        "duplicate_business_bookkeeping": "only permanently-unresolved business keys differ; no new path evidence",
        "changed_evidence": "same fault keys, changed check evidence; read the per-fault rows first",
        "recovery_echo": "a fixed-path fault disappeared; usually a second call for one incident",
        "new_or_changed_fault": "a fault key appeared or a fixed-path check failed; treat as new evidence",
    }.get(verdict, "unclassified")

    observations = []
    groups = _fault_groups(faults)
    for name in faults[:6]:
        kind = next((group for group in groups if name in groups[group]), "other")
        observations.append({"fault": name, "kind": kind, "evidence": _evidence_row(diagnosis, name)})
    return {
        "ok": True,
        "verdict": verdict,
        "note": notes,
        "faults": faults,
        "groups": groups,
        "signature": signature,
        "last_ai_fingerprint": last,
        "review_trigger": review_trigger,
        "deltas": deltas,
        "observations": observations,
        "scope": "read-only mirror of the protected patrol trigger; changes nothing and proves nothing about user-visible health",
    }


def run(request):
    request = request if isinstance(request, dict) else {}
    operation = request.get("operation", "inspect")
    if operation == "self_test":
        return self_test()
    if operation == "inspect":
        return inspect_endpoint(request)
    if operation == "audit_trigger":
        return audit_trigger(request)
    return {"ok": False, "error": "unknown_operation",
            "operations": ["self_test", "inspect", "audit_trigger"]}
