#!/usr/bin/env python3
"""Maintain region priority without placing an LLM in the forwarding path."""

import datetime
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


def choose_region(probe, allow_other=True, direct_fallback=False):
    if probe("US_AUTO") or probe("US_AUTO"):
        return "US_AUTO"
    if allow_other and probe("OTHER_AUTO"):
        return "OTHER_AUTO"
    return "DIRECT" if direct_fallback else None


def main():
    config = json.loads(Path("/etc/net-gateway/config.json").read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = "http://" + config["external-controller"]

    def request(path, method="GET", data=None, timeout=35):
        query = urllib.request.Request(
            base + path,
            data=json.dumps(data).encode() if data is not None else None,
            method=method,
            headers={"Authorization": "Bearer " + config["secret"], "Content-Type": "application/json"},
        )
        with opener.open(query, timeout=timeout) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}

    def probe(region):
        provider = "us" if region == "US_AUTO" else "other"
        try:
            request("/providers/proxies/" + provider + "/healthcheck")
            query = urllib.parse.urlencode({
                "url": "https://www.gstatic.com/generate_204", "timeout": 5000, "expected": "204",
            })
            result = request("/proxies/" + region + "/delay?" + query, timeout=10)
            return isinstance(result.get("delay"), (int, float))
        except (urllib.error.URLError, OSError, ValueError):
            return False

    policy_path=Path('/var/lib/net-gateway-agent/approved-policy.json')
    approved=json.loads(policy_path.read_text()) if policy_path.exists() else {}
    preferences=approved.get('preferences',{})
    region = 'DIRECT' if preferences.get('mode')=='direct' else choose_region(probe, preferences.get('allow_other_regions',True), preferences.get('allow_proxy_direct_fallback',False))
    if region is not None:
        request("/proxies/PROXY", method="PUT", data={"name": region})
    summary = {
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "selected_region": region,
        "status": "ready" if region else "all_regions_unavailable",
        "direct_fallback": preferences.get('allow_proxy_direct_fallback',False),
    }
    path = Path("/var/lib/net-gateway/health-state.json")
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as target:
        json.dump(summary, target)
    temporary.replace(path)
    print(json.dumps(summary))
    return 0 if region else 1


if __name__ == "__main__":
    raise SystemExit(main())
