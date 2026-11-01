#!/usr/bin/env python3
"""Apply only gateway-owned forwarding settings; restore their original values."""

import json
from pathlib import Path
import subprocess
import sys

STATE = Path("/var/lib/net-gateway/original-network.json")


def main():
    operation = sys.argv[1]
    if operation == "restore":
        if STATE.exists():
            data = json.loads(STATE.read_text())
            for name, value in data["sysctls"].items():
                path = Path("/proc/sys") / name
                if path.exists():
                    path.write_text(value)
        subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", "net_gateway_guard"], capture_output=True)
        subprocess.run(["/usr/sbin/nft", "delete", "table", "ip", "net_gateway_nat"], capture_output=True)
        return

    route = json.loads(subprocess.check_output(["ip", "-j", "route", "get", "192.168.2.1"], text=True))[0]
    interface = route["dev"]
    values = {
        "net/ipv4/ip_forward": "1",
        "net/ipv4/conf/all/send_redirects": "0",
        "net/ipv4/conf/default/send_redirects": "0",
        f"net/ipv4/conf/{interface}/send_redirects": "0",
        "net/ipv4/conf/all/rp_filter": "2",
        f"net/ipv4/conf/{interface}/rp_filter": "2",
    }
    if not STATE.exists():
        STATE.write_text(json.dumps({"sysctls": {name: (Path("/proc/sys") / name).read_text() for name in values}}, indent=2))
        STATE.chmod(0o600)
    for name, value in values.items():
        (Path("/proc/sys") / name).write_text(value)
    subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", "net_gateway_guard"], capture_output=True)
    subprocess.run(["/usr/sbin/nft", "delete", "table", "ip", "net_gateway_nat"], capture_output=True)
    rules = f'''table inet net_gateway_guard {{
      chain input {{ type filter hook input priority -10; policy accept;
        iifname "lo" accept
        ip saddr {{ 192.168.2.2, 192.168.2.4, 10.203.0.0/30 }} accept
        tcp dport 7890 drop
        ip saddr != 192.168.2.0/24 tcp dport 80 drop
        ip saddr != 192.168.2.0/24 udp dport 53 drop
        ip saddr != 192.168.2.0/24 tcp dport 53 drop
      }}
    }}
    table ip net_gateway_nat {{
      chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
        oifname "{interface}" ip saddr {{ 192.168.2.0/24, 10.203.0.0/30 }} ip daddr != 192.168.2.0/24 masquerade
      }}
    }}'''
    subprocess.run(["/usr/sbin/nft", "-f", "-"], input=rules, text=True, check=True)


if __name__ == "__main__":
    main()
