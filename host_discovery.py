import subprocess
import re

from utils import save_json

def discover_hosts():

    print("[+] Discovering Hosts")

    result = subprocess.run(
        ["arp-scan", "--localnet"],
        capture_output=True,
        text=True
    )

    pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)"

    matches = re.findall(pattern, result.stdout)

    hosts = []

    for ip, mac in matches:

        hosts.append({
            "ip": ip,
            "mac": mac,
            "hostname": "",
            "ports": [],
            "services": {},
            "os": "",
            "firewall": "",
            "ssl": {}
        })

    save_json("results/hosts.json", hosts)

    print(f"[+] Found {len(hosts)} hosts")

    return hosts
