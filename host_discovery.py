import subprocess
from utils import save_json

def discover_hosts():

    print("[+] Discovering Hosts")

    try:

        result = subprocess.run(
            ["arp-scan", "--localnet"],
            capture_output=True,
            text=True
        )

        print("\n=== ARP SCAN OUTPUT ===")
        print(result.stdout)
        print("=======================\n")

        hosts = []

        for line in result.stdout.splitlines():

            parts = line.split()

            if len(parts) < 2:
                continue

            ip = parts[0]
            mac = parts[1]

            # Validate IP and MAC
            if "." in ip and ":" in mac:

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

    except Exception as e:

        print(f"[!] Host Discovery Error: {e}")

        return []
