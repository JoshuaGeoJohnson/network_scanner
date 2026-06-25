import subprocess
import re

from utils import load_json, save_json


def detect_firewall():

    print("[+] Firewall Detection")

    hosts = load_json(
        "results/hosts.json"
    )

    route = subprocess.run(
        ["ip", "route"],
        capture_output=True,
        text=True
    )

    gateway = "Unknown"

    match = re.search(
        r"default via (\d+\.\d+\.\d+\.\d+)",
        route.stdout
    )

    if match:
        gateway = match.group(1)

    for host in hosts:

        ip = host["ip"]

        print(
            f"    Scanning firewall on {ip}"
        )

        result = subprocess.run(
            [
                "nmap",
                "-sA",
                ip
            ],
            capture_output=True,
            text=True
        )

        print(
            f"    Finished firewall scan on {ip}"
        )

        if "filtered" in result.stdout.lower():

            host["firewall"] = {
                "status": "Detected",
                "device_ip": gateway
            }

        else:

            host["firewall"] = {
                "status": "Not Detected",
                "device_ip": gateway
            }

    save_json(
        "results/hosts.json",
        hosts
    )

    print(
        "[+] Firewall Detection Finished"
    )
