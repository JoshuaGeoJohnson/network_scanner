import subprocess
import re

from utils import load_json, save_json


def scan_ports():

    print("[+] Starting Port Scan")

    hosts = load_json("results/hosts.json")

    for host in hosts:

        ip = host["ip"]

        print(f"[+] Scanning {ip}")

        try:

            result = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "--top-ports",
                    "5000",
                    "-T4",
                    ip
                ],
                capture_output=True,
                text=True
            )

            matches = re.findall(
                r"(\d+)/tcp\s+open",
                result.stdout
            )

            ports = []

            for port in matches:
                ports.append(int(port))

            ports.sort()

            host["ports"] = ports

            print(
                f"    Found {len(ports)} open ports"
            )

        except Exception as e:

            print(
                f"    Error scanning {ip}: {e}"
            )

            host["ports"] = []

    save_json(
        "results/hosts.json",
        hosts
    )

    print("[+] Port Scan Finished")
