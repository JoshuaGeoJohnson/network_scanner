import subprocess
import re

from utils import load_json, save_json

def detect_os():

    hosts = load_json("results/hosts.json")

    for host in hosts:

        ip = host["ip"]

        print(f"[+] OS Detection {ip}")

        result = subprocess.run(
            [
                "nmap",
                "-A",
                ip
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout

        os_name = "Unknown"

        # First try Service Info
        service_match = re.search(
            r"Service Info:\s*OS:\s*([^;]+)",
            output
        )

        if service_match:
            os_name = service_match.group(1)

        else:

            patterns = [
                r"Running:\s*(.+)",
                r"Running \(JUST GUESSING\):\s*(.+)",
                r"OS details:\s*(.+)"
            ]

            for pattern in patterns:

                match = re.search(pattern, output)

                if match:
                    os_name = match.group(1)
                    break

        host["os"] = os_name

    save_json("results/hosts.json", hosts)

    print("[+] OS Detection Finished")
