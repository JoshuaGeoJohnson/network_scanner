import subprocess
import re

from utils import load_json
from utils import save_json


def scan_ports(
    scan_mode,
    custom_ports=None
):

    print("[+] Starting Port Scan")

    hosts = load_json(
        "results/hosts.json"
    )

    for host in hosts:

        ip = host["ip"]

        print(
            f"[+] Scanning {ip}"
        )

        if scan_mode == "top5000":

            command = [

                "nmap",

                "-Pn",

                "--top-ports",

                "5000",

                ip
            ]

        elif scan_mode == "all":

            command = [

                "nmap",

                "-Pn",

                "-p-",

                ip
            ]

        elif scan_mode == "custom":

            command = [

                "nmap",

                "-Pn",

                "-p",

                custom_ports,

                ip
            ]

        else:

            print(
                "Invalid scan mode"
            )

            return

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        ports = []

        matches = re.findall(
            r"(\d+)/tcp\s+open",
            result.stdout
        )

        for port in matches:

            ports.append(
                int(port)
            )

        host["ports"] = ports

        print(
            f"    Found {len(ports)} open ports"
        )

    save_json(
        "results/hosts.json",
        hosts
    )

    print(
        "[+] Port Scan Finished"
    )
