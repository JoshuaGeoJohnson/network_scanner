import subprocess

from utils import load_json, save_json


def detect_hostnames():

    print("[+] Detecting Hostnames")

    hosts = load_json("results/hosts.json")

    for host in hosts:

        ip = host["ip"]

        try:

            result = subprocess.run(
                ["nbtscan", ip],
                capture_output=True,
                text=True
            )

            hostname = ""

            for line in result.stdout.splitlines():

                if "<00>" in line:

                    parts = line.split()

                    if len(parts) > 1:

                        hostname = parts[0]
                        break

            host["hostname"] = hostname

        except Exception:

            host["hostname"] = ""

    save_json(
        "results/hosts.json",
        hosts
    )

    print("[+] Hostname Detection Finished")
