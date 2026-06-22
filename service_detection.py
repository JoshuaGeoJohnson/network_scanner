import subprocess

from utils import load_json
from utils import save_json


def detect_services():

    print("[+] Detecting Services")

    hosts = load_json(
        "results/hosts.json"
    )

    for host in hosts:

        ip = host["ip"]

        if len(host["ports"]) == 0:
            continue

        ports = ",".join(
            str(port)
            for port in host["ports"]
        )

        print(
            f"[+] Service Scan {ip}"
        )

        result = subprocess.run(
            [
                "nmap",
                "-sV",
                "--version-all",
                "-Pn",
                "-p",
                ports,
                ip
            ],
            capture_output=True,
            text=True
        )

        services = {}

        for line in result.stdout.splitlines():

            if "/tcp" not in line:
                continue

            if "open" not in line:
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            port = parts[0].split("/")[0]

            service = parts[2]

            version = ""

            if len(parts) > 3:
                version = " ".join(
                    parts[3:]
                )

            services[port] = {
    "port": port,
    "service": service,
    "version": version,
    "protocol": "tcp"
}

        host["services"] = services

    save_json(
        "results/hosts.json",
        hosts
    )

    print(
        "[+] Service Detection Finished"
    )
