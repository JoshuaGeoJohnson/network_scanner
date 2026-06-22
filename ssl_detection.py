import subprocess
import re
from datetime import datetime

from utils import load_json, save_json


def detect_ssl():

    print("[+] SSL Detection")

    hosts = load_json(
        "results/hosts.json"
    )

    ssl_ports = [
        443,
        8443,
        9443,
        7070
    ]

    ansi_escape = re.compile(
        r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
    )

    for host in hosts:

        ip = host["ip"]

        host["ssl"] = {}

        for port in host["ports"]:

            if port not in ssl_ports:
                continue

            print(
                f"    SSL Scan {ip}:{port}"
            )

            try:

                result = subprocess.run(
                    [
                        "sslscan",
                        f"{ip}:{port}"
                    ],
                    capture_output=True,
                    text=True
                )

                output = result.stdout

                tls12 = (
                    "TLSv1.2   enabled"
                    in output
                )

                tls13 = (
                    "TLSv1.3   enabled"
                    in output
                )

                subject = ""

                valid_from = ""

                valid_until = ""

                expiration_status = (
                    "Unknown"
                )

                subject_match = re.search(
                    r"Subject:\s+(.*)",
                    output
                )

                if subject_match:

                    subject = (
                        ansi_escape.sub(
                            "",
                            subject_match.group(1)
                        )
                        .strip()
                    )

                before_match = re.search(
                    r"Not valid before:\s*(.+)",
                    output
                )

                if before_match:

                    valid_from = (
                        ansi_escape.sub(
                            "",
                            before_match.group(1)
                        )
                        .strip()
                    )

                after_match = re.search(
                    r"Not valid after:\s*(.+)",
                    output
                )

                if after_match:

                    valid_until = (
                        ansi_escape.sub(
                            "",
                            after_match.group(1)
                        )
                        .strip()
                    )

                try:

                    if valid_until:

                        clean_date = " ".join(
                            valid_until.split()
                        )

                        expiry_date = (
                            datetime.strptime(
                                clean_date,
                                "%b %d %H:%M:%S %Y GMT"
                            )
                        )

                        if (
                            expiry_date
                            < datetime.now()
                        ):

                            expiration_status = (
                                "Expired"
                            )

                        else:

                            expiration_status = (
                                "Valid"
                            )

                except Exception:

                    expiration_status = (
                        "Unknown"
                    )

                host["ssl"] = {

                    "port": port,

                    "tls12": tls12,

                    "tls13": tls13,

                    "certificate_subject":
                        subject,

                    "valid_from":
                        valid_from,

                    "valid_until":
                        valid_until,

                    "expiration_status":
                        expiration_status
                }

                break

            except Exception as e:

                print(
                    f"SSL Error on {ip}:{port}"
                )

    save_json(
        "results/hosts.json",
        hosts
    )

    print(
        "[+] SSL Detection Finished"
    )
