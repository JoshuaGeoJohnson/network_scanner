import json

from utils import load_json


def build_fingerprints():

    print("[+] Building Service Fingerprints")

    hosts = load_json(
        "results/hosts.json"
    )

    fingerprints = []

    for host in hosts:

        ip = host["ip"]

        for port in host["ports"]:

            service_info = host[
                "services"
            ].get(
                str(port),
                {}
            )

            service_name = service_info.get(
                "service",
                ""
            )

            version = service_info.get(
                "version",
                ""
            )

            # Improve service identification

            if (
                "ssl/realserver" in service_name.lower()
                and host["ssl"]
            ):

                cert = host["ssl"].get(
                    "certificate_subject",
                    ""
                )

                if "anydesk" in cert.lower():

                    service_name = (
                        "AnyDesk Remote Access"
                    )

            fingerprint = {

                "ip": ip,

                "port": port,

                "service": service_name,

                "version": version,

                "protocol": service_info.get(
                    "protocol",
                    "tcp"
                ),

                "os_family": host.get(
                    "os_family",
                    "Unknown"
                ),

                "firewall": host.get(
                    "firewall",
                    {}
                )

            }

            # SSL Information

            if host["ssl"]:

                fingerprint[
                    "certificate"
                ] = host["ssl"].get(
                    "certificate_subject",
                    ""
                )

                fingerprint[
                    "tls12"
                ] = host["ssl"].get(
                    "tls12",
                    False
                )

                fingerprint[
                    "tls13"
                ] = host["ssl"].get(
                    "tls13",
                    False
                )

                fingerprint[
                    "certificate_valid_from"
                ] = host["ssl"].get(
                    "valid_from",
                    ""
                )

                fingerprint[
                    "certificate_valid_until"
                ] = host["ssl"].get(
                    "valid_until",
                    ""
                )

                fingerprint[
                    "certificate_status"
                ] = host["ssl"].get(
                    "expiration_status",
                    ""
                )

            fingerprints.append(
                fingerprint
            )

    with open(
        "results/fingerprints.json",
        "w"
    ) as f:

        json.dump(
            fingerprints,
            f,
            indent=4
        )

    print(
        "[+] Fingerprints Built"
    )
