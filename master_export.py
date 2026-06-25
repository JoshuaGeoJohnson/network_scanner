import json

from utils import load_json


def create_master_scan():

    print("[+] Creating Master Scan")

    topology = load_json(
        "results/topology.json"
    )

    hosts = load_json(
        "results/hosts.json"
    )

    risks = load_json(
        "results/risks.json"
    )

    try:

        cves = load_json(
            "results/cves.json"
        )

    except Exception:

        cves = []

    total_hosts = len(hosts)

    total_ports = 0

    total_services = 0

    total_vulnerabilities = 0

    critical_count = 0

    high_count = 0

    medium_count = 0

    low_count = 0

    # Merge CVEs into hosts

    for host in hosts:

        host["vulnerabilities"] = []

        total_ports += len(
            host.get(
                "ports",
                []
            )
        )

        total_services += len(
            host.get(
                "services",
                {}
            )
        )

        for cve_entry in cves:

            if host["ip"] != cve_entry["ip"]:
                continue

            vuln_block = {

                "port":
                    cve_entry.get(
                        "port"
                    ),

                "service":
                    cve_entry.get(
                        "service"
                    ),

                "detected_version":
                    cve_entry.get(
                        "detected_version"
                    ),

                "total_cves":
                    cve_entry.get(
                        "total_cves",
                        0
                    ),

                "findings":
                    cve_entry.get(
                        "vulnerabilities",
                        []
                    )

            }

            host[
                "vulnerabilities"
            ].append(
                vuln_block
            )

            total_vulnerabilities += (
                cve_entry.get(
                    "total_cves",
                    0
                )
            )

            for finding in cve_entry.get(
                "vulnerabilities",
                []
            ):

                severity = (
                    finding.get(
                        "severity",
                        ""
                    )
                    .lower()
                )

                if severity == "critical":

                    critical_count += 1

                elif severity == "high":

                    high_count += 1

                elif severity == "medium":

                    medium_count += 1

                elif severity == "low":

                    low_count += 1

    security_summary = {

        "total_hosts":
            total_hosts,

        "total_open_ports":
            total_ports,

        "total_services":
            total_services,

        "total_vulnerabilities":
            total_vulnerabilities,

        "critical":
            critical_count,

        "high":
            high_count,

        "medium":
            medium_count,

        "low":
            low_count

    }

    master_scan = {

        "security_summary":
            security_summary,

        "topology":
            topology,

        "hosts":
            hosts,

        "risks":
            risks

    }

    with open(
        "results/master_scan.json",
        "w"
    ) as f:

        json.dump(
            master_scan,
            f,
            indent=4
        )

    print(
        "[+] Master Scan Created"
    )
