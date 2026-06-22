import json

from utils import load_json


def export_results():

    print("[+] Exporting Results")

    hosts = load_json(
        "results/hosts.json"
    )

    ports_data = []
    services_data = []
    os_data = []
    firewall_data = []
    ssl_data = []

    for host in hosts:

        ports_data.append({
            "ip": host["ip"],
            "ports": host["ports"]
        })

        services_data.append({
            "ip": host["ip"],
            "services": host["services"]
        })

        os_data.append({
            "ip": host["ip"],
            "os": host["os"]
        })

        firewall_data.append({
            "ip": host["ip"],
            "firewall": host["firewall"]
        })

        ssl_data.append({
            "ip": host["ip"],
            "ssl": host["ssl"]
        })

    with open(
        "results/ports.json",
        "w"
    ) as f:
        json.dump(
            ports_data,
            f,
            indent=4
        )

    with open(
        "results/services.json",
        "w"
    ) as f:
        json.dump(
            services_data,
            f,
            indent=4
        )

    with open(
        "results/os.json",
        "w"
    ) as f:
        json.dump(
            os_data,
            f,
            indent=4
        )

    with open(
        "results/firewall.json",
        "w"
    ) as f:
        json.dump(
            firewall_data,
            f,
            indent=4
        )

    with open(
        "results/ssl.json",
        "w"
    ) as f:
        json.dump(
            ssl_data,
            f,
            indent=4
        )

    print("[+] Export Finished")
