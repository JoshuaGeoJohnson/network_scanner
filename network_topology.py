import json

from utils import load_json


def build_topology():

    print("[+] Building Topology")

    hosts = load_json(
        "results/hosts.json"
    )

    topology = {

        "gateway": None,
        "devices": []

    }

    for host in hosts:

        if host["firewall"]:

            gateway = host[
                "firewall"
            ].get(
                "gateway"
            )

            topology[
                "gateway"
            ] = gateway

        topology[
            "devices"
        ].append({

            "ip": host["ip"],
            "mac": host["mac"],
            "os": host["os"]

        })

    with open(
        "results/topology.json",
        "w"
    ) as f:

        json.dump(
            topology,
            f,
            indent=4
        )

    print(
        "[+] Topology Built"
    )
