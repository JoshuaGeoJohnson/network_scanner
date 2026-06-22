import json

from utils import load_json


def create_master_scan():

    print("[+] Creating Master Scan")

    hosts = load_json(
        "results/hosts.json"
    )

    risks = load_json(
        "results/risks.json"
    )

    topology = load_json(
        "results/topology.json"
    )

    master = {

        "topology": topology,
        "hosts": hosts,
        "risks": risks

    }

    with open(
        "results/master_scan.json",
        "w"
    ) as f:

        json.dump(
            master,
            f,
            indent=4
        )

    print(
        "[+] Master Scan Created"
    )
