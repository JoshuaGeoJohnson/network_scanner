from utils import load_json
from utils import save_json


def normalize_os():

    print("[+] Normalizing OS")

    hosts = load_json(
        "results/hosts.json"
    )

    for host in hosts:

        os_guess = host["os"].lower()

        if "windows" in os_guess:

            host["os_family"] = "Windows"

        elif "android" in os_guess:

            host["os_family"] = "Android"

        elif "linux" in os_guess:

            host["os_family"] = "Linux"

        elif "freebsd" in os_guess:

            host["os_family"] = "FreeBSD"

        else:

            host["os_family"] = "Unknown"

    save_json(
        "results/hosts.json",
        hosts
    )

    print(
        "[+] OS Normalization Finished"
    )
