import socket

from utils import load_json
from utils import save_json


def grab_banners():

    print("[+] Banner Grabbing")

    hosts = load_json(
        "results/hosts.json"
    )

    banners = []

    for host in hosts:

        ip = host["ip"]

        for port in host["ports"]:

            banner = ""

            try:

                sock = socket.socket()

                sock.settimeout(3)

                sock.connect(
                    (ip, port)
                )

                data = sock.recv(
                    1024
                )

                banner = (
                    data.decode(
                        errors="ignore"
                    )
                    .strip()
                )

                sock.close()

            except Exception:
                pass

            banners.append({

                "ip": ip,

                "port": port,

                "banner": banner

            })

    save_json(
        "results/banners.json",
        banners
    )

    print(
        "[+] Banner Grabbing Finished"
    )
