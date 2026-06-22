import json
import csv
import os

from utils import load_json


def generate_reports():

    print("[+] Generating Reports")

    hosts = load_json(
        "results/hosts.json"
    )

    os.makedirs(
        "reports",
        exist_ok=True
    )

    # JSON Report
    with open(
        "reports/report.json",
        "w"
    ) as f:

        json.dump(
            hosts,
            f,
            indent=4
        )

    # CSV Report
    with open(
        "reports/report.csv",
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "IP",
            "MAC",
            "OS",
            "Ports",
            "Firewall"
        ])

        for host in hosts:

            writer.writerow([
                host["ip"],
                host["mac"],
                host["os"],
                ",".join(
                    map(str, host["ports"])
                ),
                host["firewall"]
            ])

    # HTML Report

    html = """
    <html>
    <head>
        <title>Network Scanner Report</title>
    </head>

    <body>

    <h1>Network Scanner Report</h1>

    <table border="1">

    <tr>
        <th>IP</th>
        <th>MAC</th>
        <th>OS</th>
        <th>Ports</th>
        <th>Firewall</th>
    </tr>
    """

    for host in hosts:

        html += f"""
        <tr>
            <td>{host['ip']}</td>
            <td>{host['mac']}</td>
            <td>{host['os']}</td>
            <td>{host['ports']}</td>
            <td>{host['firewall']}</td>
        </tr>
        """

    html += """
    </table>
    </body>
    </html>
    """

    with open(
        "reports/report.html",
        "w"
    ) as f:

        f.write(html)

    print("[+] Reports Generated")
