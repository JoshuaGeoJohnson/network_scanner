import os
import json


def get_severity(cvss):

    if cvss is None:
        return "Unknown"

    if cvss >= 9.0:
        return "Critical"

    elif cvss >= 7.0:
        return "High"

    elif cvss >= 4.0:
        return "Medium"

    else:
        return "Low"


print("[+] Building CVE Index")

index = {}

cve_root = (
    "vulnerability_db/cvelistV5/cves"
)

count = 0

for root, dirs, files in os.walk(
    cve_root
):

    for file in files:

        if not file.endswith(".json"):
            continue

        path = os.path.join(
            root,
            file
        )

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:

                data = json.load(f)

            cve_id = (
                data.get(
                    "cveMetadata",
                    {}
                )
                .get(
                    "cveId",
                    ""
                )
            )

            cna = (
                data.get(
                    "containers",
                    {}
                )
                .get(
                    "cna",
                    {}
                )
            )

            affected = cna.get(
                "affected",
                []
            )

            descriptions = cna.get(
                "descriptions",
                []
            )

            description = ""

            if descriptions:

                description = (
                    descriptions[0].get(
                        "value",
                        ""
                    )
                )

            cvss = None

            metrics = cna.get(
                "metrics",
                []
            )

            for metric in metrics:

                for key, value in metric.items():

                    if not isinstance(
                        value,
                        dict
                    ):
                        continue

                    score = value.get(
                        "baseScore"
                    )

                    if score is not None:

                        cvss = float(
                            score
                        )

                        break

                if cvss is not None:
                    break

            severity = get_severity(
                cvss
            )

            for item in affected:

                product = (
                    item.get(
                        "product",
                        ""
                    )
                    .lower()
                    .strip()
                )

                if (
                    not product
                    or product == "n/a"
                ):
                    continue

                versions = item.get(
                    "versions",
                    []
                )

                affected_version = ""

                for version_entry in versions:

                    if version_entry.get(
                        "lessThan"
                    ):

                        affected_version = (
                            "before "
                            + str(
                                version_entry[
                                    "lessThan"
                                ]
                            )
                        )

                        break

                    elif version_entry.get(
                        "lessThanOrEqual"
                    ):

                        affected_version = (
                            "<= "
                            + str(
                                version_entry[
                                    "lessThanOrEqual"
                                ]
                            )
                        )

                        break

                    elif version_entry.get(
                        "version"
                    ):

                        affected_version = (
                            str(
                                version_entry[
                                    "version"
                                ]
                            )
                        )

                        break

                if (
                    affected_version.lower()
                    in [
                        "",
                        "0",
                        "n/a",
                        "unknown"
                    ]
                ):
                    continue

                if (
                    product
                    not in index
                ):

                    index[
                        product
                    ] = []

                index[
                    product
                ].append({

                    "cve":
                        cve_id,

                    "product":
                        product,

                    "affected_version":
                        affected_version,

                    "cvss":
                        cvss,

                    "severity":
                        severity,

                    "description":
                        description

                })

            count += 1

            if count % 10000 == 0:

                print(
                    f"[+] Indexed {count} CVEs"
                )

        except Exception:
            continue

with open(
    "vulnerability_db/cve_index.json",
    "w"
) as f:

    json.dump(
        index,
        f,
        indent=4
    )

print(
    f"[+] CVE Index Created ({len(index)} products)"
)
