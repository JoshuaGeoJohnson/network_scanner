import json

from utils import load_json
from utils import save_json

from version_utils import (
    version_less_or_equal,
    extract_version
)

from product_normalizer import (
    normalize_product
)


def map_cves():

    print("[+] Mapping CVEs")

    fingerprints = load_json(
        "results/fingerprints.json"
    )

    with open(
        "vulnerability_db/cve_index.json",
        "r"
    ) as f:

        cve_index = json.load(f)

    findings = []

    for fp in fingerprints:

        service = fp.get(
            "service",
            ""
        ).lower()

        raw_version = fp.get(
            "version",
            ""
        )

        ip = fp.get(
            "ip",
            ""
        )

        port = fp.get(
            "port",
            ""
        )

        if service in [
            "",
            "unknown",
            "anydesk remote access"
        ]:
            continue

        if raw_version == "":
            continue

        detected_version = extract_version(
            raw_version
        )

        if detected_version:

            version = detected_version

        else:

            version = raw_version

        product = normalize_product(
            service,
            raw_version
        )

        print(
            f"[+] Searching {product} {version}"
        )

        vulnerabilities = []

        seen = set()

        service_cves = cve_index.get(
            product,
            []
        )

        for cve in service_cves:

            try:

                cve_id = cve.get(
                    "cve",
                    ""
                )

                if cve_id in seen:
                    continue

                affected_version = cve.get(
                    "affected_version",
                    ""
                )

                if affected_version == "":
                    continue

                result = None

                if affected_version.lower().startswith(
                    "before "
                ):

                    target = (
                        affected_version
                        .replace(
                            "before ",
                            ""
                        )
                        .strip()
                    )

                    result = version_less_or_equal(
                        version,
                        target
                    )

                elif affected_version.startswith(
                    "<="
                ):

                    target = (
                        affected_version
                        .replace(
                            "<=",
                            ""
                        )
                        .strip()
                    )

                    result = version_less_or_equal(
                        version,
                        target
                    )

                else:

                    result = version_less_or_equal(
                        version,
                        affected_version
                    )

                if result is False:
                    continue

                if result is True:

                    version_status = (
                        "Affected"
                    )

                else:

                    version_status = (
                        "Unknown"
                    )

                vulnerabilities.append({

                    "cve":
                        cve_id,

                    "cvss":
                        cve.get(
                            "cvss",
                            None
                        ),

                    "severity":
                        cve.get(
                            "severity",
                            "Unknown"
                        ),

                    "affected_version":
                        affected_version,

                    "version_check":
                        version_status,

                    "description":
                        cve.get(
                            "description",
                            ""
                        )[:300]

                })

                seen.add(
                    cve_id
                )

            except Exception:

                continue

        vulnerabilities.sort(

            key=lambda x:
            x["cvss"]
            if x["cvss"] is not None
            else 0,

            reverse=True
        )

        findings.append({

            "ip":
                ip,

            "port":
                port,

            "service":
                service,

            "product":
                product,

            "detected_version":
                version,

            "total_cves":
                len(
                    vulnerabilities
                ),

            "vulnerabilities":
                vulnerabilities[:50]

        })

    save_json(
        "results/cves.json",
        findings
    )

    print(
        "[+] CVE Mapping Finished"
    )
