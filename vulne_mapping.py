import json
import subprocess

from utils import load_json
from utils import save_json

from product_normalizer import (
    normalize_product
)

from version_utils import (
    extract_version
)


def map_vulne_cves():

    print(
        "[+] Vulne API Mapping"
    )

    fingerprints = load_json(
        "results/fingerprints.json"
    )

    services = []

    seen = set()

    for fp in fingerprints:

        service = fp.get(
            "service",
            ""
        )

        version = fp.get(
            "version",
            ""
        )

        if not version:
            continue

        clean_version = extract_version(
            version
        )

        if clean_version:
            version = clean_version

        product = normalize_product(
            service,
            version
        )

        key = (
            product,
            version
        )

        if key in seen:
            continue

        seen.add(key)

        services.append({

            "service":
                product,

            "version":
                version

        })

    with open(
        "vulne/services.json",
        "w"
    ) as f:

        json.dump(
            services,
            f,
            indent=4
        )

    subprocess.run(
        [
            "python3",
            "cve_retriever.py"
        ],
        cwd="vulne",
        check=False
    )

    try:

        with open(
            "vulne/vulnerability_results.json",
            "r"
        ) as f:

            results = json.load(f)

    except Exception:

        results = []

    save_json(
        "results/vulne_cves.json",
        results
    )

    print(
        "[+] Vulne Mapping Finished"
    )
