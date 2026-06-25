import re


def normalize_version(
    version
):

    if not version:

        return ""

    match = re.search(
        r'(\d+(?:\.\d+)+(?:[a-z]\d*)?)',
        version,
        re.IGNORECASE
    )

    if match:

        return match.group(1)

    return version.strip()
