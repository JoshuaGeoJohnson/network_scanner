import re


def extract_version(text):

    if not text:
        return None

    text = str(text).lower()

    match = re.search(
        r'(\d+(?:\.\d+)+(?:p\d+)?)',
        text
    )

    if match:
        return match.group(1)

    return None


def normalize_version(version):

    version = extract_version(
        version
    )

    if not version:
        return None

    version = version.replace(
        "p",
        "."
    )

    return [
        int(x)
        for x in version.split(".")
    ]


def compare_versions(
    v1,
    v2
):

    a = normalize_version(v1)
    b = normalize_version(v2)

    if not a or not b:
        return None

    max_len = max(
        len(a),
        len(b)
    )

    while len(a) < max_len:
        a.append(0)

    while len(b) < max_len:
        b.append(0)

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def version_less_or_equal(
    detected,
    target
):

    result = compare_versions(
        detected,
        target
    )

    if result is None:
        return None

    return result <= 0


def version_less_than(
    detected,
    target
):

    result = compare_versions(
        detected,
        target
    )

    if result is None:
        return None

    return result < 0
