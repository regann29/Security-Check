"""Clean up and safety-check whatever the user typed as their domain."""
import ipaddress
import re
from urllib.parse import urlparse


class InvalidDomain(ValueError):
    pass


_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED = (".local", ".localhost", ".internal", ".lan", ".home", ".corp",
            ".test", ".invalid", ".example")


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value:
        raise InvalidDomain("Please enter a domain, like example.com.")

    # Accept a pasted web address or email address and pull out the domain.
    if "//" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.split(":")[0].rstrip(".")
    if value.startswith("www."):
        value = value[4:]

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InvalidDomain("Please enter a domain name (like example.com), not an IP address.")

    labels = value.split(".")
    if (
        not value
        or len(value) > 253
        or len(labels) < 2
        or value == "localhost"
        or value.endswith(_BLOCKED)
        or labels[-1].isdigit()
        or not all(_LABEL.match(label) for label in labels)
    ):
        raise InvalidDomain("That doesn't look like a valid domain. Try something like example.com.")
    return value
