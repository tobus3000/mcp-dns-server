import re
from typing import Tuple

import idna


async def validate_fqdn(domain: str) -> Tuple[bool, str]:
    """
    Validate a Fully Qualified Domain Name (FQDN) according to DNS RFC rules.
    Covers RFC 1035, RFC 1123, and IDNA processing.

    Returns:
        Tuple[bool, str]: (is_valid, message) where is_valid is True if the FQDN
        is valid and message describes the result or error.
    """

    if not isinstance(domain, str) or not domain:
        return False, "Domain must be a non-empty string"

    # Remove a trailing dot if present (FQDN canonical form)
    if domain.endswith("."):
        domain = domain[:-1]

    # Convert IDN to ASCII (punycode). If this fails → invalid.
    try:
        domain_ascii = idna.encode(domain).decode("ascii")
    except idna.IDNAError as e:
        return False, f"Invalid IDN encoding: {str(e)}"

    # Entire FQDN length (in ASCII) must be <= 253 chars
    if len(domain_ascii) > 253:
        description = f"FQDN length {len(domain_ascii)} exceeds maximum " "of 253 characters"
        return False, description

    # Split into labels
    labels = domain_ascii.split(".")

    # No empty labels allowed (e.g. "example..com")
    if any(label == "" for label in labels):
        description = (
            "FQDN contains empty labels (consecutive dots or trailing " "dot after removal)"
        )
        return False, description

    # RFC label regex:
    # - Letters, digits, hyphens
    # - Cannot start or end with hyphen
    # - Length 1–63
    label_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

    for label in labels:
        if not label_regex.match(label):
            description = (
                f"Label '{label}' is invalid (must be 1-63 chars, "
                "alphanumeric/hyphen, not start/end with hyphen)"
            )
            return False, description

    return True, "Valid FQDN"
