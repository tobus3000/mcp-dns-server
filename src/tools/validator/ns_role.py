"""Nameserver role detection module.

This module provides functionality to test whether a DNS server is authoritative,
a recursive resolver, or operates in mixed mode.

Example usage:
    import asyncio
    from ns_role import verify_nameserver_role

    async def main():
        for ns in ["192.168.200.1", "192.168.200.4"]:
            result = await verify_nameserver_role(ns)
            print(result)

    asyncio.run(main())
"""

import dns.flags

from src.resolver import Resolver
from src.typedefs import ToolResult


async def verify_nameserver_role(
    nameserver: str,
    domain: str = "example.com",
    authority_test_domain: str | None = None,
) -> ToolResult:
    """
    Test whether a given DNS server is authoritative, a resolver, or mixed-mode.

    Args:
        nameserver (str): IP or hostname of the DNS server to test.
        domain (str): Domain used to test recursion (default: example.com).
        authority_test_domain (str | None): Zone used to test authority.
            If None, uses the server's reverse domain.

    Returns:
        str: Human-readable report describing the detected role.
    """
    resolver = Resolver(nameservers=[nameserver])
    results = {"recursive": False, "authoritative": False}

    # --- 1. Test for recursion (resolver role) ---
    recursion_result = await resolver.async_resolve(domain, "A", nameserver=nameserver)
    if (
        recursion_result.success
        and recursion_result.response
        and recursion_result.rcode == 0
    ):
        if recursion_result.response.answer:
            results["recursive"] = True

    # --- 2. Test for authority (AA bit set) ---
    # Default to reverse lookup of the server’s own IP
    if not authority_test_domain:
        authority_test_domain = Resolver.get_reverse_name(nameserver)

    if authority_test_domain:
        soa_result = await resolver.async_resolve(
            authority_test_domain, "SOA", nameserver=nameserver
        )
        if soa_result.success and soa_result.response:
            if soa_result.response.flags & dns.flags.AA:
                results["authoritative"] = True

    # --- 3. Evaluate and report ---
    if results["authoritative"] and not results["recursive"]:
        return ToolResult(
            success=True, output=f"{nameserver} is an *authoritative* nameserver."
        )
    if results["recursive"] and not results["authoritative"]:
        return ToolResult(
            success=True, output=f"{nameserver} is a *DNS resolver* (recursive server)."
        )
    if results["authoritative"] and results["recursive"]:
        return ToolResult(
            success=True,
            output=f"{nameserver} appears to operate in *mixed mode* "
            f"(both authoritative and recursive).\n"
            f"Recommendation: Split authoritative and caching roles "
            f"onto separate servers or IP addresses for better security and performance.",
        )
    return ToolResult(
        success=False,
        error="Could not determine {nameserver}'s role — the server may be "
        + "unreachable or misconfigured.",
    )


async def verify_nameserver_role_impl(
    nameserver: str, domain: str | None, authority_test_domain: str | None
) -> ToolResult:
    """Test whether a given DNS server is authoritative, a resolver, or mixed-mode.

    Args:
        nameserver (str): IP or hostname of the DNS server to test.
        domain (str): Domain used to test recursion (default: example.com).
        authority_test_domain (str | None): Zone used to test authority.
            If None, uses the server's reverse domain.

    Returns:
        ToolResults: Human-readable report describing the detected role.
    """
    if not domain:
        domain = "example.com"
    return await verify_nameserver_role(
        nameserver=nameserver,
        domain=domain,
        authority_test_domain=authority_test_domain,
    )
