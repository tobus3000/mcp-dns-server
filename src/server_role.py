import dns.flags
from typing import Optional
try:
    from .typedefs import ToolResult
    from .resolver import Resolver
except ImportError:
    from typedefs import ToolResult
    from resolver import Resolver

async def test_nameserver_role(
    nameserver: str,
    domain: str = "example.com",
    authority_test_domain: Optional[str] = None,
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
    if recursion_result.success and recursion_result.response and recursion_result.rcode == 0:
        if recursion_result.response.answer:
            results["recursive"] = True

    # --- 2. Test for authority (AA bit set) ---
    # Default to reverse lookup of the server’s own IP
    if not authority_test_domain:
        authority_test_domain = Resolver.get_reverse_name(nameserver)

    if authority_test_domain:
        soa_result = await resolver.async_resolve(
            authority_test_domain,
            "SOA",
            nameserver=nameserver
        )
        if soa_result.success and soa_result.response:
            if soa_result.response.flags & dns.flags.AA:
                results["authoritative"] = True

    # --- 3. Evaluate and report ---
    if results["authoritative"] and not results["recursive"]:
        return ToolResult(
            success=True,
            output=f"{nameserver} is an *authoritative* nameserver."
        )
    if results["recursive"] and not results["authoritative"]:
        return ToolResult(
            success=True,
            output=f"{nameserver} is a *DNS resolver* (recursive server)."
        )
    if results["authoritative"] and results["recursive"]:
        return ToolResult(
            success=True,
            output=f"{nameserver} appears to operate in *mixed mode* "
            f"(both authoritative and recursive).\n"
            f"Recommendation: Split authoritative and caching roles "
            f"onto separate servers or IP addresses for better security and performance."
        )
    return ToolResult(
        success=False,
        error="Could not determine {nameserver}'s role — the server may be " 
        + "unreachable or misconfigured."
    )


# Example usage
if __name__ == "__main__":
    import asyncio

    async def main():
        for ns in ["192.168.200.1", "192.168.200.4"]:
            result = await test_nameserver_role(ns)
            print(result)

    asyncio.run(main())
