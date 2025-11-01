import aiohttp
import time
import dns.rcode
from resolver import Resolver
from typedefs import ToolResult

# Cache for IANA TLDs (memory-only)
_IANA_TLD_CACHE: set[str] = set()
_IANA_TLD_LAST_FETCH = 0
_IANA_TLD_CACHE_TTL = 86400  # 1 day

async def fetch_iana_tlds(force_refresh: bool = False) -> set[str]:
    """Fetch the official IANA TLD list (cached for 1 day)."""
    global _IANA_TLD_CACHE, _IANA_TLD_LAST_FETCH
    if not force_refresh and (
        time.time() - _IANA_TLD_LAST_FETCH < _IANA_TLD_CACHE_TTL
    ) and _IANA_TLD_CACHE:
        return _IANA_TLD_CACHE

    url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url,timeout=aiohttp.ClientTimeout(10)) as resp:
                text = await resp.text()
                tlds = {
                    line.strip().lower()
                    for line in text.splitlines()
                    if line and not line.startswith("#")
                }
                _IANA_TLD_CACHE = tlds
                _IANA_TLD_LAST_FETCH = time.time()
                return tlds
    except Exception:
        # Network unavailable or blocked → fall back later
        return set()


async def is_valid_tld(domain: str, alternative_roots: list[str] | None = None) -> ToolResult:
    """
    Check if the TLD of a given domain is valid, supporting both global (IANA)
    and enterprise (non-public) DNS root environments.

    Strategy:
      1. Check IANA list if available → authoritative source.
      2. If not in IANA, try DNS lookup via enterprise or local resolvers.
         - Query NS for the TLD directly.
         - Consider it valid if an authoritative response exists.

    Args:
        domain (str): Domain name to test (e.g. "example.com").
        alternative_roots (list[str] | None): Optional IPs of enterprise root DNS servers.
                                             Falls back to resolver.nameservers if not provided.

    Returns:
        bool: True if the TLD is valid (IANA or enterprise-recognized), else False.
    """
    domain = domain.strip().rstrip('.')
    labels = domain.split('.')
    if len(labels) == 0:
        return ToolResult(
                success=False,
                error="No top-level domain could be derived from domain name."
            )

    tld = labels[-1].lower()
    tld_zone = f"{tld}."

    # Step 1: Check IANA TLDs first (cached)
    iana_tlds = await fetch_iana_tlds()
    if iana_tlds and tld in iana_tlds:
        return ToolResult(
            success=True,
            output=(f"TLD {tld_zone} is an official top-level domain and "
                    + "is part of the IANA TLD list.")
        )

    resolver = Resolver()
    # Step 2: Try enterprise/local root servers
    target_nameservers = alternative_roots or resolver.resolver.nameservers
    for ns in target_nameservers:
        result = await resolver.async_resolve(
            domain=tld_zone,
            rdtype="NS",
            nameserver=str(ns)
        )

        if result.success and result.rcode == dns.rcode.NOERROR:
            # Accept if we got any delegation or authoritative NS response
            if result.response and (result.response.answer or result.response.authority):
                return ToolResult(
                    success=True,
                    output=f"TLD {tld_zone} is a valid top-level domain in this environment."
                )

        elif result.rcode == dns.rcode.NXDOMAIN:
            # Authoritatively does not exist
            return ToolResult(
                success=False,
                error=f"The TLD {tld_zone} does not authoritatively exist."
            )

    return ToolResult(
        success=False,
        error=f"The TLD {tld_zone} is not an official top-level-domain."
    )

async def tld_check_impl(domain: str) -> ToolResult:
    """Performs a TLD validation for the given domain.

    Args:
        domain (str): The domain to extract the top-level-domain from.

    Returns:
        ToolResult: The result of the verification.
    """
    return await is_valid_tld(domain=domain.strip())
