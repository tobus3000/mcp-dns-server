import ipaddress
from typing import Any

import dns.rcode
import dns.rdataclass
import dns.rdatatype

from dns_mcp_server.resolver import Resolver
from dns_mcp_server.typedefs import ToolResult


async def available_rdatatypes_impl() -> ToolResult:
    """Retrieve a list of all available DNS record types.

    Returns:
        ToolResult: Result object containing the list of DNS record types.
    """
    rdatatypes = [dns.rdatatype.to_text(rdtype) for rdtype in dns.rdatatype.RdataType]
    return ToolResult(success=True, output=rdatatypes)


async def simple_dns_lookup_impl(hostname: str) -> ToolResult:
    """Resolve the A record of a given hostname.

    Args:
        hostname (str): The hostname to resolve.

    Returns:
        ToolResult: Result object containing the resolved IP addresses or error details.
    """
    record_type = "A"
    resolver = Resolver()
    result = await resolver.async_resolve(hostname, record_type)

    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype,
        )
        return ToolResult(
            success=True,
            output=[str(rr) for rr in rrset] if rrset else [],
            details={
                "duration": result.duration,
                "query_name": str(result.qname),
                "query_type": dns.rdatatype.to_text(result.rdtype),
                "rcode_text": (
                    dns.rcode.to_text(result.response.rcode())
                    if result.response
                    else "No response"
                ),
            },
        )
    return ToolResult(success=False, error=result.error or "Unknown error", details={})


async def advanced_dns_lookup_impl(hostname: str, record_type: str) -> ToolResult:
    """Perform an advanced DNS lookup for the given hostname and record type.

    Args:
        hostname (str): The hostname to resolve.
        record_type (str): The DNS record type to query (e.g., A, AAAA, MX, NS, TXT).

    Returns:
        ToolResult: Result object containing the resolved records or error details.
    """
    auth_nameservers = []
    resolver = Resolver(timeout=5.0)
    supported_types = [
        dns.rdatatype.to_text(rdtype) for rdtype in dns.rdatatype.RdataType
    ]
    if record_type.upper() not in supported_types:
        return ToolResult(
            success=False,
            error=f"Unsupported record type: {record_type}",
            details={"supported_record_types": supported_types},
        )
    if not record_type == "NS":
        ns_res = await resolver.async_resolve(hostname, "NS")
        if ns_res.success and ns_res.response and ns_res.qname and ns_res.rdtype:
            rrset = ns_res.response.get_rrset(
                section=ns_res.response.answer,
                name=ns_res.qname,
                rdclass=dns.rdataclass.IN,
                rdtype=ns_res.rdtype,
            )
            auth_nameservers = [str(rr) for rr in rrset] if rrset else []

    result = await resolver.async_resolve(hostname, record_type)
    records = []
    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype,
        )
        if not rrset:
            return ToolResult(
                success=result.success,
                error="No records found",
                details={
                    "duration": result.duration,
                    "query_name": str(result.qname) if result.qname else hostname,
                    "query_type": dns.rdatatype.to_text(result.rdtype),
                    "rcode_text": result.rcode_text,
                },
            )
        records = Resolver.get_records_from_rrset(rrset)

    return ToolResult(
        success=result.success,
        output=records,
        details={
            "duration": result.duration,
            "query_name": str(result.qname) if result.qname else hostname,
            "query_type": dns.rdatatype.to_text(result.rdtype)
            if result.rdtype
            else record_type,
            "rcode_text": result.rcode_text,
            "authoritative_nameservers": auth_nameservers if auth_nameservers else None,
        },
    )


async def reverse_dns_lookup_impl(ip_address: str) -> ToolResult:
    """Perform a reverse DNS lookup for the given IP address.
    Args:
        ip_address (str): The IP address to perform reverse DNS lookup on.
    Returns:
        ToolResult: Result object containing the resolved hostnames or error details.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return ToolResult(
            success=False, error=f"Invalid IP address: {ip_address}", details={}
        )
    rev_name = Resolver.get_reverse_name(ip_address)
    if rev_name is None:
        return ToolResult(
            success=False,
            error=f"Could not get reverse DNS name for IP address: {ip_address} ({ip.version})",
            details={},
        )
    record_type = "PTR"
    resolver = Resolver()
    result = await resolver.async_resolve(rev_name, record_type)

    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype,
        )
        return ToolResult(
            success=True,
            output=[str(rr) for rr in rrset] if rrset else [],
            details={
                "duration": result.duration,
                "query_name": str(result.qname),
                "query_type": dns.rdatatype.to_text(result.rdtype),
                "rcode_text": (
                    dns.rcode.to_text(result.response.rcode())
                    if result.response
                    else "No response"
                ),
                "is_local": ip.is_private or ip.is_loopback,
            },
        )
    return ToolResult(success=False, error=result.error or "Unknown error", details={})


async def dns_troubleshooting_impl(
    domain: str, nameserver: str | None = None
) -> ToolResult:
    """Perform comprehensive DNS troubleshooting using the Resolver class.

    Args:
        domain: Domain name to troubleshoot
        nameserver: Nameserver to use for the queries

    Returns:
        Dictionary containing troubleshooting results for various record types
    """
    if nameserver is None:
        resolver = Resolver(timeout=5.0)
    else:
        resolver = Resolver(nameservers=[nameserver], timeout=5.0)
    troubleshooting_results: dict[str, Any] = {}

    # Define the record types we want to check
    record_types = ["SOA", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SPF"]

    for record_type in record_types:
        result = await resolver.async_resolve(domain, record_type)
        records = []
        if result.success and result.response and result.qname and result.rdtype:
            rrset = result.response.get_rrset(
                section=result.response.answer,
                name=result.qname,
                rdclass=dns.rdataclass.IN,
                rdtype=result.rdtype,
            )
            if rrset:
                records = Resolver.get_records_from_rrset(rrset)
        troubleshooting_results[record_type] = records
    return ToolResult(
        success=True, output=troubleshooting_results, details={"domain": domain}
    )
