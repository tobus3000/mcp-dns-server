"""MCP Tools Implementations for MCP DNS server.

This module provides implementations for the tools exposed
by the Model Context Protocol (MCP) server.
"""
import traceback
from typing import Dict, Any, Optional
import ipaddress
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rdataclass
try:
    # Try relative import first (when used as part of the package)
    from .dnssec import validate_domain, pretty_report
    from .lookalike_risk import assess_domain_risk
    from .resolver import Resolver
    from .dnstrace import Trace
    from .typedefs import ToolResult
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from dnssec import validate_domain, pretty_report
    from lookalike_risk import assess_domain_risk
    from resolver import Resolver
    from dnstrace import Trace
    from typedefs import ToolResult

async def simple_dns_lookup_impl(hostname: str) -> ToolResult:
    """Resolve the A record of a given hostname.
    
    Args:
        hostname (str): The hostname to resolve.
        
    Returns:
        ToolResult: Result object containing the resolved IP addresses or error details.
    """
    record_type = 'A'
    resolver = Resolver()
    result = await resolver.async_resolve(hostname, record_type)

    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype
        )
        return ToolResult(
            success=True,
            output=[str(rr) for rr in rrset] if rrset else [],
            details={
                "duration": result.duration,
                "query_name": str(result.qname),
                "query_type": dns.rdatatype.to_text(result.rdtype),
                "rcode_text": dns.rcode.to_text(
                    result.response.rcode()
                ) if result.response else "No response"
            }
        )
    return ToolResult(
        success=False,
        error=result.error or "Unknown error",
        details={}
    )

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
    ns_res = await resolver.async_resolve(hostname, "NS")
    if ns_res.success and ns_res.response and ns_res.qname and ns_res.rdtype:
        rrset = ns_res.response.get_rrset(
            section=ns_res.response.answer,
            name=ns_res.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=ns_res.rdtype
        )
        auth_nameservers = [str(rr) for rr in rrset] if rrset else []

    result = await resolver.async_resolve(hostname, record_type)
    records = []
    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype
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
                }
            )
        records = Resolver.get_records_from_rrset(rrset)

    return ToolResult(
        success=result.success,
        output=records,
        details={
            "duration": result.duration,
            "query_name": str(result.qname) if result.qname else hostname,
            "query_type": dns.rdatatype.to_text(result.rdtype) if result.rdtype else record_type,
            "rcode_text": result.rcode_text,
            "authoritative_nameservers": auth_nameservers if auth_nameservers else None
        }
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
            success=False,
            error=f"Invalid IP address: {ip_address}",
            details={}
        )
    rev_name = Resolver.get_reverse_name(ip_address)
    if rev_name is None:
        return ToolResult(
            success=False,
            error=f"Could not get reverse DNS name for IP address: {ip_address} ({ip.version})",
            details={}
        )
    record_type = 'PTR'
    resolver = Resolver()
    result = await resolver.async_resolve(rev_name, record_type)

    if result.success and result.response and result.qname and result.rdtype:
        rrset = result.response.get_rrset(
            section=result.response.answer,
            name=result.qname,
            rdclass=dns.rdataclass.IN,
            rdtype=result.rdtype
        )
        return ToolResult(
            success=True,
            output=[str(rr) for rr in rrset] if rrset else [],
            details={
                "duration": result.duration,
                "query_name": str(result.qname),
                "query_type": dns.rdatatype.to_text(result.rdtype),
                "rcode_text": dns.rcode.to_text(
                    result.response.rcode()
                ) if result.response else "No response",
                "is_local": ip.is_private or ip.is_loopback
            }
        )
    return ToolResult(
        success=False,
        error=result.error or "Unknown error",
        details={}
    )

async def check_dnssec_impl(domain: str) -> ToolResult:
    """DNSSEC validation tool implementation.

    Args:
        domain (str): The DNSSEC enabled domain to validate.

    Returns:
        ToolResult: Validation report or error details.
    """
    try:
        return ToolResult(
            success=True,
            output=pretty_report(validate_domain(domain))
        )
    except Exception as e:
        return ToolResult(
            success=False,
            error=str(e),
            details={"traceback": traceback.format_exc()}
        )

async def lookalike_risk_impl(domain: str, check_dns: bool = False) -> ToolResult:
    """Lookalike domain risk assessment tool implementation.
    
    Args:
        domain (str): The domain to assess for lookalike risk.
        check_dns (bool): Whether to perform DNS checks on variants.
        
    Returns:
        Dict[str, Any]: Risk assessment report.
    """
    report = assess_domain_risk(domain, check_dns=check_dns)
    return ToolResult(
        success=True,
        output={
            "domain": domain,
            "risk_score": report.get('risk_score', None),
            "summary": f"{domain} → {report.get('summary', '')}",
            "variants": report.get('all_variants', []),
            "resolving_variants": report.get('resolving_variants', [])
        },
        details=report.get('details', {})
    )

async def dns_troubleshooting_impl(domain: str, nameserver: Optional[str] = None) -> ToolResult:
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
        resolver = Resolver(
            nameservers=[nameserver],
            timeout=5.0
        )
    troubleshooting_results: Dict[str, Any] = {}

    # Define the record types we want to check
    record_types = ['SOA', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SPF']

    for record_type in record_types:
        result = await resolver.async_resolve(domain, record_type)
        records = []
        if result.success and result.response and result.qname and result.rdtype:
            rrset = result.response.get_rrset(
                section=result.response.answer,
                name=result.qname,
                rdclass=dns.rdataclass.IN,
                rdtype=result.rdtype
            )
            if rrset:
                records = Resolver.get_records_from_rrset(rrset)
        troubleshooting_results[record_type] = records
    return ToolResult(
        success=True,
        output=troubleshooting_results,
        details={
            "domain": domain
        }
    )

async def dns_trace_impl(domain: str) -> ToolResult:
    """Perform a DNS trace for the given domain.

    Args:
        domain (str): The domain to trace.

    Returns:
        Dict[str, Any]: Trace report or error details.
    """
    tracer = Trace(follow_cname=True)
    tracer.perform_trace(domain.strip())
    return ToolResult(
        success=True,
        output={
            "domain": domain,
            "dns_trace": tracer.get_dig_style()
        }
    )
