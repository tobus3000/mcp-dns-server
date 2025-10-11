"""MCP Tools Implementations for MCP DNS server.

This module provides implementations for the tools exposed
by the Model Context Protocol (MCP) server.
"""
import traceback
from typing import Dict, Any, Optional
import ipaddress
import dns.message
import dns.rcode
try:
    # Try relative import first (when used as part of the package)
    from .dnssec import validate_domain, pretty_report
    from .lookalike_risk import assess_domain_risk
    from .resolver import Resolver
    from .dnstrace import Trace
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from dnssec import validate_domain, pretty_report
    from lookalike_risk import assess_domain_risk
    from resolver import Resolver
    from dnstrace import Trace

async def simple_dns_lookup_impl(hostname: str) -> Dict[str, Any]:
    """Resolve the A record of a given hostname.
    
    Args:
        hostname (str): The hostname to resolve.
        
    Returns:
        Dict[str, Any]: Dictionary containing the resolved IP addresses or error details.
    """
    record_type = 'A'
    resolver = Resolver()
    rrset, response = resolver.resolve(hostname, record_type)
    query_results: Dict[str, Any] = {}
    if not rrset:
        error_message = "No records found"
        if response:
            # Extract error type from response if available
            if isinstance(response, dns.message.Message):
                rcode_value = response.rcode()
                error_message = dns.rcode.to_text(rcode_value)
            elif hasattr(response, 'rcode'):
                error_message = dns.rcode.to_text(response.rcode())
        query_results[record_type] = {"error": error_message}
    else:
        query_results[record_type] = [str(rr) for rr in rrset]
    return {
        "hostname": hostname,
        "query_results": query_results,
        "status": "success"
    }

async def advanced_dns_lookup_impl(
    hostname: str,
    record_type: str
) -> Dict[str, Any]:
    """Perform an advanced DNS lookup for the given hostname and record type.

    Args:
        hostname (str): The hostname to resolve.
        record_type (str): The DNS record type to query (e.g., A, AAAA, MX, NS, TXT).

    Returns:
        Dict[str, Any]: Dictionary containing the resolved records or error details.
    """
    auth_nameservers = []
    resolver = Resolver(timeout=5.0)
    ns_rrset, _ = resolver.resolve(hostname, 'NS')
    if ns_rrset:
        auth_nameservers = [str(rdata) for rdata in ns_rrset]
    rrset, response = resolver.resolve(hostname, record_type)
    records = []
    if not rrset:
        rcode_value = None
        rcode_text = "No records found"
        status = "error"
        if response:
            # Extract error type from response if available
            if isinstance(response, dns.message.Message):
                rcode_value = response.rcode()
                if rcode_value == 0:
                    status = "success"
                rcode_text = dns.rcode.to_text(rcode_value)
            elif hasattr(response, 'rcode'):
                rcode_text = dns.rcode.to_text(response.rcode())
        return {
            "hostname": hostname,
            "record_type": record_type,
            "rcode": rcode_value,
            "rcode_text": rcode_text,
            "status": status
        }
    for rdata in rrset:
        if record_type == "MX":
            records.append({
                "preference": rdata.preference,
                "exchange": str(rdata.exchange)
            })
        elif record_type == "SRV":
            records.append({
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
                "target": str(rdata.target)
            })
        elif record_type == "SOA":
            records.append({
                "mname": str(rdata.mname),
                "rname": str(rdata.rname),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum
            })
        else:
            records.append(str(rdata))

    response = {
        "hostname": hostname,
        "record_type": record_type,
        "records": records,
        "status": "success"
    }
    if auth_nameservers:
        response["authoritative_nameservers"] = auth_nameservers
    return response

async def reverse_dns_lookup_impl(ip_address: str) -> Dict[str, Any]:
    """Perform a reverse DNS lookup for the given IP address.
    Args:
        ip_address (str): The IP address to perform reverse DNS lookup on.
    Returns:
        Dict[str, Any]: Dictionary containing the resolved hostnames or error details.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {
            "ip_address": ip_address,
            "error": f"Invalid IP address: {ip_address}",
            "status": "error"
        }
    rev_name = Resolver.get_reverse_name(ip_address)
    if rev_name is None:
        return {
            "ip_address": ip_address,
            "error": f"Could not get reverse DNS name for IP address: {ip_address} ({ip.version})",
            "status": "error"
        }
    resolver = Resolver(timeout=5.0)
    rrset, response = resolver.resolve(rev_name, "PTR")
    if not rrset:
        error_message = "No PTR record found"
        if response:
            # Extract error type from response if available
            if isinstance(response, dns.message.Message):
                rcode_value = response.rcode()
                error_message = dns.rcode.to_text(rcode_value)
            elif hasattr(response, 'rcode'):
                error_message = dns.rcode.to_text(response.rcode())
        return {
            "ip_address": ip_address,
            "error": error_message,
            "status": "error"
        }
    hostnames = [str(rdata) for rdata in rrset]
    return {
        "ip_address": ip_address,
        "hostnames": hostnames,
        "is_local": ip.is_private or ip.is_loopback,
        "status": "success"
    }

async def check_dnssec_impl(domain: str) -> Dict[str, Any]:
    """DNSSEC validation tool implementation.

    Args:
        domain (str): The DNSSEC enabled domain to validate.

    Returns:
        Dict[str, Any]: Validation report or error details.
    """
    try:
        return {
            "domain": domain,
            "dnssec_validation": pretty_report(validate_domain(domain)),
            "status": "success"
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "status": "error"
        }

async def lookalike_risk_impl(
    domain: str,
    check_dns: bool = False
) -> Dict[str, Any]:
    """Lookalike domain risk assessment tool implementation.
    
    Args:
        domain (str): The domain to assess for lookalike risk.
        check_dns (bool): Whether to perform DNS checks on variants.
        
    Returns:
        Dict[str, Any]: Risk assessment report.
    """
    report = assess_domain_risk(domain, check_dns=check_dns)
    return {
        "domain": domain,
        "risk_score": report.get('risk_score', None),
        "summary": f"{domain} → score={report.get('risk_score', 0):.3f}",
        "lookalike_risk_report": report.get('summary', ""),
        "variants": report.get('all_variants', []),
        "resolving_variants": report.get('resolving_variants', []),
        "details": report.get('details', {}),
        "status": "success"
    }

async def dns_troubleshooting_impl(
    domain: str,
    nameserver: Optional[str] = None
) -> Dict[str, Any]:
    """Perform comprehensive DNS troubleshooting using the Resolver class.
    
    Args:
        domain: Domain name to troubleshoot
        nameserver: Nameserver to use for the queries

    Returns:
        Dictionary containing troubleshooting results for various record types
    """
    # Create a new resolver instance using our Resolver class
    if nameserver is None:
        resolver = Resolver(timeout=5.0)
    else:
        resolver = Resolver(
            nameservers=[nameserver],
            timeout=5.0
        )
    troubleshooting_results: Dict[str, Any] = {}

    # Define the record types we want to check
    record_types = ['SOA', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']

    for record_type in record_types:
        # Get the answer from our resolver
        # No need for try/except as resolve() handles errors...
        rrset, response = resolver.resolve(domain, record_type)

        # Handle no records case or error response
        if not rrset:
            error_message = "No records found"
            if response:
                # Extract error type from response if available
                if isinstance(response, dns.message.Message):
                    rcode_value = response.rcode()
                    error_message = dns.rcode.to_text(rcode_value)
                elif hasattr(response, 'rcode'):
                    error_message = dns.rcode.to_text(response.rcode())
            troubleshooting_results[record_type] = {"error": error_message}
            continue

        # Special handling for different record types
        if record_type == 'SOA':
            soa_records = []
            for rr in rrset:
                if hasattr(rr, 'mname') and hasattr(rr, 'serial'):
                    soa_records.append({
                        "mname": str(rr.mname),
                        "rname": str(rr.rname),
                        "serial": rr.serial,
                        "refresh": rr.refresh,
                        "retry": rr.retry,
                        "expire": rr.expire,
                        "minimum": rr.minimum
                    })
            if soa_records:
                troubleshooting_results[record_type] = soa_records
            else:
                troubleshooting_results[record_type] = {"error": "Invalid SOA record format"}

        elif record_type == 'MX':
            mx_records = []
            for rr in rrset:
                if hasattr(rr, 'preference') and hasattr(rr, 'exchange'):
                    mx_records.append({
                        "preference": rr.preference,
                        "exchange": str(rr.exchange)
                    })
            if mx_records:
                troubleshooting_results[record_type] = mx_records
            else:
                troubleshooting_results[record_type] = {"error": "Invalid MX record format"}
        else:
            # For other record types, just convert to strings
            troubleshooting_results[record_type] = [str(rr) for rr in rrset]

    return {
        "domain": domain,
        "troubleshooting_results": troubleshooting_results,
        "status": "success"
    }

async def dns_trace_impl(
    domain: str
) -> Dict[str, Any]:
    """Perform a DNS trace for the given domain.

    Args:
        domain (str): The domain to trace.

    Returns:
        Dict[str, Any]: Trace report or error details.
    """
    tracer = Trace(follow_cname=True)
    tracer.perform_trace(domain.strip())
    return {
        "domain": domain,
        "dns_trace": tracer.get_dig_style(),
        "status": "success"
    }
