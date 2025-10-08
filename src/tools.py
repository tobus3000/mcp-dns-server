"""MCP Tools Implementations for MCP DNS server.

This module provides implementations for the tools exposed
by the Model Context Protocol (MCP) server.
"""
import socket
import traceback
from typing import Dict, Any, Optional
import dns.resolver
import dns.reversename
import dns.message
import dns.rcode
try:
    # Try relative import first (when used as part of the package)
    from .dnssec import validate_domain, pretty_report
    from .lookalike_risk import assess_domain_risk
    from .resolver import Resolver
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from dnssec import validate_domain, pretty_report
    from lookalike_risk import assess_domain_risk
    from resolver import Resolver

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

async def advanced_dns_lookup_impl(resolver, hostname: str, record_type: str) -> Dict[str, Any]:
    #TODO: Change to use our Resolver class.
    #TODO: Change exception handling to use our Resolver class results.
    #TODO: Smaller try/except blocks for more specific error handling.
    try:
        # Get authoritative nameservers first
        auth_nameservers = []
        try:
            ns_result = resolver.resolve(hostname, 'NS')
            auth_nameservers = [str(rdata) for rdata in ns_result]
        except Exception:
            pass  # If NS lookup fails, continue with main record lookup
        result = resolver.resolve(hostname, record_type)
        records = []
        for rdata in result:
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
    except dns.resolver.NXDOMAIN:
        return {
            "hostname": hostname,
            "record_type": record_type,
            "error": f"Hostname {hostname} does not exist",
            "status": "error"
        }
    except dns.resolver.NoAnswer:
        return {
            "hostname": hostname,
            "record_type": record_type,
            "error": f"No {record_type} record found for {hostname}",
            "status": "error"
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "record_type": record_type,
            "error": str(e),
            "status": "error"
        }

async def reverse_dns_lookup_impl(resolver, ip_address: str) -> Dict[str, Any]:
    #TODO: Change to use our Resolver class.
    #TODO: Change exception handling to use our Resolver class results.
    try:
        socket.inet_aton(ip_address)
        rev_name = dns.reversename.from_address(ip_address)
        result = resolver.resolve(rev_name, "PTR")
        hostnames = [str(rdata) for rdata in result]
        return {
            "ip_address": ip_address,
            "hostnames": hostnames,
            "status": "success"
        }
    except socket.error:
        return {
            "ip_address": ip_address,
            "error": f"Invalid IP address: {ip_address}",
            "status": "error"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "ip_address": ip_address,
            "error": f"No PTR record found for {ip_address}",
            "status": "error"
        }
    except Exception as e:
        return {
            "ip_address": ip_address,
            "error": str(e),
            "status": "error"
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
        "summary": f"{domain} → score={report['risk_score']:.3f}",
        "lookalike_risk_report": report['summary'],
        "variants": report['sample_variants'],
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
        # Get the answer from our new resolver
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
            troubleshooting_results[record_type] = soa_records if soa_records else {"error": "Invalid SOA record format"}

        elif record_type == 'MX':
            mx_records = []
            for rr in rrset:
                if hasattr(rr, 'preference') and hasattr(rr, 'exchange'):
                    mx_records.append({
                        "preference": rr.preference,
                        "exchange": str(rr.exchange)
                    })
            troubleshooting_results[record_type] = mx_records if mx_records else {"error": "Invalid MX record format"}
        else:
            # For other record types, just convert to strings
            troubleshooting_results[record_type] = [str(rr) for rr in rrset]

    return {
        "domain": domain,
        "troubleshooting_results": troubleshooting_results,
        "status": "success"
    }
