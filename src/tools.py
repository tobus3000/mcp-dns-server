import dns.resolver
import dns.name, dns.reversename, dns.dnssec, dns.query, dns.message, dns.rdatatype, dns.rdataclass
import traceback
import socket
from typing import Dict, Any
import traceback

try:
    # Try relative import first (when used as part of the package)
    from .dnssec import validate_domain, pretty_report
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from dnssec import validate_domain, pretty_report

# Use dns.resolver.Timeout instead of dns.exception.Timeout

async def simple_dns_lookup_impl(resolver, hostname: str) -> Dict[str, Any]:
    try:
        result = resolver.resolve(hostname, 'A')
        ip_addresses = [str(ip) for ip in result]
        return {
            "hostname": hostname,
            "ip_addresses": ip_addresses,
            "status": "success"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "hostname": hostname,
            "error": f"Hostname {hostname} does not exist",
            "status": "error"
        }
    except dns.resolver.NoAnswer:
        return {
            "hostname": hostname,
            "error": f"No A record found for {hostname}",
            "status": "error"
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "error": str(e),
            "status": "error"
        }

async def advanced_dns_lookup_impl(resolver, hostname: str, record_type: str) -> Dict[str, Any]:
    try:
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
        return {
            "hostname": hostname,
            "record_type": record_type,
            "records": records,
            "status": "success"
        }
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

async def check_dnssec_impl(resolver, domain: str) -> Dict[str, Any]:
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

async def dns_troubleshooting_impl(resolver, domain: str) -> Dict[str, Any]:
    troubleshooting_results = {}
    # SOA
    try:
        soa_result = resolver.resolve(domain, 'SOA')
        troubleshooting_results['SOA'] = [{
            "mname": str(rdata.mname),
            "rname": str(rdata.rname),
            "serial": rdata.serial,
            "refresh": rdata.refresh,
            "retry": rdata.retry,
            "expire": rdata.expire,
            "minimum": rdata.minimum
        } for rdata in soa_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['SOA'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['SOA'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['SOA'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['SOA'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['SOA'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # A
    try:
        a_result = resolver.resolve(domain, 'A')
        troubleshooting_results['A'] = [str(ip) for ip in a_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['A'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['A'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['A'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['A'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['A'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # AAAA
    try:
        aaaa_result = resolver.resolve(domain, 'AAAA')
        troubleshooting_results['AAAA'] = [str(ip) for ip in aaaa_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['AAAA'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['AAAA'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['AAAA'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['AAAA'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['AAAA'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # CNAME
    try:
        cname_result = resolver.resolve(domain, 'CNAME')
        troubleshooting_results['CNAME'] = [str(rdata) for rdata in cname_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['CNAME'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['CNAME'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['CNAME'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['CNAME'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['CNAME'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # MX
    try:
        mx_result = resolver.resolve(domain, 'MX')
        troubleshooting_results['MX'] = [
            {"preference": rdata.preference, "exchange": str(rdata.exchange)}
            for rdata in mx_result
        ]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['MX'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['MX'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['MX'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['MX'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['MX'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # NS
    try:
        ns_result = resolver.resolve(domain, 'NS')
        troubleshooting_results['NS'] = [str(rdata) for rdata in ns_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['NS'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['NS'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['NS'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['NS'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['NS'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    # TXT
    try:
        txt_result = resolver.resolve(domain, 'TXT')
        troubleshooting_results['TXT'] = [str(rdata) for rdata in txt_result]
    except dns.resolver.NXDOMAIN:
        troubleshooting_results['TXT'] = {"error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        troubleshooting_results['TXT'] = {"error": "NoAnswer"}
    except dns.resolver.NoNameservers:
        troubleshooting_results['TXT'] = {"error": "NoNameservers"}
    except dns.resolver.Timeout:
        troubleshooting_results['TXT'] = {"error": "Timeout"}
    except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
        troubleshooting_results['TXT'] = {"error": "System error during DNS resolution"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "error"}
    return {
        "domain": domain,
        "troubleshooting_results": troubleshooting_results,
        "status": "success"
    }
