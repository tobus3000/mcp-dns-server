"""DNS resolution utilities for the MCP DNS server.

This module provides a Resolver class that encapsulates DNS resolution functionality,
including DNSSEC-related record fetching and domain name manipulation. It uses
dnspython as the underlying DNS resolution engine.
"""
import socket
import asyncio
import time
from typing import Tuple, Optional, List, Dict, Any
import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.rcode
import dns.message
import dns.rdatatype
import dns.flags
import dns.asyncquery
try:
    from .typedefs import QueryResult
except ImportError:
    from typedefs import QueryResult

# Type aliases
SOARecord = dns.rdtypes.ANY.SOA.SOA
RRset = dns.rrset.RRset
Message = dns.message.Message

DEFAULT_TIMEOUT = 5.0
DEFAULT_EDNS_SIZE = 1232  # Conservative EDNS buffer size

class Resolver:
    """DNS resolver class providing high-level DNS resolution functionality.

    This class wraps dnspython's resolver with additional utility methods for
    DNSSEC-related operations and domain name handling.

    Attributes:
        default_timeout (float): Default timeout for DNS queries in seconds.
        resolver (dns.resolver.Resolver): Underlying dnspython resolver instance.
    """
    allowed_record_types = [
        "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV",
        "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CAA", "SPF", "LOC",
        "HINFO", "RP", "AFSDB", "CERT", "DNAME", "SSHFP", "TLSA", "URI", "SMIMEA",
        "OPENPGPKEY"
    ]

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = DEFAULT_TIMEOUT
    ):
        """Initialize the resolver with optional nameservers and timeout.

        Args:
            nameservers: Optional list of nameserver IP addresses to use.
            timeout: Query timeout in seconds (default: 5.0).
        """
        self.default_timeout = timeout
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    async def async_resolve(
        self,
        domain: str,
        rdtype: str,
        nameserver: str | None = None,
        use_tcp: bool = False,
        use_edns: bool = True,
        payload_size: int = DEFAULT_EDNS_SIZE,
        flags: int = 0,
        options: list | None = None,
        timeout: float = DEFAULT_TIMEOUT
    ) -> QueryResult:
        """Asynchronously resolve a single RRset using the configured resolver.

        Args:
            qname: The domain name to query.
            rdtype: DNS record type to query for.
            nameserver: Optional specific nameserver to query.
            use_tcp: Whether to use TCP for the query (default: False).
            use_edns: Whether to use EDNS (default: True).
            payload_size: EDNS payload size (default: 1232).
            flags: EDNS flags to set (default: 0).
            timeout: Optional query timeout override.

        Returns:
            QueryResult: Result of the DNS query operation.
        """
        try:
            qname = dns.name.from_text(domain)
            rdtype_obj = dns.rdatatype.from_text(rdtype)

            # Create the query message
            query = dns.message.make_query(
                qname,
                rdtype_obj,
                want_dnssec=bool(flags & dns.flags.DO)
            )

            # Add EDNS if requested
            if use_edns:
                query.use_edns(
                    0,  # EDNS version 0
                    flags,
                    payload_size,
                    options=options if options else []
                )
            if nameserver is None:
                if not self.resolver.nameservers:
                    return QueryResult(
                        success=False,
                        error="No nameservers configured in resolver",
                        details={}
                    )
                nameserver = str(self.resolver.nameservers[0])

            start_time = time.time()
            # Send query
            if use_tcp:
                response = await dns.asyncquery.tcp(
                    query,
                    nameserver,
                    timeout=timeout
                )
            else:
                try:
                    response = await dns.asyncquery.udp(
                        query,
                        nameserver,
                        timeout=timeout
                    )
                    if response.flags & dns.flags.TC:  # Truncated, retry with TCP
                        response = await dns.asyncquery.tcp(
                            query,
                            nameserver,
                            timeout=timeout
                        )
                except Exception as e:
                    if "Message too big" in str(e):
                        # UDP message too large, retry with TCP
                        response = await dns.asyncquery.tcp(
                            query,
                            nameserver,
                            timeout=timeout
                        )
                    else:
                        raise

            duration = time.time() - start_time
            return QueryResult(
                success=True,
                duration=duration,
                qname=qname,
                rdtype=rdtype_obj,
                response=response,
                rcode=response.rcode(),
                rcode_text=dns.rcode.to_text(response.rcode()),
                details={
                    'flags': response.flags,
                    'answer_count': len(response.answer),
                    'authority_count': len(response.authority),
                    'additional_count': len(response.additional),
                    'has_edns': response.edns >= 0,
                    'is_truncated': bool(response.flags & dns.flags.TC)
                }
            )

        except (dns.exception.DNSException, socket.error, asyncio.TimeoutError) as e:
            return QueryResult(
                success=False,
                error=str(e),
                details={'exception_type': type(e).__name__}
            )
        except Exception as e:
            return QueryResult(
                success=False,
                error=f"Unexpected error: {str(e)}",
                details={'exception_type': type(e).__name__}
            )

    def resolve(
        self,
        qname: str,
        rdtype: str,
        nameserver: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Tuple[Optional[RRset], Optional[Message]]:
        """Resolve a single RRset using the configured resolver.

        Args:
            qname: The domain name to query.
            rdtype: DNS record type to query for.
            nameserver: Optional specific nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            Tuple containing:
            - RRset object or None if no records found
            - DNS message response or None if query failed
        """
        if rdtype not in self.allowed_record_types:
            return (None, None)

        if timeout is not None:
            self.resolver.lifetime = timeout

        # Store original nameservers if we're using a specific one
        original_ns = None
        if nameserver:
            original_ns = self.resolver.nameservers
            self.resolver.nameservers = [nameserver]

        try:
            answer = self.resolver.resolve(
                qname,
                rdtype,
                raise_on_no_answer=False
            )
            result = (answer.rrset, answer.response)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            result = (None, getattr(e, 'response', None))

        # Restore original settings
        if nameserver and original_ns is not None:
            self.resolver.nameservers = original_ns
        if timeout is not None:
            self.resolver.lifetime = self.default_timeout

        return result

    def fetch_dnskey(
        self,
        qname: str,
        nameserver: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Tuple[Optional[RRset], Optional[Message]]:
        """Fetch DNSKEY records for the specified domain.

        Args:
            qname: Domain name to fetch DNSKEY records for.
            nameserver: Optional specific nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            Tuple of (DNSKEY RRset, DNS message) or (None, None) if not found.
        """
        return self.resolve(qname, 'DNSKEY', nameserver, timeout)

    def fetch_ds(
        self,
        qname: str,
        nameserver: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Tuple[Optional[RRset], Optional[Message]]:
        """Fetch DS records for the specified domain.

        Args:
            qname: Domain name to fetch DS records for.
            nameserver: Optional specific nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            Tuple of (DS RRset, DNS message) or (None, None) if not found.
        """
        return self.resolve(qname, 'DS', nameserver, timeout)

    def get_soa_serial(
        self,
        zone_name: str,
        nameserver: str,
        timeout: Optional[float] = None
    ) -> Optional[int]:
        """Get the SOA serial number for a zone from a specific nameserver.

        Args:
            zone_name: The zone name to query.
            nameserver: Nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            SOA serial number as integer, or None if not found/error.
        """
        rrset, _ = self.resolve(zone_name, 'SOA', nameserver, timeout)
        if rrset and len(rrset) > 0:
            soa_record = rrset[0]
            if isinstance(soa_record, SOARecord):
                return soa_record.serial
        return None

    @staticmethod
    def get_parent_name(qname: str) -> str:
        """Get the parent zone name for a given domain name.

        Args:
            qname: The domain name to find the parent zone for.

        Returns:
            Parent zone name as a string, with proper dot handling.
        """
        name = dns.name.from_text(qname)
        if len(name) == 1:
            return '.'
        parent = name.parent()
        # Strip trailing dot except for root zone
        parent_text = parent.to_text()
        return parent_text if parent_text == '.' else parent_text.rstrip('.')

    @staticmethod
    def get_reverse_name(ip_address: str) -> Optional[str] | None:
        """Get the reverse DNS name for a given IP address.

        Args:
            ip_address: The IP address to convert to a reverse DNS name.
        
        Returns:
            The reverse DNS name as a string, or None if the IP is invalid.
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            return rev_name.to_text().rstrip('.')
        except dns.exception.SyntaxError:
            return None

    @staticmethod
    def get_records_from_rrset(rrset: RRset) -> List[Dict[str, Any]]:
        """Extracts the records from a given RRset.
        
        Args:
            rrset: The RRset from which we extract the records.
            
        Returns:
            A list of dict/str or empty list when no records are found.
        """
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        records = []
        for rdata in rrset:
            if rdtype in ["A", "AAAA"]:
                records.append({
                    "address": str(rdata),
                    "ttl": rrset.ttl
                })
            elif rdtype in ["CNAME", "NS", "PTR"]:
                records.append({
                    "target": str(rdata),
                    "ttl": rrset.ttl
                })
            elif rdtype in ["TXT", "SPF"]:
                records.append({
                    "strings": str(rdata),
                    "ttl": rrset.ttl
                })
            elif rdtype == "MX":
                records.append({
                    "preference": rdata.preference,
                    "exchange": str(rdata.exchange),
                    "ttl": rrset.ttl,
                })
            elif rdtype == "SRV":
                records.append({
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "port": rdata.port,
                    "target": str(rdata.target),
                    "ttl": rrset.ttl,
                })
            elif rdtype == "SOA":
                records.append({
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                    "ttl": rrset.ttl,
                })
            elif rdtype == "DS":
                records.append({
                    "key_tag": rdata.key_tag,
                    "algorithm": rdata.algorithm,
                    "digest_type": rdata.digest_type,
                    "digest": rdata.digest,
                    "ttl": rrset.ttl,
                })
            elif rdtype == "RRSIG":
                records.append({
                    "type_covered": rdata.type_covered,
                    "algorithm": rdata.algorithm,
                    "labels": rdata.labels,
                    "original_ttl": rdata.original_ttl,
                    "expiration": rdata.expiration,
                    "inception": rdata.inception,
                    "key_tag": rdata.key_tag,
                    "signer": rdata.signer,
                    "signature": rdata.signature,
                    "ttl": rrset.ttl,
                })
            elif rdtype == "DNSKEY":
                records.append({
                    "flags": rdata.flags,
                    "protocol": rdata.protocol,
                    "algorithm": rdata.algorithm,
                    "key": rdata.key,
                    "ttl": rrset.ttl
                })
            elif rdtype == "NSEC":
                records.append({
                    "next": rdata.next,
                    "windows": rdata.windows,
                    "ttl": rrset.ttl
                })
            elif rdtype == "NSEC3":
                records.append({
                    "next": rdata.next,
                    "windows": rdata.windows,
                    "algorithm": rdata.algorithm,
                    "flags": rdata.flags,
                    "iterations": rdata.iterations,
                    "salt": rdata.salt,
                    "ttl": rrset.ttl
                })
            elif rdtype == "NAPTR":
                records.append({
                    "order": rdata.order,
                    "preference": rdata.preference,
                    "flags": rdata.flags,
                    "service": rdata.service,
                    "regexp": rdata.regexp,
                    "replacement": rdata.replacement,
                    "ttl": rrset.ttl
                })
            elif rdtype == "OPT":
                records.append({
                    "options": rdata.options,
                    "ttl": rrset.ttl
                })
            elif rdtype == "AFSDB":
                records.append({
                    "subtype": rdata.subtype,
                    "hostname": rdata.hostname,
                    "ttl": rrset.ttl
                })
            elif rdtype == "CERT":
                records.append({
                    "certificate_type": rdata.certificate_type,
                    "key_tag": rdata.key_tag,
                    "algorithm": rdata.algorithm,
                    "certificate": rdata.certificate,
                    "ttl": rrset.ttl
                })
            elif rdtype == "LOC":
                records.append({
                    "version": rdata.version,
                    "size": rdata.size,
                    "hprecision": rdata.hprecision,
                    "vprecision": rdata.vprecision,
                    "latitude": rdata.latitude,
                    "longitude": rdata.longitude,
                    "altitude": rdata.altitude,
                    "ttl": rrset.ttl
                })
            elif rdtype == "SSHFP":
                records.append({
                    "algorithm": rdata.algorithm,
                    "fp_type": rdata.fp_type,
                    "fingerprint": rdata.fingerprint,
                    "ttl": rrset.ttl
                })
            elif rdtype == "TLSA":
                records.append({
                    "usage": rdata.usage,
                    "selector": rdata.selector,
                    "mtype": rdata.mtype,
                    "cert": rdata.cert,
                    "ttl": rrset.ttl
                })
            elif rdtype == "CAA":
                records.append({
                    "flags": rdata.flags,
                    "tag": rdata.tag,
                    "value": rdata.value,
                    "ttl": rrset.ttl
                })
            elif rdtype in ["SVCB", "HTTPS"]:
                records.append({
                    "priority": rdata.priority,
                    "target": rdata.target,
                    "ttl": rrset.ttl
                })
            else:
                records.append(str(rdata))
        return records
