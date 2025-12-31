"""DNS resolution utilities for the MCP DNS server.

This module provides a Resolver class that encapsulates DNS resolution functionality,
including DNSSEC-related record fetching and domain name manipulation. It uses
dnspython as the underlying DNS resolution engine.
"""

import asyncio
import ipaddress
import socket
import time
from typing import Any

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.resolver
import dns.reversename
import dns.rrset
import dns.zone

from src.typedefs import AXFRResult, QueryResult

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
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "PTR",
        "SRV",
        "DNSKEY",
        "DS",
        "RRSIG",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "CAA",
        "SPF",
        "LOC",
        "HINFO",
        "RP",
        "AFSDB",
        "CERT",
        "DNAME",
        "SSHFP",
        "TLSA",
        "URI",
        "SMIMEA",
        "OPENPGPKEY",
    ]

    def __init__(self, nameservers: list[str] | None = None, timeout: float = DEFAULT_TIMEOUT):
        """Initialize the resolver with optional nameservers and timeout.

        Args:
            nameservers: Optional list of nameserver IP addresses to use.
            timeout: Query timeout in seconds (default: 5.0).
        """
        self.default_timeout = timeout
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        if nameservers:
            # Validate and convert FQDNs to IP addresses if needed
            validated_ns = self._validate_and_convert_nameservers(nameservers)
            if validated_ns:
                self.resolver.nameservers = validated_ns

    def _validate_and_convert_nameservers(self, nameservers: list[str]) -> list[str]:
        """Validate nameservers and convert FQDNs to IP addresses.

        Args:
            nameservers: List of nameserver addresses (can be IPs or FQDNs).

        Returns:
            List of validated IP addresses. FQDNs are resolved to their IPs.
            Returns empty list if no valid nameservers found.
        """
        validated = []
        for ns in nameservers:
            ns = ns.strip()
            if not ns:
                continue

            # Check if it's already an IP address (IPv4 or IPv6)
            if self._is_valid_ip(ns):
                validated.append(ns)
            else:
                # It's likely a FQDN, try to resolve it
                resolved_ips = self._resolve_nameserver_fqdn(ns)
                validated.extend(resolved_ips)

        return validated

    @staticmethod
    def _is_valid_ip(address: str) -> bool:
        """Check if a string is a valid IPv4 or IPv6 address.

        Args:
            address: The address string to validate.

        Returns:
            True if valid IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def _resolve_nameserver_fqdn(fqdn: str) -> list[str]:
        """Resolve a nameserver FQDN to its IP address(es).

        Args:
            fqdn: The fully qualified domain name to resolve.

        Returns:
            List of IP addresses. Empty list if resolution fails.
        """
        try:
            # Use socket.getaddrinfo to resolve the FQDN
            # This handles both IPv4 and IPv6 resolution
            addr_info = socket.getaddrinfo(fqdn, 53, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            ips = []
            seen = set()  # Avoid duplicates

            for _family, _socktype, _proto, _canonname, sockaddr in addr_info:
                ip = sockaddr[0]
                if ip not in seen:
                    ips.append(ip)
                    seen.add(ip)

            return ips
        except (socket.gaierror, OSError):
            # Resolution failed; return empty list
            # Could be a misconfigured FQDN or network issue
            return []

    async def async_resolve(
        self,
        domain: str,
        rdtype: str,
        rdclass: str = "IN",
        nameserver: str | None = None,
        use_tcp: bool = False,
        use_edns: bool = True,
        payload_size: int = DEFAULT_EDNS_SIZE,
        flags: int = 0,
        options: list | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> QueryResult:
        """Asynchronously resolve a single RRset using the configured resolver.

        Args:
            qname: The domain name to query.
            rdtype: DNS record type to query for.
            rdclass: The rdclass to use. Defaults to: IN
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
            qname = dns.name.from_text(Resolver.convert_idn_to_punnycode(domain))
            rdtype_obj = dns.rdatatype.from_text(rdtype)
            rdclass_obj = dns.rdataclass.from_text(rdclass)

            # Create the query message
            query = dns.message.make_query(
                qname,
                rdtype_obj,
                rdclass=rdclass_obj,
                want_dnssec=bool(flags & dns.flags.DO),
            )

            # Add EDNS if requested
            if use_edns:
                query.use_edns(
                    0,
                    flags,
                    payload_size,
                    options=options if options else [],  # EDNS version 0
                )
            if nameserver is None:
                if not self.resolver.nameservers:
                    return QueryResult(
                        success=False,
                        error="No nameservers configured in resolver",
                        details={},
                    )
                nameserver = str(self.resolver.nameservers[0])

            start_time = time.time()
            # Send query
            if use_tcp:
                response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
            else:
                try:
                    response = await dns.asyncquery.udp(query, nameserver, timeout=timeout)
                    if response.flags & dns.flags.TC:  # Truncated, retry with TCP
                        response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
                except dns.exception.DNSException as e:
                    if "Message too big" in str(e):
                        # UDP message too large, retry with TCP
                        response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
                    else:
                        return QueryResult(
                            success=False,
                            error=str(e),
                            details={"exception_type": type(e).__name__},
                        )
                except (OSError, asyncio.TimeoutError) as e:
                    return QueryResult(
                        success=False,
                        error=str(e),
                        details={"exception_type": type(e).__name__},
                    )
                except Exception as e:
                    return QueryResult(
                        success=False,
                        error=f"Unexpected error: {str(e)}",
                        details={"exception_type": type(e).__name__},
                    )

            return QueryResult(
                success=True,
                duration=time.time() - start_time,
                qname=qname,
                rdtype=rdtype_obj,
                response=response,
                rcode=response.rcode(),
                rcode_text=dns.rcode.to_text(response.rcode()),
                details={
                    "flags": response.flags,
                    "answer_count": len(response.answer),
                    "authority_count": len(response.authority),
                    "additional_count": len(response.additional),
                    "has_edns": response.edns >= 0,
                    "is_truncated": bool(response.flags & dns.flags.TC),
                },
            )

        except dns.exception.DNSException as e:
            return QueryResult(
                success=False,
                error=str(e),
                details={"exception_type": type(e).__name__},
            )
        except (OSError, asyncio.TimeoutError) as e:
            return QueryResult(
                success=False,
                error=str(e),
                details={"exception_type": type(e).__name__},
            )
        except Exception as e:
            return QueryResult(
                success=False,
                error=f"Unexpected error: {str(e)}",
                details={"exception_type": type(e).__name__},
            )

    async def async_axfr(
        self,
        zone_name: str,
        nameserver: str,
        port: int = 53,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> AXFRResult:
        """Attempt an asynchronous AXFR zone transfer.

        Args:
            zone_name (str): The zone name we try to receive.
            nameserver (str | None, optional): The DNS server to ask for the zone transfer.
            port (int, optional): DNS server port for zone transfer. Defaults to 53.
            timeout (float, optional): The overall timeout. Defaults to DEFAULT_TIMEOUT.

        Returns:
            AXFRResult: A result dictionary holding the zone data if retrieved.
        """
        try:
            start_time = time.time()
            # dns.query.xfr is blocking; run it in a thread
            axfr_iter = await asyncio.to_thread(
                dns.query.xfr, nameserver, zone_name, lifetime=timeout, port=port
            )
            first_msg = next(axfr_iter)
            rcode = first_msg.rcode()

            # dns.zone.from_xfr consumes the iterator and builds a Zone object (also blocking)
            z = await asyncio.to_thread(dns.zone.from_xfr, axfr_iter)
            return AXFRResult(
                success=True,
                zone_name=zone_name,
                nameserver=nameserver,
                response=z,
                rcode=rcode,
                rcode_text=dns.rcode.to_text(rcode),
                duration=time.time() - start_time,
                details={"names": z.nodes.items()},
            )

        except (
            dns.exception.FormError,
            dns.exception.Timeout,
            ConnectionRefusedError,
        ) as e:
            return AXFRResult(
                zone_name=zone_name,
                nameserver=nameserver,
                success=False,
                error=str(e),
                details={"exception_type": type(e).__name__},
            )

    def resolve_dnssec(
        self,
        qname: str,
        rdtype: str,
        nameserver: str | None = None,
        timeout: float | None = None,
    ) -> tuple[RRset | None, Message | None]:
        """Resolve a single RRset with DNSSEC enabled (DO flag set).

        This method is specifically for DNSSEC queries where RRSIG records
        must be returned by the nameserver.

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
            # Create a query with DNSSEC-OK flag
            qname_obj = dns.name.from_text(qname)
            rdtype_obj = dns.rdatatype.from_text(rdtype)
            query = dns.message.make_query(qname_obj, rdtype_obj, want_dnssec=True)

            # Perform the query using the resolver's nameserver
            ns_to_use = nameserver or (
                self.resolver.nameservers[0] if self.resolver.nameservers else None
            )
            if ns_to_use:
                response = dns.query.udp(
                    query, str(ns_to_use), timeout=timeout or self.default_timeout
                )
                # Extract the answer section
                if response.answer:
                    for rrset in response.answer:
                        if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                            result = (rrset, response)
                            break
                    else:
                        # Requested type not in answer, return None but keep response
                        result = (None, response)
                else:
                    result = (None, response)
            else:
                # Fallback to standard resolver
                answer = self.resolver.resolve(qname, rdtype, raise_on_no_answer=False)
                result = (answer.rrset, answer.response)
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.query.BadResponse,
        ) as e:
            result = (None, getattr(e, "response", None))

        # Restore original settings
        if nameserver and original_ns is not None:
            self.resolver.nameservers = original_ns
        if timeout is not None:
            self.resolver.lifetime = self.default_timeout

        return result

    def resolve(
        self,
        qname: str,
        rdtype: str,
        nameserver: str | None = None,
        timeout: float | None = None,
    ) -> tuple[RRset | None, Message | None]:
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
            answer = self.resolver.resolve(qname, rdtype, raise_on_no_answer=False)
            result = (answer.rrset, answer.response)
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as e:
            result = (None, getattr(e, "response", None))

        # Restore original settings
        if nameserver and original_ns is not None:
            self.resolver.nameservers = original_ns
        if timeout is not None:
            self.resolver.lifetime = self.default_timeout

        return result

    def fetch_dnskey(
        self,
        qname: str,
        nameserver: str | None = None,
        timeout: float | None = None,
    ) -> tuple[RRset | None, Message | None]:
        """Fetch DNSKEY records for the specified domain.

        DNSKEY records should be fetched with DNSSEC support enabled to ensure
        proper retrieval of RRSIG records alongside the keys.

        Args:
            qname: Domain name to fetch DNSKEY records for.
            nameserver: Optional specific nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            Tuple of (DNSKEY RRset, DNS message) or (None, None) if not found.
        """
        # Use resolve_dnssec to ensure RRSIG records are returned
        return self.resolve_dnssec(qname, "DNSKEY", nameserver, timeout)

    def fetch_ds(
        self,
        qname: str,
        nameserver: str | None = None,
        timeout: float | None = None,
    ) -> tuple[RRset | None, Message | None]:
        """Fetch DS records for the specified domain.

        DS records should be fetched with DNSSEC support enabled to ensure
        proper retrieval from authoritative nameservers.

        Args:
            qname: Domain name to fetch DS records for.
            nameserver: Optional specific nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            Tuple of (DS RRset, DNS message) or (None, None) if not found.
        """
        # Use resolve_dnssec to ensure proper DNSSEC-aware querying
        return self.resolve_dnssec(qname, "DS", nameserver, timeout)

    def get_soa_serial(
        self, zone_name: str, nameserver: str, timeout: float | None = None
    ) -> int | None:
        """Get the SOA serial number for a zone from a specific nameserver.

        Args:
            zone_name: The zone name to query.
            nameserver: Nameserver to query.
            timeout: Optional query timeout override.

        Returns:
            SOA serial number as integer, or None if not found/error.
        """
        rrset, _ = self.resolve(zone_name, "SOA", nameserver, timeout)
        if rrset and len(rrset) > 0:
            soa_record = rrset[0]
            if isinstance(soa_record, SOARecord):
                return soa_record.serial
        return None

    async def query_version_bind(
        self,
        nameserver: str,
    ) -> QueryResult:
        """Query a nameserver for its DNS software version using CHAOS TXT version.bind.

        This emulates:  dig @<nameserver> chaos txt version.bind

        Args:
            nameserver: IP address of the target DNS server.

        Returns:
            QueryResult: Result of the DNS query operation.
        """
        return await self.async_resolve(
            domain="version.bind", rdtype="TXT", rdclass="CH", nameserver=nameserver
        )

    async def query_hostname_bind(
        self,
        nameserver: str,
    ) -> QueryResult:
        """Query a nameserver for its hostname using CHAOS TXT hostname.bind.

        This emulates:  dig @<nameserver> chaos txt hostname.bind

        Args:
            nameserver: IP address of the target DNS server.

        Returns:
            QueryResult: Result of the DNS query operation.
        """
        return await self.async_resolve(
            domain="hostname.bind", rdtype="TXT", rdclass="CH", nameserver=nameserver
        )

    async def query_authors_bind(
        self,
        nameserver: str,
    ) -> QueryResult:
        """Query a nameserver for the list of authors of the DNS software.

        This emulates:  dig @<nameserver> chaos txt authors.bind

        Args:
            nameserver: IP address of the target DNS server.

        Returns:
            QueryResult: Result of the DNS query operation.
        """
        return await self.async_resolve(
            domain="authors.bind", rdtype="TXT", rdclass="CH", nameserver=nameserver
        )

    async def query_id_server(
        self,
        nameserver: str,
    ) -> QueryResult:
        """Query a nameserver for its hostname/ID using CHAOS TXT id.server.

        This emulates:  dig @<nameserver> chaos txt id.server

        Args:
            nameserver: IP address of the target DNS server.

        Returns:
            QueryResult: Result of the DNS query operation.
        """
        return await self.async_resolve(
            domain="id.server", rdtype="TXT", rdclass="CH", nameserver=nameserver
        )

    # STATIC METHODS
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
            return "."
        parent = name.parent()
        # Strip trailing dot except for root zone
        parent_text = parent.to_text()
        return parent_text if parent_text == "." else parent_text.rstrip(".")

    @staticmethod
    def get_reverse_name(ip_address: str) -> str | None | None:
        """Get the reverse DNS name for a given IP address.

        Args:
            ip_address: The IP address to convert to a reverse DNS name.

        Returns:
            The reverse DNS name as a string, or None if the IP is invalid.
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            return rev_name.to_text().rstrip(".")
        except dns.exception.SyntaxError:
            return None

    @staticmethod
    def get_records_from_rrset(rrset: RRset) -> list[dict[str, Any]]:
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
                records.append({"address": str(rdata), "ttl": rrset.ttl})
            elif rdtype in ["CNAME", "NS", "PTR"]:
                records.append({"target": str(rdata), "ttl": rrset.ttl})
            elif rdtype in ["TXT", "SPF"]:
                records.append({"strings": str(rdata), "ttl": rrset.ttl})
            elif rdtype == "MX":
                records.append(
                    {
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange),
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "SRV":
                records.append(
                    {
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": str(rdata.target),
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "SOA":
                records.append(
                    {
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "DS":
                records.append(
                    {
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "digest_type": rdata.digest_type,
                        "digest": rdata.digest,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "RRSIG":
                records.append(
                    {
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
                    }
                )
            elif rdtype == "DNSKEY":
                records.append(
                    {
                        "flags": rdata.flags,
                        "protocol": rdata.protocol,
                        "algorithm": rdata.algorithm,
                        "key": rdata.key,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "NSEC":
                records.append({"next": rdata.next, "windows": rdata.windows, "ttl": rrset.ttl})
            elif rdtype == "NSEC3":
                records.append(
                    {
                        "next": rdata.next,
                        "windows": rdata.windows,
                        "algorithm": rdata.algorithm,
                        "flags": rdata.flags,
                        "iterations": rdata.iterations,
                        "salt": rdata.salt,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "NAPTR":
                records.append(
                    {
                        "order": rdata.order,
                        "preference": rdata.preference,
                        "flags": rdata.flags,
                        "service": rdata.service,
                        "regexp": rdata.regexp,
                        "replacement": rdata.replacement,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "OPT":
                records.append({"options": rdata.options, "ttl": rrset.ttl})
            elif rdtype == "AFSDB":
                records.append(
                    {
                        "subtype": rdata.subtype,
                        "hostname": rdata.hostname,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "CERT":
                records.append(
                    {
                        "certificate_type": rdata.certificate_type,
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "certificate": rdata.certificate,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "LOC":
                records.append(
                    {
                        "version": rdata.version,
                        "size": rdata.size,
                        "hprecision": rdata.hprecision,
                        "vprecision": rdata.vprecision,
                        "latitude": rdata.latitude,
                        "longitude": rdata.longitude,
                        "altitude": rdata.altitude,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "SSHFP":
                records.append(
                    {
                        "algorithm": rdata.algorithm,
                        "fp_type": rdata.fp_type,
                        "fingerprint": rdata.fingerprint,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "TLSA":
                records.append(
                    {
                        "usage": rdata.usage,
                        "selector": rdata.selector,
                        "mtype": rdata.mtype,
                        "cert": rdata.cert,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype == "CAA":
                records.append(
                    {
                        "flags": rdata.flags,
                        "tag": rdata.tag,
                        "value": rdata.value,
                        "ttl": rrset.ttl,
                    }
                )
            elif rdtype in ["SVCB", "HTTPS"]:
                records.append(
                    {
                        "priority": rdata.priority,
                        "target": rdata.target,
                        "ttl": rrset.ttl,
                    }
                )
            else:
                records.append(str(rdata))
        return records

    @staticmethod
    def convert_idn_to_punnycode(domain: str) -> str:
        """Convert Internationalized Domain Name (IDN) to ASCII-compatible Punycode.

        Args:
            domain (str): Domain name that may contain Unicode characters.

        Returns:
            str: ASCII-compatible domain name (Punycode if needed)
        """
        try:
            # Check if domain contains non-ASCII characters.
            if any(ord(char) > 127 for char in domain):
                # Convert Unicode domain to Punycode.
                punycode_domain = domain.encode("idna").decode("ascii")
                return punycode_domain
            return domain
        except (UnicodeError, UnicodeDecodeError, UnicodeEncodeError) as _:
            return domain
