"""DNS resolution utilities for the MCP DNS server.

This module provides a Resolver class that encapsulates DNS resolution functionality,
including DNSSEC-related record fetching and domain name manipulation. It uses
dnspython as the underlying DNS resolution engine.
"""

from typing import Tuple, Optional, List
import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.message

# Type aliases
SOARecord = dns.rdtypes.ANY.SOA.SOA
RRset = dns.rrset.RRset
Message = dns.message.Message

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
        timeout: float = 5.0
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
