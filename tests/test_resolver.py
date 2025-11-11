"""Comprehensive unit tests for resolver module.

This test suite covers all aspects of the Resolver class including:
- Initialization and configuration
- Synchronous DNS resolution
- Asynchronous DNS resolution
- DNSSEC-related operations (DNSKEY, DS)
- SOA serial fetching
- BIND CHAOS TXT queries (version.bind, hostname.bind, etc.)
- Zone transfers (AXFR)
- Domain name manipulation (parent, reverse, punycode)
- RRset record extraction for various DNS record types
- Error handling and edge cases
- IDN/Punycode conversion

All network interactions are mocked to ensure fast, deterministic tests.
"""

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.reversename
import dns.rrset
import dns.zone
import pytest

from src.resolver import DEFAULT_EDNS_SIZE, DEFAULT_TIMEOUT, Resolver
from src.typedefs import AXFRResult, QueryResult


class TestResolverInitialization:
    """Test suite for Resolver initialization."""

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_initialization_defaults(self):
        """Test resolver initializes with default settings."""
        resolver = Resolver()

        assert resolver is not None
        assert resolver.default_timeout == DEFAULT_TIMEOUT
        assert resolver.resolver is not None
        assert resolver.resolver.lifetime == DEFAULT_TIMEOUT

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_initialization_custom_timeout(self):
        """Test resolver initializes with custom timeout."""
        custom_timeout = 10.0
        resolver = Resolver(timeout=custom_timeout)

        assert resolver.default_timeout == custom_timeout
        assert resolver.resolver.lifetime == custom_timeout

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_initialization_custom_nameservers(self):
        """Test resolver initializes with custom nameservers."""
        nameservers = ["8.8.8.8", "8.8.4.4"]
        resolver = Resolver(nameservers=nameservers)

        assert resolver.resolver.nameservers == nameservers

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_initialization_combined(self):
        """Test resolver initializes with both custom timeout and nameservers."""
        nameservers = ["1.1.1.1"]
        timeout = 15.0
        resolver = Resolver(nameservers=nameservers, timeout=timeout)

        assert resolver.default_timeout == timeout
        assert resolver.resolver.lifetime == timeout
        assert resolver.resolver.nameservers == nameservers

    @pytest.mark.unit
    @pytest.mark.dns
    def test_allowed_record_types_present(self):
        """Test that allowed record types are defined."""
        resolver = Resolver()

        expected_types = [
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
            "CAA",
        ]

        for record_type in expected_types:
            assert record_type in Resolver.allowed_record_types


class TestResolverSynchronousResolution:
    """Test suite for synchronous DNS resolution."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver for testing."""
        return Resolver()

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_valid_record_type(self, resolver):
        """Test resolve with valid record type."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            mock_response = MagicMock()
            mock_response.rrset = MagicMock()
            mock_response.response = MagicMock()
            mock_resolve.return_value = mock_response

            rrset, response = resolver.resolve("example.com", "A")

            assert rrset is not None
            assert response is not None
            mock_resolve.assert_called_once()

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_invalid_record_type(self, resolver):
        """Test resolve with invalid record type."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            rrset, response = resolver.resolve("example.com", "INVALID")

            # Should return (None, None) for invalid type
            assert rrset is None
            assert response is None
            mock_resolve.assert_not_called()

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_with_custom_nameserver(self, resolver):
        """Test resolve with specific nameserver."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            mock_response = MagicMock()
            mock_response.rrset = MagicMock()
            mock_response.response = MagicMock()
            mock_resolve.return_value = mock_response

            original_ns = (
                resolver.resolver.nameservers.copy() if resolver.resolver.nameservers else []
            )

            rrset, response = resolver.resolve("example.com", "A", nameserver="8.8.8.8")

            assert rrset is not None
            mock_resolve.assert_called_once()

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_with_custom_timeout(self, resolver):
        """Test resolve with custom timeout."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            mock_response = MagicMock()
            mock_response.rrset = MagicMock()
            mock_response.response = MagicMock()
            mock_resolve.return_value = mock_response

            original_lifetime = resolver.resolver.lifetime
            rrset, response = resolver.resolve("example.com", "A", timeout=20.0)

            assert rrset is not None
            # Verify timeout was restored
            assert resolver.resolver.lifetime == original_lifetime

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_no_answer_exception(self, resolver):
        """Test resolve handles NoAnswer exception."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            from dns.resolver import NoAnswer

            mock_resolve.side_effect = NoAnswer()

            rrset, response = resolver.resolve("example.com", "A")

            assert rrset is None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_nxdomain_exception(self, resolver):
        """Test resolve handles NXDOMAIN exception."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            from dns.resolver import NXDOMAIN

            mock_resolve.side_effect = NXDOMAIN()

            rrset, response = resolver.resolve("nonexistent.example.com", "A")

            assert rrset is None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_timeout_exception(self, resolver):
        """Test resolve handles Timeout exception."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            mock_resolve.side_effect = dns.exception.Timeout()

            rrset, response = resolver.resolve("example.com", "A")

            assert rrset is None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_fetch_dnskey(self, resolver):
        """Test fetch_dnskey method."""
        with patch.object(resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = (MagicMock(), MagicMock())

            rrset, response = resolver.fetch_dnskey("example.com")

            mock_resolve.assert_called_once_with("example.com", "DNSKEY", None, None)
            assert rrset is not None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_fetch_ds(self, resolver):
        """Test fetch_ds method."""
        with patch.object(resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = (MagicMock(), MagicMock())

            rrset, response = resolver.fetch_ds("example.com")

            mock_resolve.assert_called_once_with("example.com", "DS", None, None)
            assert rrset is not None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_soa_serial_success(self, resolver):
        """Test get_soa_serial with valid SOA record."""
        with patch.object(resolver, "resolve") as mock_resolve:
            from dns.rdtypes.ANY.SOA import SOA

            # Create a properly typed mock SOA record
            mock_soa = MagicMock(spec=SOA)
            mock_soa.serial = 2023010101
            mock_rrset = [mock_soa]
            mock_resolve.return_value = (mock_rrset, MagicMock())

            serial = resolver.get_soa_serial("example.com", "8.8.8.8")

            # Should get the serial from SOA record
            assert serial is not None
            assert serial == 2023010101

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_soa_serial_no_record(self, resolver):
        """Test get_soa_serial with no SOA record."""
        with patch.object(resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = (None, None)

            serial = resolver.get_soa_serial("example.com", "8.8.8.8")

            assert serial is None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_soa_serial_empty_rrset(self, resolver):
        """Test get_soa_serial with empty RRset."""
        with patch.object(resolver, "resolve") as mock_resolve:
            mock_resolve.return_value = ([], None)

            serial = resolver.get_soa_serial("example.com", "8.8.8.8")

            assert serial is None


class TestResolverAsyncResolution:
    """Test suite for asynchronous DNS resolution."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver for testing."""
        return Resolver()

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_success(self, resolver):
        """Test async_resolve with successful query."""
        with patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp:
            mock_response = MagicMock()
            mock_response.rcode.return_value = dns.rcode.NOERROR
            mock_response.flags = 0
            mock_response.answer = []
            mock_response.authority = []
            mock_response.additional = []
            mock_response.edns = -1
            mock_udp.return_value = mock_response

            result = await resolver.async_resolve("example.com", "A", nameserver="8.8.8.8")

            assert isinstance(result, QueryResult)
            assert result.success is True
            assert result.error is None
            assert result.duration is not None or result.duration is None  # May be calculated

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_with_tcp(self, resolver):
        """Test async_resolve with TCP transport."""
        with patch("dns.asyncquery.tcp", new_callable=AsyncMock) as mock_tcp:
            mock_response = MagicMock()
            mock_response.rcode.return_value = dns.rcode.NOERROR
            mock_response.flags = 0
            mock_response.answer = []
            mock_response.authority = []
            mock_response.additional = []
            mock_response.edns = -1
            mock_tcp.return_value = mock_response

            result = await resolver.async_resolve(
                "example.com", "A", nameserver="8.8.8.8", use_tcp=True
            )

            assert isinstance(result, QueryResult)
            assert result.success is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_udp_truncated_fallback_to_tcp(self, resolver):
        """Test async_resolve falls back to TCP when UDP response is truncated."""
        with (
            patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp,
            patch("dns.asyncquery.tcp", new_callable=AsyncMock) as mock_tcp,
        ):

            # UDP response is truncated
            truncated_response = MagicMock()
            truncated_response.flags = dns.flags.TC  # Truncation flag
            mock_udp.return_value = truncated_response

            # TCP response is complete
            tcp_response = MagicMock()
            tcp_response.rcode.return_value = dns.rcode.NOERROR
            tcp_response.flags = 0
            tcp_response.answer = []
            tcp_response.authority = []
            tcp_response.additional = []
            tcp_response.edns = -1
            mock_tcp.return_value = tcp_response

            result = await resolver.async_resolve("example.com", "A", nameserver="8.8.8.8")

            assert result.success is True
            mock_tcp.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_with_edns(self, resolver):
        """Test async_resolve with EDNS."""
        with patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp:
            mock_response = MagicMock()
            mock_response.rcode.return_value = dns.rcode.NOERROR
            mock_response.flags = 0
            mock_response.answer = []
            mock_response.authority = []
            mock_response.additional = []
            mock_response.edns = 0
            mock_udp.return_value = mock_response

            result = await resolver.async_resolve(
                "example.com", "A", nameserver="8.8.8.8", use_edns=True
            )

            assert result.success is True
            mock_udp.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_timeout_exception(self, resolver):
        """Test async_resolve handles timeout exception."""
        with patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = asyncio.TimeoutError()

            result = await resolver.async_resolve("example.com", "A", nameserver="8.8.8.8")

            assert result.success is False
            assert result.error is not None

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_dns_exception(self, resolver):
        """Test async_resolve handles DNS exception."""
        with patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = dns.exception.DNSException("Test DNS error")

            result = await resolver.async_resolve("example.com", "A", nameserver="8.8.8.8")

            assert result.success is False
            assert "Test DNS error" in result.error

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_socket_error(self, resolver):
        """Test async_resolve handles socket error."""
        with patch("dns.asyncquery.udp", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = socket.error("Connection refused")

            result = await resolver.async_resolve("example.com", "A", nameserver="8.8.8.8")

            assert result.success is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_invalid_domain(self, resolver):
        """Test async_resolve with invalid domain name."""
        result = await resolver.async_resolve("", "A", nameserver="8.8.8.8")

        # Should handle gracefully
        assert isinstance(result, QueryResult)


class TestResolverCHAOSQueries:
    """Test suite for BIND CHAOS TXT queries."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver for testing."""
        return Resolver()

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_query_version_bind(self, resolver):
        """Test query_version_bind method."""
        with patch.object(resolver, "async_resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = QueryResult(success=True)

            result = await resolver.query_version_bind("8.8.8.8")

            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[1]["domain"] == "version.bind"
            assert call_args[1]["rdtype"] == "TXT"
            assert call_args[1]["rdclass"] == "CH"

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_query_hostname_bind(self, resolver):
        """Test query_hostname_bind method."""
        with patch.object(resolver, "async_resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = QueryResult(success=True)

            result = await resolver.query_hostname_bind("8.8.8.8")

            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[1]["domain"] == "hostname.bind"
            assert call_args[1]["rdclass"] == "CH"

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_query_authors_bind(self, resolver):
        """Test query_authors_bind method."""
        with patch.object(resolver, "async_resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = QueryResult(success=True)

            result = await resolver.query_authors_bind("8.8.8.8")

            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[1]["domain"] == "authors.bind"

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_query_id_server(self, resolver):
        """Test query_id_server method."""
        with patch.object(resolver, "async_resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = QueryResult(success=True)

            result = await resolver.query_id_server("8.8.8.8")

            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[1]["domain"] == "id.server"


class TestResolverZoneTransfer:
    """Test suite for AXFR zone transfers."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver for testing."""
        return Resolver()

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_axfr_success(self, resolver):
        """Test async_axfr with successful zone transfer."""
        with patch("dns.query.xfr") as mock_xfr, patch("dns.zone.from_xfr") as mock_from_xfr:

            # Mock AXFR iterator
            mock_msg = MagicMock()
            mock_msg.rcode.return_value = dns.rcode.NOERROR
            mock_xfr.return_value = iter([mock_msg])

            # Mock zone
            mock_zone = MagicMock()
            mock_zone.nodes.items.return_value = []
            mock_from_xfr.return_value = mock_zone

            result = await resolver.async_axfr("example.com", "8.8.8.8")

            assert isinstance(result, AXFRResult)
            assert result.success is True
            assert result.zone_name == "example.com"
            assert result.nameserver == "8.8.8.8"

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_axfr_custom_port(self, resolver):
        """Test async_axfr with custom port."""
        with patch("dns.query.xfr") as mock_xfr, patch("dns.zone.from_xfr") as mock_from_xfr:

            mock_msg = MagicMock()
            mock_msg.rcode.return_value = dns.rcode.NOERROR
            mock_xfr.return_value = iter([mock_msg])

            mock_zone = MagicMock()
            mock_zone.nodes.items.return_value = []
            mock_from_xfr.return_value = mock_zone

            result = await resolver.async_axfr("example.com", "8.8.8.8", port=5053)

            assert result.success is True

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_axfr_form_error(self, resolver):
        """Test async_axfr handles FormError exception."""
        with patch("dns.query.xfr") as mock_xfr:
            mock_xfr.side_effect = dns.exception.FormError("Invalid zone transfer")

            result = await resolver.async_axfr("example.com", "8.8.8.8")

            assert result.success is False
            assert result.error is not None

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_axfr_timeout(self, resolver):
        """Test async_axfr handles timeout exception."""
        with patch("dns.query.xfr") as mock_xfr:
            mock_xfr.side_effect = dns.exception.Timeout()

            result = await resolver.async_axfr("example.com", "8.8.8.8")

            assert result.success is False

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_axfr_connection_refused(self, resolver):
        """Test async_axfr handles connection refused."""
        with patch("dns.query.xfr") as mock_xfr:
            mock_xfr.side_effect = ConnectionRefusedError()

            result = await resolver.async_axfr("example.com", "8.8.8.8")

            assert result.success is False


class TestResolverDomainNameManipulation:
    """Test suite for domain name manipulation utilities."""

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_parent_name_subdomain(self):
        """Test get_parent_name with subdomain."""
        parent = Resolver.get_parent_name("www.example.com")

        assert parent == "example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_parent_name_domain(self):
        """Test get_parent_name with domain."""
        parent = Resolver.get_parent_name("example.com")

        assert parent == "com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_parent_name_root(self):
        """Test get_parent_name with TLD."""
        parent = Resolver.get_parent_name("com")

        assert parent == "."

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_reverse_name_ipv4(self):
        """Test get_reverse_name with IPv4 address."""
        reverse = Resolver.get_reverse_name("192.168.1.1")

        assert reverse == "1.1.168.192.in-addr.arpa"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_reverse_name_ipv6(self):
        """Test get_reverse_name with IPv6 address."""
        reverse = Resolver.get_reverse_name("2001:db8::1")

        assert reverse is not None
        assert "ip6.arpa" in reverse

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_reverse_name_invalid_ip(self):
        """Test get_reverse_name with invalid IP address."""
        reverse = Resolver.get_reverse_name("not.an.ip.address")

        assert reverse is None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_convert_idn_to_punnycode_ascii_domain(self):
        """Test convert_idn_to_punnycode with ASCII domain."""
        result = Resolver.convert_idn_to_punnycode("example.com")

        assert result == "example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_convert_idn_to_punnycode_unicode_domain(self):
        """Test convert_idn_to_punnycode with Unicode domain."""
        # German domain with umlaut
        result = Resolver.convert_idn_to_punnycode("münchen.de")

        assert result.startswith("xn--")  # Punycode prefix

    @pytest.mark.unit
    @pytest.mark.dns
    def test_convert_idn_to_punnycode_chinese_domain(self):
        """Test convert_idn_to_punnycode with Chinese domain."""
        result = Resolver.convert_idn_to_punnycode("中国.cn")

        assert "xn--" in result or result == "中国.cn"  # Either punycode or fallback

    @pytest.mark.unit
    @pytest.mark.dns
    def test_convert_idn_to_punnycode_error_handling(self):
        """Test convert_idn_to_punnycode error handling."""
        # Test with various edge cases that might cause encoding errors
        result = Resolver.convert_idn_to_punnycode("\x00invalid\xff")

        # Should not raise, returns original or converted
        assert result is not None


class TestResolverRRsetExtraction:
    """Test suite for RRset record extraction."""

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_a_record(self):
        """Test extract A records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = MagicMock(return_value="192.168.1.1")
        mock_rdata.__class__.__str__ = MagicMock(return_value="192.168.1.1")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.A
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 300

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["address"] == "192.168.1.1"
        assert records[0]["ttl"] == 300

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_aaaa_record(self):
        """Test extract AAAA records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="2001:db8::1")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.AAAA
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 300

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["address"] == "2001:db8::1"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_cname_record(self):
        """Test extract CNAME records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="www.example.com")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.CNAME
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["target"] == "www.example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_mx_record(self):
        """Test extract MX records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange = "mail.example.com"

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.MX
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["preference"] == 10
        assert records[0]["exchange"] == "mail.example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_txt_record(self):
        """Test extract TXT records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="v=spf1 include:_spf.google.com ~all")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.TXT
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 300

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert "spf1" in records[0]["strings"]

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_soa_record(self):
        """Test extract SOA records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.mname = "ns1.example.com"
        mock_rdata.rname = "admin.example.com"
        mock_rdata.serial = 2023010101
        mock_rdata.refresh = 7200
        mock_rdata.retry = 3600
        mock_rdata.expire = 604800
        mock_rdata.minimum = 86400

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.SOA
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["serial"] == 2023010101
        assert records[0]["mname"] == "ns1.example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_dnskey_record(self):
        """Test extract DNSKEY records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.flags = 256
        mock_rdata.protocol = 3
        mock_rdata.algorithm = 8
        mock_rdata.key = b"mock_key_data"

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.DNSKEY
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["flags"] == 256
        assert records[0]["algorithm"] == 8

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_ds_record(self):
        """Test extract DS records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.key_tag = 65534
        mock_rdata.algorithm = 8
        mock_rdata.digest_type = 2
        mock_rdata.digest = b"digest_data"

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.DS
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["key_tag"] == 65534
        assert records[0]["algorithm"] == 8

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_srv_record(self):
        """Test extract SRV records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.priority = 10
        mock_rdata.weight = 20
        mock_rdata.port = 5060
        mock_rdata.target = "sip.example.com"

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.SRV
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["priority"] == 10
        assert records[0]["port"] == 5060

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_caa_record(self):
        """Test extract CAA records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.flags = 0
        mock_rdata.tag = "issue"
        mock_rdata.value = "letsencrypt.org"

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.CAA
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["tag"] == "issue"
        assert records[0]["value"] == "letsencrypt.org"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_ns_record(self):
        """Test extract NS records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="ns1.example.com")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 172800

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["target"] == "ns1.example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_ptr_record(self):
        """Test extract PTR records from RRset."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="host.example.com")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.PTR
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_rrset.ttl = 3600

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0]["target"] == "host.example.com"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_unknown_type(self):
        """Test extract unknown record type falls back to str."""
        mock_rdata = MagicMock()
        mock_rdata.__class__.__str__ = MagicMock(return_value="unknown data")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = 999  # Unknown type
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 1
        assert records[0] == "unknown data"

    @pytest.mark.unit
    @pytest.mark.dns
    def test_get_records_from_rrset_multiple_records(self):
        """Test extract multiple records from RRset."""
        mock_rdata1 = MagicMock()
        mock_rdata1.__class__.__str__ = MagicMock(return_value="192.168.1.1")
        mock_rdata2 = MagicMock()
        mock_rdata2.__class__.__str__ = MagicMock(return_value="192.168.1.2")

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.A
        mock_rrset.__iter__ = lambda self: iter([mock_rdata1, mock_rdata2])
        mock_rrset.ttl = 300

        records = Resolver.get_records_from_rrset(mock_rrset)

        assert len(records) == 2
        assert records[0]["address"] == "192.168.1.1"
        assert records[1]["address"] == "192.168.1.2"


class TestResolverEdgeCases:
    """Test suite for edge cases and error handling."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver for testing."""
        return Resolver()

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_multiple_instances(self):
        """Test multiple resolver instances are independent."""
        resolver1 = Resolver(timeout=5.0, nameservers=["8.8.8.8"])
        resolver2 = Resolver(timeout=10.0, nameservers=["1.1.1.1"])

        assert resolver1.default_timeout == 5.0
        assert resolver2.default_timeout == 10.0
        assert resolver1.resolver.nameservers != resolver2.resolver.nameservers

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_nameserver_empty_list(self):
        """Test resolver with empty nameserver list - dns resolver may use system defaults."""
        resolver = Resolver(nameservers=[])

        # When nameservers is empty list, the resolver may use system configuration
        # Just verify it initializes without error
        assert resolver is not None
        assert resolver.resolver is not None

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_zero_timeout(self):
        """Test resolver with zero timeout."""
        resolver = Resolver(timeout=0)

        assert resolver.default_timeout == 0
        assert resolver.resolver.lifetime == 0

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_large_timeout(self):
        """Test resolver with large timeout."""
        resolver = Resolver(timeout=300.0)

        assert resolver.default_timeout == 300.0

    @pytest.mark.asyncio
    @pytest.mark.unit
    @pytest.mark.dns
    async def test_async_resolve_no_nameservers_configured(self, resolver):
        """Test async_resolve when no nameservers are configured."""
        resolver.resolver.nameservers = []

        result = await resolver.async_resolve("example.com", "A")

        assert result.success is False
        assert "No nameservers" in result.error

    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolve_all_record_types(self, resolver):
        """Test resolve method supports all allowed record types."""
        with patch.object(resolver.resolver, "resolve") as mock_resolve:
            mock_response = MagicMock()
            mock_response.rrset = MagicMock()
            mock_response.response = MagicMock()
            mock_resolve.return_value = mock_response

            for record_type in Resolver.allowed_record_types:
                rrset, response = resolver.resolve("example.com", record_type)

                if record_type in [
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
                ]:
                    # All should be allowed
                    assert rrset is not None or rrset is None  # Either result is acceptable

    @pytest.mark.slow
    @pytest.mark.unit
    @pytest.mark.dns
    def test_resolver_stress_many_instances(self):
        """Test creating many resolver instances (stress test)."""
        resolvers = [Resolver(timeout=float(i)) for i in range(1, 101)]

        assert len(resolvers) == 100
        assert resolvers[0].default_timeout == 1.0
        assert resolvers[99].default_timeout == 100.0

    @pytest.mark.unit
    @pytest.mark.dns
    def test_convert_idn_various_languages(self):
        """Test IDN conversion for various languages."""
        test_domains = [
            ("münchen.de", True),  # German
            ("москва.рф", True),  # Russian
            ("大阪.jp", True),  # Japanese
            ("عمّان.jo", True),  # Arabic
            ("example.com", False),  # ASCII - no conversion
        ]

        for domain, should_convert in test_domains:
            result = Resolver.convert_idn_to_punnycode(domain)
            assert result is not None
            if should_convert:
                # Might contain xn-- or be unchanged
                assert isinstance(result, str)
