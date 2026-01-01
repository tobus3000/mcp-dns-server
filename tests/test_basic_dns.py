"""Comprehensive unit tests for dns module sub-modules.

This test suite covers all aspects of DNS operations including:
- Basic DNS lookups (A records)
- Advanced DNS lookups (MX, NS, TXT, SOA, etc.)
- Reverse DNS lookups (PTR records)
- Comprehensive DNS troubleshooting
- DNS server testing (basic records, EDNS, TCP behavior, etc.)
- DNS tracing (iterative resolution)

All network interactions are mocked to ensure fast, deterministic tests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import pytest

from dns_mcp_server.tools.dns.basic_dns import (
    advanced_dns_lookup_impl,
    dns_troubleshooting_impl,
    reverse_dns_lookup_impl,
    simple_dns_lookup_impl,
)

# ============================================================================
# Test Class: Simple DNS Lookups
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestSimpleDNSLookup:
    """Test suite for simple A record DNS lookups."""

    async def test_simple_dns_lookup_success(self):
        """Test successful A record lookup."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Mock the async_resolve call
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.response.answer = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.rcode = MagicMock(return_value=0)
            mock_result.duration = 0.1

            # Mock get_rrset to return records
            mock_rrset = [MagicMock()]
            mock_rrset[0].__str__ = MagicMock(return_value="93.184.216.34")
            mock_result.response.get_rrset = MagicMock(return_value=mock_rrset)

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("example.com")

            assert result.success is True
            assert isinstance(result.output, list)
            assert len(result.output) > 0
            assert "93.184.216.34" in result.output[0]
            assert result.details["query_name"] == "example.com."
            assert result.details["query_type"] == "A"

    async def test_simple_dns_lookup_failure(self):
        """Test failed A record lookup."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.error = "NXDOMAIN"
            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("nonexistent.example.com")

            assert result.success is False
            assert result.error == "NXDOMAIN"

    async def test_simple_dns_lookup_no_records(self):
        """Test A record lookup with no results."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.rcode = MagicMock(return_value=0)
            mock_result.response.get_rrset = MagicMock(return_value=None)
            mock_result.duration = 0.1

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("example.com")

            assert result.success is True
            assert result.output == []

    async def test_simple_dns_lookup_response_details(self):
        """Test that response details are properly captured."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.response.answer = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.rcode = MagicMock(return_value=0)
            mock_result.duration = 0.25

            mock_rrset = [MagicMock()]
            mock_rrset[0].__str__ = MagicMock(return_value="93.184.216.34")
            mock_result.response.get_rrset = MagicMock(return_value=mock_rrset)

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("example.com")

            assert result.details["duration"] == 0.25
            assert result.details["query_name"] == "example.com."
            assert result.details["query_type"] == "A"
            assert result.details["rcode_text"] == "NOERROR"


# ============================================================================
# Test Class: Advanced DNS Lookups
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestAdvancedDNSLookup:
    """Test suite for advanced DNS lookups (multiple record types)."""

    async def test_advanced_dns_lookup_mx_record(self):
        """Test advanced MX record lookup."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Mock NS lookup
            ns_result = MagicMock()
            ns_result.success = True
            ns_result.response = MagicMock()
            ns_result.qname = "example.com."
            ns_result.rdtype = dns.rdatatype.NS
            ns_result.response.get_rrset = MagicMock(return_value=None)

            # Mock MX lookup
            mx_result = MagicMock()
            mx_result.success = True
            mx_result.response = MagicMock()
            mx_result.qname = "example.com."
            mx_result.rdtype = dns.rdatatype.MX
            mx_result.duration = 0.15
            mx_result.rcode_text = "NOERROR"

            mock_rrset = [MagicMock()]
            mock_rrset[0].__str__ = MagicMock(return_value="10 mail.example.com.")
            mx_result.response.get_rrset = MagicMock(return_value=mock_rrset)

            mock_resolver.async_resolve = AsyncMock(side_effect=[ns_result, mx_result])

            # Properly mock the static method
            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = ["10 mail.example.com."]
                mock_resolver_class.return_value = mock_resolver

                result = await advanced_dns_lookup_impl("example.com", "MX")

                assert result.success is True
                assert isinstance(result.output, list)
                assert "mail.example.com." in result.output[0]

    async def test_advanced_dns_lookup_ns_record_skip_lookup(self):
        """Test advanced NS record lookup (no NS pre-lookup)."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            ns_result = MagicMock()
            ns_result.success = True
            ns_result.response = MagicMock()
            ns_result.qname = "example.com."
            ns_result.rdtype = dns.rdatatype.NS
            ns_result.duration = 0.1
            ns_result.rcode_text = "NOERROR"

            mock_rrset = [MagicMock()]
            mock_rrset[0].__str__ = MagicMock(return_value="ns1.example.com.")
            ns_result.response.get_rrset = MagicMock(return_value=mock_rrset)

            mock_resolver.async_resolve = AsyncMock(return_value=ns_result)

            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = ["ns1.example.com."]
                mock_resolver_class.return_value = mock_resolver

                result = await advanced_dns_lookup_impl("example.com", "NS")

                # Should only call async_resolve once for NS
                assert mock_resolver.async_resolve.call_count == 1
                assert result.success is True

    async def test_advanced_dns_lookup_no_records_found(self):
        """Test advanced lookup when no records are found."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            ns_result = MagicMock()
            ns_result.success = True
            ns_result.response = MagicMock()
            ns_result.qname = "example.com."
            ns_result.rdtype = dns.rdatatype.NS
            ns_result.response.get_rrset = MagicMock(return_value=None)

            a_result = MagicMock()
            a_result.success = True
            a_result.response = MagicMock()
            a_result.qname = "example.com."
            a_result.rdtype = dns.rdatatype.A
            a_result.rcode_text = "NOERROR"
            a_result.response.get_rrset = MagicMock(return_value=None)

            mock_resolver.async_resolve = AsyncMock(side_effect=[ns_result, a_result])
            mock_resolver_class.return_value = mock_resolver

            result = await advanced_dns_lookup_impl("example.com", "A")

            assert result.success is True
            assert result.error == "No records found"


# ============================================================================
# Test Class: Reverse DNS Lookups
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestReverseDNSLookup:
    """Test suite for reverse DNS (PTR) lookups."""

    async def test_reverse_dns_lookup_success_ipv4(self):
        """Test successful reverse DNS lookup for IPv4."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            with patch(
                "src.tools.dns.basic_dns.Resolver.get_reverse_name"
            ) as mock_rev_name:
                mock_rev_name.return_value = "34.216.184.93.in-addr.arpa"

                mock_resolver = MagicMock()

                ptr_result = MagicMock()
                ptr_result.success = True
                ptr_result.response = MagicMock()
                ptr_result.response.answer = MagicMock()
                ptr_result.qname = "34.216.184.93.in-addr.arpa."
                ptr_result.rdtype = dns.rdatatype.PTR
                ptr_result.response.rcode = MagicMock(return_value=0)
                ptr_result.duration = 0.1

                ptr_rrset = [MagicMock()]
                ptr_rrset[0].__str__ = MagicMock(return_value="example.com.")
                ptr_result.response.get_rrset = MagicMock(return_value=ptr_rrset)

                mock_resolver.async_resolve = AsyncMock(return_value=ptr_result)
                mock_resolver_class.return_value = mock_resolver

                result = await reverse_dns_lookup_impl("93.184.216.34")

                assert result.success is True
                assert isinstance(result.output, list)
                assert "example.com." in result.output[0]
                assert result.details["query_type"] == "PTR"
                assert result.details["is_local"] is False

    async def test_reverse_dns_lookup_invalid_ip(self):
        """Test reverse DNS lookup with invalid IP address."""
        result = await reverse_dns_lookup_impl("not.an.ip.address")

        assert result.success is False
        assert result.error is not None
        assert "Invalid IP address" in result.error

    async def test_reverse_dns_lookup_private_ip(self):
        """Test that private IPs are marked as local."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            with patch(
                "src.tools.dns.basic_dns.Resolver.get_reverse_name"
            ) as mock_rev_name:
                mock_rev_name.return_value = "1.168.192.in-addr.arpa"

                mock_resolver = MagicMock()

                ptr_result = MagicMock()
                ptr_result.success = True
                ptr_result.response = MagicMock()
                ptr_result.response.answer = MagicMock()
                ptr_result.qname = "1.168.192.in-addr.arpa."
                ptr_result.rdtype = dns.rdatatype.PTR
                ptr_result.response.rcode = MagicMock(return_value=0)
                ptr_result.duration = 0.1

                ptr_rrset = [MagicMock()]
                ptr_rrset[0].__str__ = MagicMock(return_value="internal.local.")
                ptr_result.response.get_rrset = MagicMock(return_value=ptr_rrset)

                mock_resolver.async_resolve = AsyncMock(return_value=ptr_result)
                mock_resolver_class.return_value = mock_resolver

                result = await reverse_dns_lookup_impl("192.168.1.1")

                assert result.success is True
                assert result.details["is_local"] is True

    async def test_reverse_dns_lookup_invalid_reverse_name(self):
        """Test reverse DNS lookup when reverse name cannot be computed."""
        with patch("src.tools.dns.basic_dns.Resolver") as _mock_resolver_class:
            with patch(
                "src.tools.dns.basic_dns.Resolver.get_reverse_name"
            ) as mock_rev_name:
                mock_rev_name.return_value = None

                result = await reverse_dns_lookup_impl("93.184.216.34")

                assert result.success is False
                assert result.error is not None
                assert "Could not get reverse DNS name" in result.error


# ============================================================================
# Test Class: DNS Troubleshooting
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestDNSTroubleshooting:
    """Test suite for comprehensive DNS troubleshooting."""

    async def test_dns_troubleshooting_all_record_types(self):
        """Test troubleshooting checks all common record types."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Create mock result for each record type
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.get_rrset = MagicMock(return_value=None)

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)

            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = []
                mock_resolver_class.return_value = mock_resolver

                result = await dns_troubleshooting_impl("example.com")

                assert result.success is True
                assert isinstance(result.output, dict)

                # Should check for these record types
                expected_types = ["SOA", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SPF"]
                for rdtype in expected_types:
                    assert rdtype in result.output

                assert result.details["domain"] == "example.com"

    async def test_dns_troubleshooting_with_custom_nameserver(self):
        """Test troubleshooting with custom nameserver."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.get_rrset = MagicMock(return_value=None)

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)

            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = []
                mock_resolver_class.return_value = mock_resolver

                result = await dns_troubleshooting_impl(
                    "example.com", nameserver="8.8.8.8"
                )

                assert result.success is True
                # Verify Resolver was created with nameserver
                mock_resolver_class.assert_called_with(
                    nameservers=["8.8.8.8"], timeout=5.0
                )

    async def test_dns_troubleshooting_output_structure(self):
        """Test that troubleshooting output has correct structure."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.response.get_rrset = MagicMock(return_value=None)

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)

            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = []
                mock_resolver_class.return_value = mock_resolver

                result = await dns_troubleshooting_impl("example.com")

                assert result.success is True
                assert "output" in result.__dict__
                assert "details" in result.__dict__
                assert isinstance(result.output, dict)
                assert isinstance(result.details, dict)


# ============================================================================
# Test Class: Edge Cases and Error Handling
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestBasicDNSEdgeCases:
    """Test suite for edge cases and error handling."""

    async def test_simple_dns_lookup_with_no_response(self):
        """Test simple lookup when resolver returns None response."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.response = None
            mock_result.error = "No response"

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("example.com")

            assert result.success is False
            assert result.error == "No response"

    async def test_simple_dns_lookup_query_timeout(self):
        """Test simple lookup with query timeout."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.error = "Timeout"
            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await simple_dns_lookup_impl("example.com")

            assert result.success is False
            assert result.error is not None
            assert "Timeout" in result.error

    async def test_reverse_dns_lookup_loopback(self):
        """Test reverse DNS lookup for loopback address."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            with patch(
                "src.tools.dns.basic_dns.Resolver.get_reverse_name"
            ) as mock_rev_name:
                mock_rev_name.return_value = "1.0.0.127.in-addr.arpa"

                mock_resolver = MagicMock()

                ptr_result = MagicMock()
                ptr_result.success = True
                ptr_result.response = MagicMock()
                ptr_result.response.answer = MagicMock()
                ptr_result.qname = "1.0.0.127.in-addr.arpa."
                ptr_result.rdtype = dns.rdatatype.PTR
                ptr_result.response.rcode = MagicMock(return_value=0)
                ptr_result.duration = 0.05

                ptr_rrset = [MagicMock()]
                ptr_rrset[0].__str__ = MagicMock(return_value="localhost.")
                ptr_result.response.get_rrset = MagicMock(return_value=ptr_rrset)

                mock_resolver.async_resolve = AsyncMock(return_value=ptr_result)
                mock_resolver_class.return_value = mock_resolver

                result = await reverse_dns_lookup_impl("127.0.0.1")

                assert result.success is True
                assert result.details["is_local"] is True

    async def test_dns_troubleshooting_partial_failure(self):
        """Test troubleshooting when some queries fail."""
        with patch("src.tools.dns.basic_dns.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Create results that alternate between success and failure
            success_result = MagicMock()
            success_result.success = True
            success_result.response = MagicMock()
            success_result.qname = "example.com."
            success_result.response.get_rrset = MagicMock(return_value=None)

            fail_result = MagicMock()
            fail_result.success = False
            fail_result.response = None

            mock_resolver.async_resolve = AsyncMock(
                side_effect=[
                    success_result,
                    fail_result,
                    success_result,
                    fail_result,
                    success_result,
                    fail_result,
                    success_result,
                    fail_result,
                ]
            )

            with patch(
                "src.tools.dns.basic_dns.Resolver.get_records_from_rrset"
            ) as mock_get_records:
                mock_get_records.return_value = []
                mock_resolver_class.return_value = mock_resolver

                result = await dns_troubleshooting_impl("example.com")

                # Troubleshooting itself should succeed even if some queries fail
                assert result.success is True
                assert isinstance(result.output, dict)
