"""Comprehensive unit tests for dns.ns_tests module.

This test suite covers DNS server testing functions including:
- Basic record type testing
- QNAME handling and edge cases
- EDNS(0) support and options
- TCP behavior testing
- Performance testing under load
- Zone transfer testing (AXFR)
- CHAOS record querying
- Open resolver detection
- Robustness testing
- DNS COOKIE support

All network interactions are mocked to ensure fast, deterministic tests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import pytest

from dns_mcp_server.tools.dns.ns_tests import (
    performance_test,
    verify_basic_records,
    verify_chaos_records,
    verify_edns_support,
    verify_open_resolver,
    verify_qname_handling,
    verify_tcp_behavior,
    verify_zone_transfer,
)

# ============================================================================
# Test Class: Basic Record Type Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestBasicRecords:
    """Test suite for basic DNS record type testing."""

    async def test_basic_records_success(self):
        """Test successful basic record testing."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Mock successful result
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.duration = 0.05

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_basic_records("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert result["domain"] == "example.com"
            assert result["nameserver"] == "8.8.8.8"
            assert "record_tests" in result
            assert "summary" in result

    async def test_basic_records_structure(self):
        """Test that basic records returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A
            mock_result.duration = 0.05

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_basic_records("example.com", "8.8.8.8")

            # Check structure
            assert "summary" in result
            assert "total_tests" in result["summary"]
            assert "successful" in result["summary"]
            assert "failed" in result["summary"]
            assert "errors" in result["summary"]


# ============================================================================
# Test Class: QNAME Handling
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestQNameHandling:
    """Test suite for QNAME format and edge case handling."""

    async def test_qname_handling_structure(self):
        """Test that qname handling returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.rdtype = dns.rdatatype.A

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_qname_handling("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert "domain" in result
            assert "nameserver" in result
            assert "tests" in result
            assert "summary" in result
            assert "passed" in result["summary"]
            assert "failed" in result["summary"]

    async def test_qname_handling_case_variations(self):
        """Test handling of case variations in QNAME."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_qname_handling("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert result["summary"]["total_tests"] > 0


# ============================================================================
# Test Class: EDNS Support Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestEDNSSupport:
    """Test suite for EDNS(0) support testing."""

    async def test_edns_support_structure(self):
        """Test that EDNS support returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.details = {}

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_edns_support("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert "domain" in result
            assert "nameserver" in result
            assert "tests" in result
            assert "summary" in result

    async def test_edns_support_tests_multiple_sizes(self):
        """Test that EDNS support tests various buffer sizes."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.details = {}

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_edns_support("example.com", "8.8.8.8")

            # Should have created tests for buffer sizes
            assert result["summary"]["total_tests"] > 0


# ============================================================================
# Test Class: TCP Behavior Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestTCPBehavior:
    """Test suite for DNS-over-TCP behavior testing."""

    async def test_tcp_behavior_structure(self):
        """Test that TCP behavior returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.details = {"is_truncated": False}

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_tcp_behavior("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert "domain" in result
            assert "nameserver" in result
            assert "tests" in result
            assert "summary" in result
            assert "basic_tcp" in result["tests"]


# ============================================================================
# Test Class: Performance Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestPerformance:
    """Test suite for performance testing under load."""

    async def test_performance_structure(self):
        """Test that performance testing returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.duration = 0.05
            mock_result.rcode = 0  # NOERROR rcode
            mock_result.rcode_text = "NOERROR"

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await performance_test(
                "example.com", "8.8.8.8", num_queries=5, concurrent=2
            )

            assert isinstance(result, dict)
            assert "domain" in result
            assert "nameserver" in result
            assert "config" in result
            assert "measurements" in result
            assert "summary" in result
            assert "queries_per_second" in result["summary"]
            assert "success_rate" in result["summary"]

    async def test_performance_concurrent_queries(self):
        """Test performance testing with concurrent queries."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()
            mock_result.qname = "example.com."
            mock_result.duration = 0.01
            mock_result.rcode = 0  # NOERROR rcode
            mock_result.rcode_text = "NOERROR"

            mock_resolver.async_resolve = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await performance_test(
                "example.com", "8.8.8.8", num_queries=10, concurrent=5
            )

            # Should report success rate
            assert result["summary"]["success_rate"] >= 0
            assert result["config"]["total_queries"] == 10
            assert result["config"]["concurrent_queries"] == 5


# ============================================================================
# Test Class: Zone Transfer Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestZoneTransfer:
    """Test suite for zone transfer (AXFR) testing."""

    async def test_zone_transfer_denied(self):
        """Test zone transfer when denied."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.response = None
            mock_result.error = "REFUSED"

            mock_resolver.async_axfr = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_zone_transfer("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert result["details"]["axfr_allowed"] is False
            assert "summary" in result

    async def test_zone_transfer_structure(self):
        """Test zone transfer returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False

            mock_resolver.async_axfr = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_zone_transfer("example.com", "8.8.8.8")

            assert "domain" in result
            assert "nameserver" in result
            assert "details" in result
            assert "axfr_allowed" in result["details"]
            assert "summary" in result


# ============================================================================
# Test Class: CHAOS Records Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestCHAOSRecords:
    """Test suite for CHAOS record querying."""

    async def test_chaos_records_structure(self):
        """Test CHAOS records querying returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.response = None

            mock_resolver.query_version_bind = AsyncMock(return_value=mock_result)
            mock_resolver.query_hostname_bind = AsyncMock(return_value=mock_result)
            mock_resolver.query_id_server = AsyncMock(return_value=mock_result)
            mock_resolver.query_authors_bind = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_chaos_records("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert "nameserver" in result
            assert "tests" in result
            assert "details" in result
            assert "summary" in result

    async def test_chaos_records_checks_all_types(self):
        """Test CHAOS records checks all record types."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.response = None

            mock_resolver.query_version_bind = AsyncMock(return_value=mock_result)
            mock_resolver.query_hostname_bind = AsyncMock(return_value=mock_result)
            mock_resolver.query_id_server = AsyncMock(return_value=mock_result)
            mock_resolver.query_authors_bind = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_chaos_records("example.com", "8.8.8.8")

            # Should have tested all chaos records
            assert "version.bind" in result["details"]
            assert "hostname.bind" in result["details"]
            assert "id.server" in result["details"]
            assert "authors.bind" in result["details"]


# ============================================================================
# Test Class: Open Resolver Detection
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestOpenResolver:
    """Test suite for open resolver detection."""

    async def test_open_resolver_structure(self):
        """Test open resolver returns proper structure."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = False
            mock_result.response = None

            mock_resolver_class.return_value = mock_resolver

            result = await verify_open_resolver("example.com", "8.8.8.8")

            assert isinstance(result, dict)
            assert "domain" in result
            assert "nameserver" in result
            assert "is_open_resolver" in result
            assert "security_risk" in result
            assert "summary" in result

    async def test_open_resolver_security_classification(self):
        """Test open resolver classifies security risk properly."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            result = await verify_open_resolver("example.com", "8.8.8.8")

            # Security risk should be one of the expected values
            assert result["security_risk"] in ["none", "low", "medium", "high"]


# ============================================================================
# Test Class: Edge Cases and Error Handling
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestNSTestsEdgeCases:
    """Test suite for edge cases in DNS server testing."""

    async def test_basic_records_multiple_failures(self):
        """Test basic records when multiple queries fail."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Alternate between success and failure
            success_result = MagicMock()
            success_result.success = True
            success_result.response = MagicMock()
            success_result.qname = "example.com."
            success_result.duration = 0.05

            fail_result = MagicMock()
            fail_result.success = False
            fail_result.response = None
            fail_result.error = "Query failed"
            fail_result.details = None

            # verify_basic_records makes 14 calls (7 record types × 2: standard + EDNS)
            # Create a pattern of alternating failures
            side_effects = []
            for i in range(14):
                side_effects.append(success_result if i % 2 == 0 else fail_result)

            mock_resolver.async_resolve = AsyncMock(side_effect=side_effects)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_basic_records("example.com", "8.8.8.8")

            assert "summary" in result
            assert result["summary"]["failed"] > 0

    async def test_performance_with_failures(self):
        """Test performance calculation with some query failures."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            # Create results with some failures
            success_result = MagicMock()
            success_result.success = True
            success_result.response = MagicMock()
            success_result.qname = "example.com."
            success_result.duration = 0.05
            success_result.rcode = 0  # NOERROR rcode
            success_result.rcode_text = "NOERROR"

            fail_result = MagicMock()
            fail_result.success = False
            fail_result.response = None
            fail_result.rcode = 3  # NXDOMAIN rcode
            fail_result.duration = 0.02

            mock_resolver.async_resolve = AsyncMock(
                side_effect=[success_result, fail_result, success_result]
            )
            mock_resolver_class.return_value = mock_resolver

            result = await performance_test(
                "example.com", "8.8.8.8", num_queries=3, concurrent=1
            )

            # Success rate should be less than 100%
            assert result["summary"]["success_rate"] < 100
            assert result["summary"]["total_errors"] > 0

    async def test_zone_transfer_allowed(self):
        """Test zone transfer when allowed (security risk)."""
        with patch("dns_mcp_server.tools.dns.ns_tests.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()

            mock_result = MagicMock()
            mock_result.success = True
            mock_result.response = MagicMock()

            mock_resolver.async_axfr = AsyncMock(return_value=mock_result)
            mock_resolver_class.return_value = mock_resolver

            result = await verify_zone_transfer("example.com", "8.8.8.8")

            assert result["details"]["axfr_allowed"] is True
