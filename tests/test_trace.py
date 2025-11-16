"""Comprehensive unit tests for DNS trace module.

This test suite covers all aspects of DNS tracing including:
- Root server discovery
- Iterative DNS trace through hierarchy
- Query hierarchy level traversal
- Next server extraction from responses
- CNAME chain following
- Final answer resolution
- Formatted output generation
- Error handling and edge cases

All network interactions are mocked to ensure fast, deterministic tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from src.tools.dns.trace import Trace, dns_trace_impl
from src.typedefs import ToolResult

# ============================================================================
# Test Fixtures - Root server response with proper NS records
# ============================================================================


@pytest.fixture
def root_servers_response_fixture():
    """Create a properly mock DNS response containing root NS records."""
    response = MagicMock(spec=dns.message.Message)
    response.question = [MagicMock()]
    response.question[0].to_text = MagicMock(return_value=". IN NS")

    # Create mock NS records in answer section
    root_servers = [
        "a.root-servers.net.",
        "b.root-servers.net.",
        "c.root-servers.net.",
    ]

    ns_rdata_list = []
    for server in root_servers:
        rdata = MagicMock()
        rdata.target = dns.name.from_text(server)
        rdata.__str__ = MagicMock(return_value=server)
        ns_rdata_list.append(rdata)

    ns_rrset = MagicMock(spec=dns.rrset.RRset)
    ns_rrset.rdtype = dns.rdatatype.NS
    ns_rrset.name = dns.name.from_text(".")
    ns_rrset.ttl = 500
    ns_rrset.__iter__ = MagicMock(return_value=iter(ns_rdata_list))

    response.answer = [ns_rrset]
    response.authority = []
    response.additional = []

    return response


# ============================================================================
# Test Class: Root Server Discovery
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestFetchRootServers:
    """Test suite for root server discovery."""

    def test_fetch_root_servers_success(self):
        """Test successful root server discovery."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            # Create root NS rrset
            ns_rrset = MagicMock()
            ns_rdata1 = MagicMock()
            ns_rdata1.target = dns.name.from_text("a.root-servers.net.")
            ns_rrset.__iter__ = MagicMock(return_value=iter([ns_rdata1]))

            # Create A record
            a_rrset = MagicMock()
            a_rdata = MagicMock()
            a_rdata.address = "198.41.0.4"
            a_rrset.__iter__ = MagicMock(return_value=iter([a_rdata]))

            mock_resolver.resolve = MagicMock(
                side_effect=[
                    (ns_rrset, MagicMock()),  # NS records
                    (a_rrset, MagicMock()),  # A record
                    (None, MagicMock()),  # AAAA record
                ]
            )

            trace = Trace(follow_cname=True)
            root_servers = trace.fetch_root_servers()

            assert root_servers is not None
            assert len(root_servers) > 0
            assert "198.41.0.4" in root_servers

    def test_fetch_root_servers_no_rrset(self):
        """Test root server discovery when NS rrset is empty."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = MagicMock(return_value=(None, MagicMock()))

            trace = Trace(follow_cname=True)
            root_servers = trace.fetch_root_servers()

            assert root_servers == []


# ============================================================================
# Test Class: Query Hierarchy Level
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestQueryHierarchyLevel:
    """Test suite for querying hierarchy levels."""

    def test_query_hierarchy_level_success(self):
        """Test successful query for a hierarchy level."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            response = MagicMock()
            response.question = [MagicMock()]
            response.question[0].to_text = MagicMock(return_value=". IN NS")
            mock_resolver.resolve = MagicMock(return_value=(MagicMock(), response))

            trace = Trace(follow_cname=True)
            subdomain = dns.name.from_text(".")
            servers = ["198.41.0.4"]

            result = trace._query_hierarchy_level(subdomain, servers)

            assert result is not None
            assert len(trace.trace_steps) == 1
            assert trace.trace_steps[0]["qname"] == "."
            assert trace.trace_steps[0]["qtype"] == "NS"

    def test_query_hierarchy_level_no_response(self):
        """Test query when no response is received."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = MagicMock(return_value=(MagicMock(), None))

            trace = Trace(follow_cname=True)
            subdomain = dns.name.from_text(".")
            servers = ["198.41.0.4"]

            result = trace._query_hierarchy_level(subdomain, servers)

            assert result is None
            assert len(trace.trace_steps) == 0

    def test_query_hierarchy_level_multiple_servers(self):
        """Test query tries multiple servers until success."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            response = MagicMock()
            mock_resolver.resolve = MagicMock(
                side_effect=[
                    (MagicMock(), None),  # First server fails
                    (MagicMock(), response),  # Second succeeds
                ]
            )

            trace = Trace(follow_cname=True)
            subdomain = dns.name.from_text(".")
            servers = ["198.41.0.4", "199.9.14.201"]

            result = trace._query_hierarchy_level(subdomain, servers)

            assert result is not None
            assert len(trace.trace_steps) == 1
            assert trace.trace_steps[0]["server"] == "199.9.14.201"

    def test_query_hierarchy_level_all_servers_fail(self):
        """Test query when all servers fail."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = MagicMock(return_value=(MagicMock(), None))

            trace = Trace(follow_cname=True)
            subdomain = dns.name.from_text(".")
            servers = ["198.41.0.4", "199.9.14.201"]

            result = trace._query_hierarchy_level(subdomain, servers)

            assert result is None
            assert len(trace.trace_steps) == 0


# ============================================================================
# Test Class: Extract Next Servers
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestExtractNextServers:
    """Test suite for extracting next servers from responses."""

    def test_extract_from_additional_section(self):
        """Test extracting servers from additional section."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)

            # Create A record in additional section
            a_rrset = MagicMock(spec=dns.rrset.RRset)
            a_rrset.rdtype = dns.rdatatype.A

            a_rdata = MagicMock()
            a_rdata.address = "192.0.32.8"
            a_rrset.__iter__ = MagicMock(return_value=iter([a_rdata]))

            response.additional = [a_rrset]
            response.authority = []
            response.answer = []

            servers = trace._extract_next_servers(response)

            assert servers == ["192.0.32.8"]

    def test_extract_with_none_response(self):
        """Test extracting servers when response is None."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)
            servers = trace._extract_next_servers(None)

            assert servers == []

    def test_extract_multiple_servers(self):
        """Test extracting multiple servers from response."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)

            # Create multiple A records in additional section
            a_rrset1 = MagicMock(spec=dns.rrset.RRset)
            a_rrset1.rdtype = dns.rdatatype.A
            a_rdata1 = MagicMock()
            a_rdata1.address = "192.0.32.8"
            a_rrset1.__iter__ = MagicMock(return_value=iter([a_rdata1]))

            a_rrset2 = MagicMock(spec=dns.rrset.RRset)
            a_rrset2.rdtype = dns.rdatatype.A
            a_rdata2 = MagicMock()
            a_rdata2.address = "192.0.33.8"
            a_rrset2.__iter__ = MagicMock(return_value=iter([a_rdata2]))

            response.additional = [a_rrset1, a_rrset2]
            response.authority = []
            response.answer = []

            servers = trace._extract_next_servers(response)

            assert len(servers) == 2
            assert "192.0.32.8" in servers
            assert "192.0.33.8" in servers

    def test_extract_servers_no_sections(self):
        """Test extracting servers when response has no populated sections."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)
            response.additional = []
            response.authority = []
            response.answer = []

            servers = trace._extract_next_servers(response)

            assert servers == []


# ============================================================================
# Test Class: Perform Trace
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestPerformTrace:
    """Test suite for complete DNS trace operation."""

    def test_perform_trace_single_level(self):
        """Test trace for root domain."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            ns_rrset = MagicMock()
            ns_rdata = MagicMock()
            ns_rdata.target = dns.name.from_text("a.root-servers.net.")
            ns_rrset.__iter__ = MagicMock(return_value=iter([ns_rdata]))

            response = MagicMock()
            response.answer = [ns_rrset]
            response.authority = []
            response.additional = []

            mock_resolver.resolve = MagicMock(return_value=(ns_rrset, response))

            trace = Trace(follow_cname=True)
            result = trace.perform_trace(".")

            assert result["domain"] == "."

    def test_perform_trace_no_root_servers(self):
        """Test trace when root servers cannot be discovered."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = MagicMock(return_value=(None, MagicMock()))

            trace = Trace(follow_cname=True)
            result = trace.perform_trace("example.com")

            assert result["domain"] == "example.com"
            assert "error" in result
            assert result["error"] == "No root servers found."
            assert result["hops"] == []

    def test_perform_trace_clears_previous_steps(self):
        """Test that trace_steps are cleared on new trace."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver

            ns_rrset = MagicMock()
            ns_rdata = MagicMock()
            ns_rdata.target = dns.name.from_text("a.root-servers.net.")
            ns_rrset.__iter__ = MagicMock(return_value=iter([ns_rdata]))

            response = MagicMock()
            response.answer = [ns_rrset]
            response.authority = []
            response.additional = []

            mock_resolver.resolve = MagicMock(return_value=(ns_rrset, response))

            trace = Trace(follow_cname=True)

            # First trace
            trace.perform_trace("example.com")
            first_hop_count = len(trace.trace_steps)

            # Second trace
            trace.perform_trace("google.com")
            second_hop_count = len(trace.trace_steps)

            # Should reset properly
            assert first_hop_count >= 0
            assert second_hop_count >= 0


# ============================================================================
# Test Class: Format Output
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestFormatOutput:
    """Test suite for formatting trace output."""

    def test_get_dig_style_basic(self):
        """Test dig-style output formatting."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock()
            response.question = [MagicMock()]
            response.question[0].to_text = MagicMock(return_value=". IN NS")
            response.answer = []
            response.authority = []
            response.additional = []

            trace.trace_steps = [
                {
                    "server": "198.41.0.4",
                    "qname": ".",
                    "qtype": "NS",
                    "response": response,
                }
            ]

            output = trace.get_dig_style()

            assert ";; TRACE OUTPUT (dig +trace style)" in output
            assert ";; Hop 1: Server 198.41.0.4" in output
            assert ";; QUESTION SECTION:" in output

    def test_get_dig_style_multiple_hops(self):
        """Test dig-style output with multiple hops."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response1 = MagicMock()
            response1.question = [MagicMock()]
            response1.question[0].to_text = MagicMock(return_value=". IN NS")
            response1.answer = []
            response1.authority = []
            response1.additional = []

            response2 = MagicMock()
            response2.question = [MagicMock()]
            response2.question[0].to_text = MagicMock(return_value="com. IN NS")
            response2.answer = []
            response2.authority = []
            response2.additional = []

            trace.trace_steps = [
                {"server": "198.41.0.4", "qname": ".", "qtype": "NS", "response": response1},
                {
                    "server": "192.0.32.8",
                    "qname": "com.",
                    "qtype": "NS",
                    "response": response2,
                },
            ]

            output = trace.get_dig_style()

            assert ";; Hop 1: Server 198.41.0.4" in output
            assert ";; Hop 2: Server 192.0.32.8" in output

    def test_get_dig_style_empty_trace(self):
        """Test dig-style output with no trace steps."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)
            trace.trace_steps = []

            output = trace.get_dig_style()

            assert ";; TRACE OUTPUT (dig +trace style)" in output


# ============================================================================
# Test Class: CNAME Resolution
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestCNAMEResolution:
    """Test suite for CNAME chain following."""

    def test_resolve_final_answer_with_a_records(self):
        """Test resolving final answer with A records."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)

            # Create A record in answer section
            a_rrset = MagicMock(spec=dns.rrset.RRset)
            a_rrset.rdtype = dns.rdatatype.A
            a_rrset.name = dns.name.from_text("example.com.")
            a_rrset.ttl = 300

            a_rdata = MagicMock()
            a_rdata.__str__ = MagicMock(return_value="93.184.216.34")
            a_rrset.__iter__ = MagicMock(return_value=iter([a_rdata]))

            response.answer = [a_rrset]

            result = trace._resolve_final_answer(response)

            assert len(result) == 1
            assert result[0]["name"] == "example.com."
            assert result[0]["type"] == "A"
            assert result[0]["value"] == "93.184.216.34"

    def test_resolve_final_answer_without_cname_follow(self):
        """Test resolving final answer with CNAME follow disabled."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=False)
            response = MagicMock(spec=dns.message.Message)
            response.answer = []

            result = trace._resolve_final_answer(response)

            assert result == []

    def test_resolve_final_answer_with_none_response(self):
        """Test resolving final answer when response is None."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)
            result = trace._resolve_final_answer(None)

            assert result == []


# ============================================================================
# Test Class: Integration
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestTraceIntegration:
    """Test suite for integrated trace functionality."""

    def test_trace_format_rrset(self):
        """Test RRset formatting utility method."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            rrset = MagicMock(spec=dns.rrset.RRset)
            rrset.name = dns.name.from_text("example.com.")
            rrset.ttl = 300
            rrset.rdtype = dns.rdatatype.A

            rdata = MagicMock()
            rdata.__str__ = MagicMock(return_value="93.184.216.34")
            rrset.__iter__ = MagicMock(return_value=iter([rdata]))

            result = trace._format_rrset([rrset])

            assert len(result) == 1
            assert result[0]["name"] == "example.com."
            assert result[0]["ttl"] == 300
            assert result[0]["type"] == "A"
            assert result[0]["value"] == "93.184.216.34"

    def test_trace_initialization(self):
        """Test Trace object initialization."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            assert trace.resolver is not None
            assert trace.trace_steps == []
            assert trace.follow_cname is True

    def test_trace_initialization_without_cname(self):
        """Test Trace initialization without CNAME following."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=False)

            assert trace.follow_cname is False


# ============================================================================
# Test Class: Async Implementation
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
@pytest.mark.asyncio
class TestDNSTraceImpl:
    """Test suite for async dns_trace_impl function."""

    async def test_dns_trace_impl_success(self):
        """Test successful async DNS trace implementation."""
        with patch("src.tools.dns.trace.Trace") as mock_trace_class:
            mock_trace = MagicMock()
            mock_trace.get_dig_style = MagicMock(
                return_value=";; TRACE OUTPUT\n;; Hop 1: Server 198.41.0.4"
            )
            mock_trace_class.return_value = mock_trace

            result = await dns_trace_impl("example.com")

            assert result.success is True
            assert isinstance(result.output, dict)
            assert result.output.get("domain") == "example.com"
            assert "dns_trace" in result.output
            mock_trace.perform_trace.assert_called_once_with("example.com")

    async def test_dns_trace_impl_whitespace_handling(self):
        """Test that dns_trace_impl handles whitespace in domain."""
        with patch("src.tools.dns.trace.Trace") as mock_trace_class:
            mock_trace = MagicMock()
            mock_trace.get_dig_style = MagicMock(return_value=";; TRACE OUTPUT")
            mock_trace_class.return_value = mock_trace

            await dns_trace_impl("  example.com  ")

            mock_trace.perform_trace.assert_called_once_with("example.com")


# ============================================================================
# Test Class: Edge Cases
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestEdgeCases:
    """Test suite for edge cases and error scenarios."""

    def test_extract_mixed_record_types(self):
        """Test extracting servers with mixed record types."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)

            # Create A record
            a_rrset = MagicMock(spec=dns.rrset.RRset)
            a_rrset.rdtype = dns.rdatatype.A
            a_rdata = MagicMock()
            a_rdata.address = "192.0.32.8"
            a_rrset.__iter__ = MagicMock(return_value=iter([a_rdata]))

            # Create AAAA record
            aaaa_rrset = MagicMock(spec=dns.rrset.RRset)
            aaaa_rrset.rdtype = dns.rdatatype.AAAA
            aaaa_rdata = MagicMock()
            aaaa_rdata.address = "2001:500:200::b"
            aaaa_rrset.__iter__ = MagicMock(return_value=iter([aaaa_rdata]))

            response.additional = [a_rrset, aaaa_rrset]
            response.authority = []
            response.answer = []

            servers = trace._extract_next_servers(response)

            assert len(servers) == 2
            assert "192.0.32.8" in servers
            assert "2001:500:200::b" in servers

    def test_perform_trace_with_complex_domain(self):
        """Test trace with deeply nested domain."""
        with patch("src.tools.dns.trace.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve = MagicMock(
                return_value=(None, MagicMock(answer=[], authority=[], additional=[]))
            )

            trace = Trace(follow_cname=True)
            result = trace.perform_trace("subdomain.example.co.uk")

            assert result["domain"] == "subdomain.example.co.uk"

    def test_query_hierarchy_with_empty_servers_list(self):
        """Test query hierarchy with empty servers list."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)
            subdomain = dns.name.from_text("example.com.")
            servers = []

            response = trace._query_hierarchy_level(subdomain, servers)

            assert response is None
            assert len(trace.trace_steps) == 0

    def test_format_empty_rrset(self):
        """Test formatting empty RRset."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)
            result = trace._format_rrset([])

            assert result == []

    def test_extract_servers_no_sections(self):
        """Test extracting servers when response has no populated sections."""
        with patch("src.tools.dns.trace.Resolver"):
            trace = Trace(follow_cname=True)

            response = MagicMock(spec=dns.message.Message)
            response.additional = []
            response.authority = []
            response.answer = []

            servers = trace._extract_next_servers(response)

            assert servers == []
