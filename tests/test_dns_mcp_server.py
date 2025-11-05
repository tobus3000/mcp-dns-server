"""Unit tests for the DNS MCP Server."""

import asyncio
import os
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.dns_mcp_server import DNSMCPServer


class TestDNSMCPServer:
    """Test suite for DNSMCPServer class."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Create a temporary config file for testing
        self.temp_config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        self.temp_config.write(
            """
server:
  host: "127.0.0.1"
  port: 3000

dns:
  timeout: 3

features:
  advanced_troubleshooting: true
"""
        )
        self.temp_config.close()

    def teardown_method(self):
        """Clean up after each test method."""
        os.unlink(self.temp_config.name)

    def test_server_initialization(self):
        """Test that the DNS server initializes properly."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        assert server is not None
        assert server.resolver is not None
        assert hasattr(server, "kb_manager")
        assert server.kb_manager is not None

    def test_configure_resolver_with_custom_settings(self):
        """Test configuring resolver with custom settings."""
        # Create a config with custom DNS servers
        temp_config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        temp_config.write(
            """
dns:
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  timeout: 10
"""
        )
        temp_config.close()

        server = DNSMCPServer(config_path=temp_config.name)

        # Check that custom settings were applied
        assert server.resolver.nameservers == ["8.8.8.8", "8.8.4.4"]
        assert server.resolver.lifetime == 10.0

        os.unlink(temp_config.name)

    def test_configure_resolver_with_invalid_config(self):
        """Test handling of invalid config file."""
        # Create an invalid config file
        temp_config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        temp_config.write("invalid: yaml: content:::")
        temp_config.close()

        # This should not raise an exception but log an error and use defaults
        server = DNSMCPServer(config_path=temp_config.name)

        # Check that default resolver is still created
        assert server.resolver is not None

        os.unlink(temp_config.name)

    @pytest.mark.asyncio
    async def test_simple_dns_lookup_success(self):
        """Test successful simple DNS lookup."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to return a fixed result instead of making real DNS queries
        with patch.object(server.resolver, "resolve") as mock_resolve:
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter(["93.184.216.34"]))
            mock_resolve.return_value = mock_result

            result = await server._simple_dns_lookup_impl("example.com")

            assert result["status"] == "success"
            assert result["hostname"] == "example.com"
            assert "93.184.216.34" in result["ip_addresses"]

    @pytest.mark.asyncio
    async def test_simple_dns_lookup_nxdomain(self):
        """Test simple DNS lookup with NXDOMAIN error."""
        import dns.resolver

        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to raise NXDOMAIN exception
        with patch.object(server.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
            result = await server._simple_dns_lookup_impl("nonexistent-domain-12345.com")

            assert result["status"] == "error"
            assert "nonexistent-domain-12345.com" in result["error"]

    @pytest.mark.asyncio
    async def test_simple_dns_lookup_no_answer(self):
        """Test simple DNS lookup with NoAnswer error."""
        import dns.resolver

        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to raise NoAnswer exception
        with patch.object(server.resolver, "resolve", side_effect=dns.resolver.NoAnswer):
            result = await server._simple_dns_lookup_impl("example.com")

            assert result["status"] == "error"
            assert "No A record found for example.com" in result["error"]

    @pytest.mark.asyncio
    async def test_advanced_dns_lookup_mx_record(self):
        """Test advanced DNS lookup for MX records."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock an MX record result
        mock_rdata = Mock()
        mock_rdata.preference = 10
        mock_rdata.exchange = "mail.example.com."

        with patch.object(server.resolver, "resolve") as mock_resolve:
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter([mock_rdata]))
            mock_resolve.return_value = mock_result

            result = await server._advanced_dns_lookup_impl("example.com", "MX")

            assert result["status"] == "success"
            assert result["record_type"] == "MX"
            assert len(result["records"]) > 0
            assert result["records"][0]["exchange"] == "mail.example.com."

    @pytest.mark.asyncio
    async def test_advanced_dns_lookup_nxdomain(self):
        """Test advanced DNS lookup with NXDOMAIN error."""
        import dns.resolver

        server = DNSMCPServer(config_path=self.temp_config.name)

        with patch.object(server.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
            result = await server._advanced_dns_lookup_impl("nonexistent.com", "A")

            assert result["status"] == "error"
            assert "nonexistent.com" in result["error"]

    @pytest.mark.asyncio
    async def test_reverse_dns_lookup_success(self):
        """Test successful reverse DNS lookup."""
        import dns.reversename

        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the reverse name and resolver result
        mock_rev_name = Mock()

        mock_rdata = Mock()
        mock_rdata.__str__ = Mock(return_value="example.com.")

        with patch.object(dns.reversename, "from_address", return_value=mock_rev_name):
            with patch.object(server.resolver, "resolve") as mock_resolve:
                mock_result = MagicMock()
                mock_result.__iter__ = Mock(return_value=iter([mock_rdata]))
                mock_resolve.return_value = mock_result

                result = await server.reverse_dns_lookup_impl("93.184.216.34")

                assert result["status"] == "success"
                assert result["ip_address"] == "93.184.216.34"
                assert "example.com." in result["hostnames"]

    @pytest.mark.asyncio
    async def test_reverse_dns_lookup_invalid_ip(self):
        """Test reverse DNS lookup with invalid IP address."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        result = await server._reverse_dns_lookup_impl("invalid-ip")

        assert result["status"] == "error"
        assert "invalid-ip" in result["error"]

    @pytest.mark.asyncio
    async def test_reverse_dns_lookup_nxdomain(self):
        """Test reverse DNS lookup with NXDOMAIN error."""
        import dns.resolver
        import dns.reversename

        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the reverse name and resolver to raise NXDOMAIN
        mock_rev_name = Mock()

        with patch.object(dns.reversename, "from_address", return_value=mock_rev_name):
            with patch.object(server.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
                result = await server._reverse_dns_lookup_impl("8.8.8.8")

                assert result["status"] == "error"
                assert "No PTR record found for 8.8.8.8" in result["error"]

    @pytest.mark.asyncio
    async def test_dns_troubleshooting_success(self):
        """Test successful DNS troubleshooting."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock different types of DNS records
        mock_a_result = Mock()
        mock_a_result.__iter__ = Mock(return_value=iter(["93.184.216.34"]))

        mock_aaaa_result = Mock()
        mock_aaaa_result.__iter__ = Mock(return_value=iter(["2606:2800:220:1:248:1893:25c8:1946"]))

        mock_cname_result = Mock()
        mock_cname_result.__str__ = Mock(return_value="www.example.com.")

        mock_mx_result = Mock()
        mock_mx_result.preference = 10
        mock_mx_result.exchange = "mail.example.com."

        mock_ns_result = Mock()
        mock_ns_result.__str__ = Mock(return_value="ns1.example.com.")

        mock_txt_result = Mock()
        mock_txt_result.__str__ = Mock(return_value="v=spf1 include:_spf.google.com ~all")

        # Create a mock resolver that returns different results for different record types
        def mock_resolve(hostname, record_type):
            if record_type == "A":
                return mock_a_result
            elif record_type == "AAAA":
                return mock_aaaa_result
            elif record_type == "CNAME":
                # CNAME result should be iterable for the [str(rdata) for rdata in cname_result] line
                cname_iterable = Mock()
                cname_iterable.__iter__ = Mock(return_value=iter([mock_cname_result]))
                return cname_iterable
            elif record_type == "MX":
                # MX result should be iterable for the list comprehension
                mx_iterable = Mock()
                mx_iterable.__iter__ = Mock(return_value=iter([mock_mx_result]))
                return mx_iterable
            elif record_type == "NS":
                # NS result should be iterable
                ns_iterable = Mock()
                ns_iterable.__iter__ = Mock(return_value=iter([mock_ns_result]))
                return ns_iterable
            elif record_type == "TXT":
                # TXT result should be iterable
                txt_iterable = Mock()
                txt_iterable.__iter__ = Mock(return_value=iter([mock_txt_result]))
                return txt_iterable
            else:
                # For any other type, return an empty result
                empty_result = Mock()
                empty_result.__iter__ = Mock(return_value=iter([]))
                return empty_result

        with patch.object(server.resolver, "resolve", side_effect=mock_resolve):
            result = await server._dns_troubleshooting_impl("example.com")

            assert result["status"] == "success"
            assert result["domain"] == "example.com"
            assert "A" in result["troubleshooting_results"]
            assert "AAAA" in result["troubleshooting_results"]
            assert "CNAME" in result["troubleshooting_results"]
            assert "MX" in result["troubleshooting_results"]
            assert "NS" in result["troubleshooting_results"]
            assert "TXT" in result["troubleshooting_results"]

    @pytest.mark.asyncio
    async def test_start_and_stop_server(self):
        """Test starting and stopping the server."""
        server = DNSMCPServer(config_path=self.temp_config.name)
        # Mock the server run_async method to prevent actual network operations
        with patch.object(server.server, "run_async") as mock_run_async:
            # The start method should call run_async with HTTP transport
            try:
                # We'll simulate a quick return to avoid blocking
                mock_run_async.side_effect = asyncio.TimeoutError
                await server.start(host="127.0.0.1", port=9999)
            except asyncio.TimeoutError:
                # This is expected since we mocked it to raise an exception
                pass

            # Verify that run_async was called with the correct parameters
            mock_run_async.assert_called_once_with(transport="http", host="127.0.0.1", port=9999)

    def test_initialize_knowledge_base(self):
        """Test that knowledge base is properly initialized."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Check that knowledge base manager is initialized
        assert server.kb_manager is not None
        assert hasattr(server.kb_manager, "get_all_articles")
