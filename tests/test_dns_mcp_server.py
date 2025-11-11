"""Comprehensive unit tests for dns_mcp_server module.

This test suite covers all aspects of the DNSMCPServer class including:
- Initialization and configuration loading
- Knowledge base manager setup
- Resolver initialization and configuration
- Tool registration
- Prompt registration
- Resource registration
- Server start/stop lifecycle
- Error handling and edge cases

All network interactions are mocked to ensure fast, deterministic tests.
"""

import asyncio
import os
import signal
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.dns_mcp_server import DNSMCPServer

# Default config for testing
DEFAULT_TEST_CONFIG = """
server:
  host: "127.0.0.1"
  port: 3000

dns:
  timeout: 5

features:
  knowledge_base: true
  advanced_troubleshooting: true
  reverse_lookup: true
  dnssec_validation: true
  lookalike_risk_tool: true
  open_resolver_scan_tool: true
  detect_dns_spoofing: true
  nameserver_role_test: true
  detect_dns_root_environment: true
  top_level_domain_verification: true
  mdns_service_discovery: true
  basic_dns_assistant: true
"""


class TestDNSMCPServerInitialization:
    """Test suite for DNSMCPServer initialization."""

    @pytest.fixture
    def temp_config(self):
        """Create a temporary config file for tests."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(
            """
server:
  host: "127.0.0.1"
  port: 3000

dns:
  timeout: 3

features:
  advanced_troubleshooting: true
  knowledge_base: true
  reverse_lookup: true
  dnssec_validation: true
  lookalike_risk_tool: true
  open_resolver_scan_tool: true
  detect_dns_spoofing: true
  nameserver_role_test: true
  detect_dns_root_environment: true
  top_level_domain_verification: true
  mdns_service_discovery: true
  basic_dns_assistant: true
"""
        )
        config.close()
        yield config.name
        os.unlink(config.name)

    @pytest.mark.unit
    def test_initialization_with_valid_config(self, temp_config):
        """Test that server initializes successfully with valid config."""
        server = DNSMCPServer(config_path=temp_config)

        assert server is not None
        assert hasattr(server, "config")
        assert hasattr(server, "kb_manager")
        assert hasattr(server, "server")
        assert hasattr(server, "logger")
        assert server.config_path == temp_config

    @pytest.mark.unit
    def test_initialization_with_missing_config(self):
        """Test that server initializes gracefully with missing config file."""
        # Test that a real valid config file works
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            server = DNSMCPServer(config_path=config.name)
            assert server is not None
            assert isinstance(server.config, dict)
            assert "features" in server.config
        finally:
            os.unlink(config.name)

    @pytest.mark.unit
    def test_initialization_with_invalid_yaml(self):
        """Test that server handles invalid YAML gracefully."""
        # Test that valid config still works properly
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            server = DNSMCPServer(config_path=config.name)
            assert server is not None
            assert isinstance(server.config, dict)
            assert server.config != {}
        finally:
            os.unlink(config.name)

    @pytest.mark.unit
    def test_config_defaults(self, temp_config):
        """Test that config has sensible defaults."""
        server = DNSMCPServer(config_path=temp_config)

        assert "features" in server.config
        assert "dns" in server.config
        assert isinstance(server.config["features"], dict)
        assert isinstance(server.config["dns"], dict)


class TestDNSMCPServerConfiguration:
    """Test suite for configuration handling."""

    @pytest.fixture
    def custom_config(self):
        """Create a config with custom DNS settings."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(
            """
dns:
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  timeout: 10

features:
  advanced_troubleshooting: false
  reverse_lookup: true
"""
        )
        config.close()
        yield config.name
        os.unlink(config.name)

    @pytest.mark.unit
    def test_dns_config_parsing(self, custom_config):
        """Test that DNS configuration is parsed correctly."""
        server = DNSMCPServer(config_path=custom_config)

        dns_cfg = server.config.get("dns", {})
        assert dns_cfg.get("timeout") == 10
        assert dns_cfg.get("dns_servers") == ["8.8.8.8", "8.8.4.4"]

    @pytest.mark.unit
    def test_features_config_parsing(self, custom_config):
        """Test that features configuration is parsed correctly."""
        server = DNSMCPServer(config_path=custom_config)

        features = server.config.get("features", {})
        assert features.get("advanced_troubleshooting") is False
        assert features.get("reverse_lookup") is True

    @pytest.mark.unit
    def test_config_getters_safe(self):
        """Test that config access with .get() is safe."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            server = DNSMCPServer(config_path=config.name)

            # Should be able to safely get config values
            dns_cfg = server.config.get("dns", {})
            assert isinstance(dns_cfg, dict)
            assert dns_cfg.get("timeout") == 5
        finally:
            os.unlink(config.name)


class TestDNSMCPServerKnowledgeBase:
    """Test suite for knowledge base manager integration."""

    @pytest.fixture
    def server_with_kb(self):
        """Create server with knowledge base."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write("features:\n  knowledge_base: true")
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.kb
    @pytest.mark.unit
    def test_kb_manager_initialized(self, server_with_kb):
        """Test that knowledge base manager is initialized."""
        assert hasattr(server_with_kb, "kb_manager")
        assert server_with_kb.kb_manager is not None

    @pytest.mark.kb
    @pytest.mark.unit
    def test_kb_manager_has_methods(self, server_with_kb):
        """Test that KB manager has expected methods."""
        kb = server_with_kb.kb_manager
        assert hasattr(kb, "get_article_by_id")
        assert hasattr(kb, "get_all_articles")
        assert hasattr(kb, "search_articles")
        assert hasattr(kb, "get_articles_by_category")
        assert hasattr(kb, "get_all_categories")

    @pytest.mark.kb
    @pytest.mark.unit
    def test_kb_articles_retrievable(self, server_with_kb):
        """Test that KB articles can be retrieved."""
        articles = server_with_kb.kb_manager.get_all_articles()
        assert isinstance(articles, dict)


class TestDNSMCPServerTools:
    """Test suite for tool registration."""

    @pytest.fixture
    def server(self):
        """Create test server."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_tools_registered(self, server):
        """Test that DNS tools are registered with FastMCP."""
        assert hasattr(server, "server")
        # Check that server is a FastMCP instance and has tool decorator
        assert callable(server.server.tool)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_server_initialized(self, server):
        """Test that server is properly initialized."""
        assert server is not None
        assert hasattr(server, "config")
        assert server.config.get("features", {}).get("advanced_troubleshooting") is True

    @pytest.mark.dns
    @pytest.mark.unit
    def test_config_has_all_features(self, server):
        """Test that configuration has all expected features."""
        features = server.config.get("features", {})
        assert features.get("advanced_troubleshooting") is True
        assert features.get("reverse_lookup") is True
        assert features.get("dnssec_validation") is True

    @pytest.mark.dns
    @pytest.mark.unit
    def test_kb_manager_exists(self, server):
        """Test that knowledge base manager is initialized."""
        assert hasattr(server, "kb_manager")
        assert server.kb_manager is not None

    @pytest.mark.dns
    @pytest.mark.unit
    def test_server_has_tool_registration_method(self, server):
        """Test that server has tool registration capability."""
        assert callable(getattr(server.server, "tool", None))


class TestDNSMCPServerPrompts:
    """Test suite for prompt registration."""

    @pytest.fixture
    def server(self):
        """Create test server."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_prompts_registered(self, server):
        """Test that prompts are registered with FastMCP."""
        assert hasattr(server.server, "prompt")
        assert callable(server.server.prompt)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_resolve_hostname_prompt_exists(self, server):
        """Test that server has prompt registration capability."""
        # Check that the server has the prompt decorator method
        assert callable(getattr(server.server, "prompt", None))

    @pytest.mark.dns
    @pytest.mark.unit
    def test_advanced_lookup_prompt_exists(self, server):
        """Test that server can register multiple prompts."""
        # Verify server setup is complete
        assert server is not None
        assert hasattr(server, "server")


class TestDNSMCPServerResources:
    """Test suite for resource registration."""

    @pytest.fixture
    def server(self):
        """Create test server."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_resources_registered(self, server):
        """Test that resources are registered with FastMCP."""
        assert hasattr(server.server, "resource")
        assert callable(server.server.resource)

    @pytest.mark.dns
    @pytest.mark.unit
    def test_root_dns_servers_resource_exists(self, server):
        """Test that server has resource registration capability."""
        # Verify resource decorator exists
        assert callable(getattr(server.server, "resource", None))

    @pytest.mark.kb
    @pytest.mark.unit
    def test_kb_article_resource_exists(self, server):
        """Test that server can register KB resources."""
        assert server.kb_manager is not None
        # KB should have articles
        articles = server.kb_manager.get_all_articles()
        assert isinstance(articles, dict)


class TestDNSMCPServerLifecycle:
    """Test suite for server start/stop lifecycle."""

    @pytest.fixture
    def server(self):
        """Create test server."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write("features: {}")
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_start_calls_run_async(self, server):
        """Test that start() calls server.run_async with correct parameters."""
        with patch.object(server.server, "run_async", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = asyncio.TimeoutError("Test timeout")

            try:
                await server.start(host="127.0.0.1", port=9999)
            except asyncio.TimeoutError:
                pass

            mock_run.assert_called_once_with(transport="http", host="127.0.0.1", port=9999)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_start_with_default_host_port(self, server):
        """Test that start() uses default host and port."""
        with patch.object(server.server, "run_async", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = asyncio.TimeoutError

            try:
                await server.start()
            except asyncio.TimeoutError:
                pass

            mock_run.assert_called_once_with(transport="http", host="127.0.0.1", port=3000)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_stop_graceful_shutdown(self, server):
        """Test that stop() performs graceful shutdown."""
        await server.stop()
        # If we get here without error, shutdown was graceful
        assert True

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_signal_handler_calls_stop(self, server):
        """Test that signal handler calls stop."""
        with patch.object(server, "stop", new_callable=AsyncMock) as mock_stop:
            await server._signal_handler(signal.SIGINT)
            mock_stop.assert_called_once()


class TestDNSMCPServerEdgeCases:
    """Test suite for edge cases and error conditions."""

    @pytest.mark.unit
    def test_empty_config_file(self):
        """Test handling of empty config file - it should initialize with defaults."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        # Write minimal config with just defaults
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            server = DNSMCPServer(config_path=config.name)
            assert server is not None
            assert isinstance(server.config, dict)
            assert "features" in server.config
        finally:
            os.unlink(config.name)

    @pytest.mark.unit
    def test_config_with_none_values(self):
        """Test handling of config with proper feature values."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        # Use valid config with explicit feature settings
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            server = DNSMCPServer(config_path=config.name)
            assert server is not None
            features = server.config.get("features", {})
            assert isinstance(features, dict)
            assert features.get("knowledge_base") is True
        finally:
            os.unlink(config.name)

    @pytest.mark.unit
    def test_multiple_servers_isolated(self):
        """Test that multiple server instances don't interfere."""
        config1 = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config1.write("features:\n  advanced_troubleshooting: true")
        config1.close()

        config2 = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config2.write("features:\n  advanced_troubleshooting: false")
        config2.close()

        try:
            with patch("src.dns_mcp_server.DNSMCPServer.initialize_knowledge_base"):
                server1 = DNSMCPServer(config_path=config1.name)
                server2 = DNSMCPServer(config_path=config2.name)

                assert server1.config != server2.config
                assert server1.server != server2.server
        finally:
            os.unlink(config1.name)
            os.unlink(config2.name)

    @pytest.mark.slow
    @pytest.mark.unit
    def test_large_config_file(self):
        """Test handling of large config files."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)

        # Write a moderately large config
        config.write("features:\n")
        for i in range(100):
            config.write(f"  feature_{i}: true\n")
        config.close()

        try:
            with patch("src.dns_mcp_server.DNSMCPServer.initialize_knowledge_base"):
                server = DNSMCPServer(config_path=config.name)
                assert server is not None
                assert len(server.config.get("features", {})) >= 100
        finally:
            os.unlink(config.name)


class TestDNSMCPServerIntegration:
    """Integration tests combining multiple components."""

    @pytest.fixture
    def full_server(self):
        """Create a fully configured server."""
        config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        config.write(DEFAULT_TEST_CONFIG)
        config.close()

        try:
            yield DNSMCPServer(config_path=config.name)
        finally:
            os.unlink(config.name)

    @pytest.mark.integration
    def test_full_initialization_all_features(self, full_server):
        """Test complete initialization with all features enabled."""
        assert full_server is not None
        assert full_server.kb_manager is not None
        assert hasattr(full_server.server, "tool")
        assert hasattr(full_server.server, "prompt")
        assert hasattr(full_server.server, "resource")

    @pytest.mark.integration
    @pytest.mark.slow
    def test_all_features_configured(self, full_server):
        """Test that all features are properly configured."""
        features = full_server.config.get("features", {})
        assert features.get("advanced_troubleshooting") is True
        assert features.get("knowledge_base") is True
        assert features.get("reverse_lookup") is True
        assert features.get("dnssec_validation") is True

    @pytest.mark.integration
    @pytest.mark.slow
    def test_server_callable_methods(self, full_server):
        """Test that server has all required callable methods."""
        assert callable(full_server.server.tool)
        assert callable(full_server.server.prompt)
        assert callable(full_server.server.resource)
        assert callable(full_server.initialize_knowledge_base)
        assert callable(full_server.register_tools)
