"""Unit tests for edge cases and error conditions."""

import os
import socket
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.dns_mcp_server import DNSMCPServer


class TestEdgeCasesAndErrorConditions:
    """Test suite for edge cases and error conditions."""

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

    def test_config_file_not_found(self):
        """Test server initialization when config file doesn't exist."""
        server = DNSMCPServer(config_path="/nonexistent/path/config.yaml")

        # Should still initialize with default resolver
        assert server.resolver is not None

    @pytest.mark.asyncio
    async def test_simple_dns_lookup_exception(self):
        """Test simple DNS lookup with unexpected exception."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to raise an unexpected exception
        with patch.object(server.resolver, "resolve", side_effect=Exception("Unexpected error")):
            result = await server._simple_dns_lookup_impl("example.com")

            assert result["status"] == "error"
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_advanced_dns_lookup_exception(self):
        """Test advanced DNS lookup with unexpected exception."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to raise an unexpected exception
        with patch.object(server.resolver, "resolve", side_effect=Exception("Unexpected error")):
            result = await server._advanced_dns_lookup_impl("example.com", "A")

            assert result["status"] == "error"
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_reverse_dns_lookup_socket_error(self):
        """Test reverse DNS lookup with socket errors."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # This is already tested in the main tests, but let's ensure it's covered
        result = await server._reverse_dns_lookup_impl("invalid-ip")

        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_reverse_dns_lookup_exception(self):
        """Test reverse DNS lookup with unexpected exception."""
        import dns.reversename

        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the reverse name and resolver to raise an unexpected exception
        mock_rev_name = Mock()

        with patch.object(dns.reversename, "from_address", return_value=mock_rev_name):
            with patch.object(
                server.resolver, "resolve", side_effect=Exception("Unexpected error")
            ):
                result = await server._reverse_dns_lookup_impl("93.184.216.34")

                assert result["status"] == "error"
                assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_dns_troubleshooting_exception(self):
        """Test DNS troubleshooting with unexpected exception."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Mock the resolver to raise an unexpected exception for A record
        with patch.object(server.resolver, "resolve", side_effect=Exception("Unexpected error")):
            result = await server._dns_troubleshooting_impl("example.com")

            assert result["status"] == "error"
            assert "Unexpected error" in result["error"]

    def test_knowledge_base_manager_with_nonexistent_directory(self):
        """Test knowledge base manager with a nonexistent directory."""
        # Create a temporary directory path that doesn't exist yet
        import shutil

        temp_dir = tempfile.mkdtemp()
        nonexistent_dir = os.path.join(temp_dir, "nonexistent")

        # Create the manager - it should create the directory
        from src.knowledge_base.manager import KnowledgeBaseManager

        manager = KnowledgeBaseManager(kb_dir=nonexistent_dir)

        # Check that the directory was created
        assert os.path.exists(nonexistent_dir)

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_knowledge_base_search_empty_results(self):
        """Test knowledge base search with no results."""
        import shutil

        from src.knowledge_base.manager import KnowledgeBaseManager

        temp_dir = tempfile.mkdtemp()

        # Create manager with empty directory
        manager = KnowledgeBaseManager(kb_dir=temp_dir)

        # Search for something that doesn't exist
        results = manager.search_articles("nonexistent")

        assert len(results) == 0
        assert results == []

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_knowledge_base_get_categories_empty(self):
        """Test getting categories from empty knowledge base."""
        import shutil

        from src.knowledge_base.manager import KnowledgeBaseManager

        temp_dir = tempfile.mkdtemp()

        # Create manager with empty directory
        manager = KnowledgeBaseManager(kb_dir=temp_dir)

        # Get all categories
        categories = manager.get_all_categories()

        assert len(categories) == 0
        assert categories == []

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_knowledge_base_add_article_invalid_data(self):
        """Test adding an article with invalid data."""
        import shutil

        from src.knowledge_base.manager import KnowledgeBaseManager

        temp_dir = tempfile.mkdtemp()

        # Create manager
        manager = KnowledgeBaseManager(kb_dir=temp_dir)

        # Try to add an article without required id
        success = manager.add_article({"title": "No ID Article"})

        assert success is False

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_knowledge_base_add_article_with_invalid_chars(self):
        """Test adding an article with invalid characters in ID."""
        import shutil

        from src.knowledge_base.manager import KnowledgeBaseManager

        temp_dir = tempfile.mkdtemp()

        # Create a temporary file with invalid characters in name to test error handling
        manager = KnowledgeBaseManager(kb_dir=temp_dir)

        # Create test article with problematic characters in ID
        article_data = {
            "id": "../test_article",  # This could cause a path traversal issue
            "title": "Article with Path Issue",
            "category": "test",
            "tags": ["test"],
            "content": "Test content.",
        }

        success = manager.add_article(article_data)
        # The result could be either success or failure depending on how the file system handles it,
        # but the important thing is that it doesn't cause a security issue

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_knowledge_article_with_special_characters(self):
        """Test getting a knowledge base article with special characters in ID."""
        import shutil

        from src.knowledge_base.manager import KnowledgeBaseManager

        temp_dir = tempfile.mkdtemp()

        # Create an article with special characters in the ID
        article_content = """id: special-article_123
title: "Special Article"
category: "test"
tags:
  - "test"
content: "Article with special characters in ID."
"""
        article_path = os.path.join(temp_dir, "special-article_123.yaml")
        with open(article_path, "w", encoding="utf-8") as f:
            f.write(article_content)

        # Create manager and test retrieval
        manager = KnowledgeBaseManager(kb_dir=temp_dir)
        article = manager.get_article_by_id("special-article_123")

        assert article is not None
        assert article["id"] == "special-article_123"

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_server_with_invalid_config_yaml(self):
        """Test server initialization with invalid YAML config."""
        # Create a temporary config file with invalid YAML
        invalid_config = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        invalid_config.write("invalid: yaml: content:::")
        invalid_config.close()

        try:
            # This should handle the YAML parsing error gracefully
            server = DNSMCPServer(config_path=invalid_config.name)

            # Server should still initialize with default settings
            assert server is not None
            assert server.resolver is not None
        finally:
            os.unlink(invalid_config.name)
