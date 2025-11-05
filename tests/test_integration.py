"""Integration tests for the DNS MCP Server and Knowledge Base."""

import os
import tempfile

import pytest

from src.dns_mcp_server import DNSMCPServer


class TestIntegration:
    """Integration tests for DNS MCP Server components."""

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

        # Create a temporary directory for test articles
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up after each test method."""
        os.unlink(self.temp_config.name)
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_server_initialization(self):
        """Test that the server initializes all components correctly."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Check that all components are initialized
        assert server is not None
        assert server.resolver is not None
        assert server.kb_manager is not None
        assert server.logger is not None

        # Check that knowledge base has articles
        articles = server.kb_manager.get_all_articles()
        assert isinstance(articles, dict)

    def test_knowledge_base_with_real_articles(self):
        """Test knowledge base functionality with actual article files."""
        # Create test articles
        article1_content = """id: integration_test_article
title: "Integration Test Article"
category: "test"
tags:
  - "integration"
  - "test"
content: "This is an article for integration testing."
"""
        article_path = os.path.join(self.temp_dir, "integration_test_article.yaml")
        with open(article_path, "w", encoding="utf-8") as f:
            f.write(article1_content)

        # Create a knowledge base manager with our test directory
        from src.knowledge_base.manager import KnowledgeBaseManager

        kb_manager = KnowledgeBaseManager(kb_dir=self.temp_dir)

        # Test all knowledge base functionality
        article = kb_manager.get_article_by_id("integration_test_article")
        assert article is not None
        assert article["id"] == "integration_test_article"
        assert article["title"] == "Integration Test Article"

        # Test search functionality
        search_results = kb_manager.search_articles("integration")
        assert len(search_results) == 1
        assert search_results[0]["id"] == "integration_test_article"

        # Test category functionality
        categories = kb_manager.get_all_categories()
        assert "test" in categories

        # Test category filtering
        category_articles = kb_manager.get_articles_by_category("test")
        assert len(category_articles) == 1
        assert category_articles[0]["id"] == "integration_test_article"

    @pytest.mark.asyncio
    async def test_server_with_custom_knowledge_base(self):
        """Test server with a custom knowledge base directory."""
        # Create a test article
        article_content = """id: server_test_article
title: "Server Test Article"
category: "server-test"
tags:
  - "server"
  - "test"
content: "This is an article for server testing."
"""
        article_path = os.path.join(self.temp_dir, "server_test_article.yaml")
        with open(article_path, "w", encoding="utf-8") as f:
            f.write(article_content)

        # Create a custom knowledge base manager
        from src.knowledge_base.manager import KnowledgeBaseManager

        custom_kb_manager = KnowledgeBaseManager(kb_dir=self.temp_dir)

        # Verify the custom knowledge base works
        article = custom_kb_manager.get_article_by_id("server_test_article")
        assert article is not None
        assert article["id"] == "server_test_article"

        # Server initialization should work with default knowledge base
        server = DNSMCPServer(config_path=self.temp_config.name)
        assert server.kb_manager is not None
        assert len(server.kb_manager.get_all_articles()) >= 3  # At least the default articles
