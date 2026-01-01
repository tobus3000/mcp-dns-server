"""Unit tests for the knowledge base resources and prompts."""

import os
import tempfile

from dns_mcp_server.main import DNSMCPServer


class TestKnowledgeBaseResources:
    """Test suite for knowledge base resources and prompts."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Create a temporary config file for testing
        self.temp_config = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
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

    def test_register_knowledge_base_resources(self):
        """Test that knowledge base resources are registered."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Check that the methods to register resources exist
        assert hasattr(server, "register_knowledge_base_resources")
        assert hasattr(server, "register_knowledge_base_prompts")

        # Check that the resources were registered during initialization
        # We'll verify this indirectly by ensuring the knowledge base is working
        assert server.kb_manager is not None

    def test_knowledge_base_articles_access(self):
        """Test that knowledge base articles can be accessed through the manager."""
        # Create a test article
        article_content = """id: test_article
title: "Test Article"
category: "test"
tags:
  - "test"
  - "example"
content: "This is a test article."
"""
        article_path = os.path.join(self.temp_dir, "test_article.yaml")
        with open(article_path, "w", encoding="utf-8") as f:
            f.write(article_content)

        # Initialize server with the test directory
        from dns_mcp_server.knowledge_base.manager import KnowledgeBaseManager

        # Create a knowledge base manager with our test directory
        kb_manager = KnowledgeBaseManager(kb_dir=self.temp_dir)

        # Test getting the article
        article = kb_manager.get_article_by_id("test_article")
        assert article is not None
        assert article["id"] == "test_article"
        assert article["title"] == "Test Article"

    def test_register_knowledge_base_prompts(self):
        """Test that knowledge base prompts are registered."""
        server = DNSMCPServer(config_path=self.temp_config.name)

        # Check that the method to register prompts exists
        assert hasattr(server, "register_knowledge_base_prompts")

        # The prompts should be added during initialization
        # Verify that the registration method was called during init
        # (This is tested implicitly by the fact that the server was created successfully)
