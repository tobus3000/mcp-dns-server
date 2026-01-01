"""Unit tests for the Knowledge Base Manager."""

import os
import tempfile

from dns_mcp_server.knowledge_base.manager import KnowledgeBaseManager


class TestKnowledgeBaseManager:
    """Test suite for KnowledgeBaseManager class."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Create a temporary directory for test articles
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up after each test method."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization_with_default_directory(self):
        """Test that the knowledge base manager initializes with default directory."""
        manager = KnowledgeBaseManager()
        assert manager.kb_dir is not None
        assert hasattr(manager, "articles")

    def test_initialization_with_custom_directory(self):
        """Test that the knowledge base manager initializes with custom directory."""
        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        assert manager.kb_dir == self.temp_dir
        assert os.path.exists(manager.kb_dir)

    def test_get_article_by_id(self):
        """Test getting an article by its ID."""
        # Create a test article file
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

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        article = manager.get_article_by_id("test_article")

        assert article is not None
        assert article["id"] == "test_article"
        assert article["title"] == "Test Article"
        assert article["category"] == "test"

    def test_get_article_by_id_nonexistent(self):
        """Test getting an article that doesn't exist."""
        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        article = manager.get_article_by_id("nonexistent")

        assert article is None

    def test_get_articles_by_category(self):
        """Test getting articles by category."""
        # Create test articles
        article1_content = """id: article1
title: "Article 1"
category: "test"
tags:
  - "test"
content: "This is test article 1."
"""
        article2_content = """id: article2
title: "Article 2"
category: "other"
tags:
  - "other"
content: "This is other article 2."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        test_articles = manager.get_articles_by_category("test")
        other_articles = manager.get_articles_by_category("other")

        assert len(test_articles) == 1
        assert test_articles[0]["id"] == "article1"
        assert len(other_articles) == 1
        assert other_articles[0]["id"] == "article2"

    def test_search_articles_by_title(self):
        """Test searching articles by title."""
        # Create test articles
        article1_content = """id: article1
title: "DNS Configuration Guide"
category: "configuration"
tags:
  - "dns"
  - "configuration"
content: "This is about DNS configuration."
"""
        article2_content = """id: article2
title: "Troubleshooting Guide"
category: "troubleshooting"
tags:
  - "troubleshooting"
  - "guide"
content: "This is about troubleshooting."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        results = manager.search_articles("configuration")

        assert len(results) == 1
        assert results[0]["id"] == "article1"

    def test_search_articles_by_content(self):
        """Test searching articles by content."""
        # Create test articles
        article1_content = """id: article1
title: "Test Article 1"
category: "test"
tags:
  - "test"
content: "This article is about DNS configuration processes."
"""
        article2_content = """id: article2
title: "Test Article 2"
category: "test"
tags:
  - "test"
content: "This article is about security protocols."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        results = manager.search_articles("configuration")

        assert len(results) == 1
        assert results[0]["id"] == "article1"

    def test_search_articles_by_tags(self):
        """Test searching articles by tags."""
        # Create test articles
        article1_content = """id: article1
title: "Test Article 1"
category: "test"
tags:
  - "security"
  - "best-practices"
content: "This is about security."
"""
        article2_content = """id: article2
title: "Test Article 2"
category: "test"
tags:
  - "troubleshooting"
  - "guide"
content: "This is about troubleshooting."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        results = manager.search_articles("security")

        assert len(results) == 1
        assert results[0]["id"] == "article1"

    def test_get_all_categories(self):
        """Test getting all categories."""
        # Create test articles
        article1_content = """id: article1
title: "Article 1"
category: "configuration"
tags:
  - "test"
content: "Test content."
"""
        article2_content = """id: article2
title: "Article 2"
category: "troubleshooting"
tags:
  - "test"
content: "Test content."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        categories = manager.get_all_categories()

        assert "configuration" in categories
        assert "troubleshooting" in categories
        assert len(categories) == 2

    def test_add_article(self):
        """Test adding a new article."""
        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)

        article_data = {
            "id": "new_article",
            "title": "New Article",
            "category": "test",
            "tags": ["new", "test"],
            "content": "This is a new article.",
        }

        success = manager.add_article(article_data)
        assert success is True

        # Check that the article was added
        added_article = manager.get_article_by_id("new_article")
        assert added_article is not None
        assert added_article["title"] == "New Article"

    def test_add_article_missing_id(self):
        """Test adding an article without an ID."""
        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)

        article_data = {
            "title": "Article without ID",
            "category": "test",
            "tags": ["test"],
            "content": "This article has no ID.",
        }

        success = manager.add_article(article_data)
        assert success is False

    def test_get_all_articles(self):
        """Test getting all articles."""
        # Create test articles
        article1_content = """id: article1
title: "Article 1"
category: "test"
tags:
  - "test"
content: "Test content."
"""
        article2_content = """id: article2
title: "Article 2"
category: "test"
tags:
  - "test"
content: "Test content."
"""
        article1_path = os.path.join(self.temp_dir, "article1.yaml")
        article2_path = os.path.join(self.temp_dir, "article2.yaml")

        with open(article1_path, "w", encoding="utf-8") as f:
            f.write(article1_content)
        with open(article2_path, "w", encoding="utf-8") as f:
            f.write(article2_content)

        manager = KnowledgeBaseManager(kb_dir=self.temp_dir)
        all_articles = manager.get_all_articles()

        assert len(all_articles) == 2
        assert "article1" in all_articles
        assert "article2" in all_articles
