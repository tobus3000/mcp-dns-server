"""Knowledge Base Manager for DNS MCP Server."""

import glob
import os
from pathlib import Path

import yaml


class KnowledgeBaseManager:
    """Manages DNS knowledge base articles."""

    def __init__(self, kb_dir: str | None = None) -> None:
        """Initialize the knowledge base manager.

        Args:
            kb_dir: Directory containing knowledge base articles.
                   If None, defaults to the package's data directory.
        """
        if kb_dir is None:
            # Get the directory where this module is located
            kb_dir = os.path.join(os.path.dirname(__file__), "data")

        self.kb_dir = kb_dir
        self._ensure_kb_directory()
        self.articles = self._load_all_articles()

    def _ensure_kb_directory(self) -> None:
        """Ensure the knowledge base directory exists."""
        Path(self.kb_dir).mkdir(parents=True, exist_ok=True)

    def _load_all_articles(self) -> dict[str, dict]:
        """Load all knowledge base articles from the directory.

        Returns:
            Dictionary mapping article IDs to article content
        """
        articles = {}

        # Look for both YAML and JSON files
        yaml_files = glob.glob(os.path.join(self.kb_dir, "*.yaml"))
        yaml_files.extend(glob.glob(os.path.join(self.kb_dir, "*.yml")))

        for file_path in yaml_files:
            try:
                with open(file_path, encoding="utf-8") as f:
                    article_data = yaml.safe_load(f)
                    if article_data and "id" in article_data:
                        articles[article_data["id"]] = article_data
            except Exception as e:
                print(f"Error loading knowledge base article {file_path}: {e}")

        return articles

    def get_article_by_id(self, article_id: str) -> dict | None:
        """Get a knowledge base article by its ID.

        Args:
            article_id: The ID of the article to retrieve

        Returns:
            The article content if found, None otherwise
        """
        return self.articles.get(article_id)

    def get_articles_by_category(self, category: str) -> list[dict]:
        """Get all articles in a specific category.

        Args:
            category: The category to filter by

        Returns:
            List of articles in the specified category
        """
        return [
            article
            for article in self.articles.values()
            if article.get("category", "").lower() == category.lower()
        ]

    def search_articles(self, query: str) -> list[dict]:
        """Search for articles containing the query string.

        Args:
            query: String to search for in article titles, content, or tags

        Returns:
            List of matching articles
        """
        query_lower = query.lower()
        matching_articles = []

        for article in self.articles.values():
            # Search in title, content, and tags
            title_match = query_lower in article.get("title", "").lower()
            content_match = query_lower in article.get("content", "").lower()
            tags_match = any(query_lower in tag.lower() for tag in article.get("tags", []))

            if title_match or content_match or tags_match:
                matching_articles.append(article)

        return matching_articles

    def get_all_categories(self) -> list[str]:
        """Get all unique categories in the knowledge base.

        Returns:
            List of all categories
        """
        categories = set()
        for article in self.articles.values():
            category = article.get("category")
            if category:
                categories.add(category)
        return sorted(list(categories))

    def get_all_articles(self) -> dict[str, dict]:
        """Get all articles.

        Returns:
            Dictionary of all articles
        """
        return self.articles

    def add_article(self, article_data: dict) -> bool:
        """Add a new article to the knowledge base.

        Args:
            article_data: Dictionary containing article data

        Returns:
            True if successfully added, False otherwise
        """
        if "id" not in article_data:
            print("Error: Article must have an 'id' field")
            return False

        article_id = article_data["id"]
        file_path = os.path.join(self.kb_dir, f"{article_id}.yaml")

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(article_data, f, default_flow_style=False, allow_unicode=True)

            # Reload articles to include the new one
            self.articles = self._load_all_articles()
            return True
        except Exception as e:
            print(f"Error saving knowledge base article: {e}")
            return False
