"""Mixin classes for DNSMCPServer to separate concerns and improve maintainability."""

from typing import Any, Dict

try:
    # Try relative import first (when used as part of the package)
    from .tools import (
        advanced_dns_lookup_impl,
        basic_dns_assistant_impl,
        check_dnssec_impl,
        detect_dns_root_environment_impl,
        dns_trace_impl,
        dns_troubleshooting_impl,
        lookalike_risk_impl,
        punycode_converter_impl,
        reverse_dns_lookup_impl,
        run_comprehensive_tests_impl,
        run_dns_cookie_tests_impl,
        run_edns_tests_impl,
        run_tcp_behavior_tests_impl,
        scan_server_for_dns_spoofing_impl,
        scan_subnet_for_open_resolvers_impl,
        simple_dns_lookup_impl,
        tld_check_impl,
        verify_nameserver_role_impl,
    )
    from .tools.mdns.browser import discover_mdns_services_impl
    from .typedefs import ToolResult
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from tools import (
        advanced_dns_lookup_impl,
        basic_dns_assistant_impl,
        check_dnssec_impl,
        detect_dns_root_environment_impl,
        dns_trace_impl,
        dns_troubleshooting_impl,
        lookalike_risk_impl,
        punycode_converter_impl,
        reverse_dns_lookup_impl,
        run_comprehensive_tests_impl,
        run_dns_cookie_tests_impl,
        run_edns_tests_impl,
        run_tcp_behavior_tests_impl,
        scan_server_for_dns_spoofing_impl,
        scan_subnet_for_open_resolvers_impl,
        simple_dns_lookup_impl,
        tld_check_impl,
        verify_nameserver_role_impl,
    )
    from tools.mdns.browser import discover_mdns_services_impl
    from typedefs import ToolResult


class ResourceRegistrationMixin:
    """Mixin for registering resources with the MCP server.

    Note: This mixin assumes the class has 'server' (FastMCP), 'config' (dict),
    and 'kb_manager' attributes available when registration methods are called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    config: Dict[str, Any]  # Configuration dictionary
    kb_manager: Any  # KnowledgeBaseManager instance

    def register_resolver_resources(self) -> None:
        """Register DNS Resolver resources such as root servers, etc."""

        @self.server.resource(
            uri="resource://root_dns_servers",
            name="root_dns_servers",
            description="The root servers used by this environment.",
        )
        async def get_dns_root_servers() -> ToolResult:
            return await advanced_dns_lookup_impl(hostname=".", record_type="NS")

    def register_knowledge_base_resources(self) -> None:
        """Register knowledge base articles as MCP resources."""

        @self.server.resource(
            uri="kb://article/{article_id}",
            name="dns_knowledge_base_article",
            description="Provides access to a specific DNS knowledge base article by ID",
        )
        async def get_knowledge_article(article_id: str) -> Dict[str, Any]:
            return await self._get_knowledge_article_impl(article_id)

        @self.server.resource(
            uri="kb://search/{query}",
            name="dns_knowledge_base_search",
            description="Search the DNS knowledge base for articles matching a query",
        )
        async def search_knowledge_articles(query: str) -> Dict[str, Any]:
            return await self._search_knowledge_articles_impl(query)

        @self.server.resource(
            uri="kb://categories",
            name="dns_knowledge_base_categories",
            description="Get all available categories in the DNS knowledge base",
        )
        async def get_knowledge_categories() -> Dict[str, Any]:
            return await self._get_knowledge_categories_impl()

        @self.server.resource(
            uri="kb://category/{category}",
            name="dns_knowledge_base_by_category",
            description="Get DNS knowledge base articles by category",
        )
        async def get_knowledge_by_category(category: str) -> Dict[str, Any]:
            return await self._get_knowledge_by_category_impl(category)

    async def _get_knowledge_article_impl(self, article_id: str) -> Dict[str, Any]:
        """Implementation to get a specific knowledge base article by ID."""
        article = self.kb_manager.get_article_by_id(article_id)
        if article:
            return article
        return {
            "error": f"Knowledge base article with ID '{article_id}' not found",
            "available_articles": list(self.kb_manager.get_all_articles().keys()),
        }

    async def _search_knowledge_articles_impl(self, query: str) -> Dict[str, Any]:
        """Implementation to search knowledge base articles by query."""
        results = self.kb_manager.search_articles(query)
        return {"query": query, "results": results, "count": len(results)}

    async def _get_knowledge_categories_impl(self) -> Dict[str, Any]:
        """Implementation to get all knowledge base categories."""
        categories = self.kb_manager.get_all_categories()
        return {"categories": categories, "count": len(categories)}

    async def _get_knowledge_by_category_impl(self, category: str) -> Dict[str, Any]:
        """Implementation to get knowledge base articles by category."""
        articles = self.kb_manager.get_articles_by_category(category)
        return {"category": category, "articles": articles, "count": len(articles)}
