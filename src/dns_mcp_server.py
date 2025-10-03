"""MCP DNS Server - An MCP server for DNS name resolution and troubleshooting."""
import asyncio
import logging
from typing import Any, Dict
import dns.resolver
import yaml
from fastmcp import FastMCP

try:
    from . import nstests
except ImportError:
    import nstests
try:
    # Try relative import first (when used as part of the package)
    from .knowledge_base.manager import KnowledgeBaseManager
    from .tools import (
        simple_dns_lookup_impl,
        advanced_dns_lookup_impl,
        reverse_dns_lookup_impl,
        check_dnssec_impl,
        dns_troubleshooting_impl
    )
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from knowledge_base.manager import KnowledgeBaseManager
    from tools import (
        simple_dns_lookup_impl,
        advanced_dns_lookup_impl,
        reverse_dns_lookup_impl,
        check_dnssec_impl,
        dns_troubleshooting_impl
    )
class DNSMCPServer:
    """MCP Server implementation for DNS operations."""

    def __init__(self, config_path: str = "config/config.yaml") -> None:
        """Initialize the DNS MCP server.
        
        Args:
            config_path: Path to the configuration file. Defaults to "config/config.yaml"
        """
        self.config_path = config_path
        self.server = FastMCP(
            name="DNS Resolver MCP Server",
            instructions="An MCP server that provides DNS resolution and troubleshooting capabilities.",
        )
        self.setup_logging()
        self.configure_resolver()
        self.initialize_knowledge_base()
        self.register_tools()
        self.register_knowledge_base_resources()
        self.register_knowledge_base_prompts()

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def configure_resolver(self) -> None:
        """Configure DNS resolver with custom settings."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Set custom DNS servers if specified
            if 'dns' in config and 'dns_servers' in config['dns']:
                self.resolver = dns.resolver.Resolver()
                self.resolver.nameservers = config['dns']['dns_servers']
            else:
                self.resolver = dns.resolver.Resolver()

            # Set timeout if specified
            if 'dns' in config and 'timeout' in config['dns']:
                self.resolver.lifetime = config['dns']['timeout']
            else:
                self.resolver.lifetime = 5.0  # Default timeout

        except FileNotFoundError:
            self.logger.info(f"Config file {self.config_path} not found, using default DNS servers")
            self.resolver = dns.resolver.Resolver()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self.resolver = dns.resolver.Resolver()

    def initialize_knowledge_base(self) -> None:
        """Initialize the knowledge base manager."""
        self.kb_manager = KnowledgeBaseManager()
        self.logger.info(f"Knowledge base initialized with {len(self.kb_manager.get_all_articles())} articles")

    def register_tools(self) -> None:
        """Register all DNS-related tools with the MCP server."""

        @self.server.tool(
            name="simple_dns_lookup",
            description="Perform a simple DNS lookup for a hostname to get its IP address"
        )
        async def simple_dns_lookup(hostname: str) -> Dict[str, Any]:
            return await simple_dns_lookup_impl(self.resolver, hostname)

        @self.server.tool(
            name="advanced_dns_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types"
        )
        async def advanced_dns_lookup(hostname: str, record_type: str) -> Dict[str, Any]:
            return await advanced_dns_lookup_impl(self.resolver, hostname, record_type)

        @self.server.tool(
            name="reverse_dns_lookup",
            description="Perform a reverse DNS lookup to get hostname from IP address"
        )
        async def reverse_dns_lookup(ip_address: str) -> Dict[str, Any]:
            return await reverse_dns_lookup_impl(self.resolver, ip_address)

        @self.server.tool(
            name="dns_domain_troubleshooting",
            description="Perform comprehensive DNS troubleshooting for a given domain"
        )
        async def dns_domain_troubleshooting(domain: str) -> Dict[str, Any]:
            return await dns_troubleshooting_impl(self.resolver, domain)

        @self.server.tool(
            name="dns_server_troubleshooting",
            description="Perform comprehensive DNS server troubleshooting for a given domain and nameserver"
        )
        async def dns_server_troubleshooting(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.run_comprehensive_tests(domain, nameserver)

        @self.server.tool(
            name="dns_server_edns_test",
            description="Perform EDNS tests on a given domain and nameserver"
        )
        async def dns_server_edns_test(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.test_edns_support(domain, nameserver)

        @self.server.tool(
            name="dns_udp_tcp_test",
            description="Perform UDP and TCP behavior tests on a given domain and nameserver"
        )
        async def dns_udp_tcp_test(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.test_tcp_behavior(domain, nameserver)

        @self.server.tool(
            name="check_dnssec",
            description="Check DNSSEC validation for a given domain"
        )
        async def check_dnssec(domain: str) -> Dict[str, Any]:
            return await check_dnssec_impl(self.resolver, domain)

    # ...existing code...

    async def start(self, host: str = "127.0.0.1", port: int = 3000) -> None:
        """Start the MCP server using HTTP transport.
        
        Args:
            host: The host to bind to. Defaults to "127.0.0.1"
            port: The port to listen on. Defaults to 3000
        """
        await self.server.run_async(transport="http", host=host, port=port)

    async def stop(self) -> None:
        """Stop the MCP server."""
        # FastMCP doesn't have a direct stop method - server runs until interrupted
        self.logger.info("MCP DNS Server stopped")

    def register_knowledge_base_resources(self) -> None:
        """Register knowledge base articles as MCP resources."""

        @self.server.resource(
            uri="kb://article/{article_id}",
            name="dns_knowledge_base_article",
            description="Provides access to a specific DNS knowledge base article by ID"
        )
        async def get_knowledge_article(article_id: str) -> Dict[str, Any]:
            return await self._get_knowledge_article_impl(article_id)

        @self.server.resource(
            uri="kb://search/{query}",
            name="dns_knowledge_base_search",
            description="Search the DNS knowledge base for articles matching a query"
        )
        async def search_knowledge_articles(query: str) -> Dict[str, Any]:
            return await self._search_knowledge_articles_impl(query)

        @self.server.resource(
            uri="kb://categories",
            name="dns_knowledge_base_categories",
            description="Get all available categories in the DNS knowledge base"
        )
        async def get_knowledge_categories() -> Dict[str, Any]:
            return await self._get_knowledge_categories_impl()

        @self.server.resource(
            uri="kb://category/{category}",
            name="dns_knowledge_base_by_category",
            description="Get DNS knowledge base articles by category"
        )
        async def get_knowledge_by_category(category: str) -> Dict[str, Any]:
            return await self._get_knowledge_by_category_impl(category)

    async def _get_knowledge_article_impl(self, article_id: str) -> Dict[str, Any]:
        """Implementation to get a specific knowledge base article by ID."""
        article = self.kb_manager.get_article_by_id(article_id)
        if article:
            return article
        else:
            return {
                "error": f"Knowledge base article with ID '{article_id}' not found",
                "available_articles": list(self.kb_manager.get_all_articles().keys())
            }

    async def _search_knowledge_articles_impl(self, query: str) -> Dict[str, Any]:
        """Implementation to search knowledge base articles by query."""
        results = self.kb_manager.search_articles(query)
        return {
            "query": query,
            "results": results,
            "count": len(results)
        }

    async def _get_knowledge_categories_impl(self) -> Dict[str, Any]:
        """Implementation to get all knowledge base categories."""
        categories = self.kb_manager.get_all_categories()
        return {
            "categories": categories,
            "count": len(categories)
        }

    async def _get_knowledge_by_category_impl(self, category: str) -> Dict[str, Any]:
        """Implementation to get knowledge base articles by category."""
        articles = self.kb_manager.get_articles_by_category(category)
        return {
            "category": category,
            "articles": articles,
            "count": len(articles)
        }

    def register_knowledge_base_prompts(self) -> None:
        """Register prompts to simplify interaction with the knowledge base."""

        @self.server.prompt(
            name="dns_troubleshooting_help",
            description="Get help with DNS troubleshooting using the knowledge base"
        )
        def dns_troubleshooting_help() -> str:
            """Get help with DNS troubleshooting using the knowledge base."""
            return "When asked about DNS troubleshooting, consult the knowledge base using the search function with relevant query terms."

        @self.server.prompt(
            name="dns_configuration_help",
            description="Get help with DNS configuration using the knowledge base"
        )
        def dns_configuration_help() -> str:
            """Get help with DNS configuration using the knowledge base."""
            return "When asked about DNS configuration, particularly for complex setups like Extranet, search the knowledge base for configuration guides."

        @self.server.prompt(
            name="dns_security_help",
            description="Get help with DNS security best practices using the knowledge base"
        )
        def dns_security_help() -> str:
            """Get help with DNS security best practices using the knowledge base."""
            return "When asked about DNS security, search the knowledge base for security best practices and implementation guidelines."

        @self.server.prompt
        def resolve_hostname(hostname: str) -> str:
            """Resolve a hostname to its IP address using the simple DNS lookup tool."""
            return f"Resolve {hostname} to its IP address using the simple dns lookup tool provided by the DNS MCP Server."

        @self.server.prompt
        def resolve_ip(ip: str) -> str:
            """Resolve a IP address to hostname using the reverse DNS lookup tool."""
            return f"Resolve {ip} to its hostname using the reverse DNS lookup tool provided by the DNS MCP Server."

        @self.server.prompt
        def advanced_lookup(hostname: str, record_type: str) -> str:
            """Perform an advanced DNS lookup for a hostname and record type using the advanced DNS lookup tool."""
            return f"Perform an advanced DNS lookup for {hostname} with record type {record_type} using the advanced dns lookup tool provided by the DNS MCP Server."

        @self.server.prompt
        def dns_domain_troubleshoot(domain: str) -> str:
            """Perform comprehensive DNS troubleshooting for a domain using the DNS troubleshooting tool."""
            return f"Perform DNS troubleshooting for {domain} using the dns domain troubleshooting tool provided by the DNS MCP Server."

        @self.server.prompt
        def dns_server_troubleshoot(domain: str, nameserver: str) -> str:
            """Perform comprehensive DNS server troubleshooting for a nameserver using the DNS server troubleshooting tool."""
            return f"Perform DNS server troubleshooting for domain {domain} and nameserver {nameserver} using the dns server troubleshooting tool provided by the DNS MCP Server."

        @self.server.prompt
        def dns_edns_test(domain: str, nameserver: str) -> str:
            """Perform EDNS tests for a nameserver using the DNS EDNS test tool."""
            return f"Perform EDNS tests for domain {domain} and nameserver {nameserver} using the dns server edns test tool provided by the DNS MCP Server."

        @self.server.prompt
        def dns_udp_tcp_test(domain: str, nameserver: str) -> str:
            """Perform UDP and TCP behavior tests for a nameserver using the DNS UDP/TCP test tool."""
            return f"Perform UDP and TCP behavior tests for domain {domain} and nameserver {nameserver} using the dns udp tcp test tool provided by the DNS MCP Server."

        @self.server.prompt
        def check_dnssec(domain: str) -> str:
            """Get DNSSEC status of a domain using the DNSSEC validation check tool."""
            return f"Get DNSSEC status of domain {domain} using the check_dnssec tool provided by the DNS MCP Server."

async def main() -> None:
    """Main entry point."""
    server = DNSMCPServer()
    # Start the server with HTTP transport - this will block until interrupted
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
