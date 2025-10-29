"""MCP DNS Server - An MCP server for DNS name resolution and troubleshooting."""
import asyncio
import logging
import signal
import sys
import ipaddress
from typing import Any, Dict
import yaml
from fastmcp import FastMCP
try:
    # Try relative import first (when used as part of the package)
    from . import nstests
    from .knowledge_base.manager import KnowledgeBaseManager
    from .typedefs import ToolResult
    from .tools import (
        simple_dns_lookup_impl,
        advanced_dns_lookup_impl,
        reverse_dns_lookup_impl,
        check_dnssec_impl,
        dns_troubleshooting_impl,
        lookalike_risk_impl,
        dns_trace_impl,
        punycode_converter_impl,
        scan_subnet_for_open_resolvers_impl,
        scan_server_for_dns_spoofing_impl
    )
    from .resolver import Resolver
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    import nstests
    from knowledge_base.manager import KnowledgeBaseManager
    from typedefs import ToolResult
    from tools import (
        simple_dns_lookup_impl,
        advanced_dns_lookup_impl,
        reverse_dns_lookup_impl,
        check_dnssec_impl,
        dns_troubleshooting_impl,
        lookalike_risk_impl,
        dns_trace_impl,
        punycode_converter_impl,
        scan_subnet_for_open_resolvers_impl,
        scan_server_for_dns_spoofing_impl
    )
    from resolver import Resolver

class DNSMCPServer:
    """MCP Server implementation for DNS operations."""

    def __init__(self, config_path: str = "config/config.yaml") -> None:
        """Initialize the DNS MCP server.

        Args:
            config_path: Path to the configuration file.
                Defaults to "config/config.yaml"
        """
        self.config_path = config_path
        self.server = FastMCP(
            name="DNS Resolver MCP Server",
            instructions=(
                "An MCP server that provides DNS resolution and troubleshooting"
                " capabilities."
            ),
        )
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.info(
                "Config file %s not found, using default settings",
                self.config_path
            )
            self.config = {}
        except (yaml.YAMLError, OSError) as e:
            self.logger.error("Error loading config: %s", e)
            self.config = {}

        self.setup_logging()
        self.initialize_knowledge_base()
        self.register_tools()
        self.register_tools_prompts()
        # Register KB resources and prompts if enabled in config.
        if self.config['features'].get('knowledge_base'):
            self.register_knowledge_base_resources()
            self.register_knowledge_base_prompts()

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def initialize_knowledge_base(self) -> None:
        """Initialize the knowledge base manager."""
        self.kb_manager = KnowledgeBaseManager()
        self.logger.info(
            "Knowledge base initialized with %d articles",
            len(self.kb_manager.get_all_articles())
        )

    def register_tools(self) -> None:
        """Register all DNS-related tools with the MCP server."""

        @self.server.tool(name="simple_dns_lookup",
            description="Perform a simple DNS lookup for a hostname to get its IP address",
            tags=set(("dns", "query", "lookup", "a_record")),
            enabled=True
        )
        async def simple_dns_lookup(hostname: str) -> ToolResult:
            return await simple_dns_lookup_impl(hostname.strip())

        @self.server.tool(name="advanced_dns_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types",
            tags=set(("dns", "query", "lookup", "advanced")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def advanced_dns_lookup(hostname: str, record_type: str) -> ToolResult:
            return await advanced_dns_lookup_impl(
                hostname.strip(),
                record_type.strip().upper()
            )

        @self.server.tool(name="reverse_dns_lookup",
            description="Perform a reverse DNS lookup to get hostname from IP address",
            tags=set(("dns", "query", "lookup", "reverse")),
            enabled=self.config['features'].get('reverse_lookup', False)
        )
        async def reverse_dns_lookup(ip_address: str) -> ToolResult:
            return await reverse_dns_lookup_impl(ip_address.strip())

        @self.server.tool(name="dns_domain_troubleshooting",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_domain_troubleshooting(domain: str) -> ToolResult:
            return await dns_troubleshooting_impl(domain.strip())

        @self.server.tool(name="dns_server_troubleshooting",
            description=(
                "Perform comprehensive DNS server troubleshooting for a given"
                " domain and nameserver"
            ),
            tags=set(("dns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_server_troubleshooting(
            domain: str,
            nameserver: str
        ) -> Dict[str, Any]:
            return await nstests.run_comprehensive_tests(domain, nameserver)

        @self.server.tool(name="dns_trace",
            description="Perform a DNS trace to see the resolution path for a domain",
            tags=set(("dns", "query", "troubleshooting", "trace")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_trace(domain: str) -> ToolResult:
            return await dns_trace_impl(domain)

        @self.server.tool(name="dns_server_edns_test",
            description="Perform EDNS tests on a given domain and nameserver",
            tags=set(("dns", "edns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_server_edns_test(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.test_edns_support(domain, nameserver)

        @self.server.tool(name="dns_udp_tcp_test",
            description="Perform UDP and TCP behavior tests on a given domain and nameserver.",
            tags=set(("dns", "troubleshooting", "diagnostics", "protocol", "udp", "tcp")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_udp_tcp_test(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.test_tcp_behavior(domain, nameserver)

        @self.server.tool(name="dns_cookie_test",
            description="Perform a DNS Cookie behavior test on a given domain and nameserver.",
            tags=set(("dns", "cookie", "edns", "diagnostics", "troubleshooting")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        async def dns_cookie_test(domain: str, nameserver: str) -> Dict[str, Any]:
            return await nstests.test_dns_cookie(domain, nameserver)

        @self.server.tool(name="check_dnssec",
            description="Check DNSSEC validation for a given domain",
            tags=set(("dns", "security", "dnssec", "validation")),
            enabled=self.config['features'].get('dnssec_validation', False)
        )
        async def check_dnssec(domain: str) -> ToolResult:
            return await check_dnssec_impl(domain)

        @self.server.tool(name="lookalike_risk",
            description="Assess lookalike domain risk for a given domain",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config['features'].get('lookalike_risk_tool', False)
        )
        async def lookalike_risk(domain: str, check_dns: bool = False) -> ToolResult:
            return await lookalike_risk_impl(domain, check_dns)

        @self.server.tool(name="punycode_converter",
            description="Converts any given internationalized domain name (IDN) into punycode format.",
            tags=set(("dns", "idn", "punycode", "converter")),
            enabled=True
        )
        async def punycode_converter(domain: str) -> ToolResult:
            return await punycode_converter_impl(domain)

        @self.server.tool(name="detect_open_resolvers",
            description="Scans a given subnet for open resolvers.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config['features'].get('open_resolver_scan_tool', False)
        )
        async def detect_open_resolvers(cidr: str, domain: str) -> ToolResult:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.is_private:
                return await scan_subnet_for_open_resolvers_impl(cidr, domain)

            return ToolResult(
                success=False,
                error="Tool is limited to only scan private networks in the RFC1918 range."
            )
        # async def detect_open_resolvers(cidr: str, domain: str, ctx: Context) -> ToolResult:
        #     result = await ctx.elicit(
        #         message="This will scan a very large network. Confirm with `yes` to proceed.",
        #         response_type=UserDecision
        #     )
        #     if result.action == "accept":
        #         if result.data.answer.strip().lower() == "yes":
        #             return await scan_subnet_for_open_resolvers_impl(cidr, domain)
        #         return ToolResult(
        #             success=False,
        #             error="Information not provided"
        #         )
        #     if result.action == "decline":
        #         return ToolResult(
        #             success=False,
        #             error="Information not provided"
        #         )
        #     # cancel
        #     return ToolResult(
        #         success=False,
        #         error="Operation cancelled"
        #     )

        @self.server.tool(name="detect_dns_spoofing",
            description="Detect DNS interception/spoofing including MAC-level fingerprinting.",
            tags=set(("dns", "spoofing", "mac", "fingerprinting")),
            enabled=self.config['features'].get('detect_dns_spoofing', False)
        )
        async def detect_dns_spoofing(nameserver: str, domain: str, router_mac: str | None) -> ToolResult:
            return await scan_server_for_dns_spoofing_impl(
                nameserver=nameserver,
                domain=domain,
                router_mac=router_mac
            )

    def setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if sys.platform == "win32":
            # Windows doesn't support SIGTERM properly, use SIGBREAK instead
            signals = (signal.SIGINT, signal.SIGBREAK)
        else:
            signals = (signal.SIGINT, signal.SIGTERM)

        for sig in signals:
            try:
                asyncio.get_running_loop().add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._signal_handler(s))
                )
            except NotImplementedError:
                # Some systems might not support add_signal_handler
                signal.signal(sig, lambda s, f: asyncio.create_task(self._signal_handler(s)))

    async def _signal_handler(self, sig: int) -> None:
        """Handle shutdown signals.
        
        Args:
            sig: Signal number that triggered the handler
        """
        sig_name = signal.Signals(sig).name
        self.logger.info("Received shutdown signal %s", sig_name)
        await self.stop()

    async def start(self, host: str = "127.0.0.1", port: int = 3000) -> None:
        """Start the MCP server using HTTP transport.
        
        Args:
            host: The host to bind to. Defaults to "127.0.0.1"
            port: The port to listen on. Defaults to 3000
        """
        self.setup_signal_handlers()
        try:
            self.logger.info("Starting MCP DNS Server on %s:%d", host, port)
            await self.server.run_async(transport="http", host=host, port=port)
        except (OSError, RuntimeError) as e:
            self.logger.error("Error starting server: %s", e)
            await self.stop()
            raise
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
            await self.stop()

    async def stop(self) -> None:
        """Stop the MCP server gracefully."""
        self.logger.info("Shutting down MCP DNS Server...")
        # Stop the FastMCP server
        if hasattr(self, 'server'):
            # Since FastMCP doesn't expose a stop() method, we'll clean up manually
            try:
                # First cancel all running tasks except the current one
                current = asyncio.current_task()
                pending = [t for t in asyncio.all_tasks() if t is not current]

                if pending:
                    self.logger.debug("Cancelling %d pending tasks", len(pending))
                    for task in pending:
                        task.cancel()

                    # Wait for tasks to complete or timeout
                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=5.0
                        )
                    except asyncio.TimeoutError:
                        self.logger.warning("Timeout waiting for tasks to stop")
                    except Exception as e:
                        self.logger.error("Error during task cleanup: %s", e)
            except Exception as e:
                self.logger.error("Error during server shutdown: %s", e)

        # Remove signal handlers
        if sys.platform == "win32":
            signals = (signal.SIGINT, signal.SIGBREAK)
        else:
            signals = (signal.SIGINT, signal.SIGTERM)

        for sig in signals:
            try:
                asyncio.get_running_loop().remove_signal_handler(sig)
            except (NotImplementedError, ValueError):
                # Ignore if signal handlers weren't supported or already removed
                pass
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
            return (
                "When asked about DNS troubleshooting, consult the knowledge base"
                " using the search function with relevant query terms."
            )

        @self.server.prompt(
            name="dns_configuration_help",
            description="Get help with DNS configuration using the knowledge base"
        )
        def dns_configuration_help() -> str:
            """Get help with DNS configuration using the knowledge base."""
            return (
                "When asked about DNS configuration, particularly for complex setups"
                " like Extranet, search the knowledge base for configuration guides."
            )

        @self.server.prompt(
            name="dns_security_help",
            description="Get help with DNS security best practices using the knowledge base"
        )
        def dns_security_help() -> str:
            """Get help with DNS security best practices using the knowledge base."""
            return (
                "When asked about DNS security, search the knowledge base for"
                " security best practices and implementation guidelines."
            )

    def register_tools_prompts(self) -> None:
        """Register prompts for tools with the server."""
        @self.server.prompt(name="resolve_hostname",
            description="Resolve a hostname to its IP address.",
            tags=set(("dns", "query", "lookup", "a_record")),
            enabled=True
        )
        def resolve_hostname(hostname: str) -> str:
            """Resolve a hostname to its IP address."""
            return (
                f"Resolve {hostname} to its IP address using the simple dns"
                " lookup tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="resolve_ip",
            description="Resolve an IP address to hostname using reverse DNS lookup.",
            tags=set(("dns", "query", "lookup", "reverse")),
            enabled=self.config['features'].get('reverse_lookup', False)
        )
        def resolve_ip(ip: str) -> str:
            """Resolve an IP address to hostname using reverse DNS lookup."""
            return (
                f"Resolve {ip} to its hostname using the reverse DNS lookup tool"
                " provided by the DNS MCP Server."
            )

        @self.server.prompt(name="advanced_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types",
            tags=set(("dns", "query", "lookup", "advanced")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def advanced_lookup(hostname: str, record_type: str) -> str:
            """Perform an advanced DNS lookup for a hostname and record type."""
            return (
                f"Perform an advanced DNS lookup for {hostname} with record type"
                f" {record_type} using the advanced dns lookup tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_domain_troubleshoot",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_domain_troubleshoot(domain: str) -> str:
            """Perform DNS troubleshooting for a domain."""
            return (
                f"Perform DNS troubleshooting for {domain} using"
                " the dns domain troubleshooting tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_domain_on_server_troubleshoot",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_domain_on_server_troubleshoot(domain: str, nameserver: str) -> str:
            """Perform DNS troubleshooting for a domain against a specific DNS server."""
            return (
                f"Perform DNS troubleshooting for {domain} against {nameserver} using"
                " the dns domain troubleshooting tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_server_troubleshoot",
            description=(
                "Perform comprehensive DNS server troubleshooting for a given"
                " domain and nameserver"
            ),
            tags=set(("dns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_server_troubleshoot(domain: str, nameserver: str) -> str:
            """Perform comprehensive DNS server troubleshooting."""
            return (
                f"Perform DNS server troubleshooting for domain {domain} and"
                f" nameserver {nameserver} using the dns server troubleshooting"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_domain_trace",
            description="Perform a DNS trace to see the resolution path for a domain",
            tags=set(("dns", "query", "troubleshooting", "trace")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_domain_trace(domain: str) -> str:
            """Perform a DNS trace for a domain."""
            return (
                f"Perform a DNS trace for domain {domain} using the dns trace"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_edns_test",
            description="Perform EDNS tests on a given domain and nameserver",
            tags=set(("dns", "edns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_edns_test(domain: str, nameserver: str) -> str:
            """Perform EDNS tests for a nameserver."""
            return (
                f"Perform EDNS tests for domain {domain} and"
                f" nameserver {nameserver} using the dns server edns test"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="dns_udp_tcp_test",
            description="Perform UDP and TCP behavior tests on a given domain and nameserver",
            tags=set(("dns", "troubleshooting", "diagnostics", "protocol", "udp", "tcp")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_udp_tcp_test(domain: str, nameserver: str) -> str:
            """Perform UDP and TCP behavior tests for a nameserver."""
            return (
                f"Perform UDP and TCP behavior tests for domain {domain} and"
                f" nameserver {nameserver} using the dns udp tcp test tool"
                " provided by the DNS MCP Server."
            )

        @self.server.prompt(name="check_dns_cookie",
            description="Perform DNS Cookie behavior test on a given domain and nameserver",
            tags=set(("dns", "troubleshooting", "diagnostics", "cookie", "edns", "dnscookie")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def dns_cookie_test(domain: str, nameserver: str) -> str:
            """Perform DNS Cookie test against a nameserver."""
            return (
                f"Perform a DNS Cookie test for domain {domain} against nameserver {nameserver} "
                "using the dns cookie test tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="check_dnssec",
            description="Check DNSSEC validation for a given domain",
            tags=set(("dns", "security", "dnssec", "validation")),
            enabled=self.config['features'].get('dnssec_validation', False)
        )
        def check_dnssec(domain: str) -> str:
            """Get DNSSEC status of a domain."""
            return (
                f"Get DNSSEC status of domain {domain} using the check_dnssec"
                " tool provided by the DNS MCP Server."
        )

        @self.server.prompt(name="lookalike_risk",
            description="Assess lookalike domain risk for a given domain",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config['features'].get('lookalike_risk_tool', False)
        )
        def lookalike_risk(domain: str, check_dns: bool = False) -> str:
            """Assess lookalike domain risk."""
            return (
                f"Assess lookalike domain risk for {domain} using the"
                " lookalike_risk tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="lookalike_risk_check_dns",
            description="Assess lookalike domain risk for a given domain and resolve all possible variants",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config['features'].get('lookalike_risk_tool', False)
        )
        def lookalike_risk_check_dns(domain: str, check_dns: bool = True) -> str:
            """Assess lookalike domain risk and resolve all variants."""
            return (
                f"Assess the lookalike domain risk for {domain} and resolve all variants using the"
                " lookalike_risk tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="supported_record_types",
            description="Return the DNS resource record types that are supported by this MCP server.",
            tags=set(("dns", "record_types")),
            enabled=self.config['features'].get('advanced_troubleshooting', False)
        )
        def supported_record_types() -> str:
            """Get supported DNS record types."""
            types = ', '.join(sorted(Resolver.allowed_record_types))
            return (
                f"The supported DNS record types are: {types}. Use these types with the"
                " advanced dns lookup tool provided by the DNS MCP Server."
            )

        @self.server.prompt(name="punycode_converter",
            description="Return the punycode version of an internationalized domain name (IDN).",
            tags=set(("dns", "idn", "punycode", "converter")),
            enabled=True
        )
        def punycode_converter(domain: str) -> str:
            """Convert IDN domain name to punycode."""
            return f"Convert the domain {domain} to punycode format."

        @self.server.prompt(name="detect_open_resolvers",
            description="Scan a subnet in CIDR notation for open DNS resolvers.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config['features'].get('open_resolver_scan_tool', False)
        )
        def detect_open_resolvers(cidr: str, domain: str) -> str:
            """Scan a subnet in CIDR notation for open DNS resolvers."""
            return f"Scan for open resolvers in subnet {cidr} using domain {domain}."

        @self.server.prompt(name="detect_dns_spoofing",
            description="Detect DNS interception/spoofing.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config['features'].get('open_resolver_scan_tool', False)
        )
        def detect_dns_spoofing(nameserver: str, domain: str) -> str:
            """Detect DNS interception/spoofing including MAC-level fingerprinting."""
            return f"Scan for DNS spoofing between client and {nameserver} IP using domain {domain}."

        @self.server.prompt(name="detect_dns_spoofing_with_router_mac",
            description="Detect DNS interception/spoofing including MAC-level fingerprinting.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config['features'].get('open_resolver_scan_tool', False)
        )
        def detect_dns_spoofing_with_router_mac(nameserver: str, domain: str, router_mac: str) -> str:
            """Detect DNS interception/spoofing including MAC-level fingerprinting."""
            return f"Scan for DNS spoofing on gateway with MAC address {router_mac} and nameserver IP {nameserver} using domain {domain}."



async def main() -> None:
    """Main entry point."""
    server = DNSMCPServer()
    try:
        # Start the server with HTTP transport
        await server.start()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        await server.stop()
    except (OSError, RuntimeError) as e:
        # Log any unexpected errors
        logging.error("Unexpected error: %s", e)
        await server.stop()
        sys.exit(1)


def run_server() -> None:
    """Run the server with proper asyncio event loop handling."""
    loop = None
    try:
        if sys.platform == "win32":
            # Use ProactorEventLoop on Windows for better signal handling
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        loop.run_until_complete(main())
    except KeyboardInterrupt:
        # This is a fallback in case the signal handlers don't catch it
        if loop is not None:
            loop.run_until_complete(asyncio.sleep(0))  # Let other tasks complete
    finally:
        if loop is not None:
            loop.close()


if __name__ == "__main__":
    run_server()
