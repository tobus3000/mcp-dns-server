"""MCP DNS Server - An MCP server for DNS name resolution and troubleshooting."""
import asyncio
import logging
import socket
from typing import Any, Dict

import dns.exception
import dns.resolver
import dns.reversename
import yaml
from fastmcp import FastMCP

try:
    # Try relative import first (when used as part of the package)
    from .knowledge_base.manager import KnowledgeBaseManager
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from knowledge_base.manager import KnowledgeBaseManager


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

        # Register simple DNS lookup tool
        @self.server.tool(
            name="simple_dns_lookup",
            description="Perform a simple DNS lookup for a hostname to get its IP address"
        )
        async def simple_dns_lookup(hostname: str) -> Dict[str, Any]:
            return await self._simple_dns_lookup_impl(hostname)

        # Register advanced DNS lookup tool
        @self.server.tool(
            name="advanced_dns_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types"
        )
        async def advanced_dns_lookup(hostname: str, record_type: str) -> Dict[str, Any]:
            return await self._advanced_dns_lookup_impl(hostname, record_type)

        # Register reverse DNS lookup tool
        @self.server.tool(
            name="reverse_dns_lookup",
            description="Perform a reverse DNS lookup to get hostname from IP address"
        )
        async def reverse_dns_lookup(ip_address: str) -> Dict[str, Any]:
            return await self._reverse_dns_lookup_impl(ip_address)

        # Register DNS troubleshooting tool
        @self.server.tool(
            name="dns_troubleshooting",
            description="Perform comprehensive DNS troubleshooting for a given domain"
        )
        async def dns_troubleshooting(domain: str) -> Dict[str, Any]:
            return await self._dns_troubleshooting_impl(domain)

    async def _simple_dns_lookup_impl(self, hostname: str) -> Dict[str, Any]:
        """Implementation of simple DNS lookup for hostname resolution."""
        try:
            result = self.resolver.resolve(hostname, 'A')
            ip_addresses = [str(ip) for ip in result]
            return {
                "hostname": hostname,
                "ip_addresses": ip_addresses,
                "status": "success"
            }
        except dns.resolver.NXDOMAIN:
            return {
                "hostname": hostname,
                "error": f"Hostname {hostname} does not exist",
                "status": "error"
            }
        except dns.resolver.NoAnswer:
            return {
                "hostname": hostname,
                "error": f"No A record found for {hostname}",
                "status": "error"
            }
        except Exception as e:
            return {
                "hostname": hostname,
                "error": str(e),
                "status": "error"
            }

    async def _advanced_dns_lookup_impl(self, hostname: str, record_type: str) -> Dict[str, Any]:
        """Implementation of advanced DNS lookup supporting multiple record types."""
        try:
            result = self.resolver.resolve(hostname, record_type)
            records = []

            for rdata in result:
                if record_type == "MX":
                    records.append({
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange)
                    })
                elif record_type == "SRV":
                    records.append({
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": str(rdata.target)
                    })
                elif record_type == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum
                    })
                else:
                    records.append(str(rdata))

            return {
                "hostname": hostname,
                "record_type": record_type,
                "records": records,
                "status": "success"
            }
        except dns.resolver.NXDOMAIN:
            return {
                "hostname": hostname,
                "record_type": record_type,
                "error": f"Hostname {hostname} does not exist",
                "status": "error"
            }
        except dns.resolver.NoAnswer:
            return {
                "hostname": hostname,
                "record_type": record_type,
                "error": f"No {record_type} record found for {hostname}",
                "status": "error"
            }
        except Exception as e:
            return {
                "hostname": hostname,
                "record_type": record_type,
                "error": str(e),
                "status": "error"
            }

    async def _reverse_dns_lookup_impl(self, ip_address: str) -> Dict[str, Any]:
        """Implementation of reverse DNS lookup to get hostname from IP address."""
        try:
            # Validate IP address format
            socket.inet_aton(ip_address)

            # Perform reverse DNS lookup
            rev_name = dns.reversename.from_address(ip_address)
            result = self.resolver.resolve(rev_name, "PTR")
            hostnames = [str(rdata) for rdata in result]

            return {
                "ip_address": ip_address,
                "hostnames": hostnames,
                "status": "success"
            }
        except socket.error:
            return {
                "ip_address": ip_address,
                "error": f"Invalid IP address: {ip_address}",
                "status": "error"
            }
        except dns.resolver.NXDOMAIN:
            return {
                "ip_address": ip_address,
                "error": f"No PTR record found for {ip_address}",
                "status": "error"
            }
        except Exception as e:
            return {
                "ip_address": ip_address,
                "error": str(e),
                "status": "error"
            }

    async def _dns_troubleshooting_impl(self, domain: str) -> Dict[str, Any]:
        """Implementation of comprehensive DNS troubleshooting for a given domain."""
        troubleshooting_results = {}

        # Check A record
        try:
            a_result = self.resolver.resolve(domain, 'A')
            troubleshooting_results['A'] = [str(ip) for ip in a_result]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['A'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['A'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['A'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['A'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            # System-level errors that suggest a more serious issue
            troubleshooting_results['A'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        # Check AAAA record
        try:
            aaaa_result = self.resolver.resolve(domain, 'AAAA')
            troubleshooting_results['AAAA'] = [str(ip) for ip in aaaa_result]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['AAAA'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['AAAA'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['AAAA'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['AAAA'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            troubleshooting_results['AAAA'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        # Check CNAME
        try:
            cname_result = self.resolver.resolve(domain, 'CNAME')
            troubleshooting_results['CNAME'] = [str(rdata) for rdata in cname_result]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['CNAME'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['CNAME'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['CNAME'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['CNAME'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            troubleshooting_results['CNAME'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        # Check MX records
        try:
            mx_result = self.resolver.resolve(domain, 'MX')
            troubleshooting_results['MX'] = [
                {"preference": rdata.preference, "exchange": str(rdata.exchange)}
                for rdata in mx_result
            ]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['MX'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['MX'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['MX'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['MX'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            troubleshooting_results['MX'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        # Check NS records
        try:
            ns_result = self.resolver.resolve(domain, 'NS')
            troubleshooting_results['NS'] = [str(rdata) for rdata in ns_result]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['NS'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['NS'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['NS'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['NS'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            troubleshooting_results['NS'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        # Check TXT records
        try:
            txt_result = self.resolver.resolve(domain, 'TXT')
            troubleshooting_results['TXT'] = [str(rdata) for rdata in txt_result]
        except dns.resolver.NXDOMAIN:
            troubleshooting_results['TXT'] = {"error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            troubleshooting_results['TXT'] = {"error": "NoAnswer"}
        except dns.resolver.NoNameservers:
            troubleshooting_results['TXT'] = {"error": "NoNameservers"}
        except dns.exception.Timeout:
            troubleshooting_results['TXT'] = {"error": "Timeout"}
        except (ConnectionError, socket.gaierror, OSError, IOError, RuntimeError):
            troubleshooting_results['TXT'] = {"error": "System error during DNS resolution"}
        except Exception as e:
            # For other unexpected exceptions that indicate system problems,
            # return error status for the entire operation
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

        return {
            "domain": domain,
            "troubleshooting_results": troubleshooting_results,
            "status": "success"
        }

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


async def main() -> None:
    """Main entry point."""
    server = DNSMCPServer()
    # Start the server with HTTP transport - this will block until interrupted
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
# End of file