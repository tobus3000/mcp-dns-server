"""Mixin classes for DNSMCPServer to separate concerns and improve maintainability."""

import asyncio
import ipaddress
import signal
import sys
from typing import Any, Dict

from fastmcp import Context

try:
    # Try relative import first (when used as part of the package)
    from .resolver import Resolver
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
    from resolver import Resolver
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


class ToolRegistrationMixin:
    """Mixin for registering DNS tools with the MCP server.

    Note: This mixin assumes the class has 'server' (FastMCP) and 'config' (dict)
    attributes available when register_tools() is called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    config: Dict[str, Any]  # Configuration dictionary

    def register_tools(self) -> None:
        """Register all DNS-related tools with the MCP server."""

        @self.server.tool(
            name="simple_dns_lookup",
            description="Perform a simple DNS lookup for a hostname to get its IP address",
            tags=set(("dns", "query", "lookup", "a_record")),
            enabled=True,
        )
        async def simple_dns_lookup(hostname: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Querying for A record of `{hostname}`.")
            return await simple_dns_lookup_impl(hostname.strip())

        @self.server.tool(
            name="advanced_dns_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types",
            tags=set(("dns", "query", "lookup", "advanced")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def advanced_dns_lookup(hostname: str, record_type: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Querying for {record_type} record of `{hostname}`.")
            return await advanced_dns_lookup_impl(hostname.strip(), record_type.strip().upper())

        @self.server.tool(
            name="reverse_dns_lookup",
            description="Perform a reverse DNS lookup to get hostname from IP address",
            tags=set(("dns", "query", "lookup", "reverse")),
            enabled=self.config.get("features", {}).get("reverse_lookup", False),
        )
        async def reverse_dns_lookup(ip_address: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Querying PTR record of `{ip_address}`.")
            return await reverse_dns_lookup_impl(ip_address.strip())

        @self.server.tool(
            name="dns_domain_troubleshooting",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_domain_troubleshooting(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing troubleshooting tasks for domain `{domain}`.")
            return await dns_troubleshooting_impl(domain.strip())

        @self.server.tool(
            name="dns_server_troubleshooting",
            description=(
                "Perform comprehensive DNS server troubleshooting for a given"
                " domain and nameserver"
            ),
            tags=set(("dns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_server_troubleshooting(
            domain: str, nameserver: str, ctx: Context
        ) -> ToolResult:
            await ctx.info(
                f"Performing standard compliance tests against nameserver `{nameserver}` "
                + f"using domain `{domain}`."
            )
            return await run_comprehensive_tests_impl(domain, nameserver)

        @self.server.tool(
            name="dns_trace",
            description="Perform a DNS trace to see the resolution path for a domain",
            tags=set(("dns", "query", "troubleshooting", "trace")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_trace(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing DNS trace for domain `{domain}`.")
            return await dns_trace_impl(domain)

        @self.server.tool(
            name="dns_server_edns_test",
            description="Perform EDNS tests on a given domain and nameserver",
            tags=set(("dns", "edns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_server_edns_test(domain: str, nameserver: str, ctx: Context) -> ToolResult:
            await ctx.info(
                f"Performing EDNS tests against nameserver `{nameserver}` "
                + f"using domain `{domain}` for testing."
            )
            return await run_edns_tests_impl(domain, nameserver)

        @self.server.tool(
            name="dns_udp_tcp_test",
            description="Perform UDP and TCP behavior tests on a given domain and nameserver.",
            tags=set(("dns", "troubleshooting", "diagnostics", "protocol", "udp", "tcp")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_udp_tcp_test(domain: str, nameserver: str, ctx: Context) -> ToolResult:
            await ctx.info(
                f"Performing UDP/TCP validation tests against nameserver {nameserver} "
                + f"using domain `{domain}` for testing."
            )
            return await run_tcp_behavior_tests_impl(domain, nameserver)

        @self.server.tool(
            name="dns_cookie_test",
            description="Perform a DNS Cookie behavior test on a given domain and nameserver.",
            tags=set(("dns", "cookie", "edns", "diagnostics", "troubleshooting")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def dns_cookie_test(domain: str, nameserver: str, ctx: Context) -> ToolResult:
            await ctx.info(
                f"Performing DNS Cookie validation against nameserver {nameserver} "
                + f"using domain `{domain}` for testing."
            )
            return await run_dns_cookie_tests_impl(domain, nameserver)

        @self.server.tool(
            name="check_dnssec",
            description=(
                "Check DNSSEC validation for a given domain and return an in-depth "
                "report that highlights any issues found."
            ),
            tags=set(("dns", "security", "dnssec", "validation")),
            enabled=self.config.get("features", {}).get("dnssec_validation", False),
        )
        async def check_dnssec(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing DNSSEC verification tasks for domain `{domain}`.")
            return await check_dnssec_impl(domain)

        @self.server.tool(
            name="lookalike_risk",
            description="Assess lookalike domain risk for a given domain",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config.get("features", {}).get("lookalike_risk_tool", False),
        )
        async def lookalike_risk(domain: str, ctx: Context, check_dns: bool = False) -> ToolResult:
            await ctx.info(f"Performing lookalike risk verification tests for domain `{domain}`.")
            return await lookalike_risk_impl(domain, check_dns)

        @self.server.tool(
            name="punycode_converter",
            description=(
                "Converts any given internationalized domain name (IDN) into punycode format."
            ),
            tags=set(("dns", "idn", "punycode", "converter")),
            enabled=True,
        )
        async def punycode_converter(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing punycode conversion for domain `{domain}`.")
            return await punycode_converter_impl(domain)

        @self.server.tool(
            name="detect_open_resolvers",
            description="Scans a given subnet for open resolvers.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config.get("features", {}).get("open_resolver_scan_tool", False),
        )
        async def detect_open_resolvers(cidr: str, domain: str, ctx: Context) -> ToolResult:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.is_private:
                await ctx.info(f"Performing open resolver scan on private subnet `{cidr}`.")
                return await scan_subnet_for_open_resolvers_impl(cidr, domain)
            await ctx.info(
                "The tool is limited to only scan private networks. Provided network "
                + f"`{cidr}` is not a private network according to RFC1918."
            )
            return ToolResult(
                success=False,
                error="Tool is limited to only scan private networks in the RFC1918 range.",
            )

        @self.server.tool(
            name="detect_dns_spoofing",
            description="Detect DNS interception/spoofing including MAC-level fingerprinting.",
            tags=set(("dns", "spoofing", "mac", "fingerprinting")),
            enabled=self.config.get("features", {}).get("detect_dns_spoofing", False),
        )
        async def detect_dns_spoofing(
            ctx: Context, nameserver: str, domain: str, router_mac: str | None
        ) -> ToolResult:
            await ctx.info(
                f"Performing DNS spoofing detection against nameserver `{nameserver}` "
                + f"using domain {domain}."
            )
            return await scan_server_for_dns_spoofing_impl(
                nameserver=nameserver, domain=domain, router_mac=router_mac
            )

        @self.server.tool(
            name="detect_nameserver_role",
            description=(
                "Test whether a given DNS server is authoritative, a resolver, or mixed-mode."
            ),
            tags=set(("dns", "authority", "caching", "recursion", "role", "nameserver")),
            enabled=self.config.get("features", {}).get("nameserver_role_test", False),
        )
        async def detect_nameserver_role(
            ctx: Context, nameserver: str, domain: str | None, authority_test_domain: str | None
        ) -> ToolResult:
            await ctx.info(
                f"Performing role check for nameserver `{nameserver}` using domain {domain}."
            )
            return await verify_nameserver_role_impl(
                nameserver=nameserver, domain=domain, authority_test_domain=authority_test_domain
            )

        @self.server.tool(
            name="detect_dns_root_environment",
            description="Detect the DNS root infrastructure that is used for name resolution.",
            tags=set(("dns", "authority", "root", "nameserver")),
            enabled=self.config.get("features", {}).get("detect_dns_root_environment", False),
        )
        async def detect_dns_root_environment(ctx: Context) -> ToolResult:
            await ctx.info("Performing root DNS infrastructure test.")
            return await detect_dns_root_environment_impl()

        @self.server.tool(
            name="top_level_domain_verification",
            description="Verify the top-level domain part of a given domain name.",
            tags=set(("dns", "authority", "root", "TLD", "gTLD")),
            enabled=self.config.get("features", {}).get("top_level_domain_verification", False),
        )
        async def top_level_domain_verification(ctx: Context, domain: str) -> ToolResult:
            await ctx.info("Performing top-level-domain check.")
            return await tld_check_impl(domain=domain)

        @self.server.tool(
            name="mdns_service_discovery",
            description="Discover mDNS services on the local network.",
            tags=set(("mdns", "discovery", "network")),
            enabled=self.config.get("features", {}).get("mdns_service_discovery", False),
        )
        async def mdns_service_discovery(
            ctx: Context, find_all: bool = False, timeout: float = 5.0, ipv6: bool = False
        ) -> ToolResult:
            await ctx.info("Starting mDNS service discovery.")
            return await discover_mdns_services_impl(find_all=find_all, timeout=timeout, ipv6=ipv6)

        @self.server.tool(
            name="dns_assistant",
            description=(
                "Basic DNS support assistant gathers information progressively "
                "to help finding a DNS related problem."
            ),
            tags=set(("interactive", "elicitation", "dns", "assistant", "problem", "help")),
            enabled=self.config.get("features", {}).get("basic_dns_assistant", False),
        )
        async def basic_dns_assistant(ctx: Context) -> ToolResult:
            """Interactive DNS support assistant that gathers additional
            information from the user when needed.

            Args:
                ctx (Context): The MCP session context used for elicitation.

            Returns:
                ToolResult: The final analysis of the user problem and eventual
                help in how to fix the problem.
            """
            return await basic_dns_assistant_impl(ctx)


class PromptRegistrationMixin:
    """Mixin for registering prompts with the MCP server.

    Note: This mixin assumes the class has 'server' (FastMCP) and 'config' (dict)
    attributes available when register_tools_prompts() is called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    config: Dict[str, Any]  # Configuration dictionary

    def register_tools_prompts(self) -> None:
        """Register prompts for tools with the server."""

        @self.server.prompt(
            name="resolve_hostname",
            description="Resolve a hostname to its IP address.",
            tags=set(("dns", "query", "lookup", "a_record")),
            enabled=True,
        )
        def resolve_hostname(hostname: str) -> str:
            """Resolve a hostname to its IP address."""
            return (
                f"Resolve {hostname} to its IP address using the simple dns"
                " lookup tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="resolve_ip",
            description="Resolve an IP address to hostname using reverse DNS lookup.",
            tags=set(("dns", "query", "lookup", "reverse")),
            enabled=self.config.get("features", {}).get("reverse_lookup", False),
        )
        def resolve_ip(ip: str) -> str:
            """Resolve an IP address to hostname using reverse DNS lookup."""
            return (
                f"Resolve {ip} to its hostname using the reverse DNS lookup tool"
                " provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="advanced_lookup",
            description="Perform an advanced DNS lookup supporting multiple record types",
            tags=set(("dns", "query", "lookup", "advanced")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def advanced_lookup(hostname: str, record_type: str) -> str:
            """Perform an advanced DNS lookup for a hostname and record type."""
            return (
                f"Perform an advanced DNS lookup for {hostname} with record type"
                f" {record_type} using the advanced dns lookup tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_domain_troubleshoot",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_domain_troubleshoot(domain: str) -> str:
            """Perform DNS troubleshooting for a domain."""
            return (
                f"Perform DNS troubleshooting for {domain} using"
                " the dns domain troubleshooting tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_domain_on_server_troubleshoot",
            description="Perform comprehensive DNS troubleshooting for a given domain",
            tags=set(("dns", "troubleshooting", "diagnostics", "domain")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_domain_on_server_troubleshoot(domain: str, nameserver: str) -> str:
            """Perform DNS troubleshooting for a domain against a specific DNS server."""
            return (
                f"Perform DNS troubleshooting for {domain} against {nameserver} using"
                " the dns domain troubleshooting tool provided"
                " by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_server_troubleshoot",
            description=(
                "Perform comprehensive DNS server troubleshooting for a given"
                " domain and nameserver"
            ),
            tags=set(("dns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_server_troubleshoot(domain: str, nameserver: str) -> str:
            """Perform comprehensive DNS server troubleshooting."""
            return (
                f"Perform DNS server troubleshooting for domain {domain} and"
                f" nameserver {nameserver} using the dns server troubleshooting"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_domain_trace",
            description="Perform a DNS trace to see the resolution path for a domain",
            tags=set(("dns", "query", "troubleshooting", "trace")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_domain_trace(domain: str) -> str:
            """Perform a DNS trace for a domain."""
            return (
                f"Perform a DNS trace for domain {domain} using the dns trace"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_edns_test",
            description="Perform EDNS tests on a given domain and nameserver",
            tags=set(("dns", "edns", "troubleshooting", "diagnostics", "server", "nameserver")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_edns_test(domain: str, nameserver: str) -> str:
            """Perform EDNS tests for a nameserver."""
            return (
                f"Perform EDNS tests for domain {domain} and"
                f" nameserver {nameserver} using the dns server edns test"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="dns_udp_tcp_test",
            description="Perform UDP and TCP behavior tests on a given domain and nameserver",
            tags=set(("dns", "troubleshooting", "diagnostics", "protocol", "udp", "tcp")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_udp_tcp_test(domain: str, nameserver: str) -> str:
            """Perform UDP and TCP behavior tests for a nameserver."""
            return (
                f"Perform UDP and TCP behavior tests for domain {domain} and"
                f" nameserver {nameserver} using the dns udp tcp test tool"
                " provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="check_dns_cookie",
            description="Perform DNS Cookie behavior test on a given domain and nameserver",
            tags=set(("dns", "troubleshooting", "diagnostics", "cookie", "edns", "dnscookie")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def dns_cookie_test(domain: str, nameserver: str) -> str:
            """Perform DNS Cookie test against a nameserver."""
            return (
                f"Perform a DNS Cookie test for domain {domain} against nameserver {nameserver} "
                "using the dns cookie test tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="check_dnssec",
            description="Check DNSSEC validation for a given domain",
            tags=set(("dns", "security", "dnssec", "validation")),
            enabled=self.config.get("features", {}).get("dnssec_validation", False),
        )
        def check_dnssec(domain: str) -> str:
            """Get DNSSEC status of a domain."""
            return (
                f"Get DNSSEC status of domain {domain} using the check_dnssec"
                " tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="lookalike_risk",
            description="Assess lookalike domain risk for a given domain",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config.get("features", {}).get("lookalike_risk_tool", False),
        )
        def lookalike_risk(domain: str, check_dns: bool = False) -> str:
            """Assess lookalike domain risk."""
            return (
                f"Assess lookalike domain risk for {domain} using the"
                " lookalike_risk tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="lookalike_risk_check_dns",
            description=(
                "Assess lookalike domain risk for a given domain and "
                "resolve all possible variants"
            ),
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config.get("features", {}).get("lookalike_risk_tool", False),
        )
        def lookalike_risk_check_dns(domain: str, check_dns: bool = True) -> str:
            """Assess lookalike domain risk and resolve all variants."""
            return (
                f"Assess the lookalike domain risk for {domain} and resolve all variants using the"
                " lookalike_risk tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="supported_record_types",
            description=(
                "Return the DNS resource record types that are supported by this MCP server."
            ),
            tags=set(("dns", "record_types")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        def supported_record_types() -> str:
            """Get supported DNS record types."""
            types = ", ".join(sorted(Resolver.allowed_record_types))
            return (
                f"The supported DNS record types are: {types}. Use these types with the"
                " advanced dns lookup tool provided by the DNS MCP Server."
            )

        @self.server.prompt(
            name="punycode_converter",
            description="Return the punycode version of an internationalized domain name (IDN).",
            tags=set(("dns", "idn", "punycode", "converter")),
            enabled=True,
        )
        def punycode_converter(domain: str) -> str:
            """Convert IDN domain name to punycode."""
            return f"Convert the domain {domain} to punycode format."

        @self.server.prompt(
            name="detect_open_resolvers",
            description="Scan a subnet in CIDR notation for open DNS resolvers.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config.get("features", {}).get("open_resolver_scan_tool", False),
        )
        def detect_open_resolvers(cidr: str, domain: str) -> str:
            """Scan a subnet in CIDR notation for open DNS resolvers."""
            return f"Scan for open resolvers in subnet {cidr} using domain {domain}."

        @self.server.prompt(
            name="detect_dns_spoofing",
            description="Detect DNS interception/spoofing.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config.get("features", {}).get("open_resolver_scan_tool", False),
        )
        def detect_dns_spoofing(nameserver: str, domain: str) -> str:
            """Detect DNS interception/spoofing including MAC-level fingerprinting."""
            return (
                f"Scan for DNS spoofing between client and {nameserver} "
                f"IP using domain {domain}."
            )

        @self.server.prompt(
            name="detect_dns_spoofing_with_router_mac",
            description="Detect DNS interception/spoofing including MAC-level fingerprinting.",
            tags=set(("dns", "security", "scanner", "open resolver", "subnet", "network")),
            enabled=self.config.get("features", {}).get("open_resolver_scan_tool", False),
        )
        def detect_dns_spoofing_with_router_mac(
            nameserver: str, domain: str, router_mac: str
        ) -> str:
            """Detect DNS interception/spoofing including MAC-level fingerprinting."""
            return (
                f"Scan for DNS spoofing on gateway with MAC address {router_mac} "
                + f"and nameserver IP {nameserver} using domain {domain}."
            )

        @self.server.prompt(
            name="detect_nameserver_role",
            description=(
                "Test whether a given DNS server is authoritative, a resolver, or mixed-mode."
            ),
            tags=set(("dns", "authority", "caching", "recursion", "role", "nameserver")),
            enabled=self.config.get("features", {}).get("nameserver_role_test", False),
        )
        def detect_nameserver_role(nameserver: str) -> str:
            """Test whether a given DNS server is authoritative, a resolver, or mixed-mode."""
            return (
                f"Test whether nameserver {nameserver} is authoritative, "
                + "a resolver, or in mixed-mode."
            )

        @self.server.prompt(
            name="detect_nameserver_role_with_auth_domain",
            description=(
                "Test whether a given DNS server is authoritative, a resolver, or mixed-mode."
            ),
            tags=set(("dns", "authority", "caching", "recursion", "role", "nameserver")),
            enabled=self.config.get("features", {}).get("nameserver_role_test", False),
        )
        def detect_nameserver_role_with_auth_domain(
            nameserver: str, authority_test_domain: str
        ) -> str:
            """Test whether a given DNS server is authoritative, a resolver,
            or mixed-mode by testing for the known authoritative domain.
            """
            return (
                f"Test whether nameserver {nameserver} is authoritative, a resolver, or in "
                + f"mixed-mode by testing for the authoritative domain {authority_test_domain}."
            )

        @self.server.prompt(
            name="detect_dns_root_environment",
            description=(
                "Helps to detect the DNS root server infrastructure that is used "
                "for name resolution by the resolver."
            ),
            tags=set(("dns", "authority", "root", "nameserver")),
            enabled=self.config.get("features", {}).get("detect_dns_root_environment", False),
        )
        def detect_dns_root_environment() -> str:
            """Detect the DNS root server infrastructure used for name resolution."""
            return "Detect the DNS root server infrastructure that is used for name resolution."

        @self.server.prompt(
            name="top_level_domain_verification",
            description="Check if the top-level domain of a given domain is valid.",
            tags=set(("dns", "authority", "root", "TLD", "gTLD")),
            enabled=self.config.get("features", {}).get("top_level_domain_verification", False),
        )
        def top_level_domain_verification(domain: str) -> str:
            """Check if the top-level domain of a given domain is valid."""
            return f"Check if the top-level domain of domain {domain} is valid."

        @self.server.prompt(
            name="mdns_service_discovery",
            description="Discover mDNS services on the local network.",
            tags=set(("mdns", "discovery", "network")),
            enabled=self.config.get("features", {}).get("mdns_service_discovery", False),
        )
        def mdns_service_discovery(
            find_all: bool = False, timeout: float = 5.0, ipv6: bool = False
        ) -> str:
            """Discover mDNS services on the local network."""
            return (
                f"Discover mDNS services on the local network with find_all={find_all}, "
                + f"timeout={timeout}, ipv6={ipv6}."
            )

        @self.server.prompt(
            name="dns_assistant",
            description=(
                "Interactive assistant that gathers information progressively from the "
                "user to help solve a DNS related problem."
            ),
            tags=set(("interactive", "elicitation", "dns", "assistant", "problem", "help")),
            enabled=self.config.get("features", {}).get("basic_dns_assistant", False),
        )
        def dns_assistant() -> str:
            """Interactive assistant that gathers information progressively from the user
            to help solve a DNS related problem.
            """
            return "Help me solve a DNS related problem."

    def register_knowledge_base_prompts(self) -> None:
        """Register prompts to simplify interaction with the knowledge base."""

        @self.server.prompt(
            name="dns_troubleshooting_help",
            description="Get help with DNS troubleshooting using the knowledge base",
        )
        def dns_troubleshooting_help() -> str:
            """Get help with DNS troubleshooting using the knowledge base."""
            return (
                "When asked about DNS troubleshooting, consult the knowledge base"
                " using the search function with relevant query terms."
            )

        @self.server.prompt(
            name="dns_configuration_help",
            description="Get help with DNS configuration using the knowledge base",
        )
        def dns_configuration_help() -> str:
            """Get help with DNS configuration using the knowledge base."""
            return (
                "When asked about DNS configuration, particularly for complex setups"
                " like Extranet, search the knowledge base for configuration guides."
            )

        @self.server.prompt(
            name="dns_security_help",
            description="Get help with DNS security best practices using the knowledge base",
        )
        def dns_security_help() -> str:
            """Get help with DNS security best practices using the knowledge base."""
            return (
                "When asked about DNS security, search the knowledge base for"
                " security best practices and implementation guidelines."
            )


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


class ServerLifecycleMixin:
    """Mixin for server lifecycle management (signals, startup, shutdown).

    Note: This mixin assumes the class has 'server' (FastMCP) and 'logger' attributes
    available when lifecycle methods are called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    logger: Any  # Logger instance

    def setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if sys.platform == "win32":
            signals = (signal.SIGINT, signal.SIGBREAK)
        else:
            signals = (signal.SIGINT, signal.SIGTERM)

        for sig in signals:
            try:
                asyncio.get_running_loop().add_signal_handler(
                    sig, lambda s=sig: asyncio.create_task(self._signal_handler(s))
                )
            except NotImplementedError:
                signal.signal(sig, lambda s, f: asyncio.create_task(self._signal_handler(s)))

    async def _signal_handler(self, sig: int) -> None:
        """Handle shutdown signals.

        Args:
            sig: Signal number that triggered the handler
        """
        sig_name = signal.Signals(sig).name
        self.logger.info("Received shutdown signal %s", sig_name)
        await self.stop()

    async def start(self, host: str = "localhost", port: int = 3000) -> None:
        """Start the MCP server using HTTP transport.

        Args:
            host: The host to bind to. Defaults to "localhost"
            port: The port to listen on. Defaults to 3000
        """
        self.setup_signal_handlers()
        try:
            self.logger.info("Starting MCP DNS Server on %s:%d", host, port)
            await self.server.run_async(transport="http", host=host, port=port, log_level="DEBUG")
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
        if hasattr(self, "server"):
            try:
                current = asyncio.current_task()
                pending = [t for t in asyncio.all_tasks() if t is not current]

                if pending:
                    self.logger.debug("Cancelling %d pending tasks", len(pending))
                    for task in pending:
                        task.cancel()

                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True), timeout=5.0
                        )
                    except asyncio.TimeoutError:
                        self.logger.warning("Timeout waiting for tasks to stop")
                    except Exception as e:
                        self.logger.error("Error during task cleanup: %s", e)
            except Exception as e:
                self.logger.error("Error during server shutdown: %s", e)

        if sys.platform == "win32":
            signals = (signal.SIGINT, signal.SIGBREAK)
        else:
            signals = (signal.SIGINT, signal.SIGTERM)

        for sig in signals:
            try:
                asyncio.get_running_loop().remove_signal_handler(sig)
            except (NotImplementedError, ValueError):
                pass
        self.logger.info("MCP DNS Server stopped")
