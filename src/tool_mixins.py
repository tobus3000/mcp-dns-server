"""
Tool Mixin classes for DNSMCPServer to separate concerns.
"""

import ipaddress
from typing import Any

from fastmcp import Context

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
    validate_fqdn,
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
    config: dict[str, Any]  # Configuration dictionary

    def register_tools(self) -> None:
        """Register all DNS-related tools with the MCP server."""

        @self.server.tool(
            name="simple_dns_lookup",
            description=(
                "Use this tool to perform a forward DNS lookup that resolves "
                "a hostname to its IP address"
            ),
            tags=set(("dns", "forward", "query", "lookup", "a_record")),
            enabled=True,
        )
        async def simple_dns_lookup(hostname: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Querying for A record of `{hostname}`.")
            return await simple_dns_lookup_impl(hostname.strip())

        @self.server.tool(
            name="advanced_dns_lookup",
            description=(
                "Use this tool to perform an advanced DNS lookup using any of "
                "the supported DNS record types. Get the list of supported record "
                "types from the `supported_dns_record_types` resource."
            ),
            tags=set(("dns", "query", "lookup", "advanced")),
            enabled=self.config.get("features", {}).get("advanced_troubleshooting", False),
        )
        async def advanced_dns_lookup(hostname: str, record_type: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Querying for {record_type} record of `{hostname}`.")
            return await advanced_dns_lookup_impl(hostname.strip(), record_type.strip().upper())

        @self.server.tool(
            name="reverse_dns_lookup",
            description=(
                "Use this tool to perform a DNS reverse lookup to get "
                "a hostname from an IP address"
            ),
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
                f"Performing standard compliance tests against nameserver `{nameserver.strip()}` "
                + f"using domain `{domain.strip()}`."
            )
            return await run_comprehensive_tests_impl(domain.strip(), nameserver.strip())

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
            tags=set(
                (
                    "dns",
                    "edns",
                    "troubleshooting",
                    "diagnostics",
                    "server",
                    "nameserver",
                )
            ),
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
            description=(
                "Use this tool to test that the given nameserver answers UDP and TCP "
                "queries by using the specified domain."
            ),
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
                "Use this tool to check the DNSSEC validation of a given domain "
                "and return an in-depth report. When analyzing the returned report, "
                "focus your evaluation on the critical_issues list in the summary section "
                "and the CRITICAL flags in the validation_details. Pay special attention to: "
                "(1) Nameserver errors (SERVFAIL, etc.) indicating the server cannot process DNSSEC queries, "
                "(2) Missing RRSIG signatures on present records, "
                "(3) Missing or invalid DNSSEC denial proofs for absent records, "
                "(4) Broken NSEC chains that invalidate denial-of-existence proofs. "
                "These issues directly indicate DNSSEC configuration problems."
            ),
            tags=set(("dns", "security", "dnssec", "validation")),
            enabled=self.config.get("features", {}).get("dnssec_validation", False),
        )
        async def check_dnssec(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing DNSSEC verification tasks for domain `{domain}`.")
            return await check_dnssec_impl(domain)

        @self.server.tool(
            name="lookalike_risk",
            description="Use this tool to assess the lookalike domain risk for a given domain.",
            tags=set(("dns", "security", "lookalike", "typosquatting")),
            enabled=self.config.get("features", {}).get("lookalike_risk_tool", False),
        )
        async def lookalike_risk(domain: str, ctx: Context, check_dns: bool = False) -> ToolResult:
            await ctx.info(f"Performing lookalike risk verification tests for domain `{domain}`.")
            return await lookalike_risk_impl(domain, check_dns)

        @self.server.tool(
            name="punycode_converter",
            description=(
                "Use this tool to convert the specified internationalized domain name (IDN) "
                "into punycode format."
            ),
            tags=set(("dns", "idn", "punycode", "converter")),
            enabled=True,
        )
        async def punycode_converter(domain: str, ctx: Context) -> ToolResult:
            await ctx.info(f"Performing punycode conversion for domain `{domain}`.")
            return await punycode_converter_impl(domain)

        @self.server.tool(
            name="detect_open_resolvers",
            description="Use this tool to scan a given subnet for open DNS resolvers.",
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
            description=(
                "Use this tool to detect DNS interception/spoofing including MAC-level "
                "fingerprinting."
            ),
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
                "Use this tool to test whether a given DNS server is authoritative, a resolver, "
                "or operates in mixed-mode."
            ),
            tags=set(("dns", "authority", "caching", "recursion", "role", "nameserver")),
            enabled=self.config.get("features", {}).get("nameserver_role_test", False),
        )
        async def detect_nameserver_role(
            ctx: Context,
            nameserver: str,
            domain: str | None,
            authority_test_domain: str | None,
        ) -> ToolResult:
            await ctx.info(
                f"Performing role check for nameserver `{nameserver}` using domain {domain}."
            )
            return await verify_nameserver_role_impl(
                nameserver=nameserver,
                domain=domain,
                authority_test_domain=authority_test_domain,
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
            description=(
                "Use this tool to verify that the top-level domain of a specified domain "
                "name is a valid global top-level domain (gTLD)."
            ),
            tags=set(("dns", "authority", "root", "TLD", "gTLD")),
            enabled=self.config.get("features", {}).get("top_level_domain_verification", False),
        )
        async def top_level_domain_verification(ctx: Context, domain: str) -> ToolResult:
            await ctx.info("Performing top-level-domain check.")
            return await tld_check_impl(domain=domain)

        @self.server.tool(
            name="mdns_service_discovery",
            description="Use this tool to discover mDNS services on the local network.",
            tags=set(("mdns", "discovery", "network")),
            enabled=self.config.get("features", {}).get("mdns_service_discovery", False),
        )
        async def mdns_service_discovery(
            ctx: Context,
            find_all: bool = False,
            timeout: float = 5.0,
            ipv6: bool = False,
        ) -> ToolResult:
            await ctx.info("Starting mDNS service discovery.")
            return await discover_mdns_services_impl(find_all=find_all, timeout=timeout, ipv6=ipv6)

        @self.server.tool(
            name="validate_dns_fqdn",
            description=(
                "Use this tool to validate a Fully Qualified Domain Name (FQDN) "
                "according to DNS RFC rules."
            ),
            tags=set(("dns", "validation", "FQDN")),
            enabled=True,
        )
        async def validate_dns_fqdn(ctx: Context, domain: str) -> ToolResult:
            await ctx.info(f"Validating FQDN: {domain}")
            result, message = await validate_fqdn(domain=domain)
            if result:
                return ToolResult(success=True, output=f"`{domain}` is a syntactically valid FQDN.")
            else:
                return ToolResult(success=False, error=f"`{domain}` is not a valid FQDN: {message}")

        @self.server.tool(
            name="dns_assistant",
            description=(
                "Use this tool to start a DNS support assistant that gathers information "
                "progressively to help find a DNS-related problem."
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
