"""
Prompt Mixin classes for DNSMCPServer to separate concerns.
"""

from typing import Any

from resolver import Resolver


class PromptRegistrationMixin:
    """Mixin for registering prompts with the MCP server.

    Note: This mixin assumes the class has 'server' (FastMCP) and 'config' (dict)
    attributes available when register_tools_prompts() is called.
    """

    # Type hints for attributes provided by the host class
    server: Any  # FastMCP instance
    config: dict[str, Any]  # Configuration dictionary

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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            tags=set(
                ("dns", "troubleshooting", "diagnostics", "protocol", "udp", "tcp")
            ),
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            tags=set(
                ("dns", "troubleshooting", "diagnostics", "cookie", "edns", "dnscookie")
            ),
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            enabled=self.config.get("features", {}).get(
                "advanced_troubleshooting", False
            ),
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
            tags=set(
                ("dns", "security", "scanner", "open resolver", "subnet", "network")
            ),
            enabled=self.config.get("features", {}).get(
                "open_resolver_scan_tool", False
            ),
        )
        def detect_open_resolvers(cidr: str, domain: str) -> str:
            """Scan a subnet in CIDR notation for open DNS resolvers."""
            return f"Scan for open resolvers in subnet {cidr} using domain {domain}."

        @self.server.prompt(
            name="detect_dns_spoofing",
            description="Detect DNS interception/spoofing.",
            tags=set(
                ("dns", "security", "scanner", "open resolver", "subnet", "network")
            ),
            enabled=self.config.get("features", {}).get(
                "open_resolver_scan_tool", False
            ),
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
            tags=set(
                ("dns", "security", "scanner", "open resolver", "subnet", "network")
            ),
            enabled=self.config.get("features", {}).get(
                "open_resolver_scan_tool", False
            ),
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
            tags=set(
                ("dns", "authority", "caching", "recursion", "role", "nameserver")
            ),
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
            tags=set(
                ("dns", "authority", "caching", "recursion", "role", "nameserver")
            ),
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
            enabled=self.config.get("features", {}).get(
                "detect_dns_root_environment", False
            ),
        )
        def detect_dns_root_environment() -> str:
            """Detect the DNS root server infrastructure used for name resolution."""
            return "Detect the DNS root server infrastructure that is used for name resolution."

        @self.server.prompt(
            name="top_level_domain_verification",
            description="Check if the top-level domain of a given domain is valid.",
            tags=set(("dns", "authority", "root", "TLD", "gTLD")),
            enabled=self.config.get("features", {}).get(
                "top_level_domain_verification", False
            ),
        )
        def top_level_domain_verification(domain: str) -> str:
            """Check if the top-level domain of a given domain is valid."""
            return f"Check if the top-level domain of domain {domain} is valid."

        @self.server.prompt(
            name="mdns_service_discovery",
            description="Discover mDNS services on the local network.",
            tags=set(("mdns", "discovery", "network")),
            enabled=self.config.get("features", {}).get(
                "mdns_service_discovery", False
            ),
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
            tags=set(
                ("interactive", "elicitation", "dns", "assistant", "problem", "help")
            ),
            enabled=self.config.get("features", {}).get("basic_dns_assistant", False),
        )
        def dns_assistant() -> str:
            """Interactive assistant that gathers information progressively from the user
            to help solve a DNS related problem.
            """
            return "Help me solve a DNS related problem."

        @self.server.prompt(
            name="validate_dns_fqdn",
            description="Validate a Fully Qualified Domain Name (FQDN) according to DNS RFC rules.",
        )
        def validate_dns_fqdn(domain: str) -> str:
            """Validate a Fully Qualified Domain Name (FQDN) according to DNS RFC rules."""
            return (
                f"Validate the FQDN: {domain} according to DNS RFC rules using the "
                "DNS MCP tool `validate_dns_fqdn`."
            )

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
