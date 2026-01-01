"""DNS Trace tool that mimics 'dig +trace' behavior.
Performs iterative DNS resolution from root servers down to the target domain,
optionally following CNAME chains to final A/AAAA records.
"""

from typing import Any

import dns.name
import dns.rdatatype

from dns_mcp_server.resolver import Resolver
from dns_mcp_server.typedefs import ToolResult


class Trace:
    """
    DNS trace implementation similar to 'dig +trace'.
    Resolves iteratively from root servers down to the target, including optional CNAME resolution.
    """

    def __init__(self, follow_cname=True):
        """
        Initializes the Trace object with an internal Resolver.

        Args:
            follow_cname: Whether to follow CNAME chains to final A/AAAA records.
        """
        self.resolver = Resolver()
        self.trace_steps = []  # stores each hop with full DNS message
        self.follow_cname = follow_cname

    def fetch_root_servers(self):
        """Discover root servers dynamically via DNS.

        Returns:
            List of root server IP addresses.
        """
        rrset, _ = self.resolver.resolve(".", "NS")
        if not rrset:
            return []

        ns_names = [str(rr.target).rstrip(".") for rr in rrset]
        root_ips = []
        for ns in ns_names:
            for rtype in ("A", "AAAA"):
                a_rrset, _ = self.resolver.resolve(ns, rtype)
                if a_rrset:
                    for rdata in a_rrset:
                        root_ips.append(rdata.address)
        return root_ips

    def perform_trace(self, domain):
        """
        Perform an iterative DNS trace for the given domain.
        Stores all hops in self.trace_steps.

        Args:
            domain: The domain name to trace.

        Returns:
            A dictionary with the trace results, including hops and final answer.
        """
        self.trace_steps.clear()
        domain_name = dns.name.from_text(domain)

        servers = self.fetch_root_servers()
        if not servers:
            return {"domain": domain, "hops": [], "error": "No root servers found."}

        response = None
        # Iterate through each level of the domain hierarchy, from root down
        # For "example.com", labels are ['example', 'com', '']
        # We iterate backwards: [''] (root), ['com'], ['example', 'com']
        for i in range(len(domain_name.labels) - 1, -1, -1):
            subdomain = dns.name.Name(domain_name.labels[i:])
            response = self._query_hierarchy_level(subdomain, servers)

            # Extract next servers for the next iteration
            servers = self._extract_next_servers(response)
            if not servers:
                # No more servers to query, we've reached the end
                break

        final_rrset = self._resolve_final_answer(response)

        return {"domain": domain, "hops": self.trace_steps, "final_answer": final_rrset}

    def get_dig_style(self) -> str:
        """Return the trace in dig +trace style as a string with hop counts.

        Returns:
            Formatted string representing the trace output.
        """
        output_lines = ["\n;; TRACE OUTPUT (dig +trace style)\n"]
        for hop_idx, hop in enumerate(self.trace_steps, start=1):
            server = hop["server"]
            response = hop["response"]

            if not response or not hasattr(response, "question"):
                output_lines.append(f";; Hop {hop_idx}: Server {server} (No response)")
                continue

            output_lines.append(f";; Hop {hop_idx}: Server {server}")
            output_lines.append(";; QUESTION SECTION:")
            if hasattr(response, "question") and response.question:
                for question in response.question:
                    output_lines.append(f";; {question.to_text()}")

            if hasattr(response, "answer") and response.answer:
                output_lines.append(";; ANSWER SECTION:")
                for rrset in response.answer:
                    for rdata in rrset:
                        output_lines.append(
                            f"{rrset.name} {rrset.ttl} IN "
                            f"{dns.rdatatype.to_text(rrset.rdtype)} {rdata}"
                        )

            if hasattr(response, "authority") and response.authority:
                output_lines.append(";; AUTHORITY SECTION:")
                for rrset in response.authority:
                    for rdata in rrset:
                        output_lines.append(
                            f"{rrset.name} {rrset.ttl} IN "
                            f"{dns.rdatatype.to_text(rrset.rdtype)} {rdata}"
                        )

            if hasattr(response, "additional") and response.additional:
                output_lines.append(";; ADDITIONAL SECTION:")
                for rrset in response.additional:
                    for rdata in rrset:
                        output_lines.append(
                            f"{rrset.name} {rrset.ttl} IN "
                            f"{dns.rdatatype.to_text(rrset.rdtype)} {rdata}"
                        )

            output_lines.append("")  # blank line between hops

        return "\n".join(output_lines)

    def _query_hierarchy_level(self, subdomain, servers) -> Any | None:
        """Query a set of servers for a subdomain, return the response.

        Args:
            subdomain: dns.name.Name object for the current subdomain to query.
            servers: List of server IPs to query.

        Returns:
            DNS message response or None
        """
        for server in servers:
            _rrset, response = self.resolver.resolve(
                str(subdomain), "NS", nameserver=server
            )
            if not response:
                continue

            hop_info = {
                "server": server,
                "qname": str(subdomain),
                "qtype": "NS",
                "response": response,
            }
            self.trace_steps.append(hop_info)

            # Return the response after recording this hop
            # The caller will extract next servers from this response
            return response

        return None

    def _extract_next_servers(self, response) -> list[str]:
        """Extract next authoritative servers from additional, authority, or answer sections.

        Args:
            response: The DNS message from the current server.

        Returns:
            List of IP addresses of next authoritative servers.
        """
        if not response:
            return []

        next_servers = []

        # First, try to get IPs from additional section
        if hasattr(response, "additional") and response.additional:
            for rr in response.additional:
                if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    for r in rr:
                        next_servers.append(r.address)

        # If no additional records, look in authority section
        if not next_servers and hasattr(response, "authority") and response.authority:
            ns_names = []
            for rr in response.authority:
                if rr.rdtype == dns.rdatatype.NS:
                    ns_names.extend(str(r.target) for r in rr)
            for ns in ns_names:
                a_rrset, _ = self.resolver.resolve(ns, "A")
                if a_rrset:
                    for rdata in a_rrset:
                        next_servers.append(rdata.address)

        # If still no servers, try the answer section (for cases like root query)
        if not next_servers and hasattr(response, "answer") and response.answer:
            ns_names = []
            for rr in response.answer:
                if rr.rdtype == dns.rdatatype.NS:
                    ns_names.extend(str(r.target) for r in rr)
            for ns in ns_names:
                a_rrset, _ = self.resolver.resolve(ns, "A")
                if a_rrset:
                    for rdata in a_rrset:
                        next_servers.append(rdata.address)

        return next_servers

    def _format_rrset(self, rrsets) -> list[dict[str, Any]]:
        """Convert RRset(s) into list of dicts with name, ttl, type, value.

        Args:
            rrsets: A single RRset or list of RRsets

        Returns:
            List of dicts representing the records
        """
        if not rrsets:
            return []
        result = []
        for rrset in rrsets:
            for rdata in rrset:
                result.append(
                    {
                        "name": str(rrset.name),
                        "ttl": rrset.ttl,
                        "type": dns.rdatatype.to_text(rrset.rdtype),
                        "value": str(rdata),
                    }
                )
        return result

    def _resolve_final_answer(self, response) -> list[dict[str, Any]]:
        """Follow CNAME chain if enabled, otherwise return A/AAAA from the last response.

        Args:
            response: The DNS message from the last authoritative server.

        Returns:
            List of final A/AAAA records as dicts.
        """
        if not response or not hasattr(response, "answer") or not response.answer:
            return self._format_rrset(
                response.answer if (response and hasattr(response, "answer")) else None
            )

        if not self.follow_cname:
            return self._format_rrset(response.answer)

        rrsets = response.answer
        visited = set()
        final_records = []

        while True:
            new_rrsets = []
            cname_target = None
            for rrset in rrsets:
                for rdata in rrset:
                    rtype = dns.rdatatype.to_text(rrset.rdtype)
                    if rtype == "CNAME":
                        cname_target = str(rdata.target)
                    elif rtype in ("A", "AAAA"):
                        final_records.append(
                            {
                                "name": str(rrset.name),
                                "ttl": rrset.ttl,
                                "type": rtype,
                                "value": str(rdata),
                            }
                        )
            if not cname_target:
                break
            if cname_target in visited:
                break
            visited.add(cname_target)

            for rtype in ("A", "AAAA"):
                rrset_next, _ = self.resolver.resolve(cname_target, rtype)
                if rrset_next:
                    new_rrsets.append(rrset_next)
            if not new_rrsets:
                break
            rrsets = new_rrsets

        return final_records


async def dns_trace_impl(domain: str) -> ToolResult:
    """Perform a DNS trace for the given domain.

    Args:
        domain (str): The domain to trace.

    Returns:
        Dict[str, Any]: Trace report or error details.
    """
    tracer = Trace(follow_cname=True)
    tracer.perform_trace(domain.strip())
    return ToolResult(
        success=True, output={"domain": domain, "dns_trace": tracer.get_dig_style()}
    )
