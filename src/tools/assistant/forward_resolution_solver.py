from fastmcp import Context

from tools.dns import simple_dns_lookup_impl
from tools.validator import is_valid_tld
from typedefs import ToolResult


async def basic_dns_assistant_impl(ctx: Context) -> ToolResult:
    """Interactive DNS support assistant that gathers additional
    information from the user when needed.

    Args:
        ctx (Context): The MCP session context used for elicitation.

    Returns:
        ToolResult: The analysis of the user problem.
    """
    domain = await ctx.elicit(
        "What DNS name or domain are you having trouble with?", response_type=str
    )
    if domain.action != "accept":
        return ToolResult(success=False, error="DNS assistant cancelled")

    resolved_domain = await simple_dns_lookup_impl(domain.data.strip())
    # TODO: progress with checking...
    if resolved_domain.success:
        if ip := resolved_domain.output and resolved_domain.details["rcode_text"]:
            if resolved_domain.details["rcode_text"] == "NOERROR":
                if len(ip) >= 1:
                    resolved_domain.output = (
                        f"The domain {domain.data.strip()} seems to be resolving "
                        + f"correctly to IP {ip}."
                    )
                else:
                    resolved_domain.output = (
                        f"The domain {domain.data.strip()} seems to be resolving correctly but "
                        + "has no response data. This is normal and can have various reasons. "
                        + "Example: The DNS name points at a Load Balanced resource that does not "
                        + "currently have any online servers in the pool."
                    )
            elif resolved_domain.details["rcode_text"] == "NXDOMAIN":
                # Domain does not seem to exist. Check if TLD is valid.
                tld_check = await is_valid_tld(domain=domain.data.strip())
                if tld_check.success:
                    resolved_domain.output = (
                        f"The DNS name {domain.data.strip()} does "
                        + f"not exist but the {tld_check.output}"
                    )
                else:
                    resolved_domain.output = (
                        f"The DNS name {domain.data.strip()} does not exist but the problem "
                        + f"is most likely down to the top-level domain. {tld_check.output}"
                    )

        return resolved_domain
    else:
        # Failure to resolve the name requires some additional checking as to why it failed.
        tld_check = await is_valid_tld(domain=domain.data.strip())

        return tld_check
