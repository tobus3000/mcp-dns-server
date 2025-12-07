from src.resolver import Resolver
from src.typedefs import ToolResult


async def punycode_converter_impl(domain: str) -> ToolResult:
    """Perform Unicode IDN domain name conversion into punycode ASCII format.

    Args:
        domain (str): The domain name to convert to punycode.

    Returns:
        Dict[str, Any]: Punycode domain name or error details.
    """
    punycode = Resolver.convert_idn_to_punnycode(domain.strip())
    return ToolResult(success=True, output={"domain": domain, "punycode": punycode})
