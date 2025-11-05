"""Launch script for the MCP DNS Server."""

import asyncio
import os
import sys
from typing import NoReturn

# Add src directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dns_mcp_server import DNSMCPServer


async def main() -> None:
    """Main entry point for the DNS MCP server."""
    server = DNSMCPServer()
    # Start the server with HTTP transport - this will block until interrupted
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
