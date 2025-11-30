"""
MCP DNS Server - An MCP server for DNS name resolution and troubleshooting.
"""

import asyncio
import ipaddress
import signal
import sys
from typing import Any, Dict

import yaml
from fastmcp import Context, FastMCP
from fastmcp.utilities.logging import get_logger

from tools.mdns.browser import discover_mdns_services_impl

try:
    # Try relative import first (when used as part of the package)
    from .knowledge_base.manager import KnowledgeBaseManager
    from .resolver import Resolver
    from .server_mixins import (
        PromptRegistrationMixin,
        ResourceRegistrationMixin,
        ServerLifecycleMixin,
        ToolRegistrationMixin,
    )
    from .typedefs import ToolResult
except ImportError:
    # Fall back to absolute import (when running as script or standalone)
    from knowledge_base.manager import KnowledgeBaseManager
    from resolver import Resolver
    from server_mixins import (
        PromptRegistrationMixin,
        ResourceRegistrationMixin,
        ServerLifecycleMixin,
        ToolRegistrationMixin,
    )
    from typedefs import ToolResult
logger = get_logger(__name__)


class DNSMCPServer(
    ToolRegistrationMixin,
    PromptRegistrationMixin,
    ResourceRegistrationMixin,
    ServerLifecycleMixin,
):
    """MCP Server implementation for DNS operations.

    Uses mixin classes to separate concerns:
    - ToolRegistrationMixin: Registers DNS tools
    - PromptRegistrationMixin: Registers prompts and guides
    - ResourceRegistrationMixin: Registers KB and DNS resources
    - ServerLifecycleMixin: Manages server startup/shutdown and signals
    """

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
                "An MCP server that provides DNS resolution and troubleshooting" " capabilities."
            ),
            log_level="DEBUG",
        )
        self.logger = get_logger(__name__)
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.info("Config file %s not found, using default settings", self.config_path)
            self.config = {}
        except (yaml.YAMLError, OSError) as e:
            self.logger.error("Error loading config: %s", e)
            self.config = {}

        self.initialize_knowledge_base()
        self.register_tools()
        self.register_tools_prompts()
        self.register_resolver_resources()
        # Register KB resources and prompts if enabled in config.
        if self.config["features"].get("knowledge_base"):
            self.register_knowledge_base_resources()
            self.register_knowledge_base_prompts()

    def initialize_knowledge_base(self) -> None:
        """Initialize the knowledge base manager."""
        self.kb_manager = KnowledgeBaseManager()
        self.logger.info(
            "Knowledge base initialized with %d articles", len(self.kb_manager.get_all_articles())
        )


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
        logger.error("Unexpected error: %s", e)
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
