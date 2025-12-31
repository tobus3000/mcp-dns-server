"""
MCP DNS Server - An MCP server for DNS name resolution and troubleshooting.
"""

import asyncio
import sys

import yaml
from fastmcp import FastMCP
from fastmcp.utilities.logging import get_logger

from knowledge_base.manager import KnowledgeBaseManager
from prompt_mixins import PromptRegistrationMixin
from resource_mixins import ResourceRegistrationMixin
from server_mixins import ServerLifecycleMixin
from tool_mixins import ToolRegistrationMixin

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
                "An MCP server that provides DNS resolution and troubleshooting capabilities."
            ),
            log_level="DEBUG",
        )
        self.logger = get_logger(__name__)
        try:
            with open(self.config_path, encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.info("Config file %s not found, using default settings", self.config_path)
            self.config = {}
        except (yaml.YAMLError, OSError) as e:
            self.logger.error("Error loading config: %s", e)
            self.config = {}

        # Initialize knowledge base before registering resources
        self.initialize_knowledge_base()

        # Register all server components (tools, prompts, resources)
        # These must be called after self.server and self.config are initialized
        self._register_all_components()

    def initialize_knowledge_base(self) -> None:
        """Initialize the knowledge base manager."""
        self.kb_manager = KnowledgeBaseManager()
        self.logger.info(
            "Knowledge base initialized with %d articles",
            len(self.kb_manager.get_all_articles()),
        )

    def _register_all_components(self) -> None:
        """Register all tools, prompts, and resources with the server.

        This method coordinates registration across all mixins.
        Must be called after self.server and self.config are initialized.
        """
        self.register_tools()
        self.register_tools_prompts()
        self.register_resolver_resources()
        # Register KB resources and prompts if enabled in config
        if self.config.get("features", {}).get("knowledge_base", False):
            self.register_knowledge_base_resources()
            self.register_knowledge_base_prompts()


async def main() -> None:
    """Main entry point for the DNS MCP server."""
    server = DNSMCPServer()
    try:
        await server.start()
    except KeyboardInterrupt:
        await server.stop()
    except (OSError, RuntimeError) as e:
        logger.error("Unexpected error: %s", e)
        await server.stop()
        sys.exit(1)


def run_server() -> None:
    """Run the server with proper asyncio event loop handling."""
    loop = None
    try:
        if sys.platform == "win32":
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        loop.run_until_complete(main())
    except KeyboardInterrupt:
        if loop is not None:
            loop.run_until_complete(asyncio.sleep(0))
    finally:
        if loop is not None:
            loop.close()


if __name__ == "__main__":
    run_server()
