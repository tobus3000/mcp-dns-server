"""
Server Lifecycle Mixin classes for DNSMCPServer to separate concerns.
"""

import asyncio
import signal
import sys
from typing import Any


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
                signal.signal(
                    sig, lambda s, f: asyncio.create_task(self._signal_handler(s))
                )

    async def _signal_handler(self, sig: int) -> None:
        """Handle shutdown signals.

        Args:
            sig: Signal number that triggered the handler
        """
        sig_name = signal.Signals(sig).name
        self.logger.info("Received shutdown signal %s", sig_name)
        await self.stop()

    async def start(self, host: str = "0.0.0.0", port: int = 3000) -> None:
        """Start the MCP server using HTTP transport.

        Args:
            host: The host to bind to. Defaults to "0.0.0.0" (all interfaces)
            port: The port to listen on. Defaults to 3000
        """
        self.setup_signal_handlers()
        try:
            self.logger.info("Starting MCP DNS Server on %s:%d", host, port)
            await self.server.run_async(
                transport="http", host=host, port=port, log_level="DEBUG"
            )
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
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=5.0,
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
