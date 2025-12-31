"""Multicast DNS browser for discovering network services.

This module provides an async interface for discovering mDNS/Bonjour services on the local network.
It is integrated with the MCP server's async architecture and returns structured results.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
    AsyncZeroconfServiceTypes,
)

from typedefs import ToolResult

try:
    from .service_map import SERVICE_MAP
except ImportError:
    from service_map import SERVICE_MAP

_PENDING_TASKS: set[asyncio.Task] = set()


async def discover_mdns_services_impl(
    find_all: bool = False, timeout: float = 5.0, ipv6: bool = False
) -> ToolResult:
    """Discover mDNS/Bonjour services on the local network.

    Args:
        find_all (bool): Whether to search for all available services or just HTTP/HAP.
        timeout (float): How long to browse for services in seconds.
        ipv6 (bool): Whether to include IPv6 addresses in discovery.

    Returns:
        ToolResult: Complete report of discovered mDNS services.
            success: Whether the discovery operation succeeded
            output: List of discovered services with their details
            error: Error message if discovery failed
            details: Additional metadata including service types discovered
    """
    runner = AsyncRunner(
        find_all=find_all, ip_version=IPVersion.All if ipv6 else IPVersion.V4Only
    )

    try:
        success, error, services, service_types = await runner.start_browsing(
            timeout=timeout
        )

        if not success:
            return ToolResult(success=False, error=error)

        return ToolResult(
            success=True,
            output=services,
            details={
                "service_types": service_types,
                "scan_duration": timeout,
                "ipv6_enabled": ipv6,
            },
        )

    except Exception as e:
        return ToolResult(
            success=False, error=f"mDNS service discovery failed: {str(e)}"
        )

    finally:
        await runner.stop_browsing()


class MDNSServiceDiscoveryError(Exception):
    """Exception raised for errors during mDNS service discovery."""

    pass


class AsyncRunner:
    def __init__(
        self, find_all: bool = False, ip_version: IPVersion = IPVersion.V4Only
    ) -> None:
        self.find_all = find_all
        self.ip_version = ip_version
        self.aiobrowser: AsyncServiceBrowser | None = None
        self.aiozc: AsyncZeroconf | None = None
        self._discovered_services: list[dict[str, Any]] = []
        self._discovered_service_types: list[str] = []

    def _service_callback(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change is ServiceStateChange.Added:
            task = asyncio.ensure_future(
                self._process_service_info(zeroconf, service_type, name)
            )
            _PENDING_TASKS.add(task)
            task.add_done_callback(_PENDING_TASKS.discard)

    async def _process_service_info(
        self, zeroconf: Zeroconf, service_type: str, name: str
    ) -> None:
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(zeroconf, 3000)

        if info:
            addresses = [
                f"{addr}:{cast(int, info.port)}"
                for addr in info.parsed_scoped_addresses()
            ]
            meta = SERVICE_MAP.get(
                service_type,
                {
                    "category": "Unknown",
                    "description": "Unrecognized mDNS service type",
                },
            )

            service_data = {
                "name": name,
                "type": service_type,
                "category": meta.get("category"),
                "description": meta.get("description"),
                "addresses": addresses,
                "weight": info.weight,
                "priority": info.priority,
                "server": info.server,
                "properties": dict(info.properties) if info.properties else {},
            }

            self._discovered_services.append(service_data)

    async def start_browsing(
        self, timeout: float = 5.0
    ) -> tuple[bool, str | None, list[dict[str, Any]], list[str]]:
        """Start browsing for mDNS services.

        Args:
            timeout: How long to browse for services in seconds

        Returns:
            Tuple containing:
                bool: Success flag
                Optional[str]: Error message if failed
                list[dict[str, Any]]: Discovered services
                list[str]: Service types found
        """
        try:
            self.aiozc = AsyncZeroconf(ip_version=self.ip_version)

            services = ["_http._tcp.local.", "_hap._tcp.local."]
            if self.find_all:
                services = list(
                    await AsyncZeroconfServiceTypes.async_find(
                        aiozc=self.aiozc, ip_version=self.ip_version
                    )
                )

            self._discovered_service_types = services
            self.aiobrowser = AsyncServiceBrowser(
                self.aiozc.zeroconf, services, handlers=[self._service_callback]
            )

            await asyncio.sleep(timeout)

            return True, None, self._discovered_services, self._discovered_service_types

        except Exception as e:
            return False, str(e), [], []

    async def stop_browsing(self) -> None:
        """Stop browsing and cleanup resources."""
        if self.aiobrowser:
            await self.aiobrowser.async_cancel()
        if self.aiozc:
            await self.aiozc.async_close()
