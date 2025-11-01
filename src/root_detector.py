import asyncio
from typing import List, Dict, Optional, Any
try:
    from .resolver import Resolver
    from .typedefs import ToolResult
except ImportError:
    from resolver import Resolver
    from typedefs import ToolResult

class RootServerDetector:
    """Asynchronous detector for identifying which DNS root infrastructure is in use."""

    OFFICIAL_ROOT_SERVERS = {
        "a.root-servers.net.",
        "b.root-servers.net.",
        "c.root-servers.net.",
        "d.root-servers.net.",
        "e.root-servers.net.",
        "f.root-servers.net.",
        "g.root-servers.net.",
        "h.root-servers.net.",
        "i.root-servers.net.",
        "j.root-servers.net.",
        "k.root-servers.net.",
        "l.root-servers.net.",
        "m.root-servers.net.",
    }

    def __init__(self, nameservers: Optional[List[str]] = None):
        self.resolver = Resolver(nameservers=nameservers)

    async def detect_root_servers(self) -> Dict[str, Any]:
        """
        Detect which root servers are returned by the configured resolver.
        """
        try:
            result = await self.resolver.async_resolve(".", "NS")
            if not result.success or not result.response:
                return {
                    "detected_root_servers": [],
                    "is_official": False,
                    "alternative_roots": [],
                    "error": result.error or "No valid response from resolver",
                }

            ns_records = []
            for rr in result.response.answer:
                for rdata in rr:
                    ns_records.append(str(rdata.target).lower())

            ns_records = list(set(ns_records))

            official_hits = [ns for ns in ns_records if ns in self.OFFICIAL_ROOT_SERVERS]
            alternative_roots = [ns for ns in ns_records if ns not in self.OFFICIAL_ROOT_SERVERS]

            return {
                "detected_root_servers": ns_records,
                "is_official": len(alternative_roots) == 0 and len(official_hits) > 0,
                "alternative_roots": alternative_roots,
            }

        except Exception as e:
            return {
                "detected_root_servers": [],
                "is_official": False,
                "alternative_roots": [],
                "error": str(e),
            }

    async def can_access_public_roots(self) -> Dict[str, Any]:
        """
        Detect if the client can directly access the public root servers.
        """
        reachable = []
        unreachable = []
        timeout = 2.0

        async def check_reachability(server_name: str) -> bool:
            try:
                addr_result = await self.resolver.async_resolve(server_name, "A")
                if not addr_result.success or not addr_result.response.answer:
                    return False
                ip = str(addr_result.response.answer[0][0])
                loop = asyncio.get_event_loop()
                try:
                    fut = loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(),
                                                        remote_addr=(ip, 53))
                    transport, _ = await asyncio.wait_for(fut, timeout=timeout)
                    transport.close()
                    return True
                except Exception:
                    return False
            except Exception:
                return False

        tasks = [check_reachability(ns) for ns in self.OFFICIAL_ROOT_SERVERS]
        results = await asyncio.gather(*tasks)

        for ns, ok in zip(self.OFFICIAL_ROOT_SERVERS, results):
            (reachable if ok else unreachable).append(ns)

        public_accessible = len(reachable) >= 3  # heuristic: at least 3 reachable
        env = "public" if public_accessible else "enterprise/private"

        return {
            "public_accessible": public_accessible,
            "reachable_servers": reachable,
            "unreachable_servers": unreachable,
            "environment": env,
        }

    async def detect_environment(self) -> ToolResult:
        """
        Combined check for root infrastructure and environment access.
        Returns:
            ToolResult: encapsulating success, structured output, and details.
        """
        try:
            root_info = await self.detect_root_servers()
            access_info = await self.can_access_public_roots()

            success = True
            if root_info.get("error") or not root_info.get("detected_root_servers"):
                success = False

            output = {
                "root_detection": root_info,
                "access_detection": access_info,
            }

            return ToolResult(
                success=success,
                output=output,
                details={
                    "is_official_roots": root_info.get("is_official"),
                    "environment": access_info.get("environment"),
                    "reachable_root_count": len(access_info.get("reachable_servers", []))
                }
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                details={"exception_type": type(e).__name__}
            )


# Example usage
if __name__ == "__main__":
    async def main():
        detector = RootServerDetector()
        result = await detector.detect_environment()
        print(result)

    asyncio.run(main())
