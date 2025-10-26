import asyncio
import ipaddress
from typing import List, Dict, Optional

try:
    from .resolver import Resolver
    from .typedefs import ToolResult, OpenResolver
except ImportError:
    from resolver import Resolver
    from typedefs import ToolResult, OpenResolver

async def check_open_resolver(
    target: str,
    domain: str = "example.com",
    timeout: float = 2.0
) -> OpenResolver:
    """
    Probe a single target IP to determine if it behaves as an open resolver.
    Uses the provided async Resolver class.
    """
    resolver = Resolver(nameservers=[target])

    # Attempt a recursive A query for a public domain
    result = await resolver.async_resolve(
        domain=domain,
        rdtype="A",
        timeout=timeout,
    )
    success = False
    if result.success:
        answer_count = result.details.get("answer_count", 0)
        has_ra = bool(result.details.get("flags", 0) & 0x80)  # RA bit = 0x80
        duration = 0
        note = None
        if result.duration:
            duration = result.duration
        # Heuristic: consider it open if it returned an answer and recursion available
        if has_ra and answer_count > 0 and result.rcode_text == "NOERROR":
            success = True

        # Some servers respond NOERROR + no answer (referral or caching)
        if has_ra and result.rcode_text == "NOERROR":
            success = True
            note = "Possible open resolver (answered NOERROR without data)"

        return OpenResolver(
            success=success,
            ip=target,
            rcode=result.rcode,
            rcode_text=result.rcode_text,
            duration=duration,
            details={
                "recursive answer": has_ra,
                "answer_count": answer_count,
                "note": note
            }
        )
    return OpenResolver(
        success=success,
        ip=target
    )

async def detect_open_resolvers_in_subnet(
    cidr: str,
    domain: str = "example.com",
    timeout: float = 2.0,
    concurrency: int = 200,
) -> ToolResult:
    """
    Scan all hosts in the CIDR using the async Resolver to find open resolvers.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    sem = asyncio.Semaphore(concurrency)
    open_res = []
    open_res_details = []
    async def worker(ip: str):
        async with sem:
            try:
                scan_result = await check_open_resolver(
                    ip,
                    domain=domain,
                    timeout=timeout
                )
                if scan_result.success:
                    open_res.append(ip)
                    open_res_details.append(scan_result)
            except Exception:
                pass  # Ignore single-host errors

    tasks = [asyncio.create_task(worker(ip)) for ip in hosts]
    await asyncio.gather(*tasks)
    return ToolResult(
        success=True,
        output={
            "network": network.exploded,
            "rfc1918_network": network.is_private,
            "num_addresses": network.num_addresses,
            "open_resolvers": open_res
        },
        details={
            "open_resolvers": open_res_details,
            "scanned_hosts": hosts
        }
    )


# Example CLI runner
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Async Open Resolver Detector (custom Resolver)")
    parser.add_argument("cidr", help="CIDR subnet to scan, e.g. 192.0.2.0/24")
    parser.add_argument("--domain", default="example.com", help="Domain to query")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--concurrency", type=int, default=200)
    args = parser.parse_args()

    res = asyncio.run(
        detect_open_resolvers_in_subnet(
            cidr=args.cidr,
            domain=args.domain,
            timeout=args.timeout,
            concurrency=args.concurrency,
        )
    )

    print(res)
