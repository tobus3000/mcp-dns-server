import asyncio
import ipaddress

from src.resolver import Resolver
from src.typedefs import OpenResolver, ToolResult


async def check_open_resolver(
    target: str, domain: str = "example.com", timeout: float = 2.0
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
                "note": note,
            },
        )
    return OpenResolver(success=success, ip=target)


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
                    ip, domain=domain, timeout=timeout
                )
                if scan_result.success:
                    open_res.append(ip)
                    open_res_details.append(scan_result)
            except Exception:
                pass  # Ignore single-host errors

    tasks = [asyncio.create_task(worker(ip)) for ip in hosts]
    await asyncio.gather(*tasks)

    # Determine if network is private (RFC1918) or public
    is_private = network.is_private

    rating = "normal"
    cnt = len(open_res)
    if cnt > 2:
        rating = "high"
    if cnt > 10:
        rating = "very high"
    if cnt > 85:
        rating = "abnormaly high"
    percent = f"{(100 / network.num_addresses) * cnt:.2f}"
    note = [
        f"A {rating} count of {cnt} open DNS resolvers has been "
        + f"found in network {network.exploded}.",
        f"{percent}% of hosts in the network are open resolvers.",
    ]

    # Add network type context and risk assessment
    if is_private:
        note.append(
            f"This network is in the RFC1918 private range ({network.exploded}). "
            + "The risk of these open resolvers being abused for amplification attacks is small, "
            + "as they are not directly accessible from the public internet."
        )
    else:
        note.append(
            f"This network is publicly routed ({network.exploded}). "
            + "The risk of these open resolvers being abused for DNS amplification attacks is HIGH, "
            + "as they are directly accessible from the public internet and could be used in large-scale DDoS attacks."
        )

    if cnt > 2:
        if is_private:
            note.append(
                "Although the risk of external abuse is low, it is still recommended to implement "
                + "DNS filtering and/or appropriate firewall rules to prevent internal unauthorized access."
            )
        else:
            note.append(
                "Make sure to implement DNS filtering and/or appropriate firewall "
                + "rules to prevent these devices from being abused for amplification attacks. "
                + "Consider restricting recursive queries to authorized clients only."
            )
    if cnt > 85:
        note.append(
            "Such a high number of open resolvers in a network can be a sign that "
            + "a router/firewall intercepts and responds to the DNS queries instead "
            + "of the clients in that network."
        )
    return ToolResult(
        success=True,
        output={
            "summary": note,
            "network": network.exploded,
            "is_private": is_private,
            "total_addresses": network.num_addresses,
            "open_resolver_count": cnt,
            "open_resolver_ip_list": open_res,
        },
        details={"open_resolver_details": open_res_details},
    )


async def scan_subnet_for_open_resolvers_impl(cidr: str, domain: str) -> ToolResult:
    """Perform a subnet wide scan for open resolvers.

    Args:
        cidr (str): The subnet to scan for open resolvers.
        domain (str): The domain to use for the DNS queries during the scan.

    Returns:
        ToolResult: Complete list of discovered open resolvers and more details.
    """
    return await detect_open_resolvers_in_subnet(
        cidr=cidr, domain=domain, timeout=2.0, concurrency=200
    )


# Example CLI runner
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Async Open Resolver Detector (custom Resolver)"
    )
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
