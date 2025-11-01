"""A veeery simple and heuristic DNS Honeypot detection"""
#TODO: Add `detect_honeypot_dns` function to list of tools.
#TODO: Move module to `tools` sub-module.
import asyncio
import uuid
import ipaddress
from typing import List, Dict, Any
from statistics import median

try:
    from .resolver import Resolver
except ImportError:
    from resolver import Resolver

async def detect_honeypot_dns(
    resolver: Resolver,
    server: str,
    timeout: float = 3.0,
    random_queries: int = 6,
    known_domains: List[str] | None = None
) -> Dict[str, Any]:
    """
    Detect whether a DNS server is likely a honeypot/sinkhole based on heuristics,
    using the provided Resolver instance.

    Parameters
    ----------
    resolver : Resolver
        Your existing Resolver instance.
    server : str
        IP address of the DNS server to test.
    timeout : float
        Timeout per query.
    random_queries : int
        Number of random domains to query for wildcard/sinkhole detection.
    known_domains : list[str] | None
        Well-known domains for baseline resolution.

    Returns
    -------
    dict : containing:
      - score: float (0.0 - 1.0)
      - verdict: str ("likely", "possible", "unlikely")
      - evidence: list[str]
      - details: per-query data
    """

    if known_domains is None:
        known_domains = ["example.com", "iana.org", "google.com"]

    evidence = []
    details = []
    heuristics = {
        "wildcard": 0.0,
        "private_ip": 0.0,
        "same_ip_legit": 0.0,
        "no_authority": 0.0,
        "fast_response": 0.0,
    }

    # Helper: extract IPs from QueryResult.response
    def extract_ips(response):
        ips = []
        if not response or not response.answer:
            return ips
        for rrset in response.answer:
            if rrset.rdtype in (1, 28):  # A / AAAA
                for rr in rrset:
                    ips.append(str(rr.address))
        return ips

    # Helper: classify IPs
    def suspicious_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                return True
        except ValueError:
            pass
        return False

    # 1️⃣ Known domains (legitimate)
    legit_ips = []
    legit_results = []
    for dom in known_domains:
        q = await resolver.async_resolve(dom, "A", nameserver=server, timeout=timeout)
        details.append({
            "query": dom,
            "success": q.success,
            "rcode": getattr(q, "rcode_text", None),
            "ips": extract_ips(q.response),
            "duration": getattr(q, "duration", None),
        })
        if q.success and q.response:
            legit_ips.extend(extract_ips(q.response))
            legit_results.append(q)

    # 2️⃣ Random domains (nonexistent)
    random_ips = []
    random_results = []
    for _ in range(random_queries):
        rnd = f"{uuid.uuid4().hex[:10]}.invalid-test-{uuid.uuid4().hex[:6]}.com"
        q = await resolver.async_resolve(rnd, "A", nameserver=server, timeout=timeout)
        details.append({
            "query": rnd,
            "success": q.success,
            "rcode": getattr(q, "rcode_text", None),
            "ips": extract_ips(q.response),
            "duration": getattr(q, "duration", None),
        })
        if q.success and q.response:
            ips = extract_ips(q.response)
            random_ips.extend(ips)
            random_results.append(q)

    # Heuristic A: Wildcard detection
    if random_ips:
        from collections import Counter
        counts = Counter(random_ips)
        most_common_ip, count = counts.most_common(1)[0]
        proportion = count / len(random_ips)
        heuristics["wildcard"] = proportion
        if proportion > 0.6:
            evidence.append(
                f"Wildcard/sinkhole behavior: {most_common_ip} appeared in {count}/{len(random_ips)} random queries ({proportion:.0%})."
            )

    # Heuristic B: Suspicious IPs (private / loopback)
    all_ips = legit_ips + random_ips
    if all_ips:
        suspicious_count = sum(1 for ip in all_ips if suspicious_ip(ip))
        heuristics["private_ip"] = suspicious_count / len(all_ips)
        if suspicious_count:
            evidence.append(f"Returned {suspicious_count}/{len(all_ips)} private/loopback/reserved IPs.")

    # Heuristic C: Legitimate domains resolving to same IP
    if legit_ips:
        from collections import Counter
        cnt = Counter(legit_ips)
        most_common, freq = cnt.most_common(1)[0]
        heuristics["same_ip_legit"] = freq / len(legit_ips)
        if heuristics["same_ip_legit"] >= 0.6:
            evidence.append(f"Multiple legitimate domains resolve to {most_common} ({freq}/{len(legit_ips)}).")

    # Heuristic D: Missing authoritative answers (AA flag)
    aa_count = 0
    total_count = 0
    for q in legit_results + random_results:
        if q.success and q.response:
            total_count += 1
            if q.response.flags & 0x0400:  # dns.flags.AA
                aa_count += 1
    if total_count > 0 and aa_count == 0:
        heuristics["no_authority"] = 0.5
        evidence.append("No responses contained the AA (Authoritative Answer) flag.")

    # Heuristic E: Fast responses (may indicate synthetic or local sinkhole)
    rtts = [q.duration for q in legit_results + random_results if q.success and q.duration]
    if rtts:
        med_rtt = median(rtts)
        if med_rtt < 0.01:
            heuristics["fast_response"] = 0.5
            evidence.append(
                f"Very fast median response ({med_rtt*1000:.1f} ms) - possibly synthetic responses."
            )

    # Combine weighted score
    weights = {
        "wildcard": 0.35,
        "private_ip": 0.25,
        "same_ip_legit": 0.20,
        "no_authority": 0.10,
        "fast_response": 0.10,
    }
    score = sum(heuristics[h] * weights[h] for h in heuristics)
    verdict = (
        "likely" if score >= 0.6 else
        "possible" if score >= 0.35 else
        "unlikely"
    )

    if not evidence:
        evidence.append("No strong anomalies detected.")

    return {
        "server": server,
        "score": round(score, 3),
        "verdict": verdict,
        "heuristics": heuristics,
        "evidence": evidence,
        "details": details,
    }




if __name__ == "__main__":
    import argparse
    
    async def main(res):
        r = Resolver()
        result = await detect_honeypot_dns(r, res)
        import json
        print(json.dumps(result, indent=2))

    parser = argparse.ArgumentParser(description="Async Honeypot Detector (custom Resolver)")
    parser.add_argument("resolver", help="DNS resolver to scan, e.g. 192.168.1.1")
    args = parser.parse_args()
    asyncio.run(main(args.resolver))
