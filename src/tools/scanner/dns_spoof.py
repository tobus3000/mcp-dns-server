import asyncio
import time
from scapy.all import IP, UDP, DNS, DNSQR, sr1, AsyncSniffer, ICMP, Ether, ARP, get_if_hwaddr, conf
from typedefs import ToolResult

async def detect_dns_spoof_async(
    target_dns_ip: str,
    domain: str = "intercept-test.example.com",
    router_mac: str | None = None,
    expected_answer: str | None = None,
    timeout: int = 2,
    iface: str | None = None
) -> ToolResult:
    """
    Detect DNS interception/spoofing including MAC-level fingerprinting.
    
    Args:
        target_dns_ip: IP of DNS server we intend to query (possibly in another VLAN)
        router_mac: MAC address of UDM Pro or local router to detect spoofing
        test_domain: domain to test
        expected_answer: expected resolved IP (optional)
        timeout: timeout in seconds
        iface: network interface to use for sniffing
    """
    pkt = IP(dst=target_dns_ip) / UDP(sport=55555, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))

    # Measure normal ICMP hop distance to target
    icmp_ttl = None
    try:
        icmp_pkt = IP(dst=target_dns_ip) / ICMP()
        icmp_resp = sr1(icmp_pkt, verbose=0, timeout=timeout)
        if icmp_resp:
            icmp_ttl = icmp_resp.ttl
    except PermissionError:
        pass  # ICMP may need root

    response_container = {}

    def handle_packet(packet):
        if packet.haslayer(DNS) and packet[DNS].id == pkt[DNS].id:
            response_container["packet"] = packet
            return True

    sniffer = AsyncSniffer(filter=f"udp port 53", prn=handle_packet, store=False, iface=iface)
    sniffer.start()

    start = time.time()
    try:
        await asyncio.to_thread(sr1, pkt, verbose=0, timeout=timeout)
        await asyncio.sleep(timeout)
    finally:
        sniffer.stop()

    resp = response_container.get("packet")
    if not resp:
        return ToolResult(
            success=False,
            error="No DNS response received.",
            details={}
        )

    observed_server = resp[IP].src
    observed_ttl = resp[IP].ttl
    rtt = (time.time() - start) * 1000  # ms
    answer = None
    observed_mac = resp[Ether].src if resp.haslayer(Ether) else None

    if resp.haslayer(DNS) and resp[DNS].an:
        answer = resp[DNS].an.rdata

    tampered = False
    notes = []

    # TTL anomaly check
    if icmp_ttl is not None and abs(observed_ttl - icmp_ttl) > 2:
        tampered = True
        notes.append(
            f"TTL mismatch: DNS reply TTL={observed_ttl}, ICMP TTL={icmp_ttl}. "
            + "Possible local spoof."
        )

    # Latency check
    if rtt < 5:
        tampered = True
        notes.append(f"Suspiciously fast reply ({rtt:.1f} ms) — likely intercepted locally.")

    # MAC-level check
    if router_mac:
        if observed_mac and observed_mac.lower() == router_mac.lower():
            tampered = True
            notes.append(f"Reply MAC matches local router ({observed_mac}) — spoofing detected.")

    # Answer check
    if expected_answer and str(answer) != expected_answer:
        tampered = True
        notes.append(f"Answer mismatch: got {answer}, expected {expected_answer}.")

    return ToolResult(
        success=True,
        output={
            "observed_server": observed_server,
            "tampered": tampered,
            "notes": " ".join(notes) if notes else "No anomalies detected."
        },
        details={
            "domain": domain,
            "observed_mac": observed_mac,
            "answer": str(answer),
            "ttl": observed_ttl,
            "rtt_ms": round(rtt, 2)
        }
    )

async def scan_server_for_dns_spoofing_impl(nameserver: str, domain: str, router_mac: str | None = None) -> ToolResult:
    """Detect DNS interception/spoofing including MAC-level fingerprinting.
    
    Args:
        nameserver (str): The nameserver IP to be tested.
        domain (str): The domain to use for the spoofing detection.
        router_mac (str): The MAC address of the default gateway (or L3 router).
        
    Returns:
        ToolResult: Complete report of the spoofing detection operation.
    """
    return await detect_dns_spoof_async(
        target_dns_ip=nameserver,
        domain=domain,
        router_mac=router_mac        
    )

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Async DNS Interception Detector")
    parser.add_argument("ip", help="The DNS server IP we want to test.")
    parser.add_argument("domain", help="The domain name we use for testing.")
    args = parser.parse_args()

    async def main():
        result = await detect_dns_spoof_async(args.ip, args.domain)
        print(result)

    asyncio.run(main())
