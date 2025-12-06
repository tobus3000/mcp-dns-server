#!/usr/bin/env python3
"""Debug DNSSEC signature issues"""

import sys

sys.path.insert(0, "src")

import dns.rdatatype
import dns.resolver

from resolver import Resolver
from tools.validator.dnssec import check_rrset_signature, validate_domain

zone = "dnssec.works"

# Get authoritative nameservers
resolver = Resolver()
ns_rrset, _ = resolver.resolve(zone, "NS")
print(f"Found {len(ns_rrset) if ns_rrset else 0} nameservers")

if ns_rrset:
    for ns in ns_rrset:
        print(f"  {ns.target}")

        # Get NS IP
        try:
            answers = dns.resolver.resolve(ns.target, "A")
            ns_ip = str(answers[0])
            print(f"    IP: {ns_ip}")

            # Try to fetch DNSKEY from this NS
            try:
                dnskey_rrset, dnskey_resp = resolver.fetch_dnskey(zone, nameserver=ns_ip)
                print(f"    DNSKEY: {len(dnskey_rrset) if dnskey_rrset else 0} records")

                if dnskey_resp:
                    # Check for RRSIG
                    print(
                        f"    Response sections: answer={len(dnskey_resp.answer)}, authority={len(dnskey_resp.authority)}"
                    )
                    for section in (dnskey_resp.answer, dnskey_resp.authority):
                        for rrset in section:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                print(
                                    f"    Found RRSIG in section (covers {rrset[0].type_covered})"
                                )
                            elif rrset.rdtype == dns.rdatatype.DNSKEY:
                                print(f"    Found DNSKEY rrset")
            except Exception as e:
                print(f"    Error fetching DNSKEY: {e}")
        except Exception as e:
            print(f"    Error resolving NS: {e}")
