#!/usr/bin/env python3
"""Quick test of DNSSEC validation fix"""

import sys

sys.path.insert(0, "src")

import json

from tools.validator.dnssec import validate_domain

# Test with dnssec.works
result = validate_domain("dnssec.works")

# Print key validation results
print("=== DNSSEC Validation Results for dnssec.works ===")
print()
print("1. DNSKEY Records:")
print("   Present:", result["dnskey"]["present"])
print("   Count:", result["dnskey"]["count"])
print()

print("2. Trust Chain (DS validation):")
print("   Parent DS Present:", result["parent_ds"]["parent_ds_present"])
print("   Matches:", len(result["parent_ds"].get("matches", [])))
print()

print("3. DNSKEY Signature:")
print("   Present:", result["dnskey_signature"]["present"])
print("   Valid:", result["dnskey_signature"]["valid"])
print()

print("4. Record Validations:")
for rr_type in ["SOA", "NS", "A"]:
    status = "valid" if result["rrsets"][rr_type].get("valid") else "invalid/missing"
    print(f"   {rr_type}: {status}")
print()

print("5. Authoritative Nameservers:")
for ns, details in result["authoritative"].items():
    if isinstance(details, dict) and "dnskey_count" in details:
        print(f'   {ns}: {details.get("dnskey_count", 0)} DNSKEYs')
print()

print("6. Key Summary:")
keys_info = result.get("keys", {})
print(f'   SEP Keys (KSK): {keys_info.get("sep_count", 0)}')
print(f'   ZSK Keys: {keys_info.get("zsk_count", 0)}')
print(f'   Algorithms: {keys_info.get("algorithms", [])}')
