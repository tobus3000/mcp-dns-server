#!/usr/bin/env python3
"""Debug DS record validation"""

import sys

sys.path.insert(0, "src")

import dns.resolver

from tools.validator.dnssec import compute_ds_from_dnskey, validate_domain

# Test with dnssec.works
result = validate_domain("dnssec.works")

print("Parent DS Analysis:")
print(f"  Parent: {result['parent_ds']['parent']}")
print(f"  Parent DS Present: {result['parent_ds']['parent_ds_present']}")
print()

if result["parent_ds"].get("parent_ds_texts"):
    print("Parent DS Records:")
    for ds in result["parent_ds"]["parent_ds_texts"]:
        print(f"  {ds}")
else:
    print("No parent DS records found")

print()
print("Computed DS from DNSKEY:")
for algo, ds_list in result["parent_ds"].get("computed_ds", {}).items():
    print(f"  {algo}:")
    for ds in ds_list:
        print(f"    {ds}")

print()
print("Matches:")
for match in result["parent_ds"].get("matches", []):
    print(f"  Parent: {match['parent_ds'][:80]}...")
    print(f"  Computed: {match['matches_computed'][:80]}...")

print()
print("Validation Status:")
print(f"  Total DNSSEC Keys: {result['parent_ds']['dnskey_validation']['total_dnssec_keys']}")
print(f"  Validated Keys: {result['parent_ds']['dnskey_validation']['validated_keys']}")
if result["parent_ds"]["dnskey_validation"]["failed_validations"]:
    print("  Failed Validations:")
    for failure in result["parent_ds"]["dnskey_validation"]["failed_validations"]:
        print(f"    - {failure.get('error', str(failure))}")
