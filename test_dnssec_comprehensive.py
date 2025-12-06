#!/usr/bin/env python3
"""Comprehensive DNSSEC validation test"""

import sys

sys.path.insert(0, "src")

import json

from tools.validator.dnssec import interpret_validation_results, validate_domain

# Test with dnssec.works
print("=== Validating dnssec.works ===\n")
result = validate_domain("dnssec.works")

# Generate interpretation
interp = interpret_validation_results(result)

# Print summary
print("DNSSEC Status:", interp["summary"]["overall_status"])
print()

# Print key configuration
print("Key Configuration:")
for status_line in interp["key_configuration"]["status"]:
    print(f"  • {status_line}")
print()

# Print trust chain
print("Trust Chain (Chain of Trust):")
for status_line in interp["trust_chain"]["status"]:
    print(f"  • {status_line}")
print()

# Print validation details
print("Record Validation:")
if interp["validation_details"]["status"]:
    for status_line in interp["validation_details"]["status"]:
        print(f"  • {status_line}")
else:
    print("  No records validated")
print()

# Print recommendations
if interp["recommendations"]:
    print("Recommendations:")
    for rec in interp["recommendations"]:
        print(f"  ✓ {rec}")
else:
    print("✓ All checks passed - DNSSEC is properly configured!")
