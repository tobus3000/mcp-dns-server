"""Type definitions for DNS and DNSSEC validation operations.

This module provides TypedDict classes that define structured result types used
throughout the DNS Model Context Protocol (MCP) server implementation. These type
definitions ensure consistent data structures for validation results, test outcomes,
and other operational data.

The types defined here are used to:
- Structure DNSSEC validation results
- Format security test outcomes
- Maintain consistent error and warning reporting
- Document expected data shapes for API consumers

Note: TypedDict classes are used instead of regular dictionaries to provide better
type checking and IDE support while maintaining runtime flexibility.
"""

from dataclasses import dataclass, field
from typing import Any, TypedDict

import dns.message
import dns.name
import dns.rdatatype
import dns.zone


@dataclass
class QueryResult:
    """Stores the result of a DNS query test.
    details:
        'flags': response.flags,
        'answer_count': len(response.answer),
        'authority_count': len(response.authority),
        'additional_count': len(response.additional),
        'has_edns': response.edns >= 0,
        'is_truncated': bool(response.flags & dns.flags.TC)
    """

    success: bool
    qname: dns.name.Name | None = None
    rdtype: dns.rdatatype.RdataType | None = None
    response: dns.message.Message | None = None
    error: str | None = None
    rcode: int | None = None
    rcode_text: str | None = None
    duration: float | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AXFRResult:
    """Stores the result of a AXFR zone transfer operation."""

    success: bool
    zone_name: str
    nameserver: str
    response: dns.zone.Zone | None = None
    error: str | None = None
    rcode: int | None = None
    rcode_text: str | None = None
    duration: float | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Stores the result of a DNS tool operation."""

    success: bool
    output: str | list[str] | dict[str, Any] | list[dict[str, Any]] | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class OpenResolver:
    """Stores the details of a Open Resolver."""

    success: bool
    ip: str
    rcode: int | None = None
    rcode_text: str | None = None
    duration: float | None = None
    details: dict[str, Any] = field(default_factory=dict)


# Type definitions for result dictionaries
class ValidationResult(TypedDict, total=False):
    """A TypedDict representing the result of a DNSSEC validation operation.

    This class defines the structure for validation results, particularly for DNSSEC
    chain validations (NSEC/NSEC3) and other security-related checks.

    Attributes:
        valid (bool): Whether the validation passed successfully.
        error (str): A single error message if validation failed.
        errors (List[str]): Collection of error messages from validation process.
        warnings (List[str]): Non-critical issues found during validation.
        parameters (Optional[Dict[str, Any]]): Configuration parameters used in validation.
        chain (List[Dict[str, Any]]): Validation chain details (e.g., NSEC/NSEC3 chain).
        validation (Dict[str, Any]): Additional validation-specific details and metadata.
    """

    valid: bool
    error: str  # Single error string
    errors: list[str]  # List of errors
    warnings: list[str]
    parameters: dict[str, Any] | None
    chain: list[dict[str, Any]]
    validation: dict[str, Any]


class TestResult(TypedDict):
    """A TypedDict representing the result of a DNS robustness or security test.

    This class defines the structure for individual test results when performing
    DNS server robustness checks, security validations, or other diagnostic tests.

    Attributes:
        name (str): Unique identifier or name of the test.
        description (str): Human-readable description of what the test checks.
        passed (bool): Whether the test passed successfully.
        error (Optional[str]): Error message if the test failed, None otherwise.
    """

    name: str
    description: str
    passed: bool
    error: str | None


@dataclass
class UserDecision:
    """Used in elicit workflow where a user needs to provide consent."""

    answer: str
