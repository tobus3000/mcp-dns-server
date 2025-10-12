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

from typing import (
    Dict,
    Any,
    List,
    Optional,
    TypedDict
)
from dataclasses import dataclass, field
import dns.message
import dns.name
import dns.rdatatype

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
    qname: Optional[dns.name.Name] = None
    rdtype: Optional[dns.rdatatype.RdataType] = None
    response: Optional[dns.message.Message] = None
    error: Optional[str] = None
    rcode: Optional[int] = None
    rcode_text: Optional[str] = None
    duration: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ToolResult:
    """Stores the result of a DNS tool operation."""
    success: bool
    output: Optional[str|List[str]|Dict[str, Any]|List[Dict[str, Any]]] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

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
    errors: List[str]  # List of errors
    warnings: List[str]
    parameters: Optional[Dict[str, Any]]
    chain: List[Dict[str, Any]]
    validation: Dict[str, Any]

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
    error: Optional[str]
