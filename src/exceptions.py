"""Exception handling and error processing for DNS operations.

This module provides custom exception types and error handling utilities for DNS
operations in the Model Context Protocol (MCP) server. It includes functionality
for converting low-level DNS exceptions into user-friendly error messages and
standardizing error handling across the application.

The module serves three main purposes:
1. Define custom exceptions specific to DNS validation operations
2. Provide consistent error message formatting for DNS-related errors
3. Map various DNS library exceptions to human-readable messages

Note: This module works closely with the dnspython library's exception hierarchy
and provides a unified interface for error handling across the MCP server.
"""

import dns.exception
import dns.name
import dns.resolver

class ValidationError(Exception):
    """Base exception for DNSSEC validation errors."""

def handle_dns_error(error: Exception) -> str:
    """Convert DNS-related exceptions to descriptive error messages."""
    err_str = f"Unexpected error: {str(error)}"
    if isinstance(error, dns.resolver.NXDOMAIN):
        err_str = "Domain name does not exist"
    if isinstance(error, dns.resolver.NoAnswer):
        err_str = "No answer received from server"
    if isinstance(error, dns.resolver.NoNameservers):
        err_str = "No DNS servers responded"
    if isinstance(error, dns.name.LabelTooLong):
        err_str = "Domain name label too long"
    if isinstance(error, dns.name.BadLabelType):
        err_str = "Invalid characters in domain name"
    if isinstance(error, dns.exception.Timeout):
        err_str = "DNS query timed out"
    if str(error.__class__).endswith('ValidationFailure'):
        err_str = f"DNSSEC validation failed: {str(error)}"
    if isinstance(error, dns.exception.DNSException):
        err_str = f"DNS error: {str(error)}"
    return err_str
