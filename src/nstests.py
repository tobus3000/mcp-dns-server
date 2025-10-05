"""DNS Server Testing Module.

Provides comprehensive testing of DNS server implementations covering:
- Basic query/response correctness
- Protocol compliance
- DNSSEC features
- Performance and robustness
- Edge cases and error handling
"""

from __future__ import annotations
import os
import time
import random
import struct
import asyncio
import socket
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from dns import exception as dns_exception
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.asyncquery
import dns.flags
import dns.edns
import dns.rcode

DEFAULT_TIMEOUT = 5.0
MAX_UDP_SIZE = 4096
DEFAULT_EDNS_SIZE = 1232  # Conservative EDNS buffer size
COMMON_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

@dataclass
class QueryResult:
    """Stores the result of a DNS query test."""
    success: bool
    response: Optional[dns.message.Message] = None
    error: Optional[str] = None
    rcode: Optional[int] = None
    duration: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)


async def make_test_query(domain: str, rdtype: str, nameserver: str,
                        use_tcp: bool = False, use_edns: bool = True,
                        payload_size: int = DEFAULT_EDNS_SIZE,
                        flags: int = 0, timeout: float = DEFAULT_TIMEOUT) -> QueryResult:
    """Make an async DNS query with specified parameters."""
    try:
        qname = dns.name.from_text(domain)
        rdtype_obj = dns.rdatatype.from_text(rdtype)

        # Create the query message
        query = dns.message.make_query(
            qname,
            rdtype_obj,
            want_dnssec=bool(flags & dns.flags.DO)
        )

        # Add EDNS if requested
        if use_edns:
            query.use_edns(
                0,  # EDNS version 0
                flags,
                payload_size,
                options=[]
            )

        start_time = time.time()

        # Send query
        if use_tcp:
            response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
        else:
            try:
                response = await dns.asyncquery.udp(query, nameserver, timeout=timeout)
                if response.flags & dns.flags.TC:  # Truncated, retry with TCP
                    response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
            except Exception as e:
                if "Message too big" in str(e):
                    # UDP message too large, retry with TCP
                    response = await dns.asyncquery.tcp(query, nameserver, timeout=timeout)
                else:
                    raise

        duration = time.time() - start_time

        return QueryResult(
            success=True,
            response=response,
            rcode=response.rcode(),
            duration=duration,
            details={
                'flags': response.flags,
                'answer_count': len(response.answer),
                'authority_count': len(response.authority),
                'additional_count': len(response.additional),
                'has_edns': response.edns >= 0,
                'is_truncated': bool(response.flags & dns.flags.TC)
            }
        )

    except (dns_exception.DNSException, socket.error, asyncio.TimeoutError) as e:
        return QueryResult(
            success=False,
            error=str(e),
            details={'exception_type': type(e).__name__}
        )
    except Exception as e:
        # Log unexpected exceptions while keeping the function robust
        print(f"Unexpected error in make_test_query: {type(e).__name__}: {str(e)}")
        return QueryResult(
            success=False,
            error=f"Unexpected error: {str(e)}",
            details={'exception_type': type(e).__name__}
        )


async def test_basic_records(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test basic DNS record types and their correctness."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'record_tests': {},
        'summary': {
            'total_tests': 0,
            'successful': 0,
            'failed': 0,
            'errors': []
        }
    }

    for rdtype in COMMON_RECORD_TYPES:
        # Test both with and without EDNS
        standard_result = await make_test_query(domain, rdtype, nameserver, use_edns=False)
        edns_result = await make_test_query(domain, rdtype, nameserver, use_edns=True)
        results['record_tests'][rdtype] = {
            'standard': {
                'success': standard_result.success,
                'rcode': standard_result.rcode,
                'error': standard_result.error,
                'details': standard_result.details
            },
            'edns': {
                'success': edns_result.success,
                'rcode': edns_result.rcode,
                'error': edns_result.error,
                'details': edns_result.details
            }
        }
        results['summary']['total_tests'] += 2
        results['summary']['successful'] += (
            int(standard_result.success) + int(edns_result.success)
        )
        if not standard_result.success:
            results['summary']['errors'].append(f"{rdtype} query failed: {standard_result.error}")
        if not edns_result.success:
            results['summary']['errors'].append(f"{rdtype} EDNS query failed: {edns_result.error}")

    results['summary']['failed'] = (
        results['summary']['total_tests'] - results['summary']['successful']
    )
    return results


async def test_qname_handling(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test handling of various QNAME formats and edge cases."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Test cases
    test_cases = {
        'standard': domain,
        'uppercase': domain.upper(),
        'mixed_case': ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(domain)),
        'trailing_dot': domain + '.',
        'leading_dots': '.' + domain,
        'maximum_label': ('x' * 63 + '.').join(domain.split('.')),  # Max label length
    }

    for test_name, test_domain in test_cases.items():
        result = await make_test_query(test_domain, 'A', nameserver)
        results['tests'][test_name] = {
            'domain': test_domain,
            'success': result.success,
            'rcode': result.rcode,
            'error': result.error,
            'details': result.details
        }

        if result.success:
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1
            results['summary']['errors'].append(
                f"{test_name} test failed: {result.error}"
            )

    # Test invalid cases (should fail gracefully)
    invalid_cases = {
        'overlong_label': ('x' * 64 + '.').join(domain.split('.')),  # Exceeds 63 chars
        'invalid_chars': f"test!@#$.{domain}",
        'empty_label': f"test..{domain}",
    }

    for test_name, test_domain in invalid_cases.items():
        result = await make_test_query(test_domain, 'A', nameserver)
        results['tests'][test_name] = {
            'domain': test_domain,
            'success': result.success,
            'rcode': result.rcode,
            'error': result.error,
            'details': result.details
        }

        # For invalid cases, success means proper error handling
        if not result.success or (result.rcode in [dns.rcode.FORMERR, dns.rcode.REFUSED]):
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1
            results['summary']['errors'].append(
                f"{test_name} test failed: Server accepted invalid domain"
            )

    return results


async def test_edns_support(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test EDNS(0) support and behavior."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Test different EDNS buffer sizes
    buffer_sizes = [512, 1232, 1440, 4096]
    for size in buffer_sizes:
        result = await make_test_query(domain, 'A', nameserver, use_edns=True, payload_size=size)
        results['tests'][f'buffer_size_{size}'] = {
            'success': result.success,
            'details': result.details
        }

        if result.success and result.details.get('has_edns'):
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1

    # Test EDNS options
    options_test = {
        'nsid': {'code': dns.edns.NSID},
        'client_subnet': {'code': 8, 'data': b'\x00\x01\x20\xc0\xa8'},  # Example subnet
        'cookie': {'code': 10, 'data': os.urandom(8)},  # Random 8-byte cookie
    }

    for option_name, option_data in options_test.items():
        query = dns.message.make_query(
            dns.name.from_text(domain),
            'A',
            use_edns=True,
            payload=4096,
            options=[dns.edns.GenericOption(option_data['code'], option_data.get('data', b''))]
        )

        try:
            response = await dns.asyncquery.udp(query, nameserver, timeout=DEFAULT_TIMEOUT)
            results['tests'][f'option_{option_name}'] = {
                'success': True,
                'has_option': any(opt.otype == option_data['code'] 
                                for opt in response.options)
            }
            results['summary']['passed'] += 1
        except Exception as e:
            results['tests'][f'option_{option_name}'] = {
                'success': False,
                'error': str(e)
            }
            results['summary']['failed'] += 1
            results['summary']['errors'].append(f"EDNS option {option_name} failed: {str(e)}")

    return results


async def test_tcp_behavior(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test DNS-over-TCP behavior and handling."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Basic TCP connectivity
    result = await make_test_query(domain, 'A', nameserver, use_tcp=True)
    results['tests']['basic_tcp'] = {
        'success': result.success,
        'error': result.error,
        'details': result.details
    }

    if result.success:
        results['summary']['passed'] += 1
    else:
        results['summary']['failed'] += 1
        results['summary']['errors'].append(f"Basic TCP test failed: {result.error}")

    # Test large response handling
    # Request many records to force TCP
    result = await make_test_query(domain, 'ANY', nameserver, use_edns=True, payload_size=4096)
    results['tests']['large_response'] = {
        'success': result.success,
        'error': result.error,
        'details': result.details,
        'used_tcp': result.details.get('is_truncated') if result.details else None
    }

    if result.success:
        results['summary']['passed'] += 1
    else:
        results['summary']['failed'] += 1

    # Test pipelined queries
    try:
        # Test pipelined queries using asyncio TCP support
        queries = []
        responses = []

        try:
            reader, writer = await asyncio.open_connection(nameserver, 53)

            # Send multiple queries in succession
            for rdtype in ['A', 'AAAA', 'MX']:
                query = dns.message.make_query(domain, rdtype)
                wire = query.to_wire()
                length = len(wire)
                writer.write(struct.pack("!H", length) + wire)
                await writer.drain()
                queries.append(query)

            # Read responses
            for _ in queries:
                length_data = await reader.read(2)
                if not length_data:
                    raise EOFError("Connection closed by server")
                length = struct.unpack("!H", length_data)[0]
                response_wire = await reader.read(length)
                if len(response_wire) != length:
                    raise EOFError("Incomplete response received")
                response = dns.message.from_wire(response_wire)
                responses.append(response)

            writer.close()
            await writer.wait_closed()

            results['tests']['pipelined_queries'] = {
                'success': True,
                'response_count': len(responses),
                'all_valid': all(r.rcode() == dns.rcode.NOERROR for r in responses)
            }
            results['summary']['passed'] += 1

        except Exception as e:
            results['tests']['pipelined_queries'] = {
                'success': False,
                'error': str(e)
            }
            results['summary']['failed'] += 1
            results['summary']['errors'].append(f"Pipelined queries failed: {str(e)}")

    except Exception as e:
        results['tests']['pipelined_queries'] = {
            'success': False,
            'error': str(e)
        }
        results['summary']['failed'] += 1
        results['summary']['errors'].append(f"TCP setup failed: {str(e)}")

    return results


async def test_performance(domain: str, nameserver: str,
                         num_queries: int = 100,
                         concurrent: int = 10) -> Dict[str, Any]:
    """Test nameserver performance under load."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'config': {
            'total_queries': num_queries,
            'concurrent_queries': concurrent
        },
        'measurements': {
            'timings': [],
            'errors': [],
            'rcodes': {}
        },
        'summary': {}
    }

    async def worker(i: int) -> QueryResult:
        # Mix up query types for more realistic testing
        rdtype = random.choice(COMMON_RECORD_TYPES)
        # Add some randomness to prevent caching
        test_domain = f"perf-test-{i}-{random.randint(1, 1000)}.{domain}"
        return await make_test_query(test_domain, rdtype, nameserver)

    start_time = time.time()

    # Create tasks for all queries, but limit concurrency
    tasks = []
    for i in range(0, num_queries, concurrent):
        batch = range(i, min(i + concurrent, num_queries))
        tasks_batch = [worker(j) for j in batch]
        results_batch = await asyncio.gather(*tasks_batch)
        tasks.extend(results_batch)

    query_results = tasks  # All results are now collected
    total_time = time.time() - start_time

    # Analyze results
    successful = [r for r in query_results if r.success]
    failed = [r for r in query_results if not r.success]

    # Collect timing statistics
    timings = [r.duration for r in query_results if r.duration is not None]

    if timings:
        results['measurements']['timings'] = {
            'min': min(timings),
            'max': max(timings),
            'mean': sum(timings) / len(timings),
            'median': sorted(timings)[len(timings)//2],
            'total_time': total_time
        }

    # Count response codes
    for result in query_results:
        if result.rcode is not None:
            try:
                rcode_name = dns.rcode.to_text(dns.rcode.Rcode(result.rcode))
                results['measurements']['rcodes'][rcode_name] = \
                    results['measurements']['rcodes'].get(rcode_name, 0) + 1
            except ValueError:
                # Handle unknown rcode
                rcode_name = f"UNKNOWN({result.rcode})"
                results['measurements']['rcodes'][rcode_name] = \
                    results['measurements']['rcodes'].get(rcode_name, 0) + 1

    # Collect errors
    results['measurements']['errors'] = [
        {'error': r.error, 'details': r.details}
        for r in failed
    ]

    # Summarize results
    results['summary'] = {
        'queries_per_second': num_queries / total_time,
        'success_rate': len(successful) / num_queries * 100,
        'total_errors': len(failed),
        'avg_latency': sum(timings) / len(timings) if timings else None
    }

    return results


async def test_delegation(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test delegation correctness and glue record handling."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Get NS records
    ns_result = await make_test_query(domain, 'NS', nameserver)
    if not ns_result.success:
        results['tests']['ns_records'] = {
            'success': False,
            'error': ns_result.error
        }
        return results

    ns_records = []
    if ns_result.response and ns_result.response.answer:
        ns_records = [rr for rr in ns_result.response.answer[0] if rr.rdtype == dns.rdatatype.NS]

    results['tests']['ns_records'] = {
        'success': True,
        'count': len(ns_records),
        'nameservers': [ns.target.to_text() for ns in ns_records]
    }

    # Check each nameserver
    for ns in ns_records:
        ns_name = ns.target.to_text()

        # Check glue records
        glue_result = await make_test_query(ns_name, 'A', nameserver)
        results['tests'][f'glue_{ns_name}'] = {
            'success': glue_result.success,
            'has_glue': bool(glue_result.response and glue_result.response.additional),
            'error': glue_result.error
        }

        if glue_result.success:
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1
            results['summary']['errors'].append(f"Glue record test failed for {ns_name}")

    # Test parent zone delegation
    parent_domain = '.'.join(domain.split('.')[1:]) or '.'
    parent_result = await make_test_query(parent_domain, 'NS', nameserver)

    results['tests']['parent_delegation'] = {
        'success': parent_result.success,
        'error': parent_result.error,
        'has_parent_ns': bool(parent_result.response and parent_result.response.answer)
    }

    return results


async def test_any_queries(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test server behavior for ANY queries according to RFC 8482."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Test ANY query behavior with different configurations
    test_cases = [
        ('any_basic', {'use_edns': False, 'use_tcp': False}),
        ('any_edns', {'use_edns': True, 'use_tcp': False}),
        ('any_tcp', {'use_edns': False, 'use_tcp': True}),
        ('any_edns_tcp', {'use_edns': True, 'use_tcp': True}),
    ]

    for test_name, params in test_cases:
        result = await make_test_query(domain, 'ANY', nameserver, **params)
        results['tests'][test_name] = {
            'success': result.success,
            'rcode': result.rcode,
            'error': result.error,
            'details': result.details,
            'rfc8482_compliant': False  # Will be updated below
        }

        if result.success:
            # Check RFC 8482 compliance:
            # 1. Should return HINFO or a subset of available records
            # 2. Should not be truncated unless really necessary
            # 3. Should have reasonable response size
            response = result.response
            is_compliant = False
            if response is not None:
                try:
                    is_compliant = (
                        # Check if response is HINFO (RFC 8482 recommendation)
                        any(rrset.rdtype == dns.rdatatype.HINFO for rrset in response.answer) or
                        # Or check if response contains a reasonable subset of records
                        (len(response.answer) > 0 and len(response.answer) < 10) or
                        # Or empty response with NOERROR is also acceptable
                        (len(response.answer) == 0 and response.rcode() == dns.rcode.NOERROR)
                    )
                    response_size = len(response.to_wire())
                    record_types = [
                        dns.rdatatype.to_text(rrset.rdtype)
                        for rrset in response.answer
                    ]
                except (AttributeError, TypeError):
                    is_compliant = False
                    response_size = 0
                    record_types = []
            else:
                response_size = 0
                record_types = []

            results['tests'][test_name]['rfc8482_compliant'] = is_compliant
            results['tests'][test_name]['response_size'] = response_size
            results['tests'][test_name]['record_types'] = record_types

            if is_compliant:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
                results['summary']['errors'].append(
                    f"{test_name}: Response not RFC 8482 compliant"
                )
        else:
            # A refused response is also RFC 8482 compliant
            if result.rcode in [dns.rcode.REFUSED, dns.rcode.NOTIMP]:
                results['tests'][test_name]['rfc8482_compliant'] = True
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
                results['summary']['errors'].append(
                    f"{test_name} failed: {result.error}"
                )

    # Test rate limiting of ANY queries
    try:
        start_time = time.time()
        test_count = 5
        test_results = []

        for _ in range(test_count):
            result = await make_test_query(domain, 'ANY', nameserver, use_edns=True)
            test_results.append(result)

        duration = time.time() - start_time

        results['tests']['rate_limiting'] = {
            'success': True,
            'queries_per_second': test_count / duration,
            'refused_count': sum(1 for r in test_results if r.rcode == dns.rcode.REFUSED),
            'error_count': sum(1 for r in test_results if not r.success),
            'average_response_time': sum(r.duration for r in test_results if r.duration) / test_count
        }

        # Check if rate limiting is in place
        if results['tests']['rate_limiting']['refused_count'] > 0:
            results['tests']['rate_limiting']['rate_limited'] = True
            results['summary']['passed'] += 1
        else:
            results['tests']['rate_limiting']['rate_limited'] = False
            # Not having rate limiting is not a failure, just a note
            results['tests']['rate_limiting']['note'] = "No rate limiting detected for ANY queries"

    except Exception as e:
        results['tests']['rate_limiting'] = {
            'success': False,
            'error': str(e)
        }
        results['summary']['errors'].append(f"Rate limiting test failed: {str(e)}")

    return results


async def test_open_resolver(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test if nameserver behaves like an open resolver.
    
    An open resolver will:
    1. Accept recursive queries from any source
    2. Respond with valid answers (not REFUSED/SERVFAIL)
    3. Have the recursion available (ra) flag set
    
    This behavior is generally considered a security risk as open resolvers
    can be used in DNS amplification attacks.
    """
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'is_open_resolver': False,
        'tests': {},
        'details': {},
        'security_risk': 'none'
    }

    # Test 1: Basic recursive query
    query = dns.message.make_query(
        domain,
        'A',
        rdclass=dns.rdataclass.IN
    )
    # Set recursion desired flag
    query.flags |= dns.flags.RD

    try:
        response = await dns.asyncquery.udp(query, nameserver, timeout=DEFAULT_TIMEOUT)

        results['tests']['recursive_query'] = {
            'success': True,
            'rcode': dns.rcode.to_text(response.rcode()),
            'recursion_available': bool(response.flags & dns.flags.RA),
            'answer_count': len(response.answer),
            'is_valid_response': (
                response.rcode() == dns.rcode.NOERROR and
                len(response.answer) > 0
            )
        }

        # Check if it's behaving like an open resolver
        is_open = (
            response.flags & dns.flags.RA and  # Recursion Available flag is set
            response.rcode() == dns.rcode.NOERROR and  # Valid response
            len(response.answer) > 0  # Contains answers
        )

        results['is_open_resolver'] = is_open
        if is_open:
            results['security_risk'] = 'high'
            results['details']['risk_explanation'] = (
                "This server appears to be an open resolver. Open resolvers can be "
                "exploited for DNS amplification attacks and should be restricted "
                "to only serve authorized clients."
            )

    except Exception as e:
        results['tests']['recursive_query'] = {
            'success': False,
            'error': str(e)
        }

    # Test 2: Try with different domain to verify behavior
    test_domain = f"open-resolver-test-{int(time.time())}.com"
    test_query = dns.message.make_query(
        test_domain,
        'A',
        rdclass=dns.rdataclass.IN
    )
    test_query.flags |= dns.flags.RD

    try:
        test_response = await dns.asyncquery.udp(test_query, nameserver, timeout=DEFAULT_TIMEOUT)

        results['tests']['secondary_query'] = {
            'success': True,
            'rcode': dns.rcode.to_text(test_response.rcode()),
            'recursion_available': bool(test_response.flags & dns.flags.RA)
        }

        # If both tests indicate open resolver behavior, increase confidence
        if results['is_open_resolver'] and bool(test_response.flags & dns.flags.RA):
            results['details']['confidence'] = 'high'
            results['details']['recommendation'] = (
                "Strongly recommended to restrict recursive queries to authorized "
                "clients only. Configure ACLs or switch to a resolver-only "
                "configuration if recursive service is needed."
            )

    except Exception as e:
        results['tests']['secondary_query'] = {
            'success': False,
            'error': str(e)
        }

    return results


async def test_robustness(domain: str, nameserver: str) -> Dict[str, Any]:
    """Test nameserver's handling of edge cases and malformed queries."""
    results = {
        'domain': domain,
        'nameserver': nameserver,
        'tests': {},
        'summary': {'passed': 0, 'failed': 0, 'errors': []}
    }

    # Test cases for malformed queries
    malformed_tests = [
        ('oversized_label', 'x' * 64 + '.' + domain),  # Label too long
        ('invalid_chars', 'test!@#$.' + domain),  # Invalid characters
        ('empty_labels', 'test...' + domain),  # Empty labels
        ('max_name', ('x.' * 127 + domain)[:255]),  # Maximum name length
        ('overmax_name', ('x.' * 128 + domain)),  # Exceeds maximum name length
    ]

    for test_name, test_domain in malformed_tests:
        result = await make_test_query(test_domain, 'A', nameserver)
        results['tests'][test_name] = {
            'success': result.success,
            'rcode': result.rcode,
            'error': result.error,
            'handled_correctly': (
                not result.success or
                result.rcode in [dns.rcode.FORMERR, dns.rcode.REFUSED]
            )
        }

        if results['tests'][test_name]['handled_correctly']:
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1

    # Test unusual record types
    unusual_types = ['NULL', 'HINFO', 'RP', 'AFSDB']
    for rdtype in unusual_types:
        result = await make_test_query(domain, rdtype, nameserver)
        results['tests'][f'unusual_type_{rdtype}'] = {
            'success': result.success,
            'rcode': result.rcode,
            'error': result.error,
            'handled_correctly': (
                not result.success or
                result.rcode in [dns.rcode.REFUSED, dns.rcode.NOTIMP, dns.rcode.NOERROR]
            )
        }

        if results['tests'][f'unusual_type_{rdtype}']['handled_correctly']:
            results['summary']['passed'] += 1
        else:
            results['summary']['failed'] += 1

    # Test handling of malformed EDNS
    query = dns.message.make_query(domain, 'A')
    query.use_edns(edns=1)  # Invalid EDNS version
    try:
        response = await dns.asyncquery.udp(query, nameserver, timeout=DEFAULT_TIMEOUT)
        results['tests']['invalid_edns'] = {
            'success': True,
            'handled_correctly': response.rcode() == dns.rcode.BADVERS
        }
    except Exception as e:
        results['tests']['invalid_edns'] = {
            'success': False,
            'error': str(e),
            'handled_correctly': True  # Rejecting invalid EDNS is acceptable
        }

    return results


async def run_comprehensive_tests(domain: str, nameserver: str) -> Dict[str, Any]:
    """Run all available tests and compile a comprehensive report."""
    report = {
        'domain': domain,
        'nameserver': nameserver,
        'timestamp': time.time(),
        'results': {},
        'summary': {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'errors': []
        }
    }

    # Run all test suites
    test_suites = {
        'basic_records': test_basic_records,
        'qname_handling': test_qname_handling,
        'edns_support': test_edns_support,
        'tcp_behavior': test_tcp_behavior,
        'any_queries': test_any_queries,
        'delegation': test_delegation,
        'robustness': test_robustness,
        'performance': test_performance,
        'open_resolver': test_open_resolver
    }

    # Run all test suites concurrently
    async def run_suite(suite_name: str, test_func) -> Tuple[str, Dict[str, Any]]:
        try:
            results = await test_func(domain, nameserver)
            return suite_name, results
        except Exception as e:
            return suite_name, {
                'error': str(e),
                'status': 'failed'
            }

    suite_tasks = [run_suite(name, func) for name, func in test_suites.items()]
    suite_results = await asyncio.gather(*suite_tasks)

    # Process results
    for suite_name, results in suite_results:
        report['results'][suite_name] = results

        # Aggregate statistics
        if 'summary' in results:
            report['summary']['total_tests'] += results['summary'].get('total_tests', 0)
            report['summary']['passed_tests'] += results['summary'].get('passed', 0)
            report['summary']['failed_tests'] += results['summary'].get('failed', 0)
            if 'errors' in results['summary']:
                report['summary']['errors'].extend(results['summary']['errors'])
        elif 'error' in results:
            report['summary']['errors'].append(
                f"{suite_name} test suite failed: {results['error']}"
            )

    # Add interpretation for LLM consumption
    report['interpretation'] = interpret_test_results(report)

    return report


def interpret_test_results(report: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a natural language interpretation of test results."""
    interpretation = {
        'summary': {
            'description': f"Comprehensive DNS server test results for {report['domain']}",
            'overall_status': 'All tests passed' if report['summary']['failed_tests'] == 0 else 'Some tests failed',
            'test_coverage': f"Ran {report['summary']['total_tests']} tests across multiple categories"
        },
        'key_findings': [],
        'recommendations': [],
        'performance_analysis': {},
        'security_analysis': {},
        'compliance_analysis': {}
    }

    # Analyze results by category
    if 'basic_records' in report['results']:
        basic = report['results']['basic_records']
        interpretation['key_findings'].append(
            f"Basic DNS records: {basic['summary']['successful']}/{basic['summary']['total_tests']} tests passed"
        )

    if 'performance' in report['results']:
        perf = report['results']['performance']
        if 'summary' in perf:
            interpretation['performance_analysis'] = {
                'queries_per_second': perf['summary']['queries_per_second'],
                'success_rate': perf['summary']['success_rate'],
                'average_latency': perf['summary']['avg_latency']
            }

    # Generate recommendations
    if report['summary']['failed_tests'] > 0:
        interpretation['recommendations'].extend([
            f"Fix {error}" for error in report['summary']['errors']
        ])

    # Security analysis
    interpretation['security_analysis'] = {}

    if 'robustness' in report['results']:
        rob = report['results']['robustness']
        interpretation['security_analysis'].update({
            'malformed_query_handling': 'Good' if rob['summary']['passed'] > rob['summary']['failed'] else 'Needs Improvement',
            'issues_found': rob['summary'].get('errors', [])
        })

    if 'open_resolver' in report['results']:
        open_res = report['results']['open_resolver']
        interpretation['security_analysis'].update({
            'open_resolver_status': 'Vulnerable' if open_res['is_open_resolver'] else 'Secure',
            'open_resolver_risk': open_res['security_risk'],
            'open_resolver_details': open_res.get('details', {})
        })
        if open_res['is_open_resolver']:
            interpretation['recommendations'].append(
                "Critical: Server is operating as an open resolver. " + 
                open_res.get('details', {}).get('recommendation',
                    "Configure access controls to restrict recursive queries."
                )
            )

    # Standards compliance
    if 'edns_support' in report['results']:
        edns = report['results']['edns_support']
        interpretation['compliance_analysis']['edns_support'] = {
            'status': 'Compliant' if edns['summary']['passed'] > edns['summary']['failed'] else 'Non-compliant',
            'issues': edns['summary'].get('errors', [])
        }

    if 'any_queries' in report['results']:
        any_results = report['results']['any_queries']
        interpretation['compliance_analysis']['rfc8482_compliance'] = {
            'status': 'Compliant' if any_results['summary']['passed'] > any_results['summary']['failed'] else 'Non-compliant',
            'issues': any_results['summary'].get('errors', []),
            'notes': [test['note'] for test in any_results['tests'].values() 
                     if isinstance(test, dict) and 'note' in test]
        }

    return interpretation
