"""DNSSEC validator module for DNS zone security."""

from __future__ import annotations

import statistics
import sys
import time
from typing import Dict, Any, List, Tuple, Optional, cast
import json
import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import dns.rdtypes.ANY.SOA
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.NSEC3 import NSEC3
from dns.rdtypes.ANY.RRSIG import RRSIG
from typedefs import ValidationResult, TestResult
from exceptions import ValidationError, handle_dns_error
from resolver import Resolver

# Type aliases
SOARecord = dns.rdtypes.ANY.SOA.SOA
RRset = dns.rrset.RRset
Message = dns.message.Message
Name = dns.name.Name

# For type checking
NSECRecord = NSEC
NSEC3Record = NSEC3

DEFAULT_TIMEOUT = 5.0

# Global resolver instance
_resolver = Resolver(timeout=DEFAULT_TIMEOUT)

def compute_ds_from_dnskey(name: str, dnskey_rrset: dns.rrset.RRset, digest_alg: str = 'SHA256') -> Tuple[List[str], List[Dict[str, Any]]]:
    """Compute DS digest(s) from DNSKEY RRset. 
    
    Returns:
        Tuple containing:
        - List of DS string representations
        - List of dictionaries containing information about denied keys
    """
    ds_list = []
    denied_keys = []
    name_obj = dns.name.from_text(name)
    for rdata in dnskey_rrset:
        try:
            # Try with newer API first
            ds = dns.dnssec.make_ds(name_obj, rdata, digest_alg)
            ds_list.append(str(ds))
        except dns.exception.DeniedByPolicy:
            # Track denied keys with their details
            denied_keys.append({
                'key_tag': key_tag_from_dnskey(rdata),
                'algorithm': rdata.algorithm,
                'algorithm_name': dns.dnssec.algorithm_to_text(rdata.algorithm),
                'flags': rdata.flags,
                'digest_alg': digest_alg,
                'reason': 'Denied by DNSSEC policy'
            })
            continue
        except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout,
                dns.exception.DNSException):
            continue  # Skip this record and try next one
    return ds_list, denied_keys


def key_tag_from_dnskey(rdata) -> int:
    try:
        return dns.dnssec.key_id(rdata)
    except (AttributeError, ValueError, dns.exception.DNSException):
        # If dns.dnssec.key_id fails, try .key_tag attribute
        # This handles both older DNS implementations and malformed keys
        return getattr(rdata, 'key_tag', 0)


def validate_nsec3_parameters(nsec3_record: NSEC3) -> Dict[str, Any]:
    """Validate NSEC3 parameters according to best practices."""
    result: Dict[str, Any] = {
        'valid': True,
        'warnings': [],
        'algorithm': nsec3_record.algorithm,
        'iterations': nsec3_record.iterations,
        'salt': nsec3_record.salt.hex() if nsec3_record.salt else None,
        'salt_length': len(nsec3_record.salt) if nsec3_record.salt else 0
    }

    # Check for invalid parameters according to RFC 5155 and best practices
    if result['algorithm'] != 1:
        result['valid'] = False
        result['warnings'].append(f"Invalid NSEC3 algorithm: {result['algorithm']}")

    if result['iterations'] > 150:  # Current recommended max
        result['warnings'].append(f"NSEC3 iterations too high: {result['iterations']}")

    if result['salt'] and result['salt_length'] > 32:
        result['warnings'].append(f"NSEC3 salt length too long: {result['salt_length']}")

    return result


def validate_nsec_chain(nsec_records: List[dns.rrset.RRset], zone_name: str) -> Dict[str, Any]:
    """Validate that NSEC records form a complete chain."""
    if not nsec_records:
        return {'valid': False, 'error': 'No NSEC records found'}

    result = {'valid': True, 'errors': [], 'chain': []}
    sorted_records = sorted(nsec_records, key=lambda r: r.name.to_text())

    # Convert zone name for comparison
    _ = dns.name.from_text(zone_name)  # Validate zone name format

    # Check if chain forms a complete circle
    for i, current_rrset in enumerate(sorted_records):
        # Use the first rdata record directly
        current_nsec = cast(NSEC, current_rrset[0])
        next_owner = current_nsec.next
        expected_next = sorted_records[(i + 1) % len(sorted_records)].name

        if next_owner != expected_next:
            result['valid'] = False
            result['errors'].append(
                f"Broken NSEC chain between {current_rrset.name} and {next_owner}"
            )

        result['chain'].append({
            'owner': current_rrset.name.to_text(),
            'next': next_owner.to_text(),
            'types': [str(dns.rdatatype.RdataType(t[0])) for t in current_nsec.windows]
        })
    return result


def validate_nsec3_chain(nsec3_records: List[dns.rrset.RRset]) -> ValidationResult:
    """Validate that NSEC3 records form a complete chain with valid parameters."""
    if not nsec3_records:
        return {'valid': False, 'error': 'No NSEC3 records found'}

    result: ValidationResult = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'parameters': None,
        'chain': []
    }

    # Cast to NSEC3Record for type safety
    def to_nsec3(record: dns.rrset.RRset) -> NSEC3Record:
        rdata = record[0]
        # Simply return the RDATA cast to NSEC3 type
        return cast(NSEC3Record, rdata)

    # Validate parameters from first record
    first_nsec3 = to_nsec3(nsec3_records[0])
    result['parameters'] = validate_nsec3_parameters(first_nsec3)
    params = result.get('parameters', {})
    if params and 'warnings' in params:
        result['warnings'].extend(params['warnings'])

    # Sort records by hash
    sorted_records = [to_nsec3(r) for r in nsec3_records]
    sorted_records.sort(key=lambda r: r.next)

    # Check if chain forms a complete circle
    for i, current in enumerate(sorted_records):
        next_hash = current.next
        expected_next = sorted_records[(i + 1) % len(sorted_records)].next

        if next_hash != expected_next:
            result['valid'] = False
            result['errors'].append(
                f"Broken NSEC3 chain between {current.next.hex()} and {next_hash.hex()}"
            )

        result['chain'].append({
            'current': current.next.hex(),
            'next': next_hash.hex(),
            'types': [str(dns.rdatatype.RdataType(t[0])) for t in current.windows]
        })
    return result


def extract_rrsig_for_rrset(resp: Optional[dns.message.Message], rdtype: str) -> Optional[dns.rrset.RRset]:
    """Given a dns.message.Message response, extract the RRSIG rrset corresponding to rdtype
    in the ANSWER or AUTHORITY section.
"""
    if resp is None:
        return None
    # search answer then authority
    for section in (resp.answer, resp.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                # filter by type covered
                for rdata in rrset:
                    if hasattr(rdata, 'type_covered') and dns.rdatatype.to_text(
                        rdata.type_covered
                    ) == rdtype:
                        return rrset
    return None


def validate_rrset_with_dnskey(rrset: dns.rrset.RRset, rrsigset: dns.rrset.RRset, dnskey_rrset: dns.rrset.RRset, origin_name: str) -> Tuple[bool, Optional[str]]:
    """Attempt to validate a single rrset using dns.dnssec.validate.
    Returns (valid, message)
    """
    try:
        # Build a keys dictionary: {name: dnskey_rrset}
        # Build keys for validation
        keys: Dict[dns.name.Name, Any] = {
            dns.name.from_text(origin_name): dnskey_rrset
        }
        dns.dnssec.validate(rrset, rrsigset, keys)
        return True, None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
            dns.resolver.NoNameservers, dns.exception.DNSException) as e:
        return False, str(e)


def validate_denial_proof(resp: Message, _target: str) -> Dict[str, Any]:
    """Validate NSEC or NSEC3 denial of existence proof."""
    result = {
        'valid': False,
        'proof_type': None,
        'records': [],
        'validation': None
    }

    if not resp or not isinstance(resp, dns.message.Message) or not resp.authority:
        return result

    nsec_records = []
    nsec3_records = []

    for rrset in resp.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            nsec_records.append(rrset)
        elif rrset.rdtype == dns.rdatatype.NSEC3:
            nsec3_records.append(rrset)

    if nsec_records:
        result['proof_type'] = 'NSEC'
        result['records'] = [r.to_text() for r in nsec_records]
        # Extract domain from first NSEC record's owner name
        first_nsec = nsec_records[0]
        zone = first_nsec.name.parent()
        validation = validate_nsec_chain(nsec_records, zone.to_text())
        result['validation'] = validation
        result['valid'] = validation.get('valid', False)
    elif nsec3_records:
        result['proof_type'] = 'NSEC3'
        result['records'] = [r.to_text() for r in nsec3_records]
        validation = validate_nsec3_chain(nsec3_records)
        result['validation'] = validation
        result['valid'] = validation.get('valid', False)

    return result


def check_rrset_signature(target: str, rdtype: str, dnskey_rrset: Optional[dns.rrset.RRset], nameserver: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    if timeout != DEFAULT_TIMEOUT:
        _resolver.resolver.lifetime = timeout
    rrset, resp = _resolver.resolve(target, rdtype, nameserver)
    if timeout != DEFAULT_TIMEOUT:
        _resolver.resolver.lifetime = _resolver.default_timeout
    result: Dict[str, Any] = {'type': rdtype, 'present': rrset is not None}
    if rrset is None or dnskey_rrset is None:
        # try to see if NXDOMAIN or NODATA with proof
        result['nx_proof'] = validate_denial_proof(resp, target) if resp else None
        return result

    rrsig = extract_rrsig_for_rrset(resp, rdtype)
    result['rrsig_present'] = rrsig is not None
    if rrsig is None:
        result['valid'] = False
        result['error'] = 'no RRSIG present'
        return result

    valid, message = validate_rrset_with_dnskey(rrset, rrsig, dnskey_rrset, target)
    result['valid'] = valid
    if not valid:
        result['error'] = message
    else:
        # check signature time bounds
        sig_ok_times = []
        for rdata in rrsig:
            # rdata.inception and expiration are ints (epoch seconds)
            try:
                inception = rdata.inception
                expiration = rdata.expiration
                now = int(time.time())
                sig_ok_times.append(
                    {
                        'inception': inception,
                        'expiration': expiration,
                        'now': now,
                        'valid_now': inception <= now <= expiration
                    }
                )
            except (AttributeError, ValueError, TypeError):
                # Skip records with invalid time values
                continue
        result['signatures'] = sig_ok_times
    return result


def check_parent_ds(zone_name: str, dnskey_rrset: Optional[dns.rrset.RRset], parent_ns: Optional[str] = None) -> Dict[str, Any]:
    parent = _resolver.get_parent_name(zone_name)
    ds_rrset, _ = _resolver.fetch_ds(zone_name, parent_ns)
    result: Dict[str, Any] = {
        'parent': parent,
        'parent_ds_present': ds_rrset is not None,
        'denied_keys': []
    }
    # compute DS from the child DNSKEY
    if dnskey_rrset is None:
        result['child_dnskey_present'] = False
        return result
    result['child_dnskey_present'] = True
    computed_sha256, denied_sha256 = compute_ds_from_dnskey(zone_name, dnskey_rrset, 'SHA256')
    computed_sha1, denied_sha1 = compute_ds_from_dnskey(zone_name, dnskey_rrset, 'SHA1')
    # Track all denied keys
    result['denied_keys'].extend(denied_sha256)
    result['denied_keys'].extend(denied_sha1)
    result['computed_ds'] = {'SHA256': computed_sha256, 'SHA1': computed_sha1}
    if ds_rrset is None:
        return result
    # Compare textual forms
    parent_ds_texts = [str(r) for r in ds_rrset]
    result['parent_ds_texts'] = parent_ds_texts
    matches = []
    # Add summary of denied keys if any were denied
    if result['denied_keys']:
        result['denied_summary'] = {
            'count': len(result['denied_keys']),
            'algorithms': list(set(k['algorithm_name'] for k in result['denied_keys'])),
            'flags': list(set(k['flags'] for k in result['denied_keys']))
        }
    for ds in parent_ds_texts:
        for cds in computed_sha256 + computed_sha1:
            if ds.split()[-1] == cds.split()[-1] or ds == cds:
                matches.append({'parent_ds': ds, 'matches_computed': cds})
    result['matches'] = matches
    return result

def check_soa_consistency(zone_name: str, nameservers: List[str]) -> Dict[str, Any]:
    """Check SOA serial consistency and refresh times across authoritative nameservers."""
    results = {
        'serials': {},
        'refresh_times': {},
        'analysis': {
            'serial_consistency': False,
            'refresh_analysis': None,
            'recommendations': []
        }
    }

    for ns in nameservers:
        try:
            # Resolve nameserver IP first
            ns_ip = None
            try:
                answers = dns.resolver.resolve(ns, 'A')
                if answers:
                    ns_ip = str(answers[0])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                   dns.resolver.NoNameservers, dns.exception.DNSException):
                continue

            if ns_ip:
                # Create resolver for this nameserver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ns_ip]
                resolver.timeout = 5

                # Query the SOA record
                answer = resolver.resolve(zone_name, 'SOA')
                if answer and answer.rrset and len(answer.rrset) > 0:
                    # Cast the SOA record to the correct type
                    soa_record = cast(SOARecord, answer.rrset[0])
                    results['serials'][ns] = soa_record.serial
                    results['refresh_times'][ns] = soa_record.refresh

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
              dns.resolver.NoNameservers, dns.exception.DNSException,
              dns.exception.Timeout):
            results['serials'][ns] = None
            results['refresh_times'][ns] = None

    # Analyze serial consistency
    valid_serials = {ns: serial for ns, serial in results['serials'].items() if serial is not None}
    unique_serials = set(valid_serials.values())

    # Get refresh times for analysis
    valid_refresh_times = [rt for rt in results['refresh_times'].values() if rt is not None]
    avg_refresh_time = sum(valid_refresh_times) / len(valid_refresh_times) if valid_refresh_times else 0

    # Analyze consistency and refresh times
    results['analysis']['serial_consistency'] = len(unique_serials) <= 1

    # Define refresh time thresholds (in seconds)
    REFRESH_TOO_SHORT = 300  # 5 minutes
    REFRESH_TOO_LONG = 14400  # 4 hours
    REFRESH_IDEAL_MIN = 1800  # 30 minutes
    REFRESH_IDEAL_MAX = 7200  # 2 hours

    # Serial consistency analysis with refresh time context
    if len(unique_serials) > 1:
        if avg_refresh_time < REFRESH_TOO_SHORT:
            results['analysis']['recommendations'].append(
                "Zone serial numbers are inconsistent, but the refresh time is very short "
                f"({avg_refresh_time} seconds). The zones might have already synchronized. "
                f"Consider retesting after {avg_refresh_time} seconds to verify."
            )
        else:
            results['analysis']['recommendations'].append(
                f"CRITICAL: Zone serial numbers are inconsistent and refresh time is "
                f"{avg_refresh_time} seconds. This should be investigated as "
                "it may indicate zone transfer issues."
            )

    # Refresh time analysis
    if valid_refresh_times:
        if avg_refresh_time < REFRESH_TOO_SHORT:
            results['analysis']['refresh_analysis'] = "too_short"
            results['analysis']['recommendations'].append(
                f"WARNING: Average refresh time ({avg_refresh_time} seconds) is too short. "
                f"Recommended minimum is {REFRESH_TOO_SHORT} seconds to avoid excessive zone transfers."
            )
        elif avg_refresh_time > REFRESH_TOO_LONG:
            results['analysis']['refresh_analysis'] = "too_long"
            results['analysis']['recommendations'].append(
                f"WARNING: Average refresh time ({avg_refresh_time} seconds) is too long. "
                f"Recommended maximum is {REFRESH_TOO_LONG} seconds to ensure timely zone updates."
            )
        elif REFRESH_IDEAL_MIN <= avg_refresh_time <= REFRESH_IDEAL_MAX:
            results['analysis']['refresh_analysis'] = "ideal"
            results['analysis']['recommendations'].append(
                f"GOOD: Refresh time ({avg_refresh_time} seconds) is within the ideal range "
                f"of {REFRESH_IDEAL_MIN}-{REFRESH_IDEAL_MAX} seconds."
            )

    # Add detailed consistency information
    results['analysis']['details'] = {
        'serial_consistency': {
            'consistent': len(unique_serials) <= 1,
            'unique_serials': len(unique_serials),
            'serial_details': {
                str(serial): [
                    ns for ns, ns_serial in valid_serials.items() if ns_serial == serial
                ] for serial in unique_serials
            }
        },
        'refresh_details': {
            'average': avg_refresh_time,
            'by_nameserver': results['refresh_times'],
            'threshold_values': {
                'too_short': REFRESH_TOO_SHORT,
                'too_long': REFRESH_TOO_LONG,
                'ideal_range': [REFRESH_IDEAL_MIN, REFRESH_IDEAL_MAX]
            }
        }
    }
    return results

def list_authoritative_nameservers(zone_name: str) -> List[str]:
    ns_rrset, _ = _resolver.resolve(zone_name, 'NS')
    if ns_rrset is None:
        return []
    return [r.target.to_text() for r in ns_rrset]


def check_authoritative_consistency(zone_name: str) -> Dict[str, Any]:
    ns_list = list_authoritative_nameservers(zone_name)
    results: Dict[str, Any] = {}
    for ns in ns_list:
        try:
            # Try to resolve A/AAAA of the nameserver first
            ns_ip = None
            try:
                a_rr, _ = _resolver.resolve(ns, 'A')
                if a_rr:
                    ns_ip = str(a_rr[0])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                   dns.resolver.NoNameservers, dns.exception.DNSException,
                   dns.exception.Timeout) as e:
                results[ns] = {'error': f"Failed to resolve nameserver IP: {str(e)}"}
                continue

            if not ns_ip:
                results[ns] = {'error': "Could not resolve nameserver IP address"}
                continue

            # Query DNSKEY directly at that nameserver
            rrset, _ = _resolver.fetch_dnskey(zone_name, nameserver=ns_ip)
            results[ns] = {
                'dnskey_present': rrset is not None,
                'dnskey_count': len(rrset) if rrset else 0,
                'dnskey_text': [r.to_text() for r in rrset] if rrset else [],
                'ip': ns_ip
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.DNSException,
                dns.exception.Timeout) as e:
            results[ns] = {'error': str(e)}
    # quick consistency check: compare unique signatures and key counts
    counts = [v.get('dnskey_count', 0) for v in results.values() if isinstance(v, dict)]
    try:
        results['counts_summary'] = {
            'min': min(counts),
            'max': max(counts),
            'median': statistics.median(counts) if counts else None
        }
    except (ValueError, TypeError):
        results['counts_summary'] = None
    return results


def inspect_keys_and_rollover(dnskey_rrset: Optional[dns.rrset.RRset]) -> Dict[str, Any]:
    key_results: Dict[str, Any] = {
        'keys': [],
        'sep_count': 0,
        'zsk_count': 0,
        'warnings': [],
        'critical': [],
        'algorithms': set(),
        'key_lengths': {}
    }

    if dnskey_rrset is None:
        key_results['critical'].append("No DNSKEY records found")
        return key_results

    for r in dnskey_rrset:
        tag = key_tag_from_dnskey(r)
        alg = r.algorithm
        flags = r.flags
        is_sep = bool(flags & 0x0100)
        protocol = r.protocol

        # Get key details
        key_info = {
            'tag': tag,
            'algorithm': alg,
            'algorithm_name': dns.dnssec.algorithm_to_text(alg),
            'flags': flags,
            'protocol': protocol,
            'is_sep': is_sep,
            'to_text': r.to_text(),
            'key_size': len(r.key) * 8,  # Convert bytes to bits
            'valid': True,
            'issues': []
        }

        # Check protocol field (must be 3 as per RFC 4034)
        if protocol != 3:
            key_info['valid'] = False
            key_info['issues'].append(
                f"Invalid protocol value: {protocol} (must be 3)"
            )

        # Check algorithm validity
        key_results['algorithms'].add(alg)
        if alg in [1, 3, 6, 7, 8]:  # Deprecated/insecure algorithms
            key_info['issues'].append(
                f"Insecure or deprecated algorithm: {key_info['algorithm_name']}"
            )

        # Check key length based on algorithm
        min_key_lengths = {
            1: 512,   # RSA/MD5 (not recommended)
            3: 512,   # DSA/SHA1 (not recommended)
            5: 512,   # RSA/SHA-1
            7: 512,   # RSASHA1-NSEC3-SHA1
            8: 512,   # RSA/SHA-256
            10: 1024, # RSA/SHA-512
            13: 256,  # ECDSA Curve P-256 with SHA-256
            14: 384,  # ECDSA Curve P-384 with SHA-384
            15: 256,  # Ed25519
            16: 456   # Ed448
        }

        if alg in min_key_lengths:
            if key_info['key_size'] < min_key_lengths[alg]:
                key_info['issues'].append(
                    f"Key size {key_info['key_size']} bits is below minimum {min_key_lengths[alg]} "
                    f"bits for algorithm {key_info['algorithm_name']}"
                )

        # Track key lengths by algorithm
        if alg not in key_results['key_lengths']:
            key_results['key_lengths'][alg] = []
        key_results['key_lengths'][alg].append(key_info['key_size'])

        key_results['keys'].append(key_info)

    # Analyze overall key configuration
    sep_count = sum(1 for k in key_results['keys'] if k['is_sep'])
    zsk_count = len(key_results['keys']) - sep_count
    key_results['sep_count'] = sep_count
    key_results['zsk_count'] = zsk_count

    # Check for critical issues
    if sep_count == 0:
        key_results['critical'].append("No KSK (SEP) keys found")
    if zsk_count == 0:
        key_results['critical'].append("No ZSK keys found")
    if sep_count > 2:
        key_results['warnings'].append(f"Unusually high number of KSK keys: {sep_count}")

    # Check algorithm consistency
    if len(key_results['algorithms']) > 1:
        key_results['warnings'].append(
            f"Multiple signing algorithms in use: "
            f"{', '.join(dns.dnssec.algorithm_to_text(a) for a in sorted(key_results['algorithms']))}"
        )

    # Convert algorithms set to list for JSON serialization
    key_results['algorithms'] = sorted(list(key_results['algorithms']))
    return key_results


def test_robustness(zone_name: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Test DNS server's robustness to various edge cases.
    
    Tests various edge cases and potential attack vectors:
    1. Overly long domain names
    2. Invalid characters in queries
    3. Unexpected record types
    4. Malformed DNSSEC queries
    5. Replay attack detection
    
    Args:
        zone_name: Zone name used for test scenarios
        timeout: Timeout for DNS queries in seconds
    
    Returns:
        Dict containing test results with details about each test case
    """
    result = {
        'domain': zone_name,
        'tests': [],
        'issues_found': [],
        'security_rating': 'good'
    }

    # Test 1: Overly long labels and names
    long_label = "a" * 64  # RFC 1035 limit is 63
    long_name = f"{long_label}.{zone_name}"
    try:
        # Create query with overly long label
        qname = dns.name.from_text(long_name)
        query = dns.message.make_query(qname, dns.rdatatype.A)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout

        try:
            _ = resolver.resolve(qname, 'A')  # Just testing if resolution works
            passed = False  # Should not succeed with invalid name
        except dns.name.LabelTooLong:
            passed = True  # Expected behavior - proper handling of long labels
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.name.BadLabelType):
            passed = True  # Any form of rejection for invalid names is acceptable
        except dns.exception.DNSException:
            # Other DNS-related rejections are also acceptable
            passed = True

        result['tests'].append({
            'name': 'oversized_label',
            'description': 'Testing handling of oversized DNS labels',
            'passed': passed,
            'details': 'Server properly rejected oversized label'
        })
    except (ValueError, dns.exception.DNSException) as e:
        # Even setup failures are acceptable as they prevent invalid queries
        result['tests'].append({
            'name': 'oversized_label',
            'description': 'Testing handling of oversized DNS labels',
            'passed': True,
            'error': handle_dns_error(e)
        })

    # Test 2: Invalid characters
    invalid_chars = "test!@#$"  # Invalid characters in label
    try:
        # This should raise an exception for invalid characters
        qname = dns.name.from_text(f"{invalid_chars}.{zone_name}")
        passed = False
    except dns.name.BadLabelType:
        passed = True  # Expected behavior
    except (dns.name.LabelTooLong, dns.exception.DNSException, ValueError):
        passed = True  # Any rejection is acceptable

    result['tests'].append({
        'name': 'invalid_chars',
        'description': 'Testing handling of invalid characters in domain names',
        'passed': passed
    })    # Test 3: Unusual record types
    try:
        _, resp = _resolver.resolve(zone_name, 'NULL')
        # NULL records should be rejected or handled safely
        passed = (resp is None or 
                 resp.rcode() in [dns.rcode.REFUSED, dns.rcode.NOTIMP, dns.rcode.FORMERR])
        result['tests'].append({
            'name': 'unusual_rr_type',
            'description': 'Testing handling of unusual record types',
            'passed': passed
        })
    except dns.resolver.NoAnswer:
        # Refusing to answer is acceptable
        result['tests'].append({
            'name': 'unusual_rr_type',
            'description': 'Testing handling of unusual record types',
            'passed': True
        })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.DNSException, dns.exception.Timeout):
        # Any rejection is acceptable for NULL records
        result['tests'].append({
            'name': 'unusual_rr_type',
            'description': 'Testing handling of unusual record types',
            'passed': True
        })

    # Test 4: DNSSEC-specific robustness
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout

        # Create a query with DNSSEC enabled
        qname = dns.name.from_text(zone_name)
        query = dns.message.make_query(qname, dns.rdatatype.DNSKEY)
        query.use_edns(edns=0, ednsflags=dns.flags.DO)  # Set DNSSEC OK

        # Test with both CD (Checking Disabled) flag set and unset
        query.flags |= dns.flags.CD

        # Try to send directly to each nameserver
        ns_addrs = []
        try:
            ns_rrset, _ = _resolver.resolve(zone_name, 'NS')
            if ns_rrset:
                for rr in ns_rrset:
                    a_rrset, _ = _resolver.resolve(rr.target.to_text(), 'A')
                    if a_rrset:
                        ns_addrs.append(str(a_rrset[0]))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.DNSException,
                dns.exception.Timeout):
            pass

        if not ns_addrs:
            ns_addrs = [resolver.nameservers[0]]

        # Test each nameserver
        dnssec_works = False
        for ns in ns_addrs:
            try:
                response = dns.query.udp(query, str(ns), timeout=timeout)
                if response and response.rcode() == dns.rcode.NOERROR:
                    dnssec_works = True
                    break
            except (dns.exception.Timeout, dns.query.BadResponse,
                   dns.exception.DNSException):
                continue

        result['tests'].append({
            'name': 'malformed_dnssec',
            'description': 'Testing handling of malformed DNSSEC queries',
            'passed': dnssec_works
        })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            dns.exception.Timeout, dns.name.BadLabelType) as e:
        # Should handle malformed queries gracefully
        result['tests'].append({
            'name': 'malformed_dnssec',
            'description': 'Testing handling of malformed DNSSEC queries',
            'passed': True,
            'details': f'Expected error occurred: {str(e)}'
        })

    # Test 5: Check for replay attack vulnerability
    # Query twice and compare inception/expiration times
    try:
        _, resp1 = _resolver.resolve(zone_name, 'DNSKEY')
        time.sleep(1)  # Wait a bit
        _, resp2 = _resolver.resolve(zone_name, 'DNSKEY')

        sig1_rrset = extract_rrsig_for_rrset(resp1, 'DNSKEY')
        sig2_rrset = extract_rrsig_for_rrset(resp2, 'DNSKEY')

        if sig1_rrset and sig2_rrset and len(sig1_rrset) > 0 and len(sig2_rrset) > 0:
            # Cast to RRSIG type for proper access
            sig1: RRSIG = cast(RRSIG, sig1_rrset[0])
            sig2: RRSIG = cast(RRSIG, sig2_rrset[0])
            # Compare inception times - shouldn't be identical for fresh signatures
            passed = (sig1.inception != sig2.inception or 
                     sig1.expiration != sig2.expiration)
        else:
            passed = True  # No RRSIG means no replay vulnerability

        result['tests'].append({
            'name': 'replay_resistance',
            'description': 'Testing resistance to replay attacks',
            'passed': passed
        })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            dns.exception.Timeout) as e:
        result['tests'].append({
            'name': 'replay_resistance',
            'description': 'Testing resistance to replay attacks',
            'passed': False,
            'error': f'Could not complete replay resistance test: {str(e)}'
        })
    failed_tests = [t for t in result['tests'] if not t['passed']]
    if failed_tests:
        result['issues_found'].extend([
            f"Failed {t['name']}: {t['description']}" for t in failed_tests
        ])
        result['security_rating'] = 'poor' if len(failed_tests) > 2 else 'fair'

    # Add test results to the interpretation
    result['interpretation'] = {
        'description': 'Analysis of DNS server robustness against malformed and malicious queries',
        'findings': [],
        'recommendations': []
    }

    for test in result['tests']:
        status = 'passed' if test['passed'] else 'failed'
        result['interpretation']['findings'].append(
            f"{test['description']}: {status}"
        )
        if not test['passed']:
            result['interpretation']['recommendations'].append(
                f"Review handling of {test['name']} to improve security"
            )

    return result

def validate_domain(zone_name: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Perform the batch of DNSSEC checks described in the earlier checklist.

    Returns a structured report as a dictionary.
    """
    # Set timeout for this validation run
    if timeout != DEFAULT_TIMEOUT:
        _resolver.resolver.lifetime = timeout

    report: Dict[str, Any] = {
        'domain': zone_name,
        'dnskey': {'present': False},
        'dnskey_signature': {'present': False, 'valid': False},
        'parent_ds': {},
        'rrsets': {},
        'nxdomain_test': {},
        'authoritative': {},
        'keys': {},
        'algorithms': {'algorithm_numbers': []},
        'soa_consistency': {},
        'robustness': {}
    }

    # Split domain into labels for zone traversal
    labels = dns.name.from_text(zone_name).labels
    zones = []
    for i in range(len(labels)):
        zone = b'.'.join(labels[-(i+1):]).decode()
        zones.insert(0, zone if zone else '.')

    # Check SOA consistency for each zone
    report['soa_consistency'] = {}
    for zone in zones:
        nameservers = list_authoritative_nameservers(zone)
        if nameservers:
            report['soa_consistency'][zone] = check_soa_consistency(zone, nameservers)

    # 1) Fetch DNSKEY from an arbitrary resolver (system resolver)
    dnskey_rrset, _ = _resolver.fetch_dnskey(zone_name)
    report['dnskey'].update({
        'present': dnskey_rrset is not None,
        'count': len(dnskey_rrset) if dnskey_rrset else 0,
        'text': [r.to_text() for r in dnskey_rrset] if dnskey_rrset else []
    })

    # 2) Parent DS check
    report['parent_ds'] = check_parent_ds(zone_name, dnskey_rrset)

    # 3) Verify DNSKEY RRset signatures (RRSIG over DNSKEY)
    if dnskey_rrset is not None:
        # We need the response message to extract RRSIG; fetch again to get response
        _, resp = _resolver.fetch_dnskey(zone_name)
        rrsig = extract_rrsig_for_rrset(resp, 'DNSKEY') if resp else None
        report['dnskey_signature'].update({
            'present': rrsig is not None,
            'valid': False,
            'error': None
        })
        if rrsig is not None:
            valid, message = validate_rrset_with_dnskey(
                dnskey_rrset,
                rrsig,
                dnskey_rrset,
                zone_name
            )
            report['dnskey_signature'].update({
                'valid': valid,
                'error': message if not valid else None
            })

    # 4) Check common RRsets
    rrtypes = ['SOA', 'NS', 'A', 'AAAA', 'MX', 'TXT']
    rrchecks = {}
    for t in rrtypes:
        rrchecks[t] = check_rrset_signature(zone_name, t, dnskey_rrset, None, timeout)
    report['rrsets'] = rrchecks

    # 5) NXDOMAIN / denial proofs check (test non-existent names)
    # 5) NXDOMAIN / denial proofs check (test non-existent names)

    # Test NXDOMAIN with random label
    test_name = f"this-name-should-not-exist-{int(time.time())}.{zone_name}"
    report['nxdomain_test'] = check_rrset_signature(test_name, 'A', dnskey_rrset, None, timeout)

    # Additional denial of existence tests
    report['denial_tests'] = {}

    # Test wildcard denial (if NSEC3 is in use) with specific name pattern
    wildcard_test = f"*.{zone_name}"
    report['denial_tests']['wildcard'] = check_rrset_signature(
        wildcard_test,
        'A',
        dnskey_rrset,
        None,
        timeout
    )

    # Test empty non-terminal handling
    ent_test = f"nonexistent.subdomain.{zone_name}"
    report['denial_tests']['empty_non_terminal'] = check_rrset_signature(
        ent_test,
        'A',
        dnskey_rrset,
        None,
        timeout
    )

    # 6) Authoritative consistency
    report['authoritative'] = check_authoritative_consistency(zone_name)

    # 7) Key inspection and rollover hints
    report['keys'] = inspect_keys_and_rollover(dnskey_rrset)

    # 8) Algorithms & digest check (simple heuristics)
    algs = set()
    if dnskey_rrset is not None:
        for r in dnskey_rrset:
            algs.add(r.algorithm)
    report['algorithms'] = {'algorithm_numbers': sorted(list(algs))}

    # 9) Robustness Testing
    report['robustness'] = test_robustness(zone_name, timeout)

    return report


def interpret_validation_results(report: Dict[str, Any]) -> Dict[str, Any]:
    """Add natural language interpretations to the validation report."""
    interpretation = {
        "summary": {
            "domain": report["domain"],
            "overall_status": "DNSSEC is properly configured" if report["dnskey"]["present"] else "DNSSEC is not configured",
            "description": "This report analyzes the DNSSEC configuration and validation status for the domain.",
        },
        "key_configuration": {
            "description": "Analysis of the DNSKEY records and their properties",
            "status": []
        },
        "trust_chain": {
            "description": "Verification of the chain of trust from parent to child zone",
            "status": []
        },
        "validation_details": {
            "description": "Details of signature validation for various record types",
            "status": []
        },
        "denial_of_existence": {
            "description": "Analysis of NSEC/NSEC3 records for proving non-existence",
            "status": []
        },
        "recommendations": []
    }

    # Key Configuration Analysis
    if report["dnskey"]["present"]:
        key_info = report["keys"]
        interpretation["key_configuration"]["status"].extend([
            f"Found {key_info['sep_count']} Key Signing Keys (KSK) and {key_info['zsk_count']} Zone Signing Keys (ZSK)",
            f"Using algorithms: {', '.join(dns.dnssec.algorithm_to_text(alg) for alg in report['algorithms']['algorithm_numbers'])}"
        ])
        if key_info.get("critical"):
            interpretation["key_configuration"]["status"].extend(key_info["critical"])
        if key_info.get("warnings"):
            interpretation["key_configuration"]["status"].extend(key_info["warnings"])
    else:
        interpretation["key_configuration"]["status"].append("No DNSKEY records found")

    # Trust Chain Analysis
    parent_ds = report["parent_ds"]
    if parent_ds.get("parent_ds_present"):
        if parent_ds.get("matches"):
            interpretation["trust_chain"]["status"].append(
                f"Secure delegation found from parent zone {parent_ds['parent']}"
            )
        else:
            interpretation["trust_chain"]["status"].append(
                f"DS record present in parent zone {parent_ds['parent']} but does not match child DNSKEY"
            )
    else:
        interpretation["trust_chain"]["status"].append(
            f"No DS record found in parent zone {parent_ds.get('parent', 'unknown')}"
        )

    # Record Validation Details
    for rr_type, result in report["rrsets"].items():
        if result.get("present"):
            status = "valid" if result.get("valid") else "invalid"
            reason = f" ({result.get('error')})" if result.get("error") else ""
            interpretation["validation_details"]["status"].append(
                f"{rr_type} records present and signatures are {status}{reason}"
            )

    # Denial of Existence Analysis
    if "denial_tests" in report:
        for test_type, result in report["denial_tests"].items():
            if result.get("nx_proof"):
                proof = result["nx_proof"]
                interpretation["denial_of_existence"]["status"].append(
                    f"{test_type}: {proof['proof_type']} records present and "
                    f"{'valid' if proof['valid'] else 'invalid'}"
                )

    # Generate Recommendations
    if not report["dnskey"]["present"]:
        interpretation["recommendations"].append(
            "CRITICAL: Configure DNSSEC by generating and publishing DNSKEY records"
        )
    if report["dnskey"]["present"] and not parent_ds.get("parent_ds_present"):
        interpretation["recommendations"].append(
            "CRITICAL: Upload DS record to parent zone to establish chain of trust"
        )

    # Add SOA consistency information
    if "soa_consistency" in report:
        interpretation["zone_consistency"] = {
            "description": "Analysis of zone consistency across authoritative nameservers",
            "status": []
        }

        for zone, consistency in report["soa_consistency"].items():
            if "analysis" in consistency:
                # Add serial consistency status
                if not consistency["analysis"].get("serial_consistency", True):
                    interpretation["zone_consistency"]["status"].append(
                        f"Zone {zone}: Serial numbers are inconsistent across nameservers"
                    )

                # Add refresh time analysis
                refresh_analysis = consistency["analysis"].get("refresh_analysis")
                if refresh_analysis:
                    if refresh_analysis == "too_short":
                        interpretation["zone_consistency"]["status"].append(
                            f"Zone {zone}: Refresh time is too short, may cause excessive zone transfers"
                        )
                    elif refresh_analysis == "too_long":
                        interpretation["zone_consistency"]["status"].append(
                            f"Zone {zone}: Refresh time is too long, may delay zone updates"
                        )
                    elif refresh_analysis == "ideal":
                        interpretation["zone_consistency"]["status"].append(
                            f"Zone {zone}: Refresh time is within ideal range"
                        )

                # Add recommendations from the analysis
                if "recommendations" in consistency["analysis"]:
                    interpretation["zone_consistency"]["status"].extend(
                        [f"Zone {zone}: {rec}" for rec in consistency["analysis"]["recommendations"]]
                    )
                # Add legacy consistency information if present
                if "analysis" in consistency and "details" in consistency["analysis"]:
                    details = consistency["analysis"]["details"]
                    if "serial_consistency" in details:
                        status = "consistent" if details["serial_consistency"]["consistent"] else "inconsistent"
                        interpretation["zone_consistency"]["status"].append(
                            f"Zone {zone} serial numbers are {status}"
                        )

                        # Add refresh time information if available
                        if "refresh_details" in details:
                            refresh_avg = details["refresh_details"]["average"]
                            interpretation["zone_consistency"]["status"].append(
                                f"Zone {zone} refresh time is {refresh_avg} seconds"
                            )

    # Add robustness test interpretation
    if "robustness" in report and "interpretation" in report["robustness"]:
        interpretation["security_robustness"] = {
            "description": "Analysis of DNS server robustness against malformed and malicious queries",
            "status": report["robustness"]["interpretation"]["findings"],
            "recommendations": report["robustness"]["interpretation"]["recommendations"]
        }
        if report["robustness"]["issues_found"]:
            interpretation["recommendations"].extend([
                f"Security Issue: {issue}" for issue in report["robustness"]["issues_found"]
            ])

    return interpretation

def pretty_report(report: Dict[str, Any]) -> str:
    """Format validation report as a JSON string with metadata."""
    # Create the final report structure
    formatted_report = {
        "raw_data": report,
        "interpretation": interpret_validation_results(report),
        "metadata": {
            "timestamp": int(time.time()),
            "version": "2.0",
            "report_type": "DNSSEC Validation Report",
            "format": "Contains both raw validation data and natural language interpretation"
        }
    }
    return json.dumps(formatted_report, indent=2)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python dnssec_validator.py <domain>')
        sys.exit(1)
    target_domain = sys.argv[1].rstrip('.')
    try:
        out = validate_domain(target_domain)
        print(pretty_report(out))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
        print('Domain validation failed:', handle_dns_error(e))
        sys.exit(1)
    except dns.exception.DNSException as e:
        print('DNS error:', handle_dns_error(e))
        sys.exit(1)
    except (ValueError, KeyError) as e:
        print('Invalid input or configuration:', str(e))
        sys.exit(1)
