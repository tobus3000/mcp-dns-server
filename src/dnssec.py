"""DNSSEC validator module for DNS zone security."""

from __future__ import annotations

import sys
import time
import statistics
from typing import Dict, Any, List, Tuple, Optional

import dns.message
import dns.name
import dns.resolver
import dns.rrset
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
import dns.dnssec
import dns.rdtypes.ANY.SOA

# Type aliases
SOARecord = dns.rdtypes.ANY.SOA.SOA
RRset = dns.rrset.RRset
Message = dns.message.Message
Name = dns.name.Name

# Required for exception handling
import dns.exception


DEFAULT_TIMEOUT = 5.0


class ValidationError(Exception):
    pass


def _resolve(domain: str, rdtype: str, nameserver: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT):
    """Resolve a single RRset using dns.resolver for convenience.
    Returns (rdataset, response) where rdataset is a dns.rrset.RRset or None.
    """
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        if answer.rrset is None:
            return None, answer.response
        return answer.rrset, answer.response
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        # return None but also the last response if available
        return None, getattr(e, 'response', None)


def fetch_dnskey(domain: str, nameserver: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT):
    rrset, resp = _resolve(domain, 'DNSKEY', nameserver, timeout)
    return rrset, resp


def fetch_ds(domain: str, nameserver: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT):
    rrset, resp = _resolve(domain, 'DS', nameserver, timeout)
    return rrset, resp


def get_parent_name(domain: str) -> str:
    name = dns.name.from_text(domain)
    if len(name) == 1:
        return '.'
    parent = name.parent()
    # Strip trailing dot except for root zone
    parent_text = parent.to_text()
    return parent_text if parent_text == '.' else parent_text.rstrip('.')


def compute_ds_from_dnskey(name: str, dnskey_rrset: dns.rrset.RRset, digest_alg: str = 'SHA256') -> List[str]:
    """Compute DS digest(s) from DNSKEY RRset. Returns list of DS string representations."""
    ds_list = []
    name_obj = dns.name.from_text(name)
    for rdata in dnskey_rrset:
        try:
            # Try with newer API first
            ds = dns.dnssec.make_ds(name_obj, rdata, digest_alg)
            ds_list.append(str(ds))
        except Exception:
            try:
                # Try with legacy API
                ds = dns.dnssec.make_ds(name_obj, rdata, digest_alg)
                ds_list.append(str(ds))
            except Exception:
                continue
    return ds_list


def key_tag_from_dnskey(rdata) -> int:
    try:
        return dns.dnssec.key_id(rdata)
    except Exception:
        # If dns.dnssec.key_id unavailable, try .key_tag attribute
        return getattr(rdata, 'key_tag', 0)


def extract_rrsig_for_rrset(resp: Optional[dns.message.Message], rdtype: str) -> Optional[dns.rrset.RRset]:
    """Given a dns.message.Message response, extract the RRSIG rrset corresponding to rdtype in the ANSWER or AUTHORITY section."""
    if resp is None:
        return None
    # search answer then authority
    for section in (resp.answer, resp.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                # filter by type covered
                for rdata in rrset:
                    if hasattr(rdata, 'type_covered') and dns.rdatatype.to_text(rdata.type_covered) == rdtype:
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
    except Exception as e:
        return False, str(e)


def check_rrset_signature(domain: str, rdtype: str, dnskey_rrset: Optional[dns.rrset.RRset], nameserver: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    rrset, resp = _resolve(domain, rdtype, nameserver, timeout)
    result: Dict[str, Any] = {'type': rdtype, 'present': rrset is not None}
    if rrset is None or dnskey_rrset is None:
        # try to see if NXDOMAIN or NODATA with proof
        result['nx_proof'] = None
        if resp is not None and isinstance(resp, dns.message.Message) and hasattr(resp, 'authority'):
            nsec_rrs = [r for r in resp.authority if r.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)]
            result['nx_proof'] = [r.to_text() for r in nsec_rrs]
        return result

    rrsig = extract_rrsig_for_rrset(resp, rdtype)
    result['rrsig_present'] = rrsig is not None
    if rrsig is None:
        result['valid'] = False
        result['error'] = 'no RRSIG present'
        return result

    valid, message = validate_rrset_with_dnskey(rrset, rrsig, dnskey_rrset, domain)
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
                sig_ok_times.append({'inception': inception, 'expiration': expiration, 'now': now, 'valid_now': inception <= now <= expiration})
            except Exception:
                continue
        result['signatures'] = sig_ok_times
    return result


def check_parent_ds(domain: str, dnskey_rrset: Optional[dns.rrset.RRset], parent_ns: Optional[str] = None) -> Dict[str, Any]:
    parent = get_parent_name(domain)
    ds_rrset, _ = fetch_ds(domain, parent_ns)
    result: Dict[str, Any] = {'parent': parent, 'parent_ds_present': ds_rrset is not None}
    # compute DS from the child DNSKEY
    if dnskey_rrset is None:
        result['child_dnskey_present'] = False
        return result
    result['child_dnskey_present'] = True
    computed_sha256 = compute_ds_from_dnskey(domain, dnskey_rrset, 'SHA256')
    computed_sha1 = compute_ds_from_dnskey(domain, dnskey_rrset, 'SHA1')
    result['computed_ds'] = {'SHA256': computed_sha256, 'SHA1': computed_sha1}
    if ds_rrset is None:
        return result
    # Compare textual forms
    parent_ds_texts = [str(r) for r in ds_rrset]
    result['parent_ds_texts'] = parent_ds_texts
    matches = []
    for ds in parent_ds_texts:
        for cds in computed_sha256 + computed_sha1:
            if ds.split()[-1] == cds.split()[-1] or ds == cds:
                matches.append({'parent_ds': ds, 'matches_computed': cds})
    result['matches'] = matches
    return result


def get_soa_serial(domain: str, nameserver: str, timeout: int = 5) -> Optional[int]:
    """Gets the SOA serial number from the specified nameserver."""
    try:
        # Create a resolver for this nameserver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        
        # Query the SOA record
        answer = resolver.resolve(domain, 'SOA')
        if answer and answer.rrset and len(answer.rrset) > 0:
            # SOA record format: mname rname serial refresh retry expire minimum
            soa_text = str(answer.rrset[0])
            # The third field is the serial number
            fields = soa_text.split()
            if len(fields) >= 3:
                return int(fields[2])
    except Exception:
        pass
    return None

def check_soa_consistency(domain: str, nameservers: List[str]) -> Dict[str, Any]:
    """Check SOA serial consistency across authoritative nameservers."""
    results = {}
    serials = {}
    
    for ns in nameservers:
        try:
            # Resolve nameserver IP first
            ns_ip = None
            try:
                a_rr, _ = _resolve(ns, 'A')
                if a_rr:
                    ns_ip = str(a_rr[0])
            except Exception as e:
                results[ns] = {'error': f"Failed to resolve nameserver IP: {str(e)}"}
                continue

            if not ns_ip:
                results[ns] = {'error': "Could not resolve nameserver IP address"}
                continue

            # Get SOA serial from this nameserver
            serial = get_soa_serial(domain, ns_ip)
            if serial is not None:
                serials[ns] = serial
                results[ns] = {'serial': serial, 'ip': ns_ip}
            else:
                results[ns] = {'error': "Could not retrieve SOA serial"}
        except Exception as e:
            results[ns] = {'error': str(e)}

    # Analyze serial consistency
    unique_serials = set(serials.values())
    results['consistency'] = {
        'consistent': len(unique_serials) <= 1,
        'unique_serials': len(unique_serials),
        'serial_details': {str(serial): [ns for ns, ns_serial in serials.items() if ns_serial == serial] 
                          for serial in unique_serials}
    }
    
    return results

def list_authoritative_nameservers(domain: str) -> List[str]:
    ns_rrset, _ = _resolve(domain, 'NS')
    if ns_rrset is None:
        return []
    return [r.target.to_text() for r in ns_rrset]


def check_authoritative_consistency(domain: str) -> Dict[str, Any]:
    ns_list = list_authoritative_nameservers(domain)
    results: Dict[str, Any] = {}
    for ns in ns_list:
        try:
            # Try to resolve A/AAAA of the nameserver first
            ns_ip = None
            try:
                a_rr, _ = _resolve(ns, 'A')
                if a_rr:
                    ns_ip = str(a_rr[0])
            except Exception as e:
                results[ns] = {'error': f"Failed to resolve nameserver IP: {str(e)}"}
                continue
                
            if not ns_ip:
                results[ns] = {'error': "Could not resolve nameserver IP address"}
                continue
                
            # Query DNSKEY directly at that nameserver
            rrset, _ = fetch_dnskey(domain, nameserver=ns_ip)
            results[ns] = {
                'dnskey_present': rrset is not None,
                'dnskey_count': len(rrset) if rrset else 0,
                'dnskey_text': [r.to_text() for r in rrset] if rrset else [],
                'ip': ns_ip
            }
        except Exception as e:
            results[ns] = {'error': str(e)}
    # quick consistency check: compare unique signatures and key counts
    counts = [v.get('dnskey_count', 0) for v in results.values() if isinstance(v, dict)]
    try:
        results['counts_summary'] = {'min': min(counts), 'max': max(counts), 'median': statistics.median(counts) if counts else None}
    except Exception:
        results['counts_summary'] = None
    return results


def inspect_keys_and_rollover(dnskey_rrset: Optional[dns.rrset.RRset]) -> Dict[str, Any]:
    key_results: Dict[str, Any] = {'keys': [], 'sep_count': 0, 'zsk_count': 0}
    if dnskey_rrset is None:
        return key_results
    for r in dnskey_rrset:
        tag = key_tag_from_dnskey(r)
        alg = r.algorithm
        flags = r.flags
        is_sep = bool(flags & 0x0100)
        key_results['keys'].append({'tag': tag, 'algorithm': alg, 'flags': flags, 'is_sep': is_sep, 'to_text': r.to_text()})
    # heuristics: detect multiple KSK-like keys (sep set) or no KSK
    sep_count = sum(1 for k in key_results['keys'] if k['is_sep'])
    key_results['sep_count'] = sep_count
    key_results['zsk_count'] = len(key_results['keys']) - sep_count
    return key_results


def validate_domain(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Perform the batch of DNSSEC checks described in the earlier checklist.

    Returns a structured report as a dictionary.
    """
    report: Dict[str, Any] = {
        'domain': domain,
        'dnskey': {'present': False},
        'dnskey_signature': {'present': False, 'valid': False},
        'parent_ds': {},
        'rrsets': {},
        'nxdomain_test': {},
        'authoritative': {},
        'keys': {},
        'algorithms': {'algorithm_numbers': []},
        'soa_consistency': {}
    }
    
    # Split domain into labels for zone traversal
    labels = dns.name.from_text(domain).labels
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
    dnskey_rrset, _ = fetch_dnskey(domain, None, timeout)
    report['dnskey'].update({
        'present': dnskey_rrset is not None,
        'count': len(dnskey_rrset) if dnskey_rrset else 0,
        'text': [r.to_text() for r in dnskey_rrset] if dnskey_rrset else []
    })

    # 2) Parent DS check
    report['parent_ds'] = check_parent_ds(domain, dnskey_rrset)

    # 3) Verify DNSKEY RRset signatures (RRSIG over DNSKEY)
    if dnskey_rrset is not None:
        # We need the response message to extract RRSIG; fetch again to get response
        _, resp = fetch_dnskey(domain, None, timeout)
        rrsig = extract_rrsig_for_rrset(resp, 'DNSKEY') if resp else None
        report['dnskey_signature'].update({
            'present': rrsig is not None,
            'valid': False,
            'error': None
        })
        if rrsig is not None:
            valid, message = validate_rrset_with_dnskey(dnskey_rrset, rrsig, dnskey_rrset, domain)
            report['dnskey_signature'].update({
                'valid': valid,
                'error': message if not valid else None
            })

    # 4) Check common RRsets
    rrtypes = ['SOA', 'NS', 'A', 'AAAA', 'MX', 'TXT']
    rrchecks = {}
    for t in rrtypes:
        rrchecks[t] = check_rrset_signature(domain, t, dnskey_rrset, None, timeout)
    report['rrsets'] = rrchecks

    # 5) NXDOMAIN / denial proofs check (test non-existent name)
    test_name = f"this-name-should-not-exist-{int(time.time())}.{domain}"
    nx_result = check_rrset_signature(test_name, 'A', dnskey_rrset, None, timeout)
    report['nxdomain_test'] = nx_result

    # 6) Authoritative consistency
    report['authoritative'] = check_authoritative_consistency(domain)

    # 7) Key inspection and rollover hints
    report['keys'] = inspect_keys_and_rollover(dnskey_rrset)

    # 8) Algorithms & digest check (simple heuristics)
    algs = set()
    if dnskey_rrset is not None:
        for r in dnskey_rrset:
            algs.add(r.algorithm)
    report['algorithms'] = {'algorithm_numbers': sorted(list(algs))}

    return report


def pretty_report(report: Dict[str, Any]) -> str:
    import json
    return json.dumps(report, indent=2)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python dnssec_validator.py <domain>')
        sys.exit(1)
    domain = sys.argv[1].rstrip('.')
    try:
        out = validate_domain(domain)
        print(pretty_report(out))
    except Exception as e:
        print('Validation failed:', e)
        raise
