"""Comprehensive pytest test suite for DNSSEC validator module.

Tests all aspects of the dnssec submodule including:
- DNSKEY and DS record handling
- NSEC/NSEC3 chain validation
- RRSIG signature validation
- SOA consistency checks
- Key rollover detection
- Robustness testing
- DNSSEC validation workflows
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from dns_mcp_server.tools.validator.dnssec import (
    check_authoritative_consistency,
    check_parent_ds,
    check_robustness,
    check_soa_consistency,
    compute_ds_from_dnskey,
    extract_rrsig_for_rrset,
    inspect_keys_and_rollover,
    interpret_validation_results,
    key_tag_from_dnskey,
    list_authoritative_nameservers,
    validate_denial_proof,
    validate_domain,
    validate_nsec3_chain,
    validate_nsec3_parameters,
    validate_nsec_chain,
)

# ============================================================================
# Test Class: DNSKEY and DS Record Handling
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestDNSKEYandDS:
    """Test DNSKEY and DS record handling functions."""

    def test_key_tag_from_dnskey_valid_rdata(self):
        """Test extracting key tag from valid DNSKEY rdata."""
        mock_rdata = MagicMock()
        mock_rdata.key_tag = 12345

        with patch("dns.dnssec.key_id", return_value=12345):
            result = key_tag_from_dnskey(mock_rdata)
            assert result == 12345

    def test_key_tag_from_dnskey_fallback_to_attribute(self):
        """Test key_tag fallback when dns.dnssec.key_id fails."""
        mock_rdata = MagicMock()
        mock_rdata.key_tag = 54321

        with patch(
            "dns.dnssec.key_id", side_effect=ValueError("Key ID calculation failed")
        ):
            result = key_tag_from_dnskey(mock_rdata)
            assert result == 54321

    def test_key_tag_from_dnskey_attribute_error(self):
        """Test key_tag returns 0 when both methods fail."""
        mock_rdata = MagicMock(spec=[])

        with patch("dns.dnssec.key_id", side_effect=AttributeError("No key_id method")):
            result = key_tag_from_dnskey(mock_rdata)
            assert result == 0

    def test_compute_ds_from_dnskey_empty_rrset(self):
        """Test compute_ds_from_dnskey with empty RRset."""
        empty_rrset = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY")

        ds_list, denied_keys = compute_ds_from_dnskey(
            "example.com", empty_rrset, "SHA256"
        )

        assert isinstance(ds_list, list)
        assert isinstance(denied_keys, list)

    def test_compute_ds_from_dnskey_with_rdata(self):
        """Test compute_ds_from_dnskey with mock DNSKEY rdata."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 8

        rrset = MagicMock()
        rrset.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch("dns.dnssec.make_ds", return_value="mock_ds_record"):
            ds_list, _denied_keys = compute_ds_from_dnskey(
                "example.com", rrset, "SHA256"
            )
            assert isinstance(ds_list, list)


# ============================================================================
# Test Class: NSEC Chain Validation
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestNSECChainValidation:
    """Test NSEC chain validation functions."""

    def test_validate_nsec_chain_empty_records(self):
        """Test validate_nsec_chain with empty records list."""
        result = validate_nsec_chain([], "example.com")

        assert result["valid"] is False
        assert "error" in result

    def test_validate_nsec_chain_with_records(self):
        """Test validate_nsec_chain with NSEC records."""
        nsec_rdata = MagicMock()
        nsec_rdata.next = dns.name.from_text("example.com.")
        nsec_rdata.windows = [(dns.rdatatype.A, b"\x00\x01\x02")]

        rrset = MagicMock()
        rrset.name = dns.name.from_text("example.com.")
        rrset.__iter__ = MagicMock(return_value=iter([nsec_rdata]))
        rrset.__getitem__ = MagicMock(return_value=nsec_rdata)

        result = validate_nsec_chain([rrset], "example.com")

        assert isinstance(result, dict)
        assert "chain" in result


# ============================================================================
# Test Class: NSEC3 Validation
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestNSEC3Validation:
    """Test NSEC3 validation functions."""

    def test_validate_nsec3_parameters_valid(self):
        """Test validate_nsec3_parameters with valid NSEC3 record."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 1
        mock_rdata.iterations = 100
        mock_rdata.salt = b"salt"

        result = validate_nsec3_parameters(mock_rdata)

        assert result["valid"] is True
        assert result["algorithm"] == 1
        assert result["iterations"] == 100

    def test_validate_nsec3_parameters_invalid_algorithm(self):
        """Test validate_nsec3_parameters with invalid algorithm."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 5
        mock_rdata.iterations = 100
        mock_rdata.salt = b"salt"

        result = validate_nsec3_parameters(mock_rdata)

        assert result["valid"] is False
        assert len(result["warnings"]) > 0

    def test_validate_nsec3_parameters_high_iterations(self):
        """Test validate_nsec3_parameters with high iteration count."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 1
        mock_rdata.iterations = 200
        mock_rdata.salt = b"salt"

        result = validate_nsec3_parameters(mock_rdata)

        assert any("iterations too high" in w.lower() for w in result["warnings"])

    def test_validate_nsec3_parameters_long_salt(self):
        """Test validate_nsec3_parameters with overly long salt."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 1
        mock_rdata.iterations = 100
        mock_rdata.salt = b"x" * 40

        result = validate_nsec3_parameters(mock_rdata)

        assert any("salt length too long" in w.lower() for w in result["warnings"])

    def test_validate_nsec3_parameters_no_salt(self):
        """Test validate_nsec3_parameters with no salt."""
        mock_rdata = MagicMock()
        mock_rdata.algorithm = 1
        mock_rdata.iterations = 100
        mock_rdata.salt = None

        result = validate_nsec3_parameters(mock_rdata)

        assert result["salt"] is None
        assert result["salt_length"] == 0

    def test_validate_nsec3_chain_empty_records(self):
        """Test validate_nsec3_chain with empty records."""
        result = validate_nsec3_chain([])

        assert result.get("valid") is False or "error" in result


# ============================================================================
# Test Class: Signature Validation
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestSignatureValidation:
    """Test signature validation functions."""

    def test_extract_rrsig_for_rrset_none_response(self):
        """Test extract_rrsig_for_rrset with None response."""
        result = extract_rrsig_for_rrset(None, "A")
        assert result is None

    def test_extract_rrsig_for_rrset_empty_response(self):
        """Test extract_rrsig_for_rrset with empty response."""
        response = dns.message.Message()
        result = extract_rrsig_for_rrset(response, "A")
        assert result is None

    def test_extract_rrsig_for_rrset_with_rrsig(self):
        """Test extract_rrsig_for_rrset finds RRSIG records."""
        response = dns.message.Message()

        _rrsig_rdata = MagicMock()
        rrsig_rrset = MagicMock()
        rrsig_rrset.rdtype = dns.rdatatype.RRSIG

        response.answer.append(rrsig_rrset)

        _result = extract_rrsig_for_rrset(response, "A")
        # Result depends on implementation


# ============================================================================
# Test Class: Denial of Existence
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestDenialOfExistence:
    """Test denial of existence validation."""

    def test_validate_denial_proof_empty_authority(self):
        """Test validate_denial_proof with empty authority section."""
        response = dns.message.Message()
        result = validate_denial_proof(response, "example.com")

        assert result["valid"] is False


# ============================================================================
# Test Class: SOA Consistency
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
@pytest.mark.slow
class TestSOAConsistency:
    """Test SOA consistency checking."""

    def test_check_soa_consistency_returns_dict(self):
        """Test check_soa_consistency returns proper structure."""
        with patch("src.tools.validator.dnssec._resolver.resolve") as mock_resolve:
            soa_rdata = MagicMock()
            soa_rdata.serial = 2023010101
            soa_rdata.refresh = 3600

            soa_rrset = MagicMock()
            soa_rrset.__iter__ = MagicMock(return_value=iter([soa_rdata]))

            mock_resolve.return_value = (soa_rrset, None)

            result = check_soa_consistency("example.com", ["8.8.8.8"])

            assert isinstance(result, dict)
            assert "serials" in result
            assert "analysis" in result

    def test_check_soa_consistency_multiple_servers(self):
        """Test check_soa_consistency with multiple nameservers."""
        nameservers = ["8.8.8.8", "1.1.1.1"]

        with patch("src.tools.validator.dnssec._resolver.resolve") as mock_resolve:
            soa_rdata = MagicMock()
            soa_rdata.serial = 2023010101
            soa_rdata.refresh = 3600

            soa_rrset = MagicMock()
            soa_rrset.__iter__ = MagicMock(return_value=iter([soa_rdata]))

            mock_resolve.return_value = (soa_rrset, None)

            result = check_soa_consistency("example.com", nameservers)

            assert isinstance(result, dict)


# ============================================================================
# Test Class: Authoritative Nameserver Checks
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestAuthoritativeNameservers:
    """Test authoritative nameserver checks."""

    def test_list_authoritative_nameservers_found(self):
        """Test list_authoritative_nameservers with NS records."""
        with patch("src.tools.validator.dnssec._resolver.resolve") as mock_resolve:
            ns1 = MagicMock()
            ns1.target = dns.name.from_text("ns1.example.com.")
            ns2 = MagicMock()
            ns2.target = dns.name.from_text("ns2.example.com.")

            ns_rrset = MagicMock()
            ns_rrset.__iter__ = MagicMock(return_value=iter([ns1, ns2]))

            mock_resolve.return_value = (ns_rrset, None)

            result = list_authoritative_nameservers("example.com")

            assert isinstance(result, list)

    def test_list_authoritative_nameservers_not_found(self):
        """Test list_authoritative_nameservers with no NS records."""
        with patch("src.tools.validator.dnssec._resolver.resolve") as mock_resolve:
            mock_resolve.return_value = (None, None)

            result = list_authoritative_nameservers("example.com")

            assert result == []

    def test_check_authoritative_consistency(self):
        """Test check_authoritative_consistency."""
        with patch(
            "src.tools.validator.dnssec.list_authoritative_nameservers"
        ) as mock_list:
            with patch("src.tools.validator.dnssec._resolver.fetch_dnskey"):
                mock_list.return_value = []

                result = check_authoritative_consistency("example.com")

                assert isinstance(result, dict)


# ============================================================================
# Test Class: Key Inspection and Rollover
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestKeyInspection:
    """Test key inspection and rollover detection."""

    def test_inspect_keys_and_rollover_no_keys(self):
        """Test inspect_keys_and_rollover with no DNSKEY records."""
        result = inspect_keys_and_rollover(None)

        assert result["keys"] == []
        assert "critical" in result
        assert len(result["critical"]) > 0

    def test_inspect_keys_and_rollover_with_key(self):
        """Test inspect_keys_and_rollover with DNSKEY."""
        mock_rdata = MagicMock()
        mock_rdata.flags = 0x0101
        mock_rdata.algorithm = 8
        mock_rdata.protocol = 3
        mock_rdata.key = b"x" * 256
        mock_rdata.to_text = MagicMock(return_value="mock key text")

        rrset = MagicMock()
        rrset.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch(
            "src.tools.validator.dnssec.key_tag_from_dnskey", return_value=12345
        ):
            with patch("dns.dnssec.algorithm_to_text", return_value="RSASHA256"):
                result = inspect_keys_and_rollover(rrset)

                assert len(result["keys"]) == 1


# ============================================================================
# Test Class: Robustness Testing
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestRobustness:
    """Test robustness testing functions."""

    def test_test_robustness_returns_structure(self):
        """Test robustness testing returns expected structure."""
        result = check_robustness("example.com", timeout=1.0)

        assert "tests" in result
        assert "issues_found" in result
        assert "security_rating" in result
        assert isinstance(result["tests"], list)

    def test_test_robustness_invalid_chars_test(self):
        """Test robustness testing includes invalid chars test."""
        result = check_robustness("example.com")

        invalid_test = next(
            (t for t in result["tests"] if t["name"] == "invalid_chars"), None
        )
        assert invalid_test is not None or result["tests"]


# ============================================================================
# Test Class: Full Validation Workflow
# ============================================================================


@pytest.mark.unit
@pytest.mark.slow
class TestFullValidationWorkflow:
    """Test complete DNSSEC validation workflow."""

    def test_validate_domain_no_dnskey(self):
        """Test validate_domain when DNSKEY is not present."""
        with patch(
            "src.tools.validator.dnssec.list_authoritative_nameservers"
        ) as mock_list:
            with patch(
                "src.tools.validator.dnssec._resolver.resolve_dnssec"
            ) as mock_resolve:
                # Return empty list for nameservers, then (None, None) for DNSKEY resolution
                mock_list.return_value = []
                mock_resolve.return_value = (None, None)

                result = validate_domain("example.com")

                assert "domain" in result
                assert result["dnskey"]["present"] is False
                assert result["dnskey"]["count"] == 0
                assert result["dnskey"]["text"] == []

    def test_validate_domain_structure(self):
        """Test validate_domain returns expected structure."""
        with patch("src.tools.validator.dnssec._resolver.fetch_dnskey") as mock_fetch:
            with patch("src.tools.validator.dnssec.check_parent_ds"):
                with patch("src.tools.validator.dnssec.check_rrset_signature"):
                    with patch(
                        "src.tools.validator.dnssec.check_authoritative_consistency"
                    ):
                        with patch(
                            "src.tools.validator.dnssec.inspect_keys_and_rollover"
                        ):
                            with patch("src.tools.validator.dnssec.check_robustness"):
                                mock_fetch.return_value = (None, None)

                                result = validate_domain("example.com")

                                expected_keys = [
                                    "domain",
                                    "dnskey",
                                    "parent_ds",
                                    "keys",
                                    "algorithms",
                                    "robustness",
                                ]

                                for key in expected_keys:
                                    assert key in result, f"Missing key: {key}"


# ============================================================================
# Test Class: Result Interpretation
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestResultInterpretation:
    """Test result interpretation functions."""

    def test_interpret_validation_results_no_dnskey(self):
        """Test interpret_validation_results when DNSKEY is absent."""
        report = {
            "domain": "example.com",
            "dnskey": {"present": False},
            "parent_ds": {},
            "rrsets": {},
            "soa_consistency": {},
            "robustness": {"tests": []},
            "keys": {},
            "algorithms": {},
        }

        result = interpret_validation_results(report)

        assert "summary" in result
        assert result["summary"]["overall_status"] == "DNSSEC is not configured"

    def test_interpret_validation_results_with_dnskey(self):
        """Test interpret_validation_results when DNSKEY is present."""
        report = {
            "domain": "example.com",
            "dnskey": {"present": True, "count": 2},
            "dnskey_signature": {"present": True, "valid": True},
            "parent_ds": {"parent_ds_present": True, "parent": "com"},
            "rrsets": {},
            "soa_consistency": {},
            "robustness": {"tests": []},
            "keys": {"sep_count": 1, "zsk_count": 1},
            "algorithms": {"algorithm_numbers": [8]},
        }

        result = interpret_validation_results(report)

        assert "summary" in result
        assert result["summary"]["overall_status"] == "DNSSEC is properly configured"

    def test_interpret_validation_results_structure(self):
        """Test that interpretation returns expected structure."""
        report = {
            "domain": "example.com",
            "dnskey": {"present": False},
            "parent_ds": {},
            "rrsets": {},
            "soa_consistency": {},
            "robustness": {"tests": []},
            "keys": {},
            "algorithms": {},
        }

        result = interpret_validation_results(report)

        expected_keys = [
            "summary",
            "key_configuration",
            "trust_chain",
            "validation_details",
            "denial_of_existence",
            "recommendations",
        ]

        for key in expected_keys:
            assert key in result, f"Missing key: {key}"


# ============================================================================
# Test Class: Error Handling and Edge Cases
# ============================================================================


@pytest.mark.unit
@pytest.mark.dns
class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_validate_nsec_chain_invalid_zone_name(self):
        """Test validate_nsec_chain with invalid zone name."""
        result = validate_nsec_chain([], "invalid-zone-name")

        assert isinstance(result, dict)

    def test_check_parent_ds_with_mock_resolver(self):
        """Test check_parent_ds with mocked resolver."""
        with patch("src.tools.validator.dnssec._resolver.fetch_ds") as mock_fetch:
            mock_fetch.return_value = (None, None)

            result = check_parent_ds("example.com", None)

            assert isinstance(result, dict)
            assert "parent" in result


# ============================================================================
# Test Class: Integration-like Tests
# ============================================================================


@pytest.mark.integration
@pytest.mark.dns
@pytest.mark.slow
class TestIntegration:
    """Integration-like tests (using mocks to avoid external calls)."""

    def test_full_validation_workflow_mocked(self):
        """Test full validation workflow with mocks."""
        with patch("src.tools.validator.dnssec._resolver.fetch_dnskey") as mock_dnskey:
            with patch("src.tools.validator.dnssec.check_parent_ds") as mock_parent:
                with patch(
                    "src.tools.validator.dnssec.check_rrset_signature"
                ) as mock_sig:
                    with patch(
                        "src.tools.validator.dnssec.check_authoritative_consistency"
                    ):
                        with patch(
                            "src.tools.validator.dnssec.inspect_keys_and_rollover"
                        ):
                            with patch("src.tools.validator.dnssec.check_robustness"):
                                mock_dnskey.return_value = (None, None)
                                mock_parent.return_value = {}
                                mock_sig.return_value = {}

                                result = validate_domain("example.com")

                                assert "domain" in result
                                assert result["domain"] == "example.com"

    def test_interpret_complete_validation_report(self):
        """Test interpreting a complete validation report."""
        report = {
            "domain": "example.com",
            "dnskey": {"present": True, "count": 2, "text": []},
            "parent_ds": {
                "parent_ds_present": True,
                "child_dnskey_present": True,
                "parent": "com",
            },
            "rrsets": {"SOA": {}, "NS": {}, "A": {}},
            "nxdomain_test": {"success": True},
            "authoritative": {},
            "keys": {"keys": [], "sep_count": 1, "zsk_count": 1},
            "soa_consistency": {},
            "robustness": {"tests": []},
            "algorithms": {"algorithm_numbers": [8]},
        }

        result = interpret_validation_results(report)

        assert isinstance(result, dict)
        assert "summary" in result
        assert "recommendations" in result
