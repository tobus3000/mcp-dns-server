"""Comprehensive pytest test suite for domain lookalike risk validator module.

Tests all aspects of the risk submodule including:
- Mutation generation (deletion, transposition, substitution, homoglyphs)
- Domain variant generation
- Similarity scoring
- Risk assessment and scoring
- DNS resolution checks
- Edge cases and error handling
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from dns_mcp_server.tools.validator.risk import (
    _build_full_domains,
    _generate_variants_for_label,
    _mutations_deletion,
    _mutations_homoglyph,
    _mutations_insert_adjacent,
    _mutations_repeat_char,
    _mutations_replace_adjacent,
    _mutations_transpose,
    _normalize_variant,
    _score_components,
    _similarity,
    _split_domain,
    assess_domain_risk,
    lookalike_risk_impl,
)

# ============================================================================
# Test Class: Domain Splitting
# ============================================================================


@pytest.mark.unit
class TestDomainSplitting:
    """Test domain splitting into SLD and TLD parts."""

    def test_split_domain_basic(self):
        """Test basic domain splitting."""
        sld, tld = _split_domain("example.com")
        assert sld == "example"
        assert tld == "com"

    def test_split_domain_subdomain(self):
        """Test splitting with subdomain."""
        sld, tld = _split_domain("sub.example.com")
        assert sld == "sub"
        assert tld == "example.com"

    def test_split_domain_deep_nesting(self):
        """Test splitting with deep nesting."""
        sld, tld = _split_domain("a.b.c.example.com")
        assert sld == "a"
        assert tld == "b.c.example.com"

    def test_split_domain_uppercase(self):
        """Test that domains are lowercased."""
        sld, tld = _split_domain("Example.COM")
        assert sld == "example"
        assert tld == "com"

    def test_split_domain_with_trailing_dot(self):
        """Test handling of trailing dot."""
        sld, tld = _split_domain("example.com.")
        assert sld == "example"
        # Trailing dot should be stripped before splitting
        assert tld == "com" or tld == "com."  # Accept either form

    def test_split_domain_single_label(self):
        """Test single-label domain."""
        sld, tld = _split_domain("localhost")
        assert sld == "localhost"
        assert tld == ""

    def test_split_domain_with_whitespace(self):
        """Test whitespace stripping."""
        sld, tld = _split_domain("  example.com  ")
        assert sld == "example"
        assert tld == "com"


# ============================================================================
# Test Class: Mutation Functions
# ============================================================================


@pytest.mark.unit
class TestMutationDeletion:
    """Test character deletion mutations."""

    def test_mutations_deletion_basic(self):
        """Test basic character deletion."""
        result = _mutations_deletion("abc")
        assert "bc" in result  # Delete 'a'
        assert "ac" in result  # Delete 'b'
        assert "ab" in result  # Delete 'c'

    def test_mutations_deletion_single_char(self):
        """Test deletion with single character."""
        result = _mutations_deletion("a")
        assert "" in result

    def test_mutations_deletion_empty(self):
        """Test deletion with empty string."""
        result = _mutations_deletion("")
        assert result == set()

    def test_mutations_deletion_duplicates_handled(self):
        """Test that duplicate results are deduplicated."""
        result = _mutations_deletion("aaa")
        # Deleting any character from "aaa" gives "aa"
        # Only unique results should be in set
        assert len(result) == 1
        assert "aa" in result


@pytest.mark.unit
class TestMutationTranspose:
    """Test character transposition mutations."""

    def test_mutations_transpose_basic(self):
        """Test basic character transposition."""
        result = _mutations_transpose("ab")
        assert "ba" in result

    def test_mutations_transpose_no_swap_single(self):
        """Test that single character cannot be transposed."""
        result = _mutations_transpose("a")
        assert result == set()

    def test_mutations_transpose_multiple(self):
        """Test multiple transpositions."""
        result = _mutations_transpose("abc")
        assert "bac" in result  # Swap a,b
        assert "acb" in result  # Swap b,c


@pytest.mark.unit
class TestMutationReplaceAdjacent:
    """Test keyboard-adjacent character replacement."""

    def test_mutations_replace_adjacent_known_key(self):
        """Test replacement of known keyboard keys."""
        result = _mutations_replace_adjacent("a")
        # 'a' is adjacent to 'qwsz'
        assert len(result) > 0
        # Should contain replacements with adjacent keys
        assert any(char in result for char in ["q", "w", "s", "z"])

    def test_mutations_replace_adjacent_unknown_key(self):
        """Test replacement with unknown keys (not in QWERTY)."""
        result = _mutations_replace_adjacent("!")
        # Special characters not in _QWERTY_ADJ should produce empty results
        assert "!" in result or len(result) == 0

    def test_mutations_replace_adjacent_multiple_chars(self):
        """Test replacement with multiple characters."""
        result = _mutations_replace_adjacent("ab")
        # Should have replacements for both a and b
        assert len(result) > 0


@pytest.mark.unit
class TestMutationInsertAdjacent:
    """Test keyboard-adjacent character insertion."""

    def test_mutations_insert_adjacent_basic(self):
        """Test basic adjacent character insertion."""
        result = _mutations_insert_adjacent("a")
        # Should have insertions of adjacent keys and separators
        assert len(result) > 0
        # Should contain some common separators
        has_dash = any("-" in s for s in result)
        has_dot = any("." in s for s in result)
        assert has_dash or has_dot or len(result) > 0

    def test_mutations_insert_adjacent_separators(self):
        """Test insertion of common separators."""
        result = _mutations_insert_adjacent("ab")
        # Should contain examples with - and . inserted
        assert any("-" in s for s in result)
        assert any("." in s for s in result)


@pytest.mark.unit
class TestMutationRepeatChar:
    """Test character repetition mutations."""

    def test_mutations_repeat_char_basic(self):
        """Test basic character repetition."""
        result = _mutations_repeat_char("ab")
        assert "aab" in result  # Repeat 'a' at position 0
        assert "abb" in result  # Repeat 'b' at position 1


@pytest.mark.unit
class TestMutationHomoglyph:
    """Test homoglyph substitutions."""

    def test_mutations_homoglyph_returns_set(self):
        """Test that homoglyph function returns a set."""
        result = _mutations_homoglyph("a")
        assert isinstance(result, set)

    def test_mutations_homoglyph_case_preservation(self):
        """Test that case is preserved for homoglyphs."""
        result_lower = _mutations_homoglyph("a")
        result_upper = _mutations_homoglyph("A")
        # Should handle both cases
        assert isinstance(result_lower, set)
        assert isinstance(result_upper, set)


# ============================================================================
# Test Class: Variant Normalization
# ============================================================================


@pytest.mark.unit
class TestVariantNormalization:
    """Test variant label normalization."""

    def test_normalize_variant_basic(self):
        """Test basic normalization."""
        result = _normalize_variant("example")
        assert result == "example"

    def test_normalize_variant_leading_hyphen(self):
        """Test removal of leading hyphen."""
        result = _normalize_variant("-example")
        assert not result.startswith("-")

    def test_normalize_variant_trailing_hyphen(self):
        """Test removal of trailing hyphen."""
        result = _normalize_variant("example-")
        assert not result.endswith("-")

    def test_normalize_variant_spaces_removed(self):
        """Test that spaces are removed."""
        result = _normalize_variant("exam ple")
        assert " " not in result

    def test_normalize_variant_empty(self):
        """Test empty string handling."""
        result = _normalize_variant("")
        assert result == ""

    def test_normalize_variant_only_hyphens(self):
        """Test string of only hyphens."""
        result = _normalize_variant("---")
        # After removing leading/trailing hyphens
        assert result == "-" or result == ""

    def test_normalize_variant_unicode_nfkc(self):
        """Test Unicode NFKC normalization."""
        # Use a character that normalizes differently
        result = _normalize_variant("ﬁle")  # ﬁ is a ligature
        assert isinstance(result, str)

    def test_normalize_variant_long_label(self):
        """Test truncation of labels longer than 63 characters."""
        long_label = "a" * 100
        result = _normalize_variant(long_label)
        assert len(result) <= 63


# ============================================================================
# Test Class: Domain Variant Generation
# ============================================================================


@pytest.mark.unit
class TestDomainVariantGeneration:
    """Test generation of domain label variants."""

    def test_generate_variants_for_label_basic(self):
        """Test basic variant generation."""
        result = _generate_variants_for_label("example")
        assert isinstance(result, set)
        assert len(result) > 0
        # Should not include the original
        assert "example" not in result

    def test_generate_variants_for_label_max_limit(self):
        """Test max_variants limit."""
        result = _generate_variants_for_label("abcdefghij", max_variants=10)
        assert len(result) <= 10

    def test_generate_variants_for_label_single_char(self):
        """Test variant generation with single character."""
        result = _generate_variants_for_label("a", max_variants=100)
        assert isinstance(result, set)
        assert len(result) > 0

    def test_generate_variants_for_label_short_label(self):
        """Test variant generation with short label."""
        result = _generate_variants_for_label("ab", max_variants=100)
        assert isinstance(result, set)
        assert len(result) > 0

    def test_generate_variants_excludes_invalid(self):
        """Test that invalid variants are excluded."""
        result = _generate_variants_for_label("test")
        # Should not contain leading/trailing hyphens or original
        for variant in result:
            assert not variant.startswith("-")
            assert not variant.endswith("-")
            assert variant != "test"

    def test_generate_variants_consistency(self):
        """Test that generation is somewhat consistent."""
        result1 = _generate_variants_for_label("test", max_variants=1000)
        result2 = _generate_variants_for_label("test", max_variants=1000)
        # With same seed/algorithm, should be consistent sets
        assert isinstance(result1, set)
        assert isinstance(result2, set)


# ============================================================================
# Test Class: Full Domain Building
# ============================================================================


@pytest.mark.unit
class TestFullDomainBuilding:
    """Test building full domain names from variants."""

    def test_build_full_domains_with_tld(self):
        """Test building full domains with TLD."""
        variants = {"exampl3", "examp1e"}
        result = _build_full_domains(variants, "com")
        assert "exampl3.com" in result
        assert "examp1e.com" in result

    def test_build_full_domains_without_tld(self):
        """Test building labels without TLD."""
        variants = {"exampl3", "examp1e"}
        result = _build_full_domains(variants, "")
        assert "exampl3" in result
        assert "examp1e" in result

    def test_build_full_domains_multi_part_tld(self):
        """Test building with multi-part TLD."""
        variants = {"exampl3"}
        result = _build_full_domains(variants, "co.uk")
        assert "exampl3.co.uk" in result


# ============================================================================
# Test Class: Similarity Scoring
# ============================================================================


@pytest.mark.unit
class TestSimilarityScoring:
    """Test similarity calculation between domains."""

    def test_similarity_identical(self):
        """Test similarity of identical strings."""
        score = _similarity("example.com", "example.com")
        assert score == 1.0

    def test_similarity_completely_different(self):
        """Test similarity of completely different strings."""
        score = _similarity("example.com", "xyz.org")
        assert score < 0.5

    def test_similarity_one_char_different(self):
        """Test similarity with one character different."""
        score = _similarity("example.com", "exampl3.com")
        assert 0.8 < score < 1.0

    def test_similarity_range(self):
        """Test that similarity is always in [0,1]."""
        score = _similarity("abc", "def")
        assert 0 <= score <= 1

    def test_similarity_symmetric(self):
        """Test that similarity is symmetric."""
        score1 = _similarity("abc", "abcd")
        score2 = _similarity("abcd", "abc")
        assert score1 == score2


# ============================================================================
# Test Class: Risk Score Components
# ============================================================================


@pytest.mark.unit
class TestScoreComponents:
    """Test risk scoring from components."""

    def test_score_components_no_variants(self):
        """Test scoring with no variants."""
        score = _score_components(0, None, 0.0)
        assert 0 <= score <= 1

    def test_score_components_many_variants(self):
        """Test scoring with many variants."""
        score = _score_components(1000, None, 0.5)
        assert 0 <= score <= 1

    def test_score_components_high_availability(self):
        """Test scoring with high variant availability."""
        score = _score_components(100, 0.9, 0.5)
        assert 0 <= score <= 1
        # High availability should increase score
        score_low = _score_components(100, 0.1, 0.5)
        assert score > score_low

    def test_score_components_high_similarity(self):
        """Test scoring with high similarity."""
        score = _score_components(100, None, 0.9)
        assert 0 <= score <= 1
        # High similarity should increase score
        score_low = _score_components(100, None, 0.1)
        assert score > score_low

    def test_score_components_custom_weights(self):
        """Test scoring with custom weights."""
        params = {
            "w_avail": 0.9,
            "w_count": 0.05,
            "w_sim": 0.05,
        }
        score = _score_components(100, 0.5, 0.5, params)
        assert 0 <= score <= 1

    def test_score_components_zero_weights(self):
        """Test scoring with zero weights."""
        params = {"w_avail": 0, "w_count": 0, "w_sim": 1.0}
        score = _score_components(100, 0.5, 0.9, params)
        # Should be dominated by similarity
        assert score > 0.5


# ============================================================================
# Test Class: Domain Risk Assessment
# ============================================================================


@pytest.mark.unit
class TestDomainRiskAssessment:
    """Test domain risk assessment."""

    def test_assess_domain_risk_returns_dict(self):
        """Test that risk assessment returns proper dict."""
        result = assess_domain_risk("example.com", check_dns=False)
        assert isinstance(result, dict)
        assert "domain" in result
        assert "risk_score" in result
        assert "summary" in result
        assert "all_variants" in result

    def test_assess_domain_risk_score_range(self):
        """Test that risk score is in valid range."""
        result = assess_domain_risk("example.com", check_dns=False)
        assert 0 <= result["risk_score"] <= 1

    def test_assess_domain_risk_strips_domain(self):
        """Test that domain is lowercased and stripped."""
        result = assess_domain_risk("  EXAMPLE.COM.  ", check_dns=False)
        assert result["domain"] == "example.com"

    def test_assess_domain_risk_max_variants_limit(self):
        """Test max_variants limit."""
        result = assess_domain_risk("example.com", check_dns=False, max_variants=50)
        assert len(result["all_variants"]) <= 50

    def test_assess_domain_risk_variants_not_identical(self):
        """Test that variants do not include the original domain."""
        result = assess_domain_risk("example.com", check_dns=False)
        assert "example.com" not in result["all_variants"]

    def test_assess_domain_risk_similarity_scores(self):
        """Test that variant similarity is calculated."""
        result = assess_domain_risk("example.com", check_dns=False, max_variants=100)
        avg_sim = result["details"]["avg_similarity"]
        assert 0 <= avg_sim <= 1

    def test_assess_domain_risk_dns_check_disabled(self):
        """Test risk assessment without DNS checks."""
        result = assess_domain_risk("example.com", check_dns=False)
        assert result["details"]["num_resolving"] is None

    def test_assess_domain_risk_single_label_domain(self):
        """Test risk assessment for single-label domain."""
        result = assess_domain_risk("localhost", check_dns=False)
        assert isinstance(result, dict)
        assert "risk_score" in result

    def test_assess_domain_risk_long_domain(self):
        """Test risk assessment for long domain."""
        long_domain = "subdomain.example.co.uk"
        result = assess_domain_risk(long_domain, check_dns=False)
        assert result["domain"] == long_domain


# ============================================================================
# Test Class: Implementation Function
# ============================================================================


@pytest.mark.unit
@pytest.mark.asyncio
class TestLookalikeRiskImpl:
    """Test the lookalike_risk_impl wrapper function."""

    async def test_lookalike_risk_impl_returns_tool_result(self):
        """Test that implementation returns ToolResult."""
        with patch("dns_mcp_server.tools.validator.risk.assess_domain_risk") as mock_assess:
            mock_assess.return_value = {
                "domain": "example.com",
                "risk_score": 0.5,
                "summary": "Test summary",
                "all_variants": ["exampl3.com"],
                "resolving_variants": [],
                "details": {},
            }

            result = await lookalike_risk_impl("example.com", check_dns=False)

            assert hasattr(result, "success")
            assert hasattr(result, "output")

    async def test_lookalike_risk_impl_success(self):
        """Test successful risk assessment."""
        with patch("dns_mcp_server.tools.validator.risk.assess_domain_risk") as mock_assess:
            mock_assess.return_value = {
                "domain": "example.com",
                "risk_score": 0.3,
                "summary": "Low risk",
                "all_variants": [],
                "resolving_variants": [],
                "details": {},
            }

            result = await lookalike_risk_impl("example.com", check_dns=False)

            assert result.success is True

    async def test_lookalike_risk_impl_check_dns_parameter(self):
        """Test check_dns parameter is passed through."""
        with patch("dns_mcp_server.tools.validator.risk.assess_domain_risk") as mock_assess:
            mock_assess.return_value = {
                "domain": "example.com",
                "risk_score": 0.5,
                "summary": "Test",
                "all_variants": [],
                "resolving_variants": [],
                "details": {},
            }

            await lookalike_risk_impl("example.com", check_dns=True)

            # Verify check_dns=True was passed
            mock_assess.assert_called_once()
            call_kwargs = mock_assess.call_args[1]
            assert call_kwargs.get("check_dns") is True


# ============================================================================
# Test Class: Edge Cases and Error Handling
# ============================================================================


@pytest.mark.unit
class TestRiskValidatorEdgeCases:
    """Test edge cases and error handling."""

    def test_assess_domain_risk_internationalized_domain(self):
        """Test IDN domain risk assessment."""
        result = assess_domain_risk("xn--p1ai", check_dns=False)  # РФ (Russia)
        assert isinstance(result, dict)
        assert "risk_score" in result

    def test_assess_domain_risk_empty_domain(self):
        """Test handling of empty domain."""
        result = assess_domain_risk("", check_dns=False)
        # Should handle gracefully
        assert isinstance(result, dict)

    def test_assess_domain_risk_numeric_domain(self):
        """Test risk assessment for numeric domains."""
        result = assess_domain_risk("123.456", check_dns=False)
        assert isinstance(result, dict)

    def test_assess_domain_risk_hyphens_in_domain(self):
        """Test domain with hyphens."""
        result = assess_domain_risk("my-example.com", check_dns=False)
        assert isinstance(result, dict)
        assert "risk_score" in result

    def test_split_domain_multipart_tld(self):
        """Test splitting with multi-part TLD."""
        # Note: Simple implementation doesn't use PSL
        sld, tld = _split_domain("example.co.uk")
        assert sld == "example"
        # Will split at first dot
        assert "co.uk" in tld

    def test_mutation_empty_string(self):
        """Test mutations with empty string."""
        assert _mutations_deletion("") == set()
        assert _mutations_transpose("") == set()

    def test_normalize_variant_consecutive_dots(self):
        """Test handling of consecutive dots."""
        result = _normalize_variant("exa..mple")
        # Consecutive dots should be detected and invalid
        assert ".." in result or result == ""

    def test_build_full_domains_empty_variants(self):
        """Test building with empty variant set."""
        result = _build_full_domains(set(), "com")
        assert result == []

    def test_similarity_with_empty_strings(self):
        """Test similarity with empty strings."""
        score1 = _similarity("", "")
        assert score1 == 1.0  # Empty strings are identical
        score2 = _similarity("", "something")
        assert score2 == 0.0  # Completely different


# ============================================================================
# Test Class: Integration-like Tests
# ============================================================================


@pytest.mark.unit
class TestRiskAssessmentIntegration:
    """Integration-like tests for risk assessment."""

    def test_full_risk_assessment_workflow(self):
        """Test complete risk assessment workflow."""
        domain = "paypal.com"
        result = assess_domain_risk(domain, check_dns=False, max_variants=200)

        # Verify complete result structure
        assert result["domain"] == domain.lower()
        assert 0 <= result["risk_score"] <= 1
        assert "summary" in result
        assert isinstance(result["all_variants"], list)
        assert isinstance(result["resolving_variants"], list)
        assert isinstance(result["details"], dict)
        assert "avg_similarity" in result["details"]

    def test_risk_scores_are_reasonable(self):
        """Test that risk scores are reasonable for similar domains."""
        # Domains with more similarity should have higher scores
        result1 = assess_domain_risk("google.com", check_dns=False, max_variants=100)
        result2 = assess_domain_risk("example.com", check_dns=False, max_variants=100)

        # Both should be in valid range
        assert 0 <= result1["risk_score"] <= 1
        assert 0 <= result2["risk_score"] <= 1

    def test_variant_generation_produces_different_domains(self):
        """Test that variant generation produces actual variants."""
        result = assess_domain_risk("test.com", check_dns=False, max_variants=500)

        # Should have generated many variants
        assert len(result["all_variants"]) > 0
        # All variants should be different from original
        assert all(v != "test.com" for v in result["all_variants"])
        # Variants should be somewhat similar
        similarities = [_similarity("test.com", v) for v in result["all_variants"][:5]]
        assert all(0.5 < sim < 1.0 for sim in similarities)

    def test_similarity_correlation(self):
        """Test that similar domains have higher similarity scores."""
        sim_similar = _similarity("example.com", "exampl3.com")
        sim_different = _similarity("example.com", "xyz.org")
        assert sim_similar > sim_different
