"""
lookalike_risk.py

Generate look-alike domain variants and estimate a probability (0..1) representing
how "at risk" the target domain is from look-alike / typosquatting attacks.

Features:
 - Typo-squatting variants (deletion, insertion, substitution, transposition)
 - Keyboard-adjacent substitutions
 - Common homoglyph substitutions for visual confusion
 - Options to check DNS for whether variant resolves
 - Scoring: combines number of variants, availability (if checked) and visual similarity

Usage:
    from lookalike_risk import assess_domain_risk
    report = assess_domain_risk("example.com", check_dns=False, max_variants=500)
    print(report["risk_score"], report["summary"])
"""

from __future__ import annotations
import random
import string
import unicodedata
from typing import List, Set, Dict, Tuple, Optional
import difflib
import math
try:
    from .resolver import Resolver
except:
    from resolver import Resolver

# ----- Configurable small datasets (keyboard adjacency + homoglyphs) -----
# Keyboard adjacency (QWERTY) for simple substitution/insertion choices
_QWERTY_ADJ = {
    'a': 'qwsz',
    'b': 'vghn',
    'c': 'xdfv',
    'd': 'ersfxc',
    'e': 'wsdfr',
    'f': 'drtgvc',
    'g': 'ftyhvb',
    'h': 'gyujnb',
    'i': 'ujko',
    'j': 'huikmn',
    'k': 'jiolm,',
    'l': 'kop;.',
    'm': 'njk,',
    'n': 'bhjm',
    'o': 'iklp',
    'p': 'ol;[',
    'q': 'wa',
    'r': 'tefd',
    's': 'awedxz',
    't': 'ryfg',
    'u': 'yhji',
    'v': 'cfgb',
    'w': 'qase',
    'x': 'zsdc',
    'y': 'tghu',
    'z': 'asx',
    '1': '2q',
    '2': '13w',
    '3': '24e',
    '4': '35r',
    '5': '46t',
    '6': '57y',
    '7': '68u',
    '8': '79i',
    '9': '80o',
    '0': '9p',
    '-': 'p0=',
}

# Homoglyph substitutions - small but useful mapping
_HOMOGLYPHS = {
    'a': ['@', 'á', 'à', 'ä', 'ɑ', 'Α'],   # includes greek/latin lookalikes
    'b': ['6', '8', 'ß'],
    'c': ['ç', '¢', 'с'],  # cyrillic 'с'
    'd': ['cl'],           # 'cl' looks like 'd' in some fonts
    'e': ['3', 'é', 'è', 'ë'],
    'i': ['1', 'l', 'í', 'ı'],  # dotless i
    'l': ['1', 'I', '|', 'Ɩ'],
    'o': ['0', 'Ο', 'ο', '°'],
    's': ['5', '$', 'ѕ'],  # cyrillic 'ѕ'
    't': ['7', '+'],
    'm': ['rn'],           # 'rn' looks like 'm'
    'u': ['µ'],
    'y': ['γ'],
    'g': ['9'],
}

# Characters we generally don't modify (TLD separators, dots)
_SAFE_CHARS = set(string.ascii_letters + string.digits + '-')

# ----- Utility functions -----

def _split_domain(domain: str) -> Tuple[str, str]:
    """Split "example.co.uk" into ("example", "co.uk") by taking the leftmost label
    as the 'sld' we mutate, and the remainder as TLD/psl part.
    This is simple: it doesn't consult a public suffix list. If you want PSL-aware
    splitting, integrate e.g. the 'publicsuffix2' package.
    
    Args:
        domain: full domain name
        
    Returns:
        Tuple of (sld, tld_part)
    """
    parts = domain.strip().lower().split('.')
    if len(parts) < 2:
        return domain, ''
    sld = parts[0]
    tld = '.'.join(parts[1:])
    return sld, tld

def _mutations_deletion(s: str) -> Set[str]:
    """Delete one character
    
    Args:
        s: input string
    
    Returns:
        Set of strings with one character deleted
    """
    out = set()
    for i in range(len(s)):
        out.add(s[:i] + s[i+1:])
    return out

def _mutations_transpose(s: str) -> Set[str]:
    """Swap adjacent characters
    
    Args:
        s: input string
    
    Returns:
        Set of strings with adjacent characters swapped
    """
    out = set()
    for i in range(len(s) - 1):
        out.add(s[:i] + s[i+1] + s[i] + s[i+2:])
    return out

def _mutations_replace_adjacent(s: str) -> Set[str]:
    """Replace characters with keyboard-adjacent characters
    
    Args:
        s: input string

    Returns:
        Set of strings with one character replaced by an adjacent key
    """
    out = set()
    for i, ch in enumerate(s):
        low = ch.lower()
        if low in _QWERTY_ADJ:
            for repl in _QWERTY_ADJ[low]:
                new = s[:i] + repl + s[i+1:]
                out.add(new)
    return out

def _mutations_insert_adjacent(s: str) -> Set[str]:
    """Insert keyboard-adjacent characters
    
    Args:
        s: input string

    Returns:
        Set of strings with one character inserted (adjacent key)
    """
    out = set()
    for i, ch in enumerate(s):
        low = ch.lower()
        if low in _QWERTY_ADJ:
            for repl in _QWERTY_ADJ[low]:
                new = s[:i] + repl + s[i:]
                out.add(new)
    # also insert common separators or dots
    for i in range(1, len(s)):
        out.add(s[:i] + '-' + s[i:])
        out.add(s[:i] + '.' + s[i:])  # might create subdomain-like forms
    return out

def _mutations_repeat_char(s: str) -> Set[str]:
    """Repeat a character (double letters omitted or added)
    
    Args:
        s: input string

    Returns:
        Set of strings with one character duplicated
    """
    out = set()
    for i in range(len(s)):
        out.add(s[:i] + s[i] + s[i:] )  # duplicate
    return out

def _mutations_homoglyph(s: str) -> Set[str]:
    """Substitute characters with homoglyphs (one-per-string substitutions)
    
    Args:
        s: input string

    Returns:
        Set of strings with one character replaced by a homoglyph
    """
    out = set()
    for i, ch in enumerate(s):
        low = ch.lower()
        if low in _HOMOGLYPHS:
            for glyph in _HOMOGLYPHS[low]:
                # preserve case where reasonable
                if ch.isupper():
                    glyph_candidate = glyph.upper()
                else:
                    glyph_candidate = glyph
                out.add(s[:i] + glyph_candidate + s[i+1:])
    return out

def _normalize_variant(label: str) -> str:
    """Normalize a label (NFKC) and remove impossible characters for DNS labels if needed.
    
    Args:
        label: input label string

    Returns:
        Normalized label string, or empty string if invalid
    """
    norm = unicodedata.normalize('NFKC', label)
    # strip spaces
    norm = norm.replace(' ', '')
    # remove leading/trailing hyphen issues
    if norm.startswith('-'):
        norm = norm[1:]
    if norm.endswith('-'):
        norm = norm[:-1]
    # very naive safe-char filter: allow any Unicode but keep label relatively small
    if len(norm) == 0:
        return ''
    if len(norm) > 63:
        return norm[:63]
    return norm


def _generate_variants_for_label(label: str, max_variants: int = 500) -> Set[str]:
    """Combine many mutation strategies to produce variants for the leftmost label.
    
    Args:
        label: input label (e.g. "example" from "example.com")

    Returns:
        Set of plausible look-alike variants (up to max_variants)
    """
    gen: Set[str] = set()
    # simple typos
    gen |= _mutations_deletion(label)
    gen |= _mutations_transpose(label)
    gen |= _mutations_replace_adjacent(label)
    gen |= _mutations_insert_adjacent(label)
    gen |= _mutations_repeat_char(label)
    gen |= _mutations_homoglyph(label)

    # additional heuristic substitutions: replace letter with visually similar multi-char combos
    # e.g. 'm' -> 'rn', 'd' -> 'cl'
    for i, ch in enumerate(label):
        if ch.lower() == 'm':
            gen.add(label[:i] + 'rn' + label[i+1:])
        if ch.lower() == 'd':
            gen.add(label[:i] + 'cl' + label[i+1:])

    # produce some extra random single edit variants to expand coverage
    letters = string.ascii_lowercase + string.digits
    for _ in range(50):
        i = random.randrange(0, max(1, len(label)))
        new = label[:i] + random.choice(letters) + label[i+1:]
        gen.add(new)

    # normalize and filter invalid labels
    cleaned = set()
    for v in gen:
        nv = _normalize_variant(v)
        # don't include identical or empty
        if not nv or nv == label:
            continue
        # avoid labels that start/end with hyphen or contain consecutive dots
        if nv.startswith('-') or nv.endswith('-'):
            continue
        if '..' in nv:
            continue
        cleaned.add(nv)
        if len(cleaned) >= max_variants:
            break
    return cleaned

def _build_full_domains(label_variants: Set[str], tld_part: str) -> List[str]:
    """Append TLD part back. If tld_part is empty, return labels only.
    
    Args:
        label_variants: set of label variants (e.g. "examp1e", "exampl3")
        tld_part: TLD/psl part (e.g. "com" or "co.uk")

    Returns:
        List of full domain variants
    """
    out = []
    for lab in label_variants:
        if tld_part:
            out.append(f"{lab}.{tld_part}")
        else:
            out.append(lab)
    return out

# ----- Similarity and scoring helpers -----

def _similarity(a: str, b: str) -> float:
    """Return a similarity ratio between 0 and 1 using SequenceMatcher.
    
    Args:
        a: first string
        b: second string

    Returns:
        Similarity ratio (0..1)
    """
    return difflib.SequenceMatcher(None, a, b).ratio()

def _score_components(
    num_variants: int,
    prop_resolving: Optional[float],
    avg_similarity: float,
    params: Optional[Dict] = None) -> float:
    """Combine components into a single risk score in [0,1].
    - num_variants: total plausible variants generated (raw)
    - prop_resolving: proportion (0..1) of variants that resolve (None if not checked)
    - avg_similarity: average similarity (0..1) between variants and original

    The function is tunable. Default behavior:
      - variant_factor = log10(1+num_variants) / log10(1+max_var_cap)
      - availability factor: prop_resolving (if known) else 0.5
      - similarity factor: avg_similarity
      - final score = weighted sum, clamped [0,1]
    
    Args:
        num_variants: number of generated variants
        prop_resolving: proportion of variants that resolved (0..1) or None
        avg_similarity: average similarity (0..1)
        params: optional dict of parameters to tune scoring
            - max_var_cap: int, cap for scaling variant count (default 1000)
            - w_avail: weight for availability factor (default 0.5)
            - w_count: weight for variant count factor (default 0.25)
            - w_sim: weight for similarity factor (default 0.25)

    Returns:
        Risk score in [0,1]
    """
    if params is None:
        params = {}
    max_var_cap = params.get('max_var_cap', 1000)  # scale for counting variants
    w_avail = params.get('w_avail', 0.5)
    w_count = params.get('w_count', 0.25)
    w_sim = params.get('w_sim', 0.25)

    # variant factor: logarithmic scaling so doubling variants has diminishing returns
    variant_factor = math.log10(1 + num_variants) / math.log10(1 + max_var_cap)
    variant_factor = max(0.0, min(variant_factor, 1.0))

    # availability factor: if None (no DNS check) we assume a moderate default
    if prop_resolving is None:
        availability = 0.5
    else:
        availability = max(0.0, min(prop_resolving, 1.0))

    sim = max(0.0, min(avg_similarity, 1.0))

    score = w_avail * availability + w_count * variant_factor + w_sim * sim
    score = max(0.0, min(score, 1.0))
    return score

# ----- Main API -----

def assess_domain_risk(domain: str,
                       check_dns: bool = False,
                       max_variants: int = 500,
                       timeout: float = 2.0) -> Dict:
    """
    Assess look-alike/typosquatting risk for `domain`.

    Args:
      domain: domain to assess, e.g. "example.com"
      check_dns: if True, attempt to resolve each generated variant (requires dnspython).
      max_variants: cap on how many variants to keep/generate
      timeout: DNS query timeout in seconds (if check_dns enabled)

    Returns:
      dict with keys:
        - domain
        - risk_score (0..1)
        - summary (str)
        - details: dict with
        - all_variants
        - all_variants_count
        - resolving_variants (if check_dns)
    """
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]

    sld, tld_part = _split_domain(domain)
    # 1) Generate label variants
    label_variants = _generate_variants_for_label(sld, max_variants=max_variants)
    # 2) Build full candidate domains
    candidates = _build_full_domains(label_variants, tld_part)
    # deduplicate and remove exact match if present
    candidates = list(dict.fromkeys(candidates))
    candidates = [c for c in candidates if c != domain]

    # limit to max_variants
    if len(candidates) > max_variants:
        candidates = candidates[:max_variants]

    # 3) Optionally check DNS resolution (simple A/AAAA/NS query)
    resolving = set()
    if check_dns:
        resolver = Resolver(timeout=timeout)
        for cand in candidates:
            # Query NS first (fast indicator domain exists) then A/AAAA
            rrset, _ = resolver.resolve(cand, 'NS')
            if rrset is not None and len(rrset) > 0:
                resolving.add(cand)
                continue
            rrset, _ = resolver.resolve(cand, 'A')
            if rrset is not None and len(rrset) > 0:
                resolving.add(cand)
                continue
            rrset, _ = resolver.resolve(cand, 'AAAA')
            if rrset is not None and len(rrset) > 0:
                resolving.add(cand)
                continue

    # 4) Compute similarity scores
    sim_scores = [ _similarity(domain, c) for c in candidates ]
    avg_similarity = float(sum(sim_scores) / len(sim_scores)) if sim_scores else 0.0

    num_variants = len(candidates)
    num_resolving = len(resolving) if check_dns else None
    prop_resolving = None
    if num_resolving:
        if (check_dns and num_variants > 0):
            prop_resolving = num_resolving / num_variants

    risk_score = _score_components(num_variants=num_variants,
                                   prop_resolving=prop_resolving,
                                   avg_similarity=avg_similarity)

    sorted_candidates = sorted(candidates, key=lambda c: (_similarity(domain, c), c), reverse=True)

    details = {
        'num_variants_generated': num_variants,
        'num_resolving': num_resolving,
        'prop_resolving': prop_resolving,
        'avg_similarity': avg_similarity,
    }

    return {
        'domain': domain,
        'risk_score': risk_score,
        'summary': f"Estimated risk {risk_score:.3f} (variants={num_variants}, resolving={num_resolving})",
        'details': details,
        'all_variants': sorted_candidates,
        'all_variants_count': num_variants,
        'resolving_variants': list(resolving),
    }

# ----- Example runner -----

if __name__ == "__main__":
    test_domains = [
        "example.com",
        "google.com",
        "paypal.com",
        "xn--p1ai"  # example punycode
    ]
    for td in test_domains:
        try:
            report = assess_domain_risk(td, check_dns=False, max_variants=300)
            print(f"{td} → score={report['risk_score']:.3f}  summary={report['summary']}")
            print(" sample:", report['sample_variants'][:6])
            print()
        except Exception as e:
            print("Error for", td, e)
