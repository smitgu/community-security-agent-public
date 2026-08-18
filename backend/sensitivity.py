"""
sensitivity.py — Local document sensitivity classification and anonymisation layer.

Pipeline (all steps run on-device, no external API calls):
  1. Regex scan  — fast, catches credentials, explicit labels, structured PII
  2. spaCy NER   — context-aware scan for ORG / PERSON / LOCATION / GPE / LOC entities
  3. Classify    — returns CONFIDENTIAL | INTERNAL | PUBLIC
  4. Scrub       — replaces detected entities with stable HMAC-SHA256 tokens, builds mapping table
  5. Generalise  — reduces precision of salaries (to $20k bands) and dates (to quarters)
  6. Encrypt     — Fernet-encrypts mapping table for secure storage
  7. De-anonymise— restores real names from mapping table after Gemini has responded

Usage in api.py:
    from sensitivity import sensitivity_gate, deanonymize, ConfidentialDocumentError
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# ── Cryptographic Secrets Derivation ───────────────────────────────────────────

_HMAC_SECRET = None
_fernet = None

def _get_hmac_secret() -> bytes:
    """Retrieve or derive the HMAC secret for stable pseudonymisation."""
    global _HMAC_SECRET
    if _HMAC_SECRET is None:
        raw = os.getenv("HMAC_SECRET") or os.getenv("CHROMA_SECRET")
        if not raw:
            raise RuntimeError("HMAC_SECRET or CHROMA_SECRET must be set")
        _HMAC_SECRET = raw.encode("utf-8")
    return _HMAC_SECRET

def _get_fernet() -> Fernet:
    """Retrieve or derive a stable 32-byte Fernet key for mapping encryption."""
    global _fernet
    if _fernet is None:
        secret = os.getenv("FERNET_KEY") or os.getenv("CHROMA_SECRET")
        if not secret:
            raise RuntimeError("FERNET_KEY or CHROMA_SECRET must be set")
        derived = hashlib.sha256(secret.encode("utf-8")).digest()
        fernet_key = base64.urlsafe_b64encode(derived)
        _fernet = Fernet(fernet_key)
    return _fernet

# ── Mapping Encryption / Decryption ─────────────────────────────────────────────

def encrypt_mapping(mapping: dict) -> str:
    """Encrypt the reverse-mapping dictionary using Fernet."""
    if not mapping:
        return ""
    try:
        data = json.dumps(mapping).encode("utf-8")
        return _get_fernet().encrypt(data).decode("ascii")
    except Exception as e:
        logger.error("encrypt_mapping: encryption failed: %s", e)
        return ""

def decrypt_mapping(encrypted_str: str) -> dict:
    """Decrypt the Fernet-encrypted mapping back into a Python dictionary."""
    if not encrypted_str:
        return {}
    try:
        decrypted = _get_fernet().decrypt(encrypted_str.encode("ascii"))
        return json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        logger.warning("decrypt_mapping: failed to decrypt mapping: %s", e)
        return {}

# ── spaCy lazy loader ─────────────────────────────────────────────────────────
_nlp = None

def _get_nlp():
    """Lazily load spaCy model so API startup is not blocked."""
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load("en_core_web_lg")
            logger.info("sensitivity: spaCy model 'en_core_web_lg' loaded")
        except Exception as e:
            logger.warning(
                "sensitivity: spaCy model 'en_core_web_lg' unavailable (%s). "
                "NER scan will be skipped. Run: "
                "python -m spacy download en_core_web_lg", e
            )
            _nlp = None
    return _nlp

# ── Custom exception ──────────────────────────────────────────────────────────

class ConfidentialDocumentError(Exception):
    """Raised when a document is classified CONFIDENTIAL to block external API calls."""
    pass

# ── Regex patterns ────────────────────────────────────────────────────────────

# Patterns that hard-classify a document as CONFIDENTIAL
_CONFIDENTIAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bconfidential\b",                                   "explicit_confidential_label"),
    (r"(?i)do\s+not\s+distribute",                              "do_not_distribute"),
    (r"(?i)internal\s+use\s+only",                              "internal_use_only"),
    (r"(?i)not\s+for\s+release",                                "not_for_release"),
    (r"(?i)(private|secret)\s+key",                             "private_key"),
    (r"(?i)api[_\s]?key\s*[=:]\s*\S+",                         "api_key_assignment"),
    (r"(?i)password\s*[=:]\s*\S+",                              "password_assignment"),
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",                    "bearer_token"),
    (r"\b\d{3}-\d{2}-\d{4}\b",                                  "ssn_pattern"),
    (r"(?i)active\s+investigation",                              "active_investigation"),
]

# Patterns that classify a document as INTERNAL (if not already CONFIDENTIAL)
_INTERNAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\binternal\s+report\b",                              "internal_report"),
    (r"(?i)\bour\s+company\b",                                  "our_company"),
    (r"(?i)\bour\s+organi[sz]ation\b",                          "our_org"),
    (r"(?i)\bour\s+(team|staff|management|board)\b",            "our_team"),
    (r"(?i)\bemployee\b",                                        "employee_mention"),
    (r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",      "email_address"),
    (r"(?i)\bproprietary\b",                                     "proprietary"),
    (r"(?i)\bunpublished\b",                                     "unpublished"),
]

# Supplemental Regex PII patterns for redaction (from PDF specification)
_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",     "EMAIL"),
    (r"\b\+?\d[\d\s\-().]{7,}\d\b",                             "PHONE"),
    (r"\b\d{3}-\d{2}-\d{4}\b",                                  "SSN"),
]

# NER entity labels that trigger INTERNAL classification and are redacted
_INTERNAL_NER_LABELS = {"ORG", "PERSON", "GPE", "LOC"}
_CONFIDENTIAL_NER_LABELS: set[str] = set()

# ── Detection dataclass ───────────────────────────────────────────────────────

@dataclass
class DetectedEntity:
    entity_type: str        # NER label (ORG, PERSON…) or regex category name
    original_value: str     # what was found in the text
    placeholder: str = ""   # the [TYPE:hash] token that replaces it
    source: str = "regex"   # "regex" or "ner"

# ── Step 1: Regex scan ────────────────────────────────────────────────────────

def _regex_scan(text: str) -> tuple[str, list[DetectedEntity]]:
    """Scan text for CONFIDENTIAL and INTERNAL regex signals."""
    level = "PUBLIC"
    found: list[DetectedEntity] = []

    for pattern, category in _CONFIDENTIAL_PATTERNS:
        for m in re.finditer(pattern, text):
            found.append(DetectedEntity(
                entity_type=category,
                original_value=m.group(0),
                source="regex",
            ))
            level = "CONFIDENTIAL"

    if level != "CONFIDENTIAL":
        for pattern, category in _INTERNAL_PATTERNS:
            for m in re.finditer(pattern, text):
                found.append(DetectedEntity(
                    entity_type=category,
                    original_value=m.group(0),
                    source="regex",
                ))
                if level == "PUBLIC":
                    level = "INTERNAL"

    return level, found

# ── Step 2: spaCy NER scan ────────────────────────────────────────────────────

def _ner_scan(text: str) -> tuple[str, list[DetectedEntity]]:
    """Run spaCy NER scan on the document."""
    nlp = _get_nlp()
    if nlp is None:
        return "PUBLIC", []

    # Only scan first 10 000 chars to keep latency reasonable
    doc = nlp(text[:10_000])

    level = "PUBLIC"
    found: list[DetectedEntity] = []

    for ent in doc.ents:
        if ent.label_ in _CONFIDENTIAL_NER_LABELS:
            found.append(DetectedEntity(
                entity_type=ent.label_,
                original_value=ent.text,
                source="ner",
            ))
            level = "CONFIDENTIAL"
        elif ent.label_ in _INTERNAL_NER_LABELS:
            found.append(DetectedEntity(
                entity_type=ent.label_,
                original_value=ent.text,
                source="ner",
            ))
            if level == "PUBLIC":
                level = "INTERNAL"

    return level, found

# ── Step 3: Combine and classify ──────────────────────────────────────────────

def _classify(regex_level: str, ner_level: str) -> str:
    """Return the highest (most restrictive) classification."""
    priority = {"CONFIDENTIAL": 2, "INTERNAL": 1, "PUBLIC": 0}
    both = [regex_level, ner_level]
    return max(both, key=lambda x: priority.get(x, 0))

# ── Step 4: Pseudonymisation with Hashing (HMAC-SHA256) ───────────────────────

def pseudonymise(value: str, prefix: str = "ID") -> str:
    """Produce a stable, opaque, and semantic token from a PII value via HMAC-SHA256."""
    secret = _get_hmac_secret()
    digest = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"[{prefix}:{digest}]"

def _scrub(text: str, ner_entities: list[DetectedEntity]) -> tuple[str, dict[str, str]]:
    """
    Replace PII (NER entities + supplementary regex entities) with stable HMAC tokens.
    Returns (scrubbed_text, mapping_table).
    """
    mapping: dict[str, str] = {}
    
    # 1. Gather all unique raw candidate values to scrub
    # Combine spaCy NER hits and any supplementary regex patterns (EMAIL, PHONE, SSN)
    candidates: list[tuple[str, str]] = []  # list of (raw_text, category)
    
    # Add spaCy NER entities
    for ent in ner_entities:
        candidates.append((ent.original_value, ent.entity_type))
        
    # Supplement with Regex PII patterns
    for pattern, label in _SENSITIVE_PATTERNS:
        for m in re.finditer(pattern, text):
            candidates.append((m.group(0), label))

    if not candidates:
        return text, {}

    # Sort candidates by length (descending) so we replace longer multi-word phrases
    # before individual sub-words (e.g. "Jane Doe" before "Jane")
    unique_candidates = sorted(list(set(candidates)), key=lambda x: len(x[0]), reverse=True)

    scrubbed = text
    for orig, label in unique_candidates:
        # Construct prefix (e.g. PERSON -> PERSON, ORG -> ORG, EMAIL -> EMAIL)
        prefix = label.upper()
        token = pseudonymise(orig, prefix=prefix)
        mapping[token] = orig
        scrubbed = scrubbed.replace(orig, token)

    return scrubbed, mapping

# ── Step 5: Data Generalisation and Structured Abstraction ─────────────────────

def generalise_salary(text: str) -> str:
    """Replace exact salary figures with band labels (e.g. Band: $120k–$140k)."""
    def _band(m):
        try:
            val = int(re.sub(r'[,$]', '', m.group(1)))
            band_low = (val // 20000) * 20000
            band_high = band_low + 20000
            return f"Band: ${band_low//1000}k-${band_high//1000}k"
        except Exception:
            return m.group(0)
    # Matches figures like $134,500 per annum, $134,500 p.a., or just $134500
    return re.sub(r'\$([\d,]+)(?:\.\d+)?\s*(?:per annum|p\.a\.)?', _band, text)

def generalise_dates(text: str) -> str:
    """Round dates and timestamps to the nearest quarter (e.g. Q1 2024)."""
    def _qtr(m):
        try:
            raw_val = m.group(0)
            # Standardize Z offset for fromisoformat compatibility
            if raw_val.endswith('Z'):
                raw_val = raw_val[:-1] + '+00:00'
            dt = datetime.fromisoformat(raw_val)
            q = (dt.month - 1) // 3 + 1
            return f"Q{q} {dt.year}"
        except ValueError:
            return m.group(0)
    # Matches dates like 2024-03-14 or timestamps like 2024-03-14 09:32:11
    return re.sub(r'\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b', _qtr, text)

# ── De-anonymisation / Re-identification ──────────────────────────────────────

def deanonymize(text: str, mapping: dict[str, str]) -> str:
    """Restore real entity names in a string using the mapping table."""
    if not mapping:
        return text
    # Sort keys by length descending to prevent substring collisions
    for placeholder, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(placeholder, original)
    return text

# ── Main Entry Point ──────────────────────────────────────────────────────────

def sensitivity_gate(
    raw_text: str,
) -> tuple[str, str, dict[str, str], list[dict]]:
    """
    Run the full local sensitivity and data protection pipeline.
    
    Returns:
        safe_text    – text safe to send externally (anonymised and generalised)
        level        – "PUBLIC" | "INTERNAL" | "CONFIDENTIAL"
        mapping      – { "[ORG:4a12...]": "Acme Corp", … }
        entities     – list of dicts describing what was detected (for audit log)
    """
    # ── 1. Regex Scan
    regex_level, regex_hits = _regex_scan(raw_text)

    # ── 2. spaCy NER Scan
    ner_level, ner_hits = _ner_scan(raw_text)

    # ── 3. Classify Document Tier
    level = _classify(regex_level, ner_level)

    all_hits = regex_hits + ner_hits
    entities = [
        {
            "entity_type":    e.entity_type,
            "original_value": e.original_value,
            "source":         e.source,
        }
        for e in all_hits
    ]

    logger.info(
        "sensitivity_gate: level=%s regex=%s ner=%s entities=%d",
        level, regex_level, ner_level, len(entities),
    )

    # ── 4. Act on Classification
    if level == "CONFIDENTIAL":
        raise ConfidentialDocumentError(
            f"Document classified CONFIDENTIAL — {len(entities)} sensitive signal(s) detected. "
            "Stored internally. No external API call made."
        )

    if level == "INTERNAL":
        # 1. Apply data generalisation first to prevent overlap issues
        safe_text = generalise_salary(raw_text)
        safe_text = generalise_dates(safe_text)
        
        # 2. Scrub NER and Regex PII entities using stable HMAC-SHA256 tokens
        safe_text, mapping = _scrub(safe_text, ner_hits)
        
        return safe_text, level, mapping, entities

    # PUBLIC — return unchanged
    return raw_text, level, {}, entities
