"""Local-only tests for the sensitivity gate (no Gemini, no DB, no spaCy)."""
import os
import sys

os.environ.setdefault("CHROMA_SECRET", "test-secret")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sensitivity as s  # noqa: E402


def test_scrub_respects_token_boundaries():
    ents = [s.DetectedEntity("GPE", "US", source="ner")]
    text = "Bridged 4M USDC to a US exchange."
    scrubbed, mapping = s._scrub(text, ents)
    assert "USDC" in scrubbed, scrubbed
    assert "[GPE:" in scrubbed
    assert s.deanonymize(scrubbed, mapping) == text


def test_scrub_email_round_trip():
    text = "Contact ops@acme.io for details."
    scrubbed, mapping = s._scrub(text, [])
    assert "ops@acme.io" not in scrubbed
    assert s.deanonymize(scrubbed, mapping) == text


def test_pseudonymise_is_stable():
    assert s.pseudonymise("Acme", "ORG") == s.pseudonymise("Acme", "ORG")
    assert s.pseudonymise("Acme", "ORG") != s.pseudonymise("Acme Corp", "ORG")


def test_explicit_confidential_label_blocks():
    level, hits = s._regex_scan("CONFIDENTIAL - do not distribute")
    assert level == "CONFIDENTIAL"
    assert {h.entity_type for h in hits} >= {"explicit_confidential_label", "do_not_distribute"}


def test_internal_signals_scrub_but_do_not_block():
    safe, level, mapping, entities = s.sensitivity_gate(
        "Internal report: employee alice@acme.io approved the transfer."
    )
    assert level == "INTERNAL"
    assert "alice@acme.io" not in safe
    assert mapping and s.deanonymize(safe, mapping).count("alice@acme.io") == 1


def test_public_text_passes_unchanged():
    text = "Attacker drained the pool via a flash loan on 2024-03-14."
    safe, level, mapping, _ = s.sensitivity_gate(text)
    assert level == "PUBLIC" and safe == text and mapping == {}


def test_salary_band_keeps_following_space():
    out = s.generalise_salary("paid $134,500 to the contractor")
    assert out == "paid Band: $120k-$140k to the contractor", out


def test_dates_round_to_quarter():
    assert s.generalise_dates("mined 2024-03-14T09:32:11Z") == "mined Q1 2024"


def test_fernet_mapping_round_trip():
    m = {"[ORG:abc]": "Acme"}
    assert s.decrypt_mapping(s.encrypt_mapping(m)) == m
