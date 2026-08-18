"""
chroma.py — Encrypted local ChromaDB data layer for the web application.

All content stored in ChromaDB is encrypted at rest using AES-256-GCM,
with keys derived from a master secret via SHA-256 (HKDF-style derivation).

Collections mirror the PostgreSQL schema in db.py:
  - incidents       : incident reports with IoC embeddings
  - company_policies: policy documents for semantic search
  - allowed_users   : (metadata-only, no embeddings needed)

Environment / config:
  CHROMA_SECRET   — master secret used to derive the AES encryption key.
                    Falls back to config.json  →  chroma.secret
  CHROMA_PATH     — directory where ChromaDB persists data on disk.
                    Falls back to config.json  →  chroma.path  (default: ./chroma_db)

Install dependencies:
    pip install chromadb cryptography

Usage:
    from chroma import init_chroma, get_collection

    await init_chroma()                          # call once on API startup
    col = get_collection("incidents")            # retrieve a named collection
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from typing import Any
from dotenv import load_dotenv

import chromadb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)
load_dotenv()

# ── Constants ──────────────────────────────────────────────────────────────────

# Salt used in SHA-256 key derivation — change this only before first use;
# rotating it renders all existing ciphertext unreadable.
_KDF_SALT = b"bgin-react-agent-chroma-v1"

# AES-256-GCM nonce length (bytes)
_NONCE_LEN = 12

# Names of ChromaDB collections that will be created on init
COLLECTION_NAMES = ("incidents", "company_policies")

# ── Module-level singletons ────────────────────────────────────────────────────

_client: chromadb.ClientAPI | None = None
_aesgcm: AESGCM | None = None
_collections: dict[str, chromadb.Collection] = {}


# ── Config helpers ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load config.json if it exists, otherwise return empty dict."""
    try:
        with open("config.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _chroma_secret() -> str:
    """
    Return the master secret used for key derivation.
    Priority:
      1. CHROMA_SECRET environment variable
      2. config.json → chroma.secret
    Raises RuntimeError if neither is set.
    """
    secret = os.getenv("CHROMA_SECRET")
    if secret:
        return secret
    cfg = _load_config()
    secret = cfg.get("chroma", {}).get("secret")
    if secret:
        return secret
    raise RuntimeError(
        "No ChromaDB secret configured. "
        "Set CHROMA_SECRET env var or add chroma.secret to config.json."
    )


def _chroma_path() -> str:
    """
    Return the filesystem path where ChromaDB will persist data.
    Priority:
      1. CHROMA_PATH environment variable
      2. config.json → chroma.path
      3. Default: ./chroma_db
    """
    path = os.getenv("CHROMA_PATH")
    if path:
        return path
    cfg = _load_config()
    return cfg.get("chroma", {}).get("path", "./chroma_db")


# ── Key derivation ─────────────────────────────────────────────────────────────

def _derive_key(secret: str) -> bytes:
    """
    Derive a 256-bit AES key from the master secret using SHA-256.

    Process:
      1. UTF-8 encode the secret and prepend the fixed KDF salt.
      2. Hash with SHA-256 to produce a 32-byte key.

    This is a simple single-round derivation intentionally compatible with
    the hashlib.sha256 already used throughout the backend. For higher
    security requirements this could be replaced with PBKDF2 or scrypt, but
    for this local demo SHA-256 with a fixed salt is sufficient
    provided CHROMA_SECRET is kept confidential.
    """
    material = _KDF_SALT + secret.encode("utf-8")
    key = hashlib.sha256(material).digest()          # 32 bytes = AES-256
    logger.debug("chroma: AES-256 key derived via SHA-256 (key not logged)")
    return key


# ── Encryption / decryption helpers ───────────────────────────────────────────

def encrypt(plaintext: str) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM.

    Returns a Base64-encoded string:  nonce (12 B) || ciphertext+tag

    The module must be initialised (init_chroma called) before use.
    """
    if _aesgcm is None:
        raise RuntimeError("chroma.py is not initialised — call init_chroma() first.")
    nonce = secrets.token_bytes(_NONCE_LEN)
    ciphertext = _aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt(token: str) -> str:
    """
    Decrypt a Base64-encoded AES-256-GCM token produced by encrypt().

    Returns the original UTF-8 plaintext.
    """
    if _aesgcm is None:
        raise RuntimeError("chroma.py is not initialised — call init_chroma() first.")
    raw = base64.b64decode(token.encode("ascii"))
    nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return _aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def content_hash(text: str) -> str:
    """
    Return the SHA-256 hex digest of *text* — used as a deduplication key,
    consistent with the sha256: tags already stored by the backend.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Initialisation ─────────────────────────────────────────────────────────────

async def init_chroma() -> None:
    """
    Initialise the ChromaDB client, derive the encryption key, and ensure
    all required collections exist on disk.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _client, _aesgcm, _collections

    if _client is not None:
        logger.debug("chroma.init_chroma: already initialised, skipping.")
        return

    # 1. Derive encryption key
    secret = _chroma_secret()
    key = _derive_key(secret)
    _aesgcm = AESGCM(key)
    logger.info("chroma.init_chroma: AES-256-GCM cipher ready.")

    # 2. Create persistent ChromaDB client (chromadb >= 1.0 API)
    db_path = _chroma_path()
    os.makedirs(db_path, exist_ok=True)
    _client = chromadb.PersistentClient(path=db_path)
    logger.info("chroma.init_chroma: PersistentClient created at %s", db_path)

    # 3. Ensure collections exist
    for name in COLLECTION_NAMES:
        col = _client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},   # cosine similarity for embeddings
        )
        _collections[name] = col
        logger.info("chroma.init_chroma: collection '%s' ready (%d docs).", name, col.count())

    logger.info("chroma.init_chroma: initialisation complete.")


# ── Collection access ──────────────────────────────────────────────────────────

def get_collection(name: str) -> chromadb.Collection:
    """
    Return a ChromaDB collection by name.

    Raises:
        RuntimeError  — if init_chroma() has not been called yet.
        KeyError      — if the collection name is not in COLLECTION_NAMES.
    """
    if _client is None:
        raise RuntimeError("chroma.py is not initialised — call init_chroma() first.")
    if name not in _collections:
        raise KeyError(
            f"Unknown collection '{name}'. "
            f"Available: {list(COLLECTION_NAMES)}"
        )
    return _collections[name]


def is_ready() -> bool:
    """Return True if the module has been successfully initialised."""
    return _client is not None and _aesgcm is not None


# ── Smoke test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    async def _smoke_test() -> None:
        print("Running chroma.py smoke tests...")

        # Requires CHROMA_SECRET to be set in the environment or config.json
        await init_chroma()

        # --- Encryption round-trip ---
        original = "Test incident: 0xdeadbeef flash-loan exploit"
        token = encrypt(original)
        recovered = decrypt(token)
        assert recovered == original, f"Round-trip failed: {recovered!r} != {original!r}"
        print("  ✅ AES-256-GCM encrypt/decrypt round-trip passed.")

        # --- Different nonces produce different ciphertext ---
        token2 = encrypt(original)
        assert token != token2, "Nonce reuse detected — tokens should differ."
        print("  ✅ Unique nonce per encryption call confirmed.")

        # --- content_hash consistency with db.py convention ---
        h = content_hash("hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert h == expected, f"Hash mismatch: {h}"
        print("  ✅ content_hash matches hashlib.sha256.")

        # --- Collection access ---
        for name in COLLECTION_NAMES:
            col = get_collection(name)
            assert col is not None
            print(f"  ✅ Collection '{name}' accessible (count={col.count()}).")

        print("\n✅ All chroma.py smoke tests passed.")

    asyncio.run(_smoke_test())
