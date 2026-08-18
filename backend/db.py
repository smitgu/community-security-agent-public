"""
db.py — Async PostgreSQL data layer for the web application.

Uses psycopg (psycopg3) for native asyncio support.
Connection: checks DATABASE_URL env var first, then falls back to config.json.

Install drivers:
    pip install "psycopg[binary]"

Run schema once to initialise tables:
    psql -h localhost -U postgres -d bgin_agent -f schema.sql
  or set DATABASE_URL and call `asyncio.run(init_db())` from this module.

IoC deduplication uses a two-pass strategy:
  Pass 1 — difflib character ratio  (fast, zero cost, catches obvious duplicates)
  Pass 2 — ChromaDB embedding cosine similarity  (semantic, catches paraphrases)

This ensures that near-identical IoC descriptions like:
  "no real-time monitoring"  vs  "lack of real-time on-chain monitoring"
  "5 of 9 validator keys stolen"  vs  "Admin key compromise: 5 of 9 validator keys stolen"
are correctly identified as duplicates and not added twice.
"""

from __future__ import annotations

import asyncio
import datetime
import difflib
import hashlib
import json
import logging
import math
import os
import re
import sys

# psycopg3 requires SelectorEventLoop on Windows (not ProactorEventLoop)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)

# ── Embedding function (lazy singleton) ───────────────────────────────────────
# Loaded on first IoC dedup call so startup is not blocked if chromadb is
# unavailable. Uses the same DefaultEmbeddingFunction (all-MiniLM-L6-v2) that
# chroma.py uses, ensuring vector space consistency.

_embed_fn = None


def _get_embed_fn():
    """
    Lazily initialise and return the ChromaDB default embedding function.
    Falls back gracefully if chromadb is not installed.
    """
    global _embed_fn
    if _embed_fn is None:
        try:
            from chromadb.utils import embedding_functions
            _embed_fn = embedding_functions.DefaultEmbeddingFunction()
            logger.debug("db: embedding function initialised (all-MiniLM-L6-v2)")
        except Exception as e:
            logger.warning(
                "db: could not load embedding function — "
                "IoC dedup will fall back to difflib only. Error: %s", e
            )
            _embed_fn = None
    return _embed_fn


# ── Connection ─────────────────────────────────────────────────────────────────

def _db_url() -> str:
    """
    Return the PostgreSQL connection URL.
    Priority:
      1. DATABASE_URL environment variable  (cloud / CI deployments)
      2. config.json in the project directory  (local development)
    """
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    try:
        with open("config.json") as f:
            cfg = json.load(f)
        p = cfg["postgres"]
        return (
            f"postgresql://{p['user']}:{p['password']}"
            f"@{p['host']}:{p['port']}/{p['dbname']}"
        )
    except FileNotFoundError:
        raise RuntimeError(
            "No database connection configured. "
            "Set DATABASE_URL or create config.json from config.json.template."
        )


async def _conn() -> psycopg.AsyncConnection:
    """Open and return a new async psycopg3 connection with dict_row cursor."""
    return await psycopg.AsyncConnection.connect(_db_url(), row_factory=dict_row)


# ── Schema initialisation ──────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables if they do not already exist. Call once on API startup."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path) as f:
        sql = f.read()
    async with await _conn() as conn:
        await conn.execute(sql)
        # Apply PII Abstraction encrypted_mapping migrations
        await conn.execute("ALTER TABLE company_policies ADD COLUMN IF NOT EXISTS encrypted_mapping TEXT;")
        await conn.execute("ALTER TABLE sensitivity_audit ADD COLUMN IF NOT EXISTS encrypted_mapping TEXT;")
    logger.info("db.init_db: schema applied and columns migrated successfully")


# ── Similarity thresholds ──────────────────────────────────────────────────────

# difflib character-level threshold — catches obvious duplicates cheaply
IOC_SIMILARITY_THRESHOLD      = 0.75

# Cosine similarity threshold for embedding-based IoC dedup.
# Set slightly lower than 1.0 to allow for minor semantic variations while
# still catching genuine paraphrases of the same indicator.
IOC_EMBED_THRESHOLD           = 0.82

# Incident name fuzzy-match threshold for find_existing_row
INCIDENT_SIMILARITY_THRESHOLD = 0.85

# Threshold used during the /dedup cleanup pass — slightly more aggressive
# to catch name variants like 'Synthetic Bridge Incident' vs
# 'Synthetic Cross-Chain Bridge Incident'
DEDUP_NAME_THRESHOLD          = 0.75


# ── Low-level similarity helpers ───────────────────────────────────────────────

def _normalise(name: str) -> str:
    """Lowercase, strip, and collapse internal whitespace."""
    return re.sub(r"\s+", " ", name.lower().strip())


def _name_similarity(a: str, b: str) -> float:
    """
    Return a similarity score (0-1) combining two signals:
      1. difflib sequence ratio (character-level)
      2. Word coverage: fraction of the SHORTER name's words that appear in
         the longer name — catches suffix variants like:
         'Synthetic Bridge Incident' vs
         'Synthetic Bridge Incident — Supplementary Findings'
    Returns the MAX of the two so either signal alone can trigger a match.
    """
    seq_ratio = difflib.SequenceMatcher(None, a, b).ratio()
    words_a, words_b = set(a.split()), set(b.split())
    if not words_a or not words_b:
        return seq_ratio
    shorter, longer = (
        (words_a, words_b) if len(words_a) <= len(words_b) else (words_b, words_a)
    )
    word_coverage = len(shorter & longer) / len(shorter)
    return max(seq_ratio, word_coverage)


def _cosine_sim(a: list[float], b: list[float]) -> float:
    """
    Compute cosine similarity between two embedding vectors.
    Returns a value in [-1, 1]; in practice always [0, 1] for text embeddings.
    """
    try:
        if not a or len(a) != len(b):
            return 0.0
        pairs = [(float(x), float(y)) for x, y in zip(a, b)]
        norm_a = math.sqrt(math.fsum(x * x for x, _ in pairs))
        norm_b = math.sqrt(math.fsum(y * y for _, y in pairs))
        denom = norm_a * norm_b
        if denom == 0.0:
            return 0.0
        dot_product = math.fsum(x * y for x, y in pairs)
        return dot_product / denom
    except Exception:
        return 0.0


def _split_ioc_field(field_str: str) -> list[str]:
    """Split a semicolon-delimited IoC field into a cleaned list."""
    return [x.strip() for x in field_str.split(";") if x.strip()]


# ── IoC deduplication — two-pass ──────────────────────────────────────────────

def _is_duplicate_ioc(incoming: str, existing_items: list[str]) -> bool:
    """
    Return True if *incoming* is a duplicate of any item in *existing_items*.

    Two-pass strategy:
      Pass 1 — difflib character ratio
        Fast and zero-cost. Catches obvious duplicates where the strings are
        nearly identical character-for-character (ratio >= 0.75).
        Short-circuits immediately so embeddings are never called for clear hits.

      Pass 2 — Semantic embedding cosine similarity
        Embeds all strings in one batch call (efficient) and computes cosine
        similarity. Catches paraphrases that difflib misses, for example:
          "no real-time monitoring"
            vs "lack of real-time on-chain monitoring"            (~0.87)
          "5 of 9 validator keys stolen"
            vs "Admin key compromise: 5 of 9 validator keys stolen" (~0.91)
          "multisig threshold insufficient"
            vs "multisig threshold insufficient (5/9)"             (~0.95)

        Falls back silently to difflib-only if the embedding model is
        unavailable (e.g. chromadb not installed, cold start).
    """
    if not existing_items:
        return False

    norm_in = _normalise(incoming)

    # ── Pass 1: fast difflib check ────────────────────────────────────────────
    for ex in existing_items:
        if (
            difflib.SequenceMatcher(None, norm_in, _normalise(ex)).ratio()
            >= IOC_SIMILARITY_THRESHOLD
        ):
            return True

    # ── Pass 2: semantic embedding check ─────────────────────────────────────
    embed = _get_embed_fn()
    if embed is None:
        # Embedding unavailable — difflib result is final
        return False

    try:
        # Batch-embed incoming + all existing items in one call for efficiency
        all_texts = [incoming] + existing_items
        vecs      = embed(all_texts)
        in_vec    = vecs[0]

        for ex_vec in vecs[1:]:
            if _cosine_sim(in_vec, ex_vec) >= IOC_EMBED_THRESHOLD:
                logger.debug(
                    "db._is_duplicate_ioc: semantic match — "
                    "incoming=%r, sim=%.3f",
                    incoming[:60],
                    _cosine_sim(in_vec, ex_vec),
                )
                return True
    except Exception as e:
        logger.warning(
            "db._is_duplicate_ioc: embedding pass failed, "
            "falling back to difflib result. Error: %s", e
        )

    return False


def _merge_ioc_lists(
    existing_str: str, incoming: list[str]
) -> tuple[str, list[str]]:
    """
    Merge *incoming* IoCs into *existing_str* (semicolon-delimited).

    Uses the two-pass duplicate check (_is_duplicate_ioc) so that semantically
    equivalent IoC descriptions are not added a second time.

    Returns:
        merged_string  — semicolon-joined string of all unique IoCs
        new_items      — list of IoCs from *incoming* that were genuinely new
    """
    existing_items = _split_ioc_field(existing_str)
    new_items = [
        x for x in incoming
        if not _is_duplicate_ioc(x, existing_items)
    ]
    return "; ".join(existing_items + new_items), new_items


# ── Incidents ──────────────────────────────────────────────────────────────────

async def find_row_by_hash(content_hash: str) -> tuple[int | None, dict | None]:
    """
    Search incidents for a row whose source_file contains sha256:<content_hash>.
    Returns (id, row_dict) or (None, None).

    This is Stage 1 of the dedup pipeline — an exact byte-level check that
    fires before Gemini is called, making re-uploads of the identical file
    essentially free.
    """
    tag = f"sha256:{content_hash}"
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT * FROM incidents WHERE source_file LIKE %s LIMIT 1",
                (f"%{tag}%",),
            )
            row = await cur.fetchone()
    if row:
        return row["id"], dict(row)
    return None, None


async def find_existing_row(
    incident_name: str,
) -> tuple[int | None, dict | None]:
    """
    Fuzzy-match incident_name against all stored incident names.

    Uses _name_similarity() which combines difflib sequence ratio with word
    coverage, so suffix variants like '— Supplementary Findings' still match
    the base incident name.

    Returns (id, row_dict) of the best match above threshold, or (None, None).
    """
    target = _normalise(incident_name)
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM incidents")
            rows = await cur.fetchall()

    best_id, best_row, best_ratio = None, None, 0.0
    for row in rows:
        ratio = _name_similarity(target, _normalise(row["incident_name"]))
        if ratio >= INCIDENT_SIMILARITY_THRESHOLD and ratio > best_ratio:
            best_id, best_row, best_ratio = row["id"], dict(row), ratio
    return best_id, best_row


async def update_existing_incident(
    row_id: int,
    existing: dict,
    new_iocs: dict,
) -> list[str]:
    """
    Merge new IoCs into an existing incident row using the two-pass dedup check.

    Only columns with genuinely new IoCs are written back to Postgres, so a
    document that adds nothing new results in zero database writes.

    Returns a flat list of all IoC strings that were actually added.
    """
    added: list[str] = []
    updates: dict[str, str] = {}

    for field in (
        "on_chain_iocs",
        "behavioral_iocs",
        "governance_operational_iocs",
    ):
        incoming = new_iocs.get(field, [])
        merged_str, new_items = _merge_ioc_lists(
            existing.get(field, ""), incoming
        )
        if new_items:
            updates[field] = merged_str
            added.extend(new_items)

    if updates:
        set_clause = ", ".join(f"{col} = %s" for col in updates)
        values     = list(updates.values()) + [row_id]
        async with await _conn() as conn:
            await conn.execute(
                f"UPDATE incidents SET {set_clause} WHERE id = %s",
                values,
            )
        logger.info(
            "db.update_existing_incident: id=%s added %d new IoC(s)",
            row_id, len(added),
        )

    return added


async def stamp_source_hash(
    row_id: int, existing_source: str, doc_hash: str
) -> None:
    """
    Append sha256:<doc_hash> to source_file on an existing incident row if not
    already present. Used to ensure future exact-duplicate uploads are caught
    by the hash guard before Gemini is invoked.
    """
    hash_tag = f"sha256:{doc_hash}"
    if hash_tag in existing_source:
        return
    new_source = (
        f"{existing_source}; {hash_tag}" if existing_source else hash_tag
    )
    async with await _conn() as conn:
        await conn.execute(
            "UPDATE incidents SET source_file = %s WHERE id = %s",
            (new_source, row_id),
        )


async def append_incident_row(
    incident_name: str,
    on_chain_iocs: list[str],
    behavioral_iocs: list[str],
    governance_iocs: list[str],
    source_file: str,
    content_hash: str | None = None,
) -> int:
    """
    Insert a new incident row and return the new row id.

    IoC lists are stored as semicolon-delimited strings for compatibility with
    the existing schema. The content_hash is embedded in the source_file field
    so the hash guard (find_row_by_hash) can locate it with a LIKE query.
    """
    timestamp = datetime.datetime.now(datetime.UTC).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    tagged_source = (
        f"{source_file} (sha256:{content_hash})" if content_hash else source_file
    )
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO incidents
                    (incident_name, on_chain_iocs, behavioral_iocs,
                     governance_operational_iocs, source_file, content_hash,
                     created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    incident_name,
                    "; ".join(on_chain_iocs),
                    "; ".join(behavioral_iocs),
                    "; ".join(governance_iocs),
                    tagged_source,
                    content_hash,
                    timestamp,
                ),
            )
            row = await cur.fetchone()
    logger.info(
        "db.append_incident_row: inserted '%s' as id=%s", incident_name, row["id"]
    )
    return row["id"]


async def read_all_incidents() -> list[dict]:
    """
    Return all incidents ordered by creation time as a list of dicts.

    Keys returned:
        timestamp, incident_name, on_chain_iocs, behavioral_iocs,
        governance_operational_iocs, source_file
    """
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT
                    id,
                    to_char(created_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS timestamp,
                    incident_name,
                    on_chain_iocs,
                    behavioral_iocs,
                    governance_operational_iocs,
                    source_file
                FROM incidents
                ORDER BY created_at
                """
            )
            return [dict(r) for r in await cur.fetchall()]


async def deduplicate_incidents() -> tuple[int, int]:
    """
    Read all incident rows, group by fuzzy incident name, merge IoCs within
    each group using the two-pass semantic dedup check, then rewrite the table
    with one canonical row per unique incident.

    Returns (rows_before, rows_after).

    Called automatically after every write and also by the /dedup command for
    a manual retroactive cleanup pass.
    """
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM incidents ORDER BY created_at")
            rows = [dict(r) for r in await cur.fetchall()]

    rows_before = len(rows)
    if rows_before == 0:
        return 0, 0

    # ── Group rows by fuzzy incident name ─────────────────────────────────────
    group_keys: list[str] = []
    groups: dict[str, list[dict]] = {}

    for row in rows:
        row_norm = _normalise(row.get("incident_name", "(unknown)"))
        best_key, best_ratio = None, 0.0
        for key in group_keys:
            ratio = _name_similarity(row_norm, key)
            if ratio >= DEDUP_NAME_THRESHOLD and ratio > best_ratio:
                best_key, best_ratio = key, ratio
        if best_key is None:
            group_keys.append(row_norm)
            groups[row_norm] = [row]
        else:
            groups[best_key].append(row)

    # ── Merge IoCs within each group using semantic dedup ─────────────────────
    merged: list[dict] = []
    for _, group in groups.items():
        base = group[0]
        for field in (
            "on_chain_iocs",
            "behavioral_iocs",
            "governance_operational_iocs",
        ):
            merged_str = base.get(field, "")
            for r in group[1:]:
                merged_str, _ = _merge_ioc_lists(
                    merged_str, _split_ioc_field(r.get(field, ""))
                )
            base[field] = merged_str

        # Consolidate source file references from all rows in the group
        sources = list({
            s.strip()
            for r in group
            for s in r.get("source_file", "").split(";")
            if s.strip()
        })
        base["source_file"] = "; ".join(sources)
        merged.append(base)

    # ── Rewrite table with merged rows ────────────────────────────────────────
    async with await _conn() as conn:
        await conn.execute("DELETE FROM incidents")
        for row in merged:
            await conn.execute(
                """
                INSERT INTO incidents
                    (incident_name, on_chain_iocs, behavioral_iocs,
                     governance_operational_iocs, source_file, content_hash,
                     created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row["incident_name"],
                    row["on_chain_iocs"],
                    row["behavioral_iocs"],
                    row["governance_operational_iocs"],
                    row["source_file"],
                    row.get("content_hash"),
                    row.get("created_at"),
                ),
            )

    rows_after = len(merged)
    if rows_before != rows_after:
        logger.info(
            "db.deduplicate_incidents: merged %d rows → %d unique incidents",
            rows_before, rows_after,
        )
    return rows_before, rows_after


# ── Company Policies ───────────────────────────────────────────────────────────

async def save_company_policy(
    policy_name: str, policy_text: str, source_file: str, encrypted_mapping: str | None = None
) -> bool:
    """
    Upsert a company policy row.
    Returns True if a new row was inserted, False if an existing row was updated.
    """
    now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO company_policies
                    (policy_name, policy_text, source_file, encrypted_mapping, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (policy_name) DO UPDATE
                    SET policy_text = EXCLUDED.policy_text,
                        source_file = EXCLUDED.source_file,
                        encrypted_mapping = EXCLUDED.encrypted_mapping,
                        updated_at  = EXCLUDED.updated_at
                RETURNING (xmax = 0) AS inserted
                """,
                (policy_name, policy_text, source_file, encrypted_mapping, now, now),
            )
            row = await cur.fetchone()
    return bool(row["inserted"])


async def read_all_policies() -> list[dict]:
    """
    Return all company policies as a list of dicts.

    Keys returned use the compatibility labels expected by the API:
        "Company Policy Name", "Policy Text", "Source File", "Timestamp", "Encrypted Mapping"
    """
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT
                    policy_name AS "Company Policy Name",
                    policy_text AS "Policy Text",
                    source_file AS "Source File",
                    encrypted_mapping AS "Encrypted Mapping",
                    to_char(updated_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS "Timestamp"
                FROM company_policies
                ORDER BY policy_name
                """
            )
            return [dict(r) for r in await cur.fetchall()]


async def find_policy_by_name(query: str) -> dict | None:
    """
    Fuzzy-match *query* against stored policy names using difflib.
    Returns the best-matching policy dict, or None if no reasonable match.
    """
    policies  = await read_all_policies()
    q_norm    = _normalise(query)
    best, best_ratio = None, 0.0
    for row in policies:
        ratio = difflib.SequenceMatcher(
            None, q_norm, _normalise(row.get("Company Policy Name", ""))
        ).ratio()
        if ratio > best_ratio:
            best, best_ratio = row, ratio
    return best if best_ratio >= 0.40 else None


# ── Allowed Users ──────────────────────────────────────────────────────────────

async def load_allowed_users() -> dict[int, str]:
    """Return {user_id: role} mapping from the allowed_users table."""
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT user_id, role FROM allowed_users")
            rows = await cur.fetchall()
    return {int(r["user_id"]): r["role"] for r in rows}


async def append_allowed_user(user_id: int, role: str = "") -> None:
    """Add user_id to allowed_users. Silently ignores if already present."""
    async with await _conn() as conn:
        await conn.execute(
            """
            INSERT INTO allowed_users (user_id, role)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO NOTHING
            """,
            (user_id, role),
        )


async def remove_allowed_user(user_id: int) -> bool:
    """Remove user_id from allowed_users. Returns True if a row was deleted."""
    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM allowed_users WHERE user_id = %s", (user_id,)
            )
            return cur.rowcount > 0


# ── Sensitivity Audit Log ─────────────────────────────────────────────────────

async def write_sensitivity_audit(
    classification: str,
    action_taken: str,
    detected_entities: list[dict],
    uploaded_by: int | None = None,
    filename: str | None = None,
    raw_document: str | None = None,
    encrypted_mapping: str | None = None,
) -> int:
    """
    Insert a sensitivity audit record and return the new row id.

    Args:
        classification:    "PUBLIC" | "INTERNAL" | "CONFIDENTIAL"
        action_taken:      "PASSED" | "SCRUBBED" | "BLOCKED"
        detected_entities: list of dicts from sensitivity_gate() entities output
        uploaded_by:       numeric user identifier of the uploader (optional)
        filename:          original filename (optional)
        raw_document:      full original text — only stored for CONFIDENTIAL docs
        encrypted_mapping: Fernet-encrypted mapping table (optional)

    Review status is automatically set to:
        - "pending"  for INTERNAL and CONFIDENTIAL (require human review)
        - "approved" for PUBLIC (no review needed)
    """
    import json as _json
    review_status = "approved" if classification == "PUBLIC" else "pending"
    # Only persist raw document text for CONFIDENTIAL docs (INTERNAL text
    # is never stored to minimise exposure of potentially sensitive content).
    stored_raw = raw_document if classification == "CONFIDENTIAL" else None

    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO sensitivity_audit
                    (uploaded_by, filename, classification, action_taken,
                     detected_entities, raw_document, encrypted_mapping, review_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    uploaded_by,
                    filename,
                    classification,
                    action_taken,
                    _json.dumps(detected_entities),
                    stored_raw,
                    encrypted_mapping,
                    review_status,
                ),
            )
            row = await cur.fetchone()
    audit_id = row["id"]
    logger.info(
        "db.write_sensitivity_audit: id=%d class=%s action=%s entities=%d",
        audit_id, classification, action_taken, len(detected_entities),
    )
    return audit_id


async def read_sensitivity_audit(
    classification: str | None = None,
    review_status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """
    Return audit records, optionally filtered by classification or review_status.
    Useful for admin review queries.

    Example:
        await db.read_sensitivity_audit(review_status="pending")
        await db.read_sensitivity_audit(classification="CONFIDENTIAL")
    """
    conditions: list[str] = []
    params: list = []

    if classification:
        conditions.append("classification = %s")
        params.append(classification)
    if review_status:
        conditions.append("review_status = %s")
        params.append(review_status)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    async with await _conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"""
                SELECT id, uploaded_at, uploaded_by, filename,
                       classification, action_taken, detected_entities,
                       review_status, reviewed_by, reviewed_at, reviewer_notes
                FROM sensitivity_audit
                {where}
                ORDER BY uploaded_at DESC
                LIMIT %s
                """,
                params,
            )
            return [dict(r) for r in await cur.fetchall()]


# ── Manual smoke test ─────────────────────────────────────────────────────────
# Runs only when this module is executed directly. It writes synthetic records
# to the configured database and is never invoked by the API import path.

if __name__ == "__main__":
    async def _smoke_test():
        print("Running db.py smoke tests...")
        await init_db()

        # ── Incidents ─────────────────────────────────────────────────────────
        rid = await append_incident_row(
            "Synthetic Bridge Incident",
            ["0xdeadbeef"],
            ["flash loan"],
            ["multisig bypass"],
            "smoke_test",
            content_hash="abc123456789abcd",
        )
        assert rid > 0, "append_incident_row should return a positive id"
        print(f"  ✅ append_incident_row returned id={rid}")

        all_inc = await read_all_incidents()
        assert any(r["incident_name"] == "Synthetic Bridge Incident" for r in all_inc), \
            "read_all_incidents should return the inserted row"
        print(f"  ✅ read_all_incidents returned {len(all_inc)} row(s)")

        existing_id, existing = await find_existing_row("Synthetic Bridge")
        assert existing_id == rid, "find_existing_row fuzzy match failed"
        print(f"  ✅ find_existing_row matched id={existing_id}")

        added = await update_existing_incident(
            rid,
            existing,
            {
                "on_chain_iocs":               ["0xnewaddress"],
                "behavioral_iocs":             [],
                "governance_operational_iocs": [],
            },
        )
        assert "0xnewaddress" in added, \
            "update_existing_incident should report the newly added IoC"
        print(f"  ✅ update_existing_incident added: {added}")

        # ── Semantic dedup test ───────────────────────────────────────────────
        # Re-fetch the row after update so existing has the new IoC
        _, existing2 = await find_existing_row("Synthetic Bridge")

        # These two are semantically equivalent — the second should be rejected
        paraphrase_pairs = [
            ("multisig bypass",      "multisig threshold insufficient"),
            ("no real-time monitoring", "lack of real-time on-chain monitoring"),
        ]
        for original, paraphrase in paraphrase_pairs:
            existing_iocs = _split_ioc_field(
                existing2.get("governance_operational_iocs", "")
            )
            is_dup = _is_duplicate_ioc(paraphrase, existing_iocs + [original])
            status = "✅ correctly rejected as duplicate" if is_dup else "⚠️  NOT caught as duplicate"
            print(f"  {status}: '{paraphrase}' vs '{original}'")

        before, after = await deduplicate_incidents()
        assert after <= before, "deduplicate should not increase row count"
        print(f"  ✅ deduplicate_incidents: {before} → {after}")

        # ── Policies ──────────────────────────────────────────────────────────
        is_new = await save_company_policy(
            "Acme Corp", "Our security policy text.", "test.pdf"
        )
        assert is_new, "First save should be a new insert"
        print("  ✅ save_company_policy: new insert confirmed")

        is_new2 = await save_company_policy(
            "Acme Corp", "Updated policy text.", "test_v2.pdf"
        )
        assert not is_new2, "Second save should be an update"
        print("  ✅ save_company_policy: upsert confirmed")

        policies = await read_all_policies()
        assert any(p["Company Policy Name"] == "Acme Corp" for p in policies)
        print(f"  ✅ read_all_policies returned {len(policies)} row(s)")

        found = await find_policy_by_name("acme")
        assert found is not None and found["Company Policy Name"] == "Acme Corp"
        print(f"  ✅ find_policy_by_name matched: {found['Company Policy Name']}")

        # ── Allowed users ─────────────────────────────────────────────────────
        await append_allowed_user(99999, "Blockchain Analyst")
        users = await load_allowed_users()
        assert 99999 in users, "append_allowed_user failed"
        print(f"  ✅ append_allowed_user: {users[99999]}")

        removed = await remove_allowed_user(99999)
        assert removed, "remove_allowed_user should return True"
        users2 = await load_allowed_users()
        assert 99999 not in users2
        print("  ✅ remove_allowed_user confirmed")

        print("\n✅ All db.py smoke tests passed.")

    asyncio.run(_smoke_test())
