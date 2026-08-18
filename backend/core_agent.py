import os
import io
import json
import logging
import re
import datetime
import difflib
import hashlib
import sys

# psycopg3 requires SelectorEventLoop on Windows (not ProactorEventLoop)
if sys.platform == "win32":
    import asyncio as _asyncio
    _asyncio.set_event_loop_policy(_asyncio.WindowsSelectorEventLoopPolicy())

import pdfplumber
import docx
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from google import genai
from dotenv import load_dotenv
import db
from sensitivity import sensitivity_gate, deanonymize, ConfidentialDocumentError
import chroma

# ── Config ────────────────────────────────────────────────────────────────────
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

GEMINI_MODEL = "gemini-2.5-flash"

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md"}

IOC_COLORS = {
    "on_chain":   "#E53935",
    "behavioral": "#FB8C00",
    "governance": "#43A047",
}
INCIDENT_COLOR = "#1565C0"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)

# ── Access control ─────────────────────────────────────────────────────────────
# ── Allowed users — backed by PostgreSQL via db.py ────────────────────────────

# ── Deduplication / hash helpers ──────────────────────────────────────────────

IOC_SIMILARITY_THRESHOLD      = 0.75
INCIDENT_SIMILARITY_THRESHOLD = 0.85
DEDUP_NAME_THRESHOLD          = 0.75


def _content_hash(text: str) -> str:
    """Return a short SHA-256 hex digest of the document text (first 16 chars)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def normalise_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.lower().strip())


def _split_ioc_field(field_str: str) -> list[str]:
    return [x.strip() for x in field_str.split(";") if x.strip()]


# ── File text extraction ───────────────────────────────────────────────────────

def extract_text_from_pdf(file_bytes: bytes) -> str:
    parts = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                parts.append(t)
    return "\n".join(parts)


def extract_text_from_docx(file_bytes: bytes) -> str:
    d = docx.Document(io.BytesIO(file_bytes))
    return "\n".join(p.text for p in d.paragraphs if p.text.strip())


def extract_text(file_bytes: bytes, filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    if ext == ".pdf":
        return extract_text_from_pdf(file_bytes)
    elif ext == ".docx":
        return extract_text_from_docx(file_bytes)
    elif ext in (".txt", ".md"):
        return file_bytes.decode("utf-8", errors="replace")
    raise ValueError(f"Unsupported file type: {ext}")


# ── Gemini helpers ────────────────────────────────────────────────────────────

gemini_client = genai.Client(api_key=GEMINI_API_KEY)

# ── Intent classification ─────────────────────────────────────────────────────

INTENT_PROMPT = """\
You are a router for a cybersecurity assistant. Classify the user message below
into EXACTLY ONE of the following intents and reply with only the intent label.

Intents:
  top5          – user wants to see the top 5 incidents by IoC count
  graph         – user wants to see the provenance graph / visualisation
  iocs          – user wants IoC details for a specific named incident
  review        – user wants to review / upload a governance or management framework
  audit         – user wants to start a NEW audit by uploading BOTH framework and policy
  auditpolicy   – user wants to audit against a STORED company policy
  listpolicies  – user wants to see the list of saved company policies
  savepolicy    – user wants to upload / save a company policy to the system
  scrape        – user wants to extract IoCs or incidents from a specific website / URL
  dedup         – user wants to deduplicate or clean up the incident database
  sheet         – user wants a link to the knowledge base
  help          – user is asking for help, commands, or what the bot can do
  contribute    – user explicitly wants to ADD / LOG / SUBMIT something to the shared KB
  query         – user wants IoC analysis WITHOUT saving anything to the KB
  report        – the message looks like an actual incident report or an IoC document
  unknown       – none of the above; a general question or irrelevant message

User message:
\"\"\"
{message}
\"\"\"

Respond with ONLY one of these exact labels (lowercase): top5 | graph | iocs | review | audit | auditpolicy | listpolicies | savepolicy | scrape | dedup | sheet | help | contribute | query | report | unknown"""


def classify_intent(message: str) -> str:
    try:
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=INTENT_PROMPT.format(message=message[:2000]),
        )
        label = response.text.strip().lower().split()[0]
        valid = {
            "top5", "graph", "iocs", "review", "audit", "auditpolicy",
            "listpolicies", "savepolicy", "scrape", "dedup", "sheet",
            "help", "contribute", "query", "report", "unknown",
        }
        return label if label in valid else "report"
    except Exception:
        return "report"


# ── Contribute-vs-query classifier ────────────────────────────────────────────

CONTRIBUTE_OR_QUERY_PROMPT = """\
A user sent a message to a blockchain security assistant that maintains a shared knowledge base (KB).
Determine whether they want to CONTRIBUTE (add to the shared KB) or QUERY (analyse only, do NOT save).

Default to QUERY if the intent is unclear — it is safer not to write to a shared KB.

Strong CONTRIBUTE signals: "add this", "log this", "submit", "record this incident",
"here is a report for the KB", "contribute", "save to KB", "store this"

Strong QUERY signals: "analyse", "check", "what IoCs", "don't save", "just looking",
"query", "not for the KB", explicit questions about a document, "analyse only",
"extract but don't store", "for my reference"

First 500 characters of the message:
\"\"\"
{text}
\"\"\"

Reply with ONLY one word: contribute   or   query"""


def classify_contribute_or_query(text: str) -> str:
    try:
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=CONTRIBUTE_OR_QUERY_PROMPT.format(text=text[:500]),
        )
        label = response.text.strip().lower().split()[0]
        return label if label in {"contribute", "query"} else "query"
    except Exception:
        return "query"


# ── Web scraping ──────────────────────────────────────────────────────────────

SCRAPING_PROMPT = """\
You are a Cyber Threat Intelligence analyst specialising in blockchain security.

You have been given the text content of a web page. The user's scraping instructions are:
"{instructions}".

Based on those instructions, extract any blockchain security incidents described on the page and
return them as a strict JSON list (and NOTHING else — no commentary, no markdown fences).

For each incident, extract exactly these fields:

[
  {{
    "incident_name": "<short name for the incident>",
    "on_chain_iocs": ["wallet address / tx hash / smart contract / token contract / block number etc."],
    "behavioral_iocs": ["flash loan abuse, reentrancy, oracle manipulation, anomalous volume, etc."],
    "governance_operational_iocs": ["multisig bypass, admin key compromise, DAO manipulation, social engineering, etc."]
  }}
]

If no incidents are found, return an empty list: []

Page content:
\"\"\"
{page_text}
\"\"\"
"""


def _fetch_url_text(url: str, max_chars: int = 30_000) -> str:
    import httpx
    import html as html_lib
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    }
    with httpx.Client(follow_redirects=True, timeout=30) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        html = resp.text
    text = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text[:max_chars]


def extract_iocs_from_url(instructions: str) -> list[dict]:
    url_match = re.search(r"https?://\S+", instructions)
    if not url_match:
        raise ValueError("No URL found in instructions.")
    url = url_match.group(0).rstrip(".,;)")
    try:
        page_text = _fetch_url_text(url)
    except Exception as fetch_err:
        raise ValueError(f"Could not fetch URL ({url}): {fetch_err}") from fetch_err
    prompt = SCRAPING_PROMPT.format(instructions=instructions, page_text=page_text)
    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL, contents=prompt
    )
    if not response or not response.text:
        raise ValueError("Gemini returned an empty response when analysing the page.")
    raw = re.sub(r"^```[a-z]*\n?", "", response.text.strip())
    raw = re.sub(r"```$", "", raw).strip()
    return json.loads(raw)


# ── IoC extraction ────────────────────────────────────────────────────────────

EXTRACTION_PROMPT = """\
You are a Cyber Threat Intelligence analyst specialising in blockchain security.

Read the incident report below and extract the following in strict JSON format:

{{
  "incident_name": "<short name for the incident>",
  "on_chain_iocs": ["wallet address / tx hash / smart contract / token contract / block number etc."],
  "behavioral_iocs": ["flash loan abuse, reentrancy, oracle manipulation, anomalous volume, etc."],
  "governance_operational_iocs": ["multisig bypass, admin key compromise, DAO manipulation, social engineering, etc."]
}}

Rules:
- Return ONLY the JSON object, no markdown fences, no extra text.
- If a category has no IoCs, return an empty list [].

Incident Report:
\"\"\"
{report}
\"\"\"
"""


def extract_iocs(report_text: str, _mapping: dict | None = None) -> dict:
    """
    Extract IoCs from report_text via Gemini.

    NOTE: call sensitivity_gate() BEFORE this function and pass safe_text here.
    Pass the returned mapping as _mapping so entity names are restored before
    the JSON is parsed and returned.
    """
    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=EXTRACTION_PROMPT.format(report=report_text),
    )
    raw = re.sub(r"^```[a-z]*\n?", "", response.text.strip())
    raw = re.sub(r"```$", "", raw).strip()
    # ── De-anonymise: restore real entity names before parsing ────────────────
    if _mapping:
        raw = deanonymize(raw, _mapping)
    return json.loads(raw)


# ── Framework review ──────────────────────────────────────────────────────────

REVIEW_PROMPT = """\
You are a senior blockchain security advisor and governance expert.

Below is a company's management / governance framework document, followed by a list of
Indicators of Compromise (IoCs) extracted from real blockchain security incidents.

Your task is to critically analyse the framework against these IoCs and produce a
structured improvement report with:

1. **Executive Summary** – overall security posture assessment (2-3 sentences)
2. **Critical Gaps** – specific weaknesses the framework has that the IoCs expose (bullet list)
3. **Recommendations** – concrete, actionable improvements mapped to each IoC category:
   - On-Chain controls
   - Behavioral / Detection controls
   - Governance & Operational controls
4. **Priority Actions** – top 3 things the company should do first

Be specific. Reference actual IoCs where relevant. Do not be generic.

---

MANAGEMENT FRAMEWORK:
\"\"\"
{framework}
\"\"\"

---

OBSERVED IoCs FROM BLOCKCHAIN INCIDENTS (from provenance graph):

On-Chain IoCs:
{onchain}

Behavioral IoCs:
{behavioral}

Governance/Operational IoCs:
{governance}
"""


# ── Audit comparison ──────────────────────────────────────────────────────────

AUDIT_COMPARISON_PROMPT = """\
You are a senior cybersecurity auditor specialising in blockchain and financial technology governance.

You have been given two documents:
1. An AUDIT FRAMEWORK — a security standard, checklist, or regulatory framework that defines requirements.
2. An ORGANISATION POLICY — the target company's existing management / governance / security policy.

Your task is to compare the organisation's policy against every requirement in the audit framework
and return a structured JSON report in EXACTLY this format (no markdown, no extra text):

{{
  "organisation": "<name of the organisation extracted from the policy, or 'Target Organisation'>",
  "audit_framework": "<name / title of the audit framework>",
  "summary": "<2-3 sentence executive summary of the overall audit result>",
  "overall_result": "PASS" | "FAIL" | "PARTIAL",
  "checklist": [
    {{
      "criterion": "<exact or paraphrased requirement from the audit framework>",
      "category": "<thematic category, e.g. Access Control, Incident Response, Key Management, Governance>",
      "result": "PASS" | "FAIL" | "PARTIAL",
      "evidence": "<one sentence: what in the policy supports or contradicts this criterion>",
      "recommendation": null
    }}
  ]
}}

Rules:
- Cover EVERY distinguishable requirement in the audit framework — do not skip any.
- Be specific: reference actual wording from both documents where possible.
- overall_result is PASS if all criteria pass, FAIL if the majority fail, PARTIAL otherwise.
- Return ONLY the JSON object.

---

AUDIT FRAMEWORK:
\"\"\"
{framework}
\"\"\"

---

ORGANISATION POLICY:
\"\"\"
{policy}
\"\"\"
"""


def run_audit_comparison(framework_text: str, policy_text: str) -> dict:
    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=AUDIT_COMPARISON_PROMPT.format(
            framework=framework_text[:8000],
            policy=policy_text[:8000],
        ),
    )
    raw = re.sub(r"^```[a-z]*\n?", "", response.text.strip())
    raw = re.sub(r"```$", "", raw).strip()
    return json.loads(raw)


def format_audit_report(result: dict) -> str:
    org       = esc(result.get("organisation", "Target Organisation"))
    framework = esc(result.get("audit_framework", "Audit Framework"))
    summary   = esc(result.get("summary", ""))
    overall   = result.get("overall_result", "PARTIAL")
    checklist = result.get("checklist", [])

    overall_badge = {
        "PASS":    "✅ <b>PASS</b>",
        "FAIL":    "❌ <b>FAIL</b>",
        "PARTIAL": "⚠️ <b>PARTIAL PASS</b>",
    }.get(overall, "⚠️ <b>PARTIAL</b>")

    result_icon = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️"}

    lines = [
        f"📋 <b>Audit Report: {org}</b>",
        f"<i>Framework: {framework}</i>",
        f"{'─' * 32}",
        "",
        f"<b>Overall Result: {overall_badge}</b>",
        "",
        "<b>Executive Summary</b>",
        summary,
        "",
        f"{'─' * 32}",
        "<b>Audit Checklist</b>",
        "",
    ]

    categories: dict[str, list[dict]] = {}
    for item in checklist:
        cat = item.get("category", "General")
        categories.setdefault(cat, []).append(item)

    for cat, items in categories.items():
        lines.append(f"<b>▸ {esc(cat)}</b>")
        for item in items:
            icon      = result_icon.get(item.get("result", "PARTIAL"), "⚠️")
            criterion = esc(item.get("criterion", ""))
            evidence  = esc(item.get("evidence", ""))
            lines.append(f"  {icon} <b>{criterion}</b>")
            lines.append(f"     <i>{evidence}</i>")
        lines.append("")

    failed = [
        item for item in checklist
        if item.get("result") != "PASS" and item.get("recommendation")
    ]
    if failed:
        lines += [
            f"{'─' * 32}",
            "<b>🔧 Recommendations to Achieve Compliance</b>",
            "",
        ]
        for item in failed:
            icon      = result_icon.get(item.get("result", "PARTIAL"), "⚠️")
            criterion = esc(item.get("criterion", ""))
            rec       = esc(item.get("recommendation", ""))
            lines.append(f"{icon} <b>{criterion}</b>")
            lines.append(f"   → {rec}")
            lines.append("")

    passed      = sum(1 for i in checklist if i.get("result") == "PASS")
    partial     = sum(1 for i in checklist if i.get("result") == "PARTIAL")
    failed_count = sum(1 for i in checklist if i.get("result") == "FAIL")
    total       = len(checklist)

    lines += [
        f"{'─' * 32}",
        f"<b>Score:</b> ✅ {passed} passed · ⚠️ {partial} partial · ❌ {failed_count} failed",
        f"<i>({total} criteria evaluated)</i>",
        "",
        "<i>Use /graph to view the incident provenance graph or /top5 to rank incidents.</i>",
    ]

    return "\n".join(lines)


def build_ioc_summary(incidents: list[dict]) -> tuple[str, str, str]:
    onchain    = set()
    behavioral = set()
    governance = set()
    for row in incidents:
        for item in row.get("on_chain_iocs", "").split(";"):
            if item.strip():
                onchain.add(item.strip())
        for item in row.get("behavioral_iocs", "").split(";"):
            if item.strip():
                behavioral.add(item.strip())
        for item in row.get("governance_operational_iocs", "").split(";"):
            if item.strip():
                governance.add(item.strip())
    fmt = lambda s: "\n".join(f"• {x}" for x in s) if s else "(none recorded)"
    return fmt(onchain), fmt(behavioral), fmt(governance)


def analyse_framework(framework_text: str, incidents: list[dict]) -> str:
    onchain, behavioral, governance = build_ioc_summary(incidents)
    prompt = REVIEW_PROMPT.format(
        framework=framework_text,
        onchain=onchain,
        behavioral=behavioral,
        governance=governance,
    )
    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL, contents=prompt
    )
    return response.text.strip()


# ── Provenance graph builder ───────────────────────────────────────────────────

def build_graph_image(incidents: list[dict]) -> io.BytesIO:
    G = nx.DiGraph()
    node_colors = {}
    node_labels = {}

    for row in incidents:
        inc_name = row.get("incident_name", "").strip()
        if not inc_name:
            continue
        inc_id = f"INC::{inc_name}"
        G.add_node(inc_id)
        node_colors[inc_id] = INCIDENT_COLOR
        node_labels[inc_id] = "\n".join(
            inc_name[i:i+20] for i in range(0, len(inc_name), 20)
        )

        for cat, key in [
            ("on_chain",   "on_chain_iocs"),
            ("behavioral", "behavioral_iocs"),
            ("governance", "governance_operational_iocs"),
        ]:
            raw = row.get(key, "")
            for idx, ioc in enumerate(raw.split(";") if raw else []):
                ioc = ioc.strip()
                if not ioc:
                    continue
                ioc_id = f"{cat}::{inc_name}::{idx}"
                G.add_node(ioc_id)
                node_colors[ioc_id] = IOC_COLORS[cat]
                short = ioc[:40] + ("…" if len(ioc) > 40 else "")
                node_labels[ioc_id] = "\n".join(
                    short[i:i+20] for i in range(0, len(short), 20)
                )
                G.add_edge(inc_id, ioc_id)

    if len(G.nodes) == 0:
        fig, ax = plt.subplots(figsize=(6, 4), facecolor="#0d1117")
        ax.text(
            0.5, 0.5,
            "No incidents logged yet.\nUpload a report to get started.",
            ha="center", va="center", color="white", fontsize=14,
        )
        ax.axis("off")
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="#0d1117")
        plt.close(fig)
        buf.seek(0)
        return buf

    incident_nodes = [n for n in G.nodes if n.startswith("INC::")]
    if len(incident_nodes) == 1:
        pos = nx.spring_layout(G, seed=42, k=2.5)
    else:
        pos = nx.shell_layout(
            G,
            nlist=[
                incident_nodes,
                [n for n in G.nodes if not n.startswith("INC::")],
            ],
        )

    colors = [node_colors.get(n, "#888888") for n in G.nodes]
    sizes  = [2200 if n.startswith("INC::") else 900 for n in G.nodes]
    labels = {n: node_labels.get(n, n) for n in G.nodes}

    fig, ax = plt.subplots(figsize=(16, 10), facecolor="#0d1117")
    ax.set_facecolor("#0d1117")
    nx.draw_networkx_edges(
        G, pos, ax=ax, edge_color="#555555", arrows=True,
        arrowstyle="-|>", arrowsize=15, width=1.2, alpha=0.7,
    )
    nx.draw_networkx_nodes(
        G, pos, ax=ax, node_color=colors, node_size=sizes, alpha=0.95
    )
    nx.draw_networkx_labels(
        G, pos, labels=labels, ax=ax,
        font_size=6, font_color="white", font_weight="bold",
    )

    legend_handles = [
        mpatches.Patch(color=INCIDENT_COLOR,           label="Incident"),
        mpatches.Patch(color=IOC_COLORS["on_chain"],   label="On-Chain IoC"),
        mpatches.Patch(color=IOC_COLORS["behavioral"], label="Behavioral IoC"),
        mpatches.Patch(color=IOC_COLORS["governance"], label="Governance/Operational IoC"),
    ]
    ax.legend(
        handles=legend_handles, loc="upper left",
        facecolor="#1a1a2e", edgecolor="#444", labelcolor="white", fontsize=9,
    )
    ax.set_title(
        "Blockchain Incident Provenance Graph",
        color="white", fontsize=14, pad=12, fontweight="bold",
    )
    ax.axis("off")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor="#0d1117")
    plt.close(fig)
    buf.seek(0)
    return buf


# ── HTML escape ────────────────────────────────────────────────────────────────

def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


# ── ChromaDB helpers ───────────────────────────────────────────────────────────

def _chroma_index_incident(row_id: int, text: str, incident_name: str,
                            content_hash: str) -> None:
    """Index an incident into ChromaDB (non-fatal if it fails)."""
    try:
        col = chroma.get_collection("incidents")
        encrypted = chroma.encrypt(text[:1000])
        col.upsert(
            ids=[str(row_id)],
            documents=[encrypted],
            metadatas=[{
                "incident_name": incident_name,
                "content_hash":  content_hash,
            }],
        )
        logger.debug("ChromaDB: indexed incident id=%s name=%r", row_id, incident_name)
    except Exception as e:
        logger.warning("ChromaDB incident index failed (non-fatal): %s", e)


def _chroma_index_policy(policy_id_or_name: str, text: str,
                          policy_name: str) -> None:
    """Index a company policy into ChromaDB (non-fatal if it fails)."""
    try:
        col = chroma.get_collection("company_policies")
        col.upsert(
            ids=[policy_id_or_name],
            documents=[chroma.encrypt(text[:1000])],
            metadatas=[{"policy_name": policy_name}],
        )
        logger.debug("ChromaDB: indexed policy %r", policy_name)
    except Exception as e:
        logger.warning("ChromaDB policy index failed (non-fatal): %s", e)


