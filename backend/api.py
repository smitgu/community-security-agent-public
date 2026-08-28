import os
import io
import json
import logging
import asyncio
import secrets
from pathlib import Path
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv

# Load the repository root's .env before importing local modules.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import db
import chroma
from core_agent import (
    classify_intent, classify_contribute_or_query, extract_iocs, 
    run_audit_comparison, analyse_framework, build_graph_image, 
    _content_hash, extract_text, extract_text_from_pdf, 
    extract_text_from_docx, build_ioc_summary, format_audit_report,
    _chroma_index_incident, _chroma_index_policy
)
from sensitivity import sensitivity_gate, deanonymize, ConfidentialDocumentError
from discourse_client import DiscourseClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Community Security Agent API")
discourse_client = DiscourseClient()

DEMO_USERNAME = os.getenv("DEMO_USERNAME", "admin")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "")
DEMO_TOKEN = os.getenv("DEMO_TOKEN", "")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.on_event("startup")
async def startup_event():
    if not DEMO_PASSWORD or not DEMO_TOKEN:
        raise RuntimeError("DEMO_PASSWORD and DEMO_TOKEN must be set in .env")
    await db.init_db()
    await chroma.init_chroma()
    logger.info("Database and ChromaDB initialized.")

# --- Models ---
class ChatMessage(BaseModel):
    message: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Auth ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    username_ok = secrets.compare_digest(form_data.username, DEMO_USERNAME)
    password_ok = secrets.compare_digest(form_data.password, DEMO_PASSWORD)
    if username_ok and password_ok:
        return {"access_token": DEMO_TOKEN, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    if DEMO_TOKEN and secrets.compare_digest(token, DEMO_TOKEN):
        return {"username": DEMO_USERNAME, "role": "admin"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# --- Core Endpoints ---

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/api/graph")
async def get_graph(current_user: dict = Depends(get_current_user)):
    try:
        incidents = await db.read_all_incidents()
        img_buf = build_graph_image(incidents)
        return StreamingResponse(img_buf, media_type="image/png")
    except Exception as e:
        logger.error(f"Error generating graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/top5")
async def get_top5(current_user: dict = Depends(get_current_user)):
    try:
        incidents = await db.read_all_incidents()
        if not incidents:
            return []
        
        def count_iocs(row: dict) -> int:
            total = 0
            for field in ("on_chain_iocs", "behavioral_iocs", "governance_operational_iocs"):
                items = row.get(field, "")
                if items:
                    total += len([x for x in items.split(";") if x.strip()])
            return total

        ranked = sorted(incidents, key=count_iocs, reverse=True)
        return ranked[:5]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat")
async def chat_handler(msg: ChatMessage, current_user: dict = Depends(get_current_user)):
    text = msg.message.strip()
    intent = classify_intent(text)
    
    if intent == "report":
        # The router labels pasted incident reports as "report"; decide
        # whether to save them (contribute) or only analyse (query).
        intent = classify_contribute_or_query(text)

    if intent in ["query", "contribute"]:
        return await process_text_report(text, intent)
    elif intent == "top5":
        return {"intent": "top5", "message": "Fetching top 5 incidents. Please check the dashboard."}
    elif intent == "graph":
        return {"intent": "graph", "message": "Graph generated. Please check the dashboard."}
    else:
        return {
            "intent": intent, 
            "message": "I understood your intent as: " + intent + ". Use the dashboard to view graphs and upload documents."
        }

@app.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...), 
    action: str = Form("extract"), # "extract", "review", "audit_framework", "audit_policy"
    policyName: str = Form(""),
    frameworkText: str = Form(""),
    current_user: dict = Depends(get_current_user)
):
    try:
        content = await file.read()
        filename = file.filename
        text = extract_text(content, filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to extract text: {e}")

    if not text.strip():
        raise HTTPException(status_code=400, detail="Document appears empty or unreadable.")

    if action == "review":
        # Review framework against the threat intelligence database
        try:
            safe_text, level, mapping, entities = sensitivity_gate(text)
        except ConfidentialDocumentError:
            return {"status": "blocked", "message": "Framework Blocked — CONFIDENTIAL."}

        # Write sensitivity audit log
        try:
            from sensitivity import encrypt_mapping
            enc_map = encrypt_mapping(mapping) if level == "INTERNAL" else None
            await db.write_sensitivity_audit(
                classification=level,
                action_taken="SCRUBBED" if level == "INTERNAL" else "PASSED",
                detected_entities=entities,
                filename=filename,
                raw_document=None if level == "PUBLIC" else text,
                encrypted_mapping=enc_map
            )
        except Exception as audit_err:
            logger.warning(f"Failed to write audit log: {audit_err}")

        incidents = await db.read_all_incidents()
        recommendations = analyse_framework(safe_text, incidents)
        
        # De-anonymise recommendations back to real names
        recommendations = deanonymize(recommendations, mapping)
        return {"status": "success", "recommendations": recommendations}
    
    elif action == "audit_policy":
        # Compare provided frameworkText against this uploaded policy text
        try:
            safe_text, level, mapping, entities = sensitivity_gate(text)
        except ConfidentialDocumentError:
            return {"status": "blocked", "message": "Policy Blocked — CONFIDENTIAL."}

        # Write sensitivity audit log
        try:
            from sensitivity import encrypt_mapping
            enc_map = encrypt_mapping(mapping) if level == "INTERNAL" else None
            await db.write_sensitivity_audit(
                classification=level,
                action_taken="SCRUBBED" if level == "INTERNAL" else "PASSED",
                detected_entities=entities,
                filename=filename,
                raw_document=None if level == "PUBLIC" else text,
                encrypted_mapping=enc_map
            )
        except Exception as audit_err:
            logger.warning(f"Failed to write audit log: {audit_err}")

        result = run_audit_comparison(frameworkText, safe_text)
        
        # De-anonymise comparison results JSON
        import json as _json
        try:
            result_str = _json.dumps(result)
            restored_str = deanonymize(result_str, mapping)
            result = _json.loads(restored_str)
        except Exception as deanonymize_err:
            logger.warning(f"Failed to de-anonymise audit results: {deanonymize_err}")

        return {"status": "success", "audit_report": format_audit_report(result), "raw_result": result}
    
    else:
        # Default: extract IoCs
        return await process_text_report(text, "contribute", source_file=filename)

async def process_text_report(text: str, intent: str, source_file: str = "upload"):
    try:
        safe_text, level, mapping, entities = sensitivity_gate(text)
    except ConfidentialDocumentError:
        # Log blocked CONFIDENTIAL documents in the database
        try:
            from sensitivity import _regex_scan, _ner_scan
            _, r_hits = _regex_scan(text)
            _, n_hits = _ner_scan(text)
            all_hits = r_hits + n_hits
            ents = [{"entity_type": e.entity_type, "original_value": e.original_value, "source": e.source} for e in all_hits]
            await db.write_sensitivity_audit(
                classification="CONFIDENTIAL",
                action_taken="BLOCKED",
                detected_entities=ents,
                filename=source_file,
                raw_document=text,
                encrypted_mapping=None
            )
        except Exception as audit_err:
            logger.warning(f"Failed to write CONFIDENTIAL audit log: {audit_err}")
        return {"status": "blocked", "message": "Document Blocked — CONFIDENTIAL."}

    # Write sensitivity audit log for processed documents
    encrypted_mapping_str = None
    if level == "INTERNAL":
        from sensitivity import encrypt_mapping
        encrypted_mapping_str = encrypt_mapping(mapping)
        
    try:
        await db.write_sensitivity_audit(
            classification=level,
            action_taken="SCRUBBED" if level == "INTERNAL" else "PASSED",
            detected_entities=entities,
            filename=source_file,
            raw_document=None if level == "PUBLIC" else text,
            encrypted_mapping=encrypted_mapping_str
        )
    except Exception as audit_err:
        logger.warning(f"Failed to write audit log: {audit_err}")

    try:
        iocs = extract_iocs(safe_text, _mapping=mapping)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gemini extraction failed: {e}")

    incident_name = iocs.get("incident_name", "Unknown")
    onchain = iocs.get("on_chain_iocs", [])
    behavioral = iocs.get("behavioral_iocs", [])
    governance = iocs.get("governance_operational_iocs", [])

    if intent == "query":
        return {
            "status": "success",
            "mode": "query",
            "incident_name": incident_name,
            "on_chain_iocs": onchain,
            "behavioral_iocs": behavioral,
            "governance_operational_iocs": governance,
            "message": "Extracted IoCs (Not saved to KB)."
        }
    
    # Save to DB (contribute)
    doc_hash = _content_hash(text)
    try:
        hash_row_id, hash_row = await db.find_row_by_hash(doc_hash)
        if hash_row_id is not None:
            return {"status": "success", "mode": "duplicate", "message": "Exact duplicate document detected."}
    except Exception:
        pass

    try:
        existing_row_id, existing_row = await db.find_existing_row(incident_name)
        if existing_row_id is not None:
            added = await db.update_existing_incident(
                existing_row_id, existing_row,
                {"on_chain_iocs": onchain, "behavioral_iocs": behavioral, "governance_operational_iocs": governance}
            )
            await db.stamp_source_hash(existing_row_id, existing_row.get("source_file", ""), doc_hash)
            _chroma_index_incident(existing_row_id, text, incident_name, doc_hash)
            
            # Post background update to Discourse
            try:
                # Find all current indicators in DB to publish complete updated view
                asyncio.create_task(discourse_client.post_finding(
                    incident_name,
                    [x.strip() for x in (existing_row.get("on_chain_iocs", "") + ";" + ";".join(onchain)).split(";") if x.strip()],
                    [x.strip() for x in (existing_row.get("behavioral_iocs", "") + ";" + ";".join(behavioral)).split(";") if x.strip()],
                    [x.strip() for x in (existing_row.get("governance_operational_iocs", "") + ";" + ";".join(governance)).split(";") if x.strip()]
                ))
            except Exception as discourse_err:
                logger.warning(f"Failed to queue Discourse update for merged incident: {discourse_err}")
                
            return {"status": "success", "mode": "merged", "added": added, "message": f"Merged new IoCs into existing incident: {incident_name}"}
        else:
            new_id = await db.append_incident_row(
                incident_name, onchain, behavioral, governance, source_file, content_hash=doc_hash
            )
            _chroma_index_incident(new_id, text, incident_name, doc_hash)
            
            # Post background finding to Discourse
            try:
                asyncio.create_task(discourse_client.post_finding(
                    incident_name, onchain, behavioral, governance
                ))
            except Exception as discourse_err:
                logger.warning(f"Failed to queue Discourse post for new incident: {discourse_err}")
                
            return {
                "status": "success", "mode": "created", 
                "incident_name": incident_name,
                "on_chain_iocs": onchain, "behavioral_iocs": behavioral, "governance_operational_iocs": governance,
                "message": f"New incident created: {incident_name}"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database write failed: {e}")

# --- Discourse Integration Endpoints ---

@app.get("/api/discourse/status")
async def get_discourse_status(current_user: dict = Depends(get_current_user)):
    return {
        "status": "connected" if not discourse_client.is_mock else "mock_mode",
        "url": discourse_client.url or "Local Mock File (discourse_mock_db.json)",
        "username": discourse_client.api_username or "community_security_agent",
        "category_id": discourse_client.category_id or "Default"
    }

@app.get("/api/discourse/findings")
async def get_discourse_findings(current_user: dict = Depends(get_current_user)):
    try:
        findings = await discourse_client.fetch_findings()
        return findings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Discourse findings: {e}")

@app.post("/api/discourse/sync")
async def sync_discourse_findings(current_user: dict = Depends(get_current_user)):
    try:
        findings = await discourse_client.fetch_findings()
        synced_created = 0
        synced_merged = 0
        total_added_iocs = 0
        
        for item in findings:
            name = item.get("incident_name")
            onchain = item.get("on_chain_iocs", [])
            behavioral = item.get("behavioral_iocs", [])
            gov = item.get("governance_operational_iocs", [])
            
            if not name:
                continue
                
            # 1. Fuzzy match against existing incidents in local database
            existing_id, existing_row = await db.find_existing_row(name)
            if existing_id is not None:
                added = await db.update_existing_incident(
                    existing_id, existing_row,
                    {"on_chain_iocs": onchain, "behavioral_iocs": behavioral, "governance_operational_iocs": gov}
                )
                if added:
                    synced_merged += 1
                    total_added_iocs += len(added)
            else:
                new_id = await db.append_incident_row(
                    name, onchain, behavioral, gov, f"Discourse Topic #{item.get('discourse_topic_id')}"
                )
                synced_created += 1
                total_added_iocs += (len(onchain) + len(behavioral) + len(gov))
                
        return {
            "status": "success",
            "created": synced_created,
            "merged": synced_merged,
            "total_iocs_added": total_added_iocs,
            "message": f"Sync completed successfully. Created {synced_created} new, merged {synced_merged} existing records. Added {total_added_iocs} new threat indicators!"
        }
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise HTTPException(status_code=500, detail=f"Sync failed: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
