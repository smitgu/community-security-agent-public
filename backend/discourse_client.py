import os
import re
import json
import httpx
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

MOCK_DB_PATH = os.path.join(os.path.dirname(__file__), "discourse_mock_db.json")

class DiscourseClient:
    def __init__(self):
        load_dotenv()
        self.url = os.getenv("DISCOURSE_URL", "").strip().rstrip("/")
        self.api_key = os.getenv("DISCOURSE_API_KEY", "").strip()
        self.api_username = os.getenv("DISCOURSE_API_USERNAME", "").strip()
        self.category_id = os.getenv("DISCOURSE_CATEGORY_ID", "").strip()
        
        # Check if we should operate in Mock Mode
        self.is_mock = not (self.url and self.api_key and self.api_username)
        if self.is_mock:
            logger.info("DiscourseClient: Running in MOCK MODE (using discourse_mock_db.json)")
            self._init_mock_db()
        else:
            logger.info(f"DiscourseClient: Configured for active connection to {self.url}")

    def _init_mock_db(self):
        if not os.path.exists(MOCK_DB_PATH):
            # Synthetic fixture used only by the local mock integration.
            seed_data = [
                {
                    "id": 1,
                    "title": "🧪 [INCIDENT] Synthetic Bridge Incident",
                    "raw": """# 🧪 Synthetic Security Finding: Bridge Incident
> Test fixture only. This is not a real incident or verified threat intelligence.

*Published by the local Community Security Agent mock.*

### ⛓️ On-Chain Indicators (IoCs)
- Example TxHash: 0x0000000000000000000000000000000000000000000000000000000000000001
- Example Contract: 0x0000000000000000000000000000000000000002

### 🧠 Behavioral Indicators
- synthetic cross-chain message replay
- synthetic withdrawal validation bypass

### 🔒 Governance & Operational Indicators
- synthetic signer rotation delay

---
### 🤖 Autonomous Agent Metadata (Structured Parse Block)
```json
{
  "incident_name": "Synthetic Bridge Incident",
  "on_chain_iocs": [
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002"
  ],
  "behavioral_iocs": [
    "synthetic cross-chain message replay",
    "synthetic withdrawal validation bypass"
  ],
  "governance_operational_iocs": [
    "synthetic signer rotation delay"
  ]
}
```
""",
                    "created_at": "2026-01-01T00:00:00Z",
                    "username": "community_security_agent_mock"
                }
            ]
            with open(MOCK_DB_PATH, "w") as f:
                json.dump(seed_data, f, indent=2)

    def _read_mock_db(self) -> list:
        try:
            with open(MOCK_DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_mock_db(self, data: list):
        with open(MOCK_DB_PATH, "w") as f:
            json.dump(data, f, indent=2)

    def _format_markdown_post(self, name: str, on_chain: list, behavioral: list, gov: list) -> str:
        on_chain_str = "\n".join(f"- {x}" for x in on_chain) if on_chain else "- (none)"
        behavioral_str = "\n".join(f"- {x}" for x in behavioral) if behavioral else "- (none)"
        gov_str = "\n".join(f"- {x}" for x in gov) if gov else "- (none)"
        
        structured_data = {
            "incident_name": name,
            "on_chain_iocs": on_chain,
            "behavioral_iocs": behavioral,
            "governance_operational_iocs": gov
        }
        
        return f"""# 🛡️ Security Finding: {name}
*Published automatically by Community Security Agent.*

### ⛓️ On-Chain Indicators (IoCs)
{on_chain_str}

### 🧠 Behavioral Indicators
{behavioral_str}

### 🔒 Governance & Operational Indicators
{gov_str}

---
### 🤖 Autonomous Agent Metadata (Structured Parse Block)
```json
{json.dumps(structured_data, indent=2)}
```
"""

    async def post_finding(self, name: str, on_chain: list, behavioral: list, gov: list) -> dict:
        """Create or update a topic in the Discourse forum."""
        raw_content = self._format_markdown_post(name, on_chain, behavioral, gov)
        title = f"🛡️ [INCIDENT] {name}"
        
        if self.is_mock:
            db_data = self._read_mock_db()
            # Check if this topic already exists in the mock DB
            existing_idx = next((i for i, x in enumerate(db_data) if x["title"] == title), None)
            
            post_data = {
                "id": existing_idx if existing_idx is not None else len(db_data) + 1,
                "title": title,
                "raw": raw_content,
                "created_at": "Just now",
                "username": "community_security_agent"
            }
            
            if existing_idx is not None:
                db_data[existing_idx] = post_data
            else:
                db_data.append(post_data)
                
            self._write_mock_db(db_data)
            return {"status": "success", "mock": True, "topic_id": post_data["id"]}
            
        else:
            # Live Discourse API call
            headers = {
                "Api-Key": self.api_key,
                "Api-Username": self.api_username,
                "Content-Type": "application/json"
            }
            payload = {
                "title": title,
                "raw": raw_content
            }
            if self.category_id:
                payload["category"] = int(self.category_id)
                
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{self.url}/posts.json", json=payload, headers=headers)
                resp.raise_for_status()
                return resp.json()

    async def fetch_findings(self) -> list[dict]:
        """Fetch and parse incident data from the Discourse board."""
        if self.is_mock:
            posts = self._read_mock_db()
        else:
            # Live Discourse fetch (categories/latest topics, reading post contents)
            headers = {
                "Api-Key": self.api_key,
                "Api-Username": self.api_username
            }
            async with httpx.AsyncClient() as client:
                # 1. Fetch latest topics
                latest_url = f"{self.url}/latest.json"
                resp = await client.get(latest_url, headers=headers)
                resp.raise_for_status()
                topics = resp.json().get("topic_list", {}).get("topics", [])
                
                posts = []
                for topic in topics:
                    # Filter to incident posts
                    if "[INCIDENT]" in topic.get("title", ""):
                        # 2. Fetch the first post details for the raw content
                        t_url = f"{self.url}/t/{topic['id']}.json"
                        t_resp = await client.get(t_url, headers=headers)
                        t_data = t_resp.json()
                        first_post = t_data.get("post_stream", {}).get("posts", [{}])[0]
                        
                        posts.append({
                            "id": topic["id"],
                            "title": topic["title"],
                            "raw": first_post.get("raw", ""),
                            "created_at": topic.get("created_at"),
                            "username": first_post.get("username")
                        })
        
        # Parse the structured JSON out of each post's raw content
        incidents = []
        for post in posts:
            raw_text = post.get("raw", "")
            match = re.search(r"```json\s*(.*?)\s*```", raw_text, re.DOTALL)
            if match:
                try:
                    inc_data = json.loads(match.group(1))
                    inc_data["discourse_topic_id"] = post["id"]
                    inc_data["posted_at"] = post.get("created_at", "Just now")
                    inc_data["publisher"] = post.get("username", "system")
                    incidents.append(inc_data)
                except Exception as e:
                    logger.warning(f"Failed to parse structured JSON block from topic #{post['id']}: {e}")
            else:
                logger.warning(f"No structured JSON block found in topic #{post['id']}")
        return incidents
