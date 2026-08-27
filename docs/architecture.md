# Architecture

## Current system

```text
React/Vite UI -> FastAPI -> local sensitivity gate -> Gemini
                         -> PostgreSQL (incidents and audit records)
                         -> encrypted local ChromaDB index
                         <-> Discourse or a labelled local mock
```

FastAPI accepts chat and document input. Uploaded documents pass through a local
sensitivity check before Gemini analysis. PostgreSQL stores incidents and audit
records; ChromaDB stores encrypted snippets; Discourse optionally shares
findings. The current graph shows incident-to-IoC relationships.

The browser/API, Gemini, and Discourse are separate trust boundaries. Chat
intent routing currently reaches Gemini before the sensitivity gate, so chat
must not contain sensitive text.

## Target direction

Combine organisation assets and controls with incoming evidence, then match and
rank findings by exploitability and impact. Responses should show priority
actions, downgrade reasons, and traceable evidence. The current implementation
provides the IoC collection and sharing foundation; organisation-aware matching,
prioritisation, and evidence drill-down are planned extensions.
