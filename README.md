# Community Security Agent

Community Security Agent is a local-first web application for collecting, reviewing,
and visualising blockchain-security incident intelligence.

The project is developed and maintained by researchers and contributors
working with the [Cyber SMART Research Center](https://cybersmartcenter.org/),
a U.S. National Science Foundation Industry-University Cooperative Research
Center (IUCRC).

The application can:

- classify chat requests and extract indicators of compromise with Gemini;
- accept PDF, DOCX, Markdown, and text uploads;
- store incident records in PostgreSQL;
- maintain an encrypted local ChromaDB index;
- visualise relationships between incidents and indicators; and
- use either a configured Discourse instance or a local mock store.

## Project status

This project is a development preview intended for local evaluation.
Authentication uses a single-user local mechanism, and the API binds to
localhost by default. It has not been hardened for production or multi-user
deployment.

Documents classified as public or scrubbed internal content may be sent to
Google's Gemini API. Review the sensitivity rules in `backend/sensitivity.py`
before using real data. Do not use confidential, personal, regulated, or
otherwise restricted data unless you have independently validated the controls
and your legal basis for processing it.

## Architecture

- `backend/` contains the FastAPI application, PostgreSQL access, sensitivity
  controls, Gemini integration, ChromaDB index, and optional Discourse client.
- `frontend/` contains the React and Vite user interface.
- PostgreSQL and ChromaDB store local application data.
- Discourse integration uses a clearly labelled synthetic local mock when no
  external instance is configured.

See [`docs/architecture.md`](docs/architecture.md) for the current data flow,
trust boundaries, and target direction.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for project scope, review expectations,
and the pull request process.

## Prerequisites

- Python 3.11 or newer
- Node.js 20.19.x, or Node.js 22.12 or newer
- Docker with Docker Compose
- A Google Gemini API key

## Local setup

1. Copy the example environment file and replace every placeholder value:

   ```powershell
   Copy-Item .env.example .env
   ```

   On macOS or Linux, use `cp .env.example .env`.

2. Start PostgreSQL:

   ```powershell
   docker compose up -d postgres
   ```

3. Create a Python virtual environment and install backend dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r backend/requirements.txt
   ```

   The optional large spaCy model improves local entity redaction:

   ```powershell
   python -m spacy download en_core_web_lg
   ```

   Without that model, the application still starts and uses regex-based sensitivity checks.

4. Start the API from the repository root:

   ```powershell
   python backend/api.py
   ```

5. In a second terminal, install and start the React UI:

   ```powershell
   Set-Location frontend
   npm ci
   npm run dev
   ```

6. Open <http://localhost:5173> and sign in with `DEMO_USERNAME` and `DEMO_PASSWORD` from `.env`.

The API health endpoint is available at <http://127.0.0.1:8000/health>.

## Local data

- PostgreSQL data is kept in the Docker volume `postgres_data`.
- ChromaDB data is written to `./chroma_db` by default.
- With no Discourse credentials, demo posts are written to `backend/discourse_mock_db.json`.
- `.env`, local databases, build outputs, and the mock Discourse store are ignored by Git.

To stop PostgreSQL while retaining its data:

```powershell
docker compose down
```

## License

Copyright (c) 2026 Community Security Agent Contributors.

This project is licensed under the [MIT License](LICENSE). Third-party
dependencies installed through the Python and npm package manifests remain
subject to their respective licenses and are not relicensed by this project.
