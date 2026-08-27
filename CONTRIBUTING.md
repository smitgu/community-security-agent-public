# Contributing

## Scope

- In scope: backend, frontend, external integrations, tests, and documentation.
- Current target: local evaluation of security-intelligence collection and
  review.
- Out of scope: production deployment, multi-tenant authentication, and real
  confidential or regulated data.

Open an issue first for large changes, new external services, or changes to data
boundaries.

## Review focus

- Correctness and clear scope
- Security, privacy, secrets, and external data flows
- API, database, and integration compatibility
- Relevant tests or manual verification
- Documentation for changed setup or behaviour

Do not commit credentials, local databases, or real incident/organisation data.
Report security-sensitive findings privately.

## Pull requests

1. Branch from `main` and keep each PR focused on one change.
2. Run only the checks relevant to the change.
3. Update `README.md` or `.env.example` when needed.
4. Link an issue when applicable, and describe the change, verification, and
   known limitations.
5. Include screenshots for visible UI changes.
